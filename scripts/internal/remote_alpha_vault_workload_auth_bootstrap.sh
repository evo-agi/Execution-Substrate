remote_alpha_vault_workload_auth_bootstrap_schema_version="execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1"

remote_alpha_vault_workload_auth_bootstrap_defaults() {
  REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="${REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH:-/etc/execution-substrate/vault/workload-zone-vault-config.json}"
  REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="${REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json}"
  REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_SOCKET_PATH="${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_SOCKET_PATH:-/run/spire/server/private/api.sock}"
  REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND="${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND:-spire-server}"
  REMOTE_ALPHA_BOOTSTRAP_BOUND_ISSUER="${REMOTE_ALPHA_BOOTSTRAP_BOUND_ISSUER:-spiffe://execution.internal}"
  # Lifetime and source limits for the Vault tokens that workload logins
  # through role service_execution receive. Non-secret.
  REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL="${REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL:-15m}"
  REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL="${REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL:-30m}"
  REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS="${REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS:-172.17.0.0/16}"
  # Where the Vault authority comes from (non-secret choice):
  #   root-token  the operator types an existing root token at the prompt;
  #   unseal-key  the operator types the unseal key; the helper makes a
  #               short-lived root token with it (sys/generate-root), uses it
  #               in memory and revokes it before it exits.
  REMOTE_ALPHA_BOOTSTRAP_AUTHORITY="${REMOTE_ALPHA_BOOTSTRAP_AUTHORITY:-root-token}"
  # Where the proof value written to both proof paths comes from:
  #   prompt    the operator types it at a hidden prompt;
  #   generate  the helper generates a random value and never shows it.
  REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE="${REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE:-prompt}"
  # Vault 2.x refuses sys/generate-root without a token unless its server
  # configuration names it in enable_unauthenticated_access. With unseal-key:
  #   as-configured     never touch Vault's configuration; fail before the
  #                     key is used if Vault refuses;
  #   temporary-config  if Vault refuses, add that one setting to
  #                     REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH, reload Vault
  #                     (no restart, no reseal), make the root token, then put
  #                     the file back byte for byte and reload again.
  REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS="${REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS:-as-configured}"
  REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH="${REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH:-/etc/vault.d/vault.hcl}"
  REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND="${REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND:-systemctl reload vault.service}"
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
  Non-secret choices (environment):
    REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=root-token (default): prompt for an
      existing root token.
    REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key: prompt for the unseal key
      instead; the helper makes a short-lived root token through
      sys/generate-root (one key share), keeps it in memory only, and revokes
      it before it exits. A failed revoke fails the run and says so.
    REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=prompt (default) or generate: with
      generate, the proof value is random, generated in memory, written to
      the proof paths and never shown.
    REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=as-configured (default) or
      temporary-config, for unseal-key only. Vault 2.x refuses
      sys/generate-root without a token unless its server configuration
      holds enable_unauthenticated_access = ["generate-root"]. The helper asks
      Vault (read-only) before it asks for the key. as-configured never
      touches Vault's configuration and fails there when Vault refuses. temporary-config then adds that one line to
      REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH (default /etc/vault.d/vault.hcl),
      runs REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND (default
      "systemctl reload vault.service": a reload, not a restart, so Vault
      stays unsealed), makes the root token, and then writes the file back
      byte for byte, reloads again and checks that Vault refuses again. It
      refuses a configuration file that already mentions
      enable_unauthenticated_access.
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
  auth/jwt/config with all selected SPIRE JWT validation public keys and bound issuer
  role service_execution, with token_ttl, token_max_ttl and token_bound_cidrs
  (defaults 15m, 30m and 172.17.0.0/16; non-secret environment
  REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL, REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL,
  REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS)
  policy runtime-identity-proof
  KV v2 proof paths proof-secrets/data/runtime-identity-vault-login and
  proof-secrets/data/codex-runtime-profile
  proof runtime field api_key present and non-empty, value never printed
  before writing, all earlier versions and the metadata of both proof paths
  are deleted permanently, so no earlier value (for example an API key
  written there by hand) stays readable
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
    "${remote_alpha_vault_workload_auth_bootstrap_schema_version}" \
    "${REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL}" \
    "${REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL}" \
    "${REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS}" \
    "${REMOTE_ALPHA_BOOTSTRAP_AUTHORITY}" \
    "${REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE}" \
    "${REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS}" \
    "${REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH}" \
    "${REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND}" <<'PY'
import base64
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

CONFIG_PATH = pathlib.Path(sys.argv[1])
SUMMARY_PATH = pathlib.Path(sys.argv[2])
SPIRE_SOCKET = sys.argv[3]
SPIRE_COMMAND = sys.argv[4]
BOUND_ISSUER = sys.argv[5]
SCHEMA_VERSION = sys.argv[6]
TOKEN_TTL_TEXT = sys.argv[7]
TOKEN_MAX_TTL_TEXT = sys.argv[8]
TOKEN_BOUND_CIDRS_TEXT = sys.argv[9]
AUTHORITY_SOURCE = sys.argv[10]
PROOF_VALUE_SOURCE = sys.argv[11]
GENERATE_ROOT_ACCESS = sys.argv[12]
VAULT_CONFIG_PATH = pathlib.Path(sys.argv[13])
VAULT_RELOAD_COMMAND_TEXT = sys.argv[14]
# The one setting temporary-config adds, and how long to wait for a reload.
UNAUTHENTICATED_GENERATE_ROOT_SETTING = 'enable_unauthenticated_access = ["generate-root"]'
UNAUTHENTICATED_ACCESS_KEYWORD = "enable_unauthenticated_access"
VAULT_RELOAD_WAIT_SECONDS = 20
# Upper bound for both token lifetimes: a workload login is short-lived by
# design and logs in again with a fresh JWT-SVID from the runtime helper.
TOKEN_TTL_CEILING_SECONDS = 24 * 3600

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
        "role_token_limits": {
            "token_ttl": TOKEN_TTL_TEXT,
            "token_max_ttl": TOKEN_MAX_TTL_TEXT,
            "token_bound_cidrs": TOKEN_BOUND_CIDRS_TEXT.split(),
        },
        "proof_path_history": "all_earlier_versions_and_metadata_deleted_before_write",
        "authority_source": AUTHORITY_SOURCE,
        "proof_value_source": PROOF_VALUE_SOURCE,
        "generate_root_access": GENERATE_ROOT_ACCESS,
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


def parse_duration_seconds(text):
    match = re.fullmatch(r"([1-9][0-9]{0,5})([smh])", text or "")
    if not match:
        return None
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]


def validate_role_token_limits():
    """Validate the non-secret role token limits before any prompt or Vault
    write. Returns (ttl_text, max_ttl_text, cidr_list)."""
    phase = "role_token_limits"
    set_next_operation(phase)
    ttl = parse_duration_seconds(TOKEN_TTL_TEXT)
    max_ttl = parse_duration_seconds(TOKEN_MAX_TTL_TEXT)
    if ttl is None or max_ttl is None:
        raise_failure(phase, "config_invalid", message_class="token_ttl_not_a_duration")
    if ttl > max_ttl or max_ttl > TOKEN_TTL_CEILING_SECONDS:
        raise_failure(phase, "config_invalid", message_class="token_ttl_out_of_range")
    cidrs = []
    for item in TOKEN_BOUND_CIDRS_TEXT.split():
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            raise_failure(phase, "config_invalid", message_class="token_bound_cidr_invalid")
        if network.prefixlen == 0:
            raise_failure(phase, "config_invalid", message_class="token_bound_cidr_matches_everything")
        cidrs.append(str(network))
    if not cidrs:
        raise_failure(phase, "config_invalid", message_class="token_bound_cidrs_empty")
    set_status(
        phase,
        "pass",
        token_ttl=TOKEN_TTL_TEXT,
        token_max_ttl=TOKEN_MAX_TTL_TEXT,
        token_bound_cidrs=cidrs,
    )
    return TOKEN_TTL_TEXT, TOKEN_MAX_TTL_TEXT, cidrs


def validate_choices():
    phase = "bootstrap_choices"
    set_next_operation(phase)
    if AUTHORITY_SOURCE not in ("root-token", "unseal-key"):
        raise_failure(phase, "config_invalid", message_class="authority_not_root_token_or_unseal_key")
    if PROOF_VALUE_SOURCE not in ("prompt", "generate"):
        raise_failure(phase, "config_invalid", message_class="proof_value_not_prompt_or_generate")
    if GENERATE_ROOT_ACCESS not in ("as-configured", "temporary-config"):
        raise_failure(phase, "config_invalid", message_class="generate_root_access_not_as_configured_or_temporary_config")
    if GENERATE_ROOT_ACCESS == "temporary-config" and AUTHORITY_SOURCE != "unseal-key":
        raise_failure(phase, "config_invalid", message_class="generate_root_access_needs_unseal_key")
    set_status(
        phase,
        "pass",
        authority_source=AUTHORITY_SOURCE,
        proof_value_source=PROOF_VALUE_SOURCE,
        generate_root_access=GENERATE_ROOT_ACCESS,
    )


def vault_reload_argv():
    try:
        return shlex.split(VAULT_RELOAD_COMMAND_TEXT)
    except ValueError:
        return []


def preflight_temporary_generate_root_access():
    """With temporary-config, check before any prompt that the Vault
    configuration file can be changed and put back, and that the reload
    command exists. Nothing is changed here."""
    if GENERATE_ROOT_ACCESS != "temporary-config":
        return
    phase = "vault_config_preflight"
    set_next_operation(phase)
    path = VAULT_CONFIG_PATH
    if not path.is_absolute():
        raise_failure(phase, "config_invalid", message_class="vault_config_path_not_absolute")
    if path.is_symlink() or not path.is_file():
        raise_failure(phase, "config_invalid", message_class="vault_config_not_a_regular_file")
    try:
        raw = path.read_bytes()
    except OSError:
        raise_failure(phase, "config_unreadable", message_class="vault_config_unreadable")
    if UNAUTHENTICATED_ACCESS_KEYWORD.encode("ascii") in raw:
        raise_failure(phase, "config_invalid", message_class="vault_config_already_mentions_enable_unauthenticated_access")
    if not os.access(path, os.W_OK) or not os.access(path.parent, os.W_OK):
        raise_failure(phase, "config_unreadable", message_class="vault_config_not_writable")
    argv = vault_reload_argv()
    if not argv or shutil.which(argv[0]) is None:
        raise_failure(phase, "config_invalid", message_class="vault_reload_command_not_found")
    set_status(
        phase,
        "pass",
        path=str(path),
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        reload_command=argv,
    )


def generate_root_status(opener, address):
    """Unauthenticated read of the generate-root attempt. Returns (status,
    True) when Vault answers, and (None, False) when Vault refuses the
    request without a token (HTTP 403, the Vault 2.x default)."""
    try:
        return vault_request(opener, None, "GET", address, "sys/generate-root/attempt", allowed_statuses=(200,)), True
    except VaultAPIError as exc:
        if exc.message_class == "http_403":
            return None, False
        raise


def preflight_generate_root_access(opener, address):
    """With unseal-key, ask Vault before the key is asked for whether it
    answers generate-root without a token. Read-only."""
    phase = "generate_root_access_preflight"
    set_next_operation(phase)
    try:
        current, allowed = generate_root_status(opener, address)
    except Exception as exc:
        fail_from_exception(phase, exc)
    if not allowed and GENERATE_ROOT_ACCESS != "temporary-config":
        raise_failure(phase, "generate_root_unauthenticated_access_disabled", message_class="vault_refuses_generate_root_without_token")
    if allowed and current.get("started"):
        raise_failure(phase, "generate_root_attempt_in_progress", message_class="another_attempt_is_running")
    set_status(phase, "pass", vault_allows_generate_root_without_token=allowed, generate_root_access=GENERATE_ROOT_ACCESS)


class TemporaryGenerateRootAccess:
    """Adds UNAUTHENTICATED_GENERATE_ROOT_SETTING to Vault's configuration
    file for the generate-root step only, and puts the file back byte for
    byte (same owner and mode) afterwards. Both changes take effect through a
    reload, which leaves Vault unsealed."""

    MARKER = (
        "# Added for one run by Execution-Substrate "
        "scripts/remote_alpha_vault_workload_auth_bootstrap.sh, which removes it "
        "before it exits. If it is still here, remove it and reload Vault."
    )

    def __init__(self):
        self.original = None
        self.file_stat = None
        self.changed = False

    def _write(self, data):
        path = VAULT_CONFIG_PATH
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temp_path = pathlib.Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chown(temp_path, self.file_stat.st_uid, self.file_stat.st_gid)
            os.chmod(temp_path, stat.S_IMODE(self.file_stat.st_mode))
            os.replace(temp_path, path)
        except BaseException:
            cleanup_path(temp_path)
            raise

    def _reload(self):
        result = subprocess.run(
            vault_reload_argv(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        return result.returncode == 0

    def _wait_until(self, opener, address, allowed_wanted):
        deadline = time.monotonic() + VAULT_RELOAD_WAIT_SECONDS
        while True:
            _, allowed = generate_root_status(opener, address)
            if allowed == allowed_wanted:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)

    def enable(self, opener, address):
        phase = "generate_root_access_enable"
        set_next_operation(phase)
        path = VAULT_CONFIG_PATH
        try:
            self.file_stat = os.lstat(path)
            if not stat.S_ISREG(self.file_stat.st_mode):
                raise_failure(phase, "config_invalid", message_class="vault_config_not_a_regular_file")
            self.original = path.read_bytes()
            if UNAUTHENTICATED_ACCESS_KEYWORD.encode("ascii") in self.original:
                raise_failure(phase, "config_invalid", message_class="vault_config_already_mentions_enable_unauthenticated_access")
            separator = b"" if not self.original or self.original.endswith(b"\n") else b"\n"
            addition = (self.MARKER + "\n" + UNAUTHENTICATED_GENERATE_ROOT_SETTING + "\n").encode("ascii")
            self._write(self.original + separator + addition)
            self.changed = True
            if not self._reload():
                raise_failure(phase, "vault_reload_failed", message_class="vault_reload_command_failed")
            if not self._wait_until(opener, address, True):
                raise_failure(phase, "generate_root_access_not_enabled", message_class="vault_still_refuses_after_reload")
            set_status(phase, "pass", path=str(path), setting_added=UNAUTHENTICATED_GENERATE_ROOT_SETTING)
        except BootstrapFailure:
            raise
        except Exception as exc:
            fail_from_exception(phase, exc)

    def restore(self, opener, address):
        """Put the file back and reload. Returns True when the file is back
        byte for byte and Vault refuses generate-root without a token again,
        or when nothing was changed."""
        if not self.changed:
            return True
        phase = "generate_root_access_restore"
        file_restored = reloaded = refuses_again = False
        try:
            self._write(self.original)
            file_restored = VAULT_CONFIG_PATH.read_bytes() == self.original
        except Exception:
            file_restored = False
        if file_restored:
            try:
                reloaded = self._reload()
            except Exception:
                reloaded = False
        if reloaded:
            try:
                refuses_again = self._wait_until(opener, address, False)
            except Exception:
                refuses_again = False
        restored = file_restored and reloaded and refuses_again
        summary["operations"][phase] = {
            "status": "pass" if restored else "fail",
            "path": str(VAULT_CONFIG_PATH),
            "file_restored_byte_for_byte": file_restored,
            "vault_reloaded": reloaded,
            "vault_refuses_generate_root_without_token_again": refuses_again,
        }
        if restored:
            self.changed = False
        return restored


def decode_generated_root_token(encoded, otp):
    """Vault returns the generated root token XORed with the one-time
    password and base64 encoded (without padding)."""
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    otp_bytes = otp.encode("ascii")
    if len(raw) != len(otp_bytes):
        raise ValueError("generated_root_token_length_mismatch")
    return bytes(a ^ b for a, b in zip(raw, otp_bytes)).decode("ascii")


def cancel_generate_root(opener, address):
    try:
        vault_request(opener, None, "DELETE", address, "sys/generate-root/attempt", allowed_statuses=(200, 204))
        return True
    except Exception:
        return False


def generate_root_token(opener, address, unseal_key):
    """Make a root token from one unseal key share. The token, the nonce and
    the one-time password stay in memory and are never recorded. With
    temporary-config, Vault's configuration is put back before this returns;
    if that fails, the token is revoked and the run fails."""
    access = TemporaryGenerateRootAccess()
    try:
        token = generate_root_token_with_access(opener, address, unseal_key, access)
    except BaseException:
        access.restore(opener, address)
        raise
    if not access.restore(opener, address):
        if not revoke_token(opener, address, token, "generated_root_token_revoke"):
            fail_root_token_revoke()
        raise_failure("generate_root_access_restore", "vault_config_restore_failed", message_class="vault_config_or_reload_not_restored")
    return token


def generate_root_token_with_access(opener, address, unseal_key, access):
    phase = "generate_root_token"
    set_next_operation(phase)
    started = False
    try:
        current, allowed = generate_root_status(opener, address)
        summary["operations"]["generate_root_access_probe"] = {
            "status": "pass",
            "vault_allows_generate_root_without_token": allowed,
        }
        if not allowed:
            if GENERATE_ROOT_ACCESS != "temporary-config":
                raise_failure(phase, "generate_root_unauthenticated_access_disabled", message_class="vault_refuses_generate_root_without_token")
            access.enable(opener, address)
            set_next_operation(phase)
            current, allowed = generate_root_status(opener, address)
            if not allowed:
                raise_failure(phase, "generate_root_access_not_enabled", message_class="vault_still_refuses_after_reload")
        if current.get("started"):
            raise_failure(phase, "generate_root_attempt_in_progress", message_class="another_attempt_is_running")
        attempt = vault_request(opener, None, "PUT", address, "sys/generate-root/attempt", payload={}, allowed_statuses=(200,))
        started = True
        nonce = attempt.get("nonce")
        otp = attempt.get("otp")
        if not isinstance(nonce, str) or not nonce or not isinstance(otp, str) or not otp:
            raise_failure(phase, "vault_api_error", message_class="generate_root_attempt_incomplete")
        if attempt.get("required") != 1:
            raise_failure(phase, "unsupported_key_threshold", message_class="more_than_one_key_share_required")
        update = vault_request(
            opener,
            None,
            "PUT",
            address,
            "sys/generate-root/update",
            payload={"key": unseal_key, "nonce": nonce},
            allowed_statuses=(200,),
        )
        encoded = update.get("encoded_token") or update.get("encoded_root_token")
        if not update.get("complete") or not isinstance(encoded, str) or not encoded:
            raise_failure(phase, "generate_root_incomplete", message_class="key_share_not_accepted")
        started = False
        token = decode_generated_root_token(encoded, otp)
        set_status(phase, "pass", key_shares_used=1, value_recorded=False)
        return token
    except BootstrapFailure:
        if started:
            cancel_generate_root(opener, address)
        raise
    except Exception as exc:
        if started:
            cancel_generate_root(opener, address)
        fail_from_exception(phase, exc)


def revoke_token(opener, address, token, phase):
    try:
        vault_request(opener, token, "POST", address, "auth/token/revoke-self", payload={}, allowed_statuses=(200, 204))
        summary["operations"][phase] = {"status": "pass", "value_recorded": False}
        return True
    except Exception as exc:
        failure_class, message_class = classify_exception(exc)
        summary["operations"][phase] = {
            "status": "fail",
            "error_classification": failure_class,
            "failure_message_class": message_class,
        }
        return False


def fail_root_token_revoke():
    """Record and raise that the generated root token may still be valid,
    keeping the Vault error class of the failed revoke beside it."""
    phase = "generated_root_token_revoke"
    cause = (summary["operations"].get(phase) or {}).get("error_classification")
    message_class = "generated_root_token_may_still_be_valid"
    record_failure(phase, "root_token_revoke_failed", message_class=message_class)
    summary["operations"][phase]["vault_error_classification"] = cause
    raise BootstrapFailure(phase, "root_token_revoke_failed", message_class=message_class)


SHORT_LIVED_AUTHORITY_TTL = "15m"


def make_short_lived_authority(opener, address, unseal_key):
    """From the unseal key: generate a root token, use it once to create an
    orphan, non-renewable root-policy token that expires after
    SHORT_LIVED_AUTHORITY_TTL, and revoke the generated root token at once.
    Returns (short-lived token, every token value made, for the redaction
    scan). Even if the final revoke fails, nothing outlives the TTL."""
    root = generate_root_token(opener, address, unseal_key)
    made = [root]
    phase = "short_lived_authority_token"
    set_next_operation(phase)
    child = None
    try:
        created = vault_request(
            opener,
            root,
            "POST",
            address,
            "auth/token/create-orphan",
            payload={
                "policies": ["root"],
                "ttl": SHORT_LIVED_AUTHORITY_TTL,
                "explicit_max_ttl": SHORT_LIVED_AUTHORITY_TTL,
                "renewable": False,
                "display_name": "es-workload-auth-bootstrap",
            },
            allowed_statuses=(200,),
        )
        child = (created.get("auth") or {}).get("client_token")
        if not isinstance(child, str) or not child:
            raise VaultAPIError("invalid_response", "token_create_without_client_token")
    except Exception as exc:
        failure_class, message_class = classify_exception(exc)
        if not isinstance(exc, BootstrapFailure):
            record_failure(phase, failure_class, message_class=message_class)
        if not revoke_token(opener, address, root, "generated_root_token_revoke"):
            # The worse outcome wins: a root token that may still be valid.
            fail_root_token_revoke()
        if isinstance(exc, BootstrapFailure):
            raise
        raise BootstrapFailure(phase, failure_class, message_class=message_class) from None
    made.append(child)
    set_status(phase, "pass", ttl=SHORT_LIVED_AUTHORITY_TTL, orphan=True, renewable=False, value_recorded=False)
    if not revoke_token(opener, address, root, "generated_root_token_revoke"):
        revoke_token(opener, address, child, "short_lived_authority_token_revoke")
        fail_root_token_revoke()
    return child, made


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


def extract_jwt_validation_pubkeys():
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
        pems = [rsa_public_key_pem(str(key["n"]), str(key["e"])) for key in jwt_svid_rsa_keys]
        public_key_digest_set = ["sha256:" + hashlib.sha256(pem.encode("utf-8")).hexdigest() for pem in pems]
        aggregate_digest = "sha256:" + hashlib.sha256("\n".join(public_key_digest_set).encode("utf-8")).hexdigest()
        set_status(
            "spire_jwt_validation_material",
            "pass",
            source="spire-server bundle show -format spiffe",
            validation_material_source=source_label,
            selected_trust_domain=selected_trust_domain,
            trust_domain_count=trust_domain_count,
            key_count=len(candidates),
            jwt_svid_rsa_key_count=len(jwt_svid_rsa_keys),
            jwt_validation_pubkeys_count=len(pems),
            vault_jwt_config_shape="jwt_validation_pubkeys_array_pem_bound_issuer",
            public_key_digest=aggregate_digest,
            public_key_digest_set=public_key_digest_set,
        )
        return pems
    raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="no_jwt_svid_rsa_key")


def preflight_spire_bundle_read():
    return extract_jwt_validation_pubkeys()


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
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
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


def configure_jwt(opener, token, address, validation_pubkeys):
    phase = "jwt_auth_config"
    set_next_operation(phase)
    try:
        vault_request(
            opener,
            token,
            "POST",
            address,
            f"auth/{AUTH_MOUNT}/config",
            {"jwt_validation_pubkeys": validation_pubkeys, "bound_issuer": BOUND_ISSUER},
            allowed_statuses=(200, 204),
        )
        set_status(
            phase,
            "pass",
            auth_mount=AUTH_MOUNT,
            bound_issuer=BOUND_ISSUER,
            validation_material_field="jwt_validation_pubkeys",
            jwt_validation_pubkeys_count=len(validation_pubkeys),
            vault_jwt_config_shape="jwt_validation_pubkeys_array_pem_bound_issuer",
        )
    except Exception as exc:
        fail_from_exception(phase, exc)


def configure_role(opener, token, address, token_limits):
    phase = "service_execution_role"
    set_next_operation(phase)
    token_ttl, token_max_ttl, token_bound_cidrs = token_limits
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
                "token_ttl": token_ttl,
                "token_max_ttl": token_max_ttl,
                "token_bound_cidrs": token_bound_cidrs,
            },
            allowed_statuses=(200, 204),
        )
        set_status(
            phase,
            "pass",
            role=ROLE,
            role_type="jwt",
            user_claim="sub",
            token_ttl=token_ttl,
            token_max_ttl=token_max_ttl,
            token_bound_cidrs=token_bound_cidrs,
        )
    except Exception as exc:
        fail_from_exception(phase, exc)


def metadata_path_from_kv_path(path):
    marker = "/data/"
    if marker not in path:
        raise ValueError("path_not_kv_v2_data_path")
    mount, rest = path.split(marker, 1)
    return f"{mount}/metadata/{rest}"


def delete_prior_proof_versions(opener, token, address):
    """Permanently delete every earlier version and the metadata of both
    proof paths before the new value is written, so that no earlier value
    stays readable through ?version=N. A path that does not exist yet is
    fine."""
    phase = "proof_secret_prior_versions"
    set_next_operation(phase)
    deleted = []
    try:
        for path in (PROOF_READ_PATH, PROOF_RUNTIME_SECRET_PATH):
            metadata_path = metadata_path_from_kv_path(path)
            vault_request(opener, token, "DELETE", address, metadata_path, allowed_statuses=(200, 204, 404))
            deleted.append(metadata_path)
        set_status(phase, "pass", metadata_paths_deleted=deleted, values_recorded=False)
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
    authority_secret = ""
    proof_secret = ""
    opener = None
    short_lived = False
    exit_code = 0
    secret_values_for_scan = []
    try:
        preflight_summary_writable()
    except SummaryPreflightError as exc:
        report_summary_preflight_failure(exc.reason)
        return 1

    try:
        validate_choices()
        preflight_temporary_generate_root_access()
        token_limits = validate_role_token_limits()
        preflight_config_readable()
        address, ca_bundle_pem = load_config()
        validation_pubkeys = preflight_spire_bundle_read()
        if AUTHORITY_SOURCE == "unseal-key":
            opener = make_opener(ca_bundle_pem)
            preflight_generate_root_access(opener, address)
        set_next_operation("prompt_bootstrap_authority")
        summary["secret_prompts_started"] = True
        if AUTHORITY_SOURCE == "unseal-key":
            authority_prompt = (
                "Vault unseal key (input hidden; not logged; used once to make a "
                f"root token that is revoked at once, and a {SHORT_LIVED_AUTHORITY_TTL} token for this run): "
            )
        else:
            authority_prompt = "Vault bootstrap authority token (input hidden; not logged): "
        try:
            authority_secret = prompt_secret(authority_prompt).strip()
        except KeyboardInterrupt:
            raise_failure("prompt_bootstrap_authority", "prompt_interrupted", message_class="keyboard_interrupt")
        except (EOFError, OSError):
            raise_failure("prompt_bootstrap_authority", "prompt_unavailable", message_class="prompt_unavailable")
        except Exception as exc:
            failure_class, message_class = classify_exception(exc)
            if failure_class == "unexpected_exception":
                failure_class = "prompt_unavailable"
            raise_failure("prompt_bootstrap_authority", failure_class, message_class=message_class)
        if not authority_secret:
            raise_failure("prompt_bootstrap_authority", "prompt_unavailable", message_class="empty_prompt")
        set_status(
            "prompt_bootstrap_authority",
            "pass",
            prompt_source="remote_tty",
            authority_source=AUTHORITY_SOURCE,
            value_recorded=False,
        )
        set_next_operation("prompt_proof_secret")
        try:
            if PROOF_VALUE_SOURCE == "generate":
                proof_secret = secrets.token_urlsafe(32)
            else:
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
        set_status(
            "prompt_proof_secret",
            "pass",
            prompt_source="generated" if PROOF_VALUE_SOURCE == "generate" else "remote_tty",
            value_recorded=False,
        )
        secret_values_for_scan = [authority_secret, proof_secret]

        if opener is None:
            opener = make_opener(ca_bundle_pem)
        if AUTHORITY_SOURCE == "unseal-key":
            root_token, made = make_short_lived_authority(opener, address, authority_secret)
            short_lived = True
            secret_values_for_scan.extend(made)
        else:
            root_token = authority_secret
        ensure_auth_mount(opener, root_token, address)
        ensure_kv_mount(opener, root_token, address)
        configure_policy(opener, root_token, address)
        configure_jwt(opener, root_token, address, validation_pubkeys)
        configure_role(opener, root_token, address, token_limits)
        delete_prior_proof_versions(opener, root_token, address)
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
        short_lived_revoked = None
        if short_lived and root_token and opener is not None:
            short_lived_revoked = revoke_token(opener, address, root_token, "short_lived_authority_token_revoke")
        try:
            write_summary(secret_values_for_scan)
        except Exception:
            exit_code = 1
        root_token = None
        authority_secret = None
        proof_secret = None
        validation_pubkey = None
        secret_values_for_scan = None

    if short_lived_revoked is True:
        print("The root token made from the unseal key was revoked at once; the short-lived token for this run is revoked too.")
    elif short_lived_revoked is False:
        print(f"WARNING: the short-lived token for this run could not be revoked; it expires by itself {SHORT_LIVED_AUTHORITY_TTL} after it was made. The root token made from the unseal key was already revoked.")
    elif summary.get("failure_class") == "root_token_revoke_failed":
        print("WARNING: the root token made from the unseal key could NOT be revoked and may still be valid. Do not ignore this: tell the person who runs this box.")
    restore_operation = summary["operations"].get("generate_root_access_restore")
    if restore_operation and restore_operation.get("status") != "pass":
        print(
            f"WARNING: Vault's configuration file {VAULT_CONFIG_PATH} may still hold the line "
            f"'{UNAUTHENTICATED_GENERATE_ROOT_SETTING}' that this run added, or Vault was not reloaded "
            f"after it was removed. Remove the line if it is there, then run: {VAULT_RELOAD_COMMAND_TEXT}"
        )
    elif restore_operation:
        print("Vault's configuration file is back byte for byte, and Vault again refuses generate-root without a token.")
    print("Remote Alpha Vault workload-auth bootstrap helper finished.")
    # Non-secret labels only, so an operator sees the outcome without the summary.
    print(f"overall_status={summary.get('overall_status')}")
    if summary.get("overall_status") != "pass":
        print(f"failure_phase={summary.get('failure_phase')} failure_class={summary.get('failure_class')}")
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
