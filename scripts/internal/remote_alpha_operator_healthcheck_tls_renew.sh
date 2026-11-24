#!/usr/bin/env bash
set -euo pipefail
set +x

remote_alpha_operator_healthcheck_tls_schema_version="execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1"
remote_alpha_operator_healthcheck_tls_summary_path_default="/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json"
remote_alpha_operator_healthcheck_tls_backup_root_default="/var/tmp/execution-substrate-remote-alpha"

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
from __future__ import annotations

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


# The same client certificate decoder is in
# scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py.
# Both tools must stay self-contained (the collector is streamed over SSH and
# its hash is pinned; the staged renew route copies only its two shell
# scripts), so each carries the decoder, and
# TestRemoteAlphaOperatorHealthcheckTLSCertificateDecoderCopiesMatch fails
# unless the lines between the BEGIN and END markers are identical in both files.
# BEGIN client-certificate-der-decoder
SUBJECT_ALT_NAME_OID = bytes((0x55, 0x1D, 0x11))
BASIC_CONSTRAINTS_OID = bytes((0x55, 0x1D, 0x13))
KEY_USAGE_OID = bytes((0x55, 0x1D, 0x0F))
EXTENDED_KEY_USAGE_OID = bytes((0x55, 0x1D, 0x25))
CLIENT_AUTH_USAGE_OID = bytes((0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02))
ANY_EXTENDED_KEY_USAGE_OID = bytes((0x55, 0x1D, 0x25, 0x00))
MAX_URI_SAN_LENGTH = 256


def der_element(data: bytes, offset: int, end: int) -> tuple[int, int, int] | None:
    """Return (tag, content start, content end) of the DER element at offset.

    Only what certificates use is accepted: one-byte tags and definite,
    minimally encoded lengths that stay inside data[:end].
    """
    if offset + 2 > end:
        return None
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        return None
    first = data[offset + 1]
    position = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or position + count > end or data[position] == 0:
            return None
        length = int.from_bytes(data[position : position + count], "big")
        if length < 0x80:
            return None
        position += count
    if length > end - position:
        return None
    return tag, position, position + length


def der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]] | None:
    """Return the DER elements that exactly fill data[start:end]."""
    children: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        element = der_element(data, offset, end)
        if element is None:
            return None
        children.append(element)
        offset = element[2]
    return children


def der_value(data: bytes, value: tuple[int, int, int]) -> tuple[int, int, int] | None:
    """Return the one element that exactly fills an extension's octet string."""
    element = der_element(data, value[1], value[2])
    if element is None or element[2] != value[2]:
        return None
    return element


def der_object_identifier_valid(content: bytes) -> bool:
    """Report whether content is an object identifier that Go's parser reads.

    That is at least one subidentifier, each in minimal base 128 and below
    2**31. Go also refuses a subidentifier longer than five bytes, which the
    value check already refuses once its leading byte is not 0x80.
    """
    if not content:
        return False
    position = 0
    while position < len(content):
        if content[position] == 0x80:
            return False
        value = 0
        while True:
            if position >= len(content) or value >= 1 << 24:
                return False
            byte = content[position]
            position += 1
            value = (value << 7) | (byte & 0x7F)
            if byte < 0x80:
                break
    return True


def der_unsigned_integer_valid(content: bytes) -> bool:
    """Report whether content is a minimal, non-negative INTEGER below 2**63."""
    if not content or content[0] >= 0x80:
        return False
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        return False
    return int.from_bytes(content, "big") < 1 << 63


def san_uris(der: bytes, value: tuple[int, int, int]) -> list[str] | None:
    """Return the URI entries of a subjectAltName value, or None if malformed."""
    names = der_value(der, value)
    if names is None or names[0] != 0x30:
        return None
    general_names = der_children(der, names[1], names[2])
    if general_names is None:
        return None
    uris: list[str] = []
    for tag, start, end in general_names:
        raw = der[start:end]
        # Go's certificate parser refuses an rfc822Name or dNSName that is not
        # IA5 text and an iPAddress that is not 4 or 16 bytes long, and ignores
        # every entry but those and the URIs, a constructed [6] among them. A
        # URI must be printable ASCII without spaces, which is stricter than
        # Go's IA5 rule for URIs.
        if tag in (0x81, 0x82) and any(byte >= 0x80 for byte in raw):
            return None
        if tag == 0x87 and len(raw) not in (4, 16):
            return None
        if tag != 0x86:
            continue
        if not raw or len(raw) > MAX_URI_SAN_LENGTH or any(byte < 33 or byte > 126 for byte in raw):
            return None
        uris.append(raw.decode("ascii"))
    return uris


def basic_constraints_ca(der: bytes, value: tuple[int, int, int]) -> bool | None:
    """Return the cA flag of a basicConstraints value, or None if malformed."""
    sequence = der_value(der, value)
    if sequence is None or sequence[0] != 0x30:
        return None
    fields = der_children(der, sequence[1], sequence[2])
    if fields is None:
        return None
    is_ca = False
    if fields and fields[0][0] == 0x01:
        tag, start, end = fields.pop(0)
        if end - start != 1 or der[start] not in (0x00, 0xFF):
            return None
        is_ca = der[start] == 0xFF
    if fields and fields[0][0] == 0x02:
        tag, start, end = fields.pop(0)
        if not der_unsigned_integer_valid(der[start:end]):
            return None
    if fields:
        return None
    return is_ca


def key_usage_signs_certificates(der: bytes, value: tuple[int, int, int]) -> bool | None:
    """Report whether a keyUsage value has keyCertSign or cRLSign, or None if malformed."""
    bits = der_value(der, value)
    if bits is None or bits[0] != 0x03:
        return None
    content = der[bits[1] : bits[2]]
    if not content or content[0] > 7 or (len(content) == 1 and content[0] != 0):
        return None
    if len(content) > 1 and content[-1] & ((1 << content[0]) - 1):
        return None
    # Bit 5 is keyCertSign and bit 6 is cRLSign, both in the first byte.
    return len(content) > 1 and content[1] & 0x06 != 0


def extended_key_usages(der: bytes, value: tuple[int, int, int]) -> list[bytes] | None:
    """Return the object identifiers of an extKeyUsage value, or None if malformed."""
    sequence = der_value(der, value)
    if sequence is None or sequence[0] != 0x30:
        return None
    usages = der_children(der, sequence[1], sequence[2])
    if usages is None:
        return None
    oids: list[bytes] = []
    for tag, start, end in usages:
        if tag != 0x06 or not der_object_identifier_valid(der[start:end]):
            return None
        oids.append(der[start:end])
    return oids


def decode_client_certificate(der: bytes) -> dict[str, object] | None:
    """Return what ES's caller rule reads from a DER client certificate.

    The certificate is decoded structurally. OpenSSL's printed SAN text cannot
    tell a URI that contains ", DNS:" apart from two SAN entries, or a DNS name
    that contains ", URI:" apart from a URI SAN. The result has:

    - "uri_sans": every URI SAN in certificate order, duplicates included;
    - "end_entity": False when basicConstraints marks a CA or keyUsage has
      keyCertSign or cRLSign, which ES refuses (contracts.md section 3A);
    - "client_auth": False when an extKeyUsage is present and allows neither
      clientAuth nor anyExtendedKeyUsage, which Go's TLS server refuses.

    None means the certificate, its extensions or a name is malformed, or the
    certificate is not version 3 although it has extensions, which Go would
    then ignore.
    """
    certificate = der_element(der, 0, len(der))
    if certificate is None or certificate[0] != 0x30 or certificate[2] != len(der):
        return None
    parts = der_children(der, certificate[1], certificate[2])
    if parts is None or [part[0] for part in parts] != [0x30, 0x30, 0x03]:
        return None
    tbs = der_children(der, parts[0][1], parts[0][2])
    if tbs is None:
        return None
    facts: dict[str, object] = {"uri_sans": [], "end_entity": True, "client_auth": True}
    if not any(item[0] == 0xA3 for item in tbs):
        return facts
    # Go reads extensions only from a version 3 TBSCertificate, as its last
    # field after the optional issuer and subject unique identifiers.
    layout = [item[0] for item in tbs]
    if layout[:7] != [0xA0, 0x02, 0x30, 0x30, 0x30, 0x30, 0x30]:
        return None
    if layout[7:] not in ([0xA3], [0x81, 0xA3], [0x82, 0xA3], [0x81, 0x82, 0xA3]):
        return None
    version = der_children(der, tbs[0][1], tbs[0][2])
    if version is None or len(version) != 1 or version[0][0] != 0x02 or der[version[0][1] : version[0][2]] != b"\x02":
        return None
    wrapper = der_children(der, tbs[-1][1], tbs[-1][2])
    if wrapper is None or len(wrapper) != 1 or wrapper[0][0] != 0x30:
        return None
    extensions = der_children(der, wrapper[0][1], wrapper[0][2])
    if extensions is None:
        return None
    values: dict[bytes, tuple[int, int, int]] = {}
    for tag, start, end in extensions:
        if tag != 0x30:
            return None
        fields = der_children(der, start, end)
        if fields is None or len(fields) not in {2, 3} or fields[0][0] != 0x06 or fields[-1][0] != 0x04:
            return None
        if len(fields) == 3 and (fields[1][0] != 0x01 or fields[1][2] - fields[1][1] != 1 or der[fields[1][1]] not in (0x00, 0xFF)):
            return None
        oid = der[fields[0][1] : fields[0][2]]
        if not der_object_identifier_valid(oid) or oid in values:
            return None
        values[oid] = fields[-1]
    if SUBJECT_ALT_NAME_OID in values:
        uris = san_uris(der, values[SUBJECT_ALT_NAME_OID])
        if uris is None:
            return None
        facts["uri_sans"] = uris
    if BASIC_CONSTRAINTS_OID in values:
        is_ca = basic_constraints_ca(der, values[BASIC_CONSTRAINTS_OID])
        if is_ca is None:
            return None
        if is_ca:
            facts["end_entity"] = False
    if KEY_USAGE_OID in values:
        signs = key_usage_signs_certificates(der, values[KEY_USAGE_OID])
        if signs is None:
            return None
        if signs:
            facts["end_entity"] = False
    if EXTENDED_KEY_USAGE_OID in values:
        usages = extended_key_usages(der, values[EXTENDED_KEY_USAGE_OID])
        if usages is None:
            return None
        if usages and CLIENT_AUTH_USAGE_OID not in usages and ANY_EXTENDED_KEY_USAGE_OID not in usages:
            facts["client_auth"] = False
    return facts
# END client-certificate-der-decoder


def cert_identity_facts(cert_path):
    """Return what ES's caller rule reads from the certificate's DER, or None."""
    proc = run(["openssl", "x509", "-in", cert_path, "-outform", "DER"])
    if proc.returncode != 0:
        return None
    return decode_client_certificate(proc.stdout)


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
# Exact URI SAN entries from the certificate's DER structure, in certificate
# order, duplicates included; the printed SAN text above is for reading only,
# because it cannot tell a URI that contains ", DNS:" or a DNS name that
# contains ", URI:" apart from separate entries. ES refuses a certificate with
# more than one URI SAN (caller authentication contract, contracts.md section
# 3A), so the expected identity must be the only one. ES also refuses a leaf
# that is not an end-entity certificate, and Go's TLS server refuses one whose
# extended key usage does not allow client authentication.
facts = cert_identity_facts(operator_cert_path) if cert.get("exists") else None
uri_sans = facts["uri_sans"] if facts is not None else None
identity = {
    "expected_uri": expected_spiffe_uri,
    "legacy_uri": legacy_spiffe_uri,
    "subject_alt_name": cert.get("subject_alt_name", ""),
    "uri_san_count": len(uri_sans) if uri_sans is not None else None,
    "matches_current_allowlist": uri_sans == [expected_spiffe_uri],
    "legacy_operator_uri_present": uri_sans is not None and legacy_spiffe_uri in uri_sans,
    "end_entity": facts["end_entity"] if facts is not None else None,
    "client_auth_usage": facts["client_auth"] if facts is not None else None,
}
identity_ok = identity["matches_current_allowlist"] and identity["end_entity"] is True and identity["client_auth_usage"] is True
identity["status"] = "pass" if identity_ok else "fail"
if uri_sans is None:
    identity["classification"] = "operator_identity_malformed"
elif identity["legacy_operator_uri_present"] and not identity["matches_current_allowlist"]:
    identity["classification"] = "legacy_operator_identity_requires_operator_local_renewal"
elif not identity["matches_current_allowlist"]:
    identity["classification"] = "operator_identity_mismatch"
elif identity["end_entity"] is not True:
    identity["classification"] = "operator_identity_not_end_entity"
elif identity["client_auth_usage"] is not True:
    identity["classification"] = "operator_identity_not_for_client_auth"
else:
    identity["classification"] = "current_operator_local_identity"

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
if not identity["matches_current_allowlist"]:
    blockers.append(f"operator certificate must carry exactly one URI SAN, {expected_spiffe_uri}")
if identity["end_entity"] is False:
    blockers.append("operator certificate must be an end-entity certificate: not a CA, and without the keyCertSign or cRLSign key usage")
if identity["client_auth_usage"] is False:
    blockers.append("operator certificate extended key usage must allow client authentication")
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
  remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT}" || return 1
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
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT}" || return 1
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
