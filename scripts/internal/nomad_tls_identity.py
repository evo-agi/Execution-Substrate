#!/usr/bin/env -S python3 -I
"""Nomad's TLS identity as ES sees it.

usage: nomad_tls_identity.py check <es-config> <nomad-addr>
       nomad_tls_identity.py pin <nomad-addr> <ca-file> <server-name>

ES reaches Nomad only at nomad.base_url, over TLS 1.3, trusting only the CA in
nomad.root_ca_file, for the name nomad.server_name, and only when the server
certificate's public key has the SHA-256 in nomad.server_spki_sha256.

  check  Make ES's checks against the running Nomad, so a wrong pin or CA
         shows up in readiness instead of as a refused submit. Also require
         nomad.base_url to be the address the operator checks use, and refuse
         a certificate with fewer than MIN_DAYS_LEFT days of validity: rerun
         scripts/70_linux_setup.sh, which issues a new one, then update the
         pin.
  pin    Print the value for nomad.server_spki_sha256: the SHA-256 of the
         public key in the certificate the running Nomad presents, after that
         certificate verified under <ca-file> for <server-name>.

Neither sends a token or a request: each only completes a TLS handshake.
Exit status: 0 and one line on stdout on success, 1 and one line on stderr on
a refusal, 2 on usage.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.parse

MIN_DAYS_LEFT = 14
TIMEOUT_SECONDS = 5
PIN_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
NAME_PATTERN = re.compile(r"(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z", re.ASCII)


class Refusal(Exception):
    pass


def _der_element(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return (tag, start of contents, end of element) of the DER element at offset."""
    if offset + 2 > len(data):
        raise Refusal("nomad tls: the server certificate does not parse")
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or start + count > len(data):
            raise Refusal("nomad tls: the server certificate does not parse")
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise Refusal("nomad tls: the server certificate does not parse")
    return tag, start, end


def subject_public_key_info(certificate: bytes) -> bytes:
    """Return the DER SubjectPublicKeyInfo of a DER X.509 certificate."""
    tag, start, _ = _der_element(certificate, 0)
    if tag != 0x30:
        raise Refusal("nomad tls: the server certificate does not parse")
    tag, offset, tbs_end = _der_element(certificate, start)
    if tag != 0x30:
        raise Refusal("nomad tls: the server certificate does not parse")
    tag, _, end = _der_element(certificate, offset)
    if tag == 0xA0:  # [0] version
        offset = end
    # serialNumber, signature, issuer, validity, subject
    for expected in (0x02, 0x30, 0x30, 0x30, 0x30):
        tag, _, end = _der_element(certificate, offset)
        if tag != expected or end > tbs_end:
            raise Refusal("nomad tls: the server certificate does not parse")
        offset = end
    tag, _, end = _der_element(certificate, offset)
    if tag != 0x30 or end > tbs_end:
        raise Refusal("nomad tls: the server certificate does not parse")
    return certificate[offset:end]


def _loopback_endpoint(address: str, field: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(address)
    try:
        host = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        host, port = None, None
    if (
        parsed.scheme != "https"
        or host is None
        or not host.is_loopback
        or not port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise Refusal(f"nomad tls: {field} must be https://<loopback IP>:<port>")
    return str(host), port


def _validated_name(server_name, field: str) -> str:
    if not isinstance(server_name, str) or not NAME_PATTERN.match(server_name):
        raise Refusal(f"nomad tls: {field} must be the DNS name in Nomad's server certificate")
    return server_name


def _context(ca_file, field: str) -> ssl.SSLContext:
    if not isinstance(ca_file, str) or not os.path.isabs(ca_file):
        raise Refusal(f"nomad tls: {field} must be an absolute path")
    try:
        if not stat.S_ISREG(os.lstat(ca_file).st_mode):
            raise OSError
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError, ValueError):
        raise Refusal(f"nomad tls: {field} is not a readable CA certificate file: {ca_file}") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def _handshake(address: str, field: str, context: ssl.SSLContext, server_name: str) -> tuple[bytes, dict, str]:
    """Return the verified server certificate (DER), its details, and its key pin."""
    host, port = _loopback_endpoint(address, field)
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as conn:
                certificate = conn.getpeercert(binary_form=True)
                details = conn.getpeercert()
    except ssl.SSLCertVerificationError as error:
        raise Refusal(
            f"nomad tls: Nomad's certificate does not verify under the CA for {server_name}: {error.verify_message}"
        ) from None
    except (OSError, ssl.SSLError) as error:
        raise Refusal(f"nomad tls: no TLS 1.3 connection to {address}: {str(error)[:200]}") from None
    if not certificate or not details:
        raise Refusal("nomad tls: Nomad presented no certificate")
    return certificate, details, hashlib.sha256(subject_public_key_info(certificate)).hexdigest()


def check(config_path: str, nomad_addr: str) -> str:
    try:
        with open(config_path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError):
        raise Refusal("nomad tls: the ES config could not be read") from None
    nomad = config.get("nomad") if isinstance(config, dict) else None
    if not isinstance(nomad, dict):
        raise Refusal("nomad tls: the ES config has no nomad block")
    base_url = nomad.get("base_url")
    if not isinstance(base_url, str):
        raise Refusal("nomad tls: nomad.base_url is missing")
    _loopback_endpoint(base_url, "nomad.base_url")
    if base_url.rstrip("/") != nomad_addr.rstrip("/"):
        raise Refusal(f"nomad tls: nomad.base_url ({base_url}) is not the Nomad address the checks use ({nomad_addr})")
    server_name = _validated_name(nomad.get("server_name"), "nomad.server_name")
    pin = nomad.get("server_spki_sha256")
    if not isinstance(pin, str) or not PIN_PATTERN.match(pin):
        raise Refusal("nomad tls: nomad.server_spki_sha256 must be 64 lowercase hex characters")
    context = _context(nomad.get("root_ca_file"), "nomad.root_ca_file")
    _, details, observed = _handshake(base_url, "nomad.base_url", context, server_name)
    if observed != pin:
        raise Refusal(
            "nomad tls: Nomad's server key does not match nomad.server_spki_sha256 "
            f"(Nomad presents {observed}); ES would refuse every request"
        )
    expires = ssl.cert_time_to_seconds(details["notAfter"])
    days_left = int((expires - time.time()) // 86400)
    expiry = time.strftime("%Y-%m-%d", time.gmtime(expires))
    if days_left < MIN_DAYS_LEFT:
        raise Refusal(
            f"nomad tls: Nomad's certificate expires {expiry} ({days_left} days); rerun scripts/70_linux_setup.sh "
            "to issue a new one, then update nomad.server_spki_sha256 and restart Nomad and ES"
        )
    return f"nomad tls: tls=1.3 server_name={server_name} key=pinned expires={expiry} days_left={days_left}"


def pin(nomad_addr: str, ca_file: str, server_name: str) -> str:
    context = _context(ca_file, "<ca-file>")
    _, _, observed = _handshake(nomad_addr, "<nomad-addr>", context, _validated_name(server_name, "<server-name>"))
    return observed


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "check":
        command = lambda: check(argv[1], argv[2])  # noqa: E731
    elif len(argv) == 4 and argv[0] == "pin":
        command = lambda: pin(argv[1], argv[2], argv[3])  # noqa: E731
    else:
        print("\n".join(__doc__.splitlines()[2:4]), file=sys.stderr)
        return 2
    try:
        print(command())
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
