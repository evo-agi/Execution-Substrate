#!/usr/bin/env python3
import argparse
import base64
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def decode_jwt_claims(token: str):
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("jwt must contain at least two segments")

    payload = parts[1]
    padding = "=" * ((4 - (len(payload) % 4)) % 4)
    raw = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
    claims = json.loads(raw.decode("utf-8"))
    if not isinstance(claims, dict):
        raise ValueError("jwt payload must decode to an object")
    return claims


def audience_matches(claims, expected: str) -> bool:
    audience = claims.get("aud")
    if isinstance(audience, str):
        return audience == expected
    if isinstance(audience, list):
        return expected in [str(item) for item in audience]
    return False


class VaultHandler(BaseHTTPRequestHandler):
    server_version = "MockVaultCompat/1.0"

    def _json_response(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def do_POST(self):
        if self.path != self.server.login_path:
            self._json_response(404, {"errors": ["not found"]})
            return

        payload = self._read_json()
        if payload.get("role") != self.server.expected_role:
            self._json_response(403, {"errors": ["invalid role"]})
            return

        jwt_value = str(payload.get("jwt", "")).strip()
        if not jwt_value:
            self._json_response(403, {"errors": ["missing jwt"]})
            return

        try:
            claims = decode_jwt_claims(jwt_value)
        except Exception as exc:
            self._json_response(403, {"errors": [f"invalid jwt: {exc}"]})
            return

        if not audience_matches(claims, self.server.expected_audience):
            self._json_response(403, {"errors": ["audience mismatch"]})
            return

        expected_subject = self.server.expected_subject
        if expected_subject and str(claims.get("sub", "")).strip() != expected_subject:
            self._json_response(403, {"errors": ["subject mismatch"]})
            return

        exp = claims.get("exp")
        try:
            if exp is not None and int(exp) <= int(time.time()):
                self._json_response(403, {"errors": ["jwt expired"]})
                return
        except Exception:
            self._json_response(403, {"errors": ["invalid exp"]})
            return

        self.server.login_count += 1
        self._json_response(
            200,
            {
                "auth": {
                    "client_token": self.server.client_token,
                }
            },
        )

    def do_GET(self):
        if self.path != self.server.secret_path:
            self._json_response(404, {"errors": ["not found"]})
            return

        if self.headers.get("X-Vault-Token") != self.server.client_token:
            self._json_response(403, {"errors": ["invalid token"]})
            return

        self.server.secret_read_count += 1
        self._json_response(
            200,
            {
                "data": {
                    "data": {
                        "message": self.server.secret_value,
                    }
                }
            },
        )

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18200)
    parser.add_argument("--auth-mount", default="jwt")
    parser.add_argument("--role", required=True)
    parser.add_argument("--bound-audience", required=True)
    parser.add_argument("--bound-subject", default="")
    parser.add_argument("--token", default="runtime-identity-vault-token")
    parser.add_argument("--secret-path", default="secret/data/runtime-identity-vault-login")
    parser.add_argument("--secret-value", default="runtime-identity-ok")
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), VaultHandler)
    server.login_path = f"/v1/auth/{args.auth_mount}/login"
    server.secret_path = "/v1/" + args.secret_path.lstrip("/")
    server.expected_role = args.role
    server.expected_audience = args.bound_audience
    server.expected_subject = args.bound_subject.strip()
    server.client_token = args.token
    server.secret_value = args.secret_value
    server.login_count = 0
    server.secret_read_count = 0

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert_file, keyfile=args.key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
