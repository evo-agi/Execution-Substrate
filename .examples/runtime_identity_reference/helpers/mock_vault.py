#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class VaultHandler(BaseHTTPRequestHandler):
    server_version = "ReferenceVault/1.0"

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
        if payload.get("role") != self.server.expected_role or payload.get("jwt") != self.server.expected_jwt:
            self._json_response(403, {"errors": ["invalid role or jwt"]})
            return

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
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18200)
    parser.add_argument("--auth-mount", default="jwt")
    parser.add_argument("--role", required=True)
    parser.add_argument("--jwt", required=True)
    parser.add_argument("--token", default="reference-vault-token")
    parser.add_argument("--secret-path", default="secret/data/runtime-identity-reference")
    parser.add_argument("--secret-value", default="runtime-identity-ok")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), VaultHandler)
    server.login_path = f"/v1/auth/{args.auth_mount}/login"
    server.secret_path = "/v1/" + args.secret_path.lstrip("/")
    server.expected_role = args.role
    server.expected_jwt = args.jwt
    server.client_token = args.token
    server.secret_value = args.secret_value

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
