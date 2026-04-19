#!/usr/bin/env python3
import argparse
import http.server
import json
import os
import socket
import threading


def handle_connection(connection, expected_audience, jwt):
    try:
        raw = b""
        while b"\n" not in raw:
            chunk = connection.recv(4096)
            if not chunk:
                break
            raw += chunk
        payload = json.loads(raw.decode("utf-8").strip() or "{}")
        audience = str(payload.get("audience", "")).strip()
        if expected_audience and audience != expected_audience:
            response = {"error": f"unexpected audience: {audience!r}"}
        else:
            response = {"jwt": jwt}
        connection.sendall((json.dumps(response) + "\n").encode("utf-8"))
    finally:
        connection.close()


def serve_http(bind_address, port, expected_audience, jwt):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            raw_length = self.headers.get("Content-Length", "0").strip()
            try:
                length = int(raw_length)
            except ValueError:
                length = 0
            payload = json.loads((self.rfile.read(length) or b"{}").decode("utf-8"))
            audience = str(payload.get("audience", "")).strip()
            if expected_audience and audience != expected_audience:
                response = {"error": f"unexpected audience: {audience!r}"}
                status = 400
            else:
                response = {"jwt": jwt}
                status = 200
            body = (json.dumps(response) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    server = http.server.ThreadingHTTPServer((bind_address, port), Handler)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket")
    parser.add_argument("--http-bind")
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--jwt", required=True)
    args = parser.parse_args()

    if bool(args.socket) == bool(args.http_bind):
        raise SystemExit("exactly one of --socket or --http-bind is required")
    if args.http_bind and args.http_port is None:
        raise SystemExit("--http-port is required with --http-bind")

    if args.http_bind:
        serve_http(args.http_bind, args.http_port, args.audience, args.jwt)
        return

    socket_path = args.socket
    socket_dir = os.path.dirname(socket_path)
    os.makedirs(socket_dir, exist_ok=True)
    try:
        os.remove(socket_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen()
    os.chmod(socket_path, 0o777)

    try:
        while True:
            connection, _ = server.accept()
            thread = threading.Thread(
                target=handle_connection,
                args=(connection, args.audience, args.jwt),
                daemon=True,
            )
            thread.start()
    finally:
        server.close()
        try:
            os.remove(socket_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
