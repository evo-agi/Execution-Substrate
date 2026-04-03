#!/usr/bin/env python3
import argparse
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--jwt", required=True)
    args = parser.parse_args()

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
