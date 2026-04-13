#!/usr/bin/env python3
"""Supported-local proof Codex shim for control-plane-normal-shell/v1.

This is intentionally not a general Codex CLI emulator. It exists only for the
repo-owned supported-local proof realization, where ES must prove the bounded
runtime contract without requiring a live upstream Codex service.
"""

import hashlib
import json
import os
import pathlib
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


REALIZATION = "supported-local-proof-codex-shim/v1"
PROFILE = "control-plane-normal-shell/v1"
WORKSPACE_MUTATION = ".codex-proof/normal-shell-proof.txt"
WORKSPACE_REPORT = ".codex-proof/codex-proof-result.json"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def parse_identity_endpoint(uri: str) -> str:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "unix":
        raise SystemExit(f"unsupported identity endpoint scheme: {parsed.scheme!r}")
    socket_path = parsed.path.strip()
    if not socket_path:
        raise SystemExit("identity endpoint path is empty")
    return socket_path


def request_identity_jwt(socket_path: str) -> str:
    request_payload = {"kind": "jwt_svid", "target": "workload_vault"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(socket_path)
        client.sendall((json.dumps(request_payload) + "\n").encode("utf-8"))
        response = b""
        while b"\n" not in response:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    finally:
        client.close()

    payload = json.loads(response.decode("utf-8").strip())
    if payload.get("error"):
        raise SystemExit(f"identity endpoint returned error: {payload}")
    jwt_value = str(payload.get("jwt", "")).strip()
    if not jwt_value:
        raise SystemExit(f"identity endpoint response did not include jwt: {payload}")
    return jwt_value


def make_opener():
    ca_cert = os.environ.get("VAULT_CACERT", "").strip()
    context = ssl.create_default_context(cafile=ca_cert or None)
    if os.environ.get("WORKLOAD_VAULT_INSECURE_SKIP_VERIFY", "").strip() == "1":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))


def json_request(opener, method: str, url: str, payload=None, headers=None):
    body = None
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {url} failed with status {exc.code}: {body_text}") from exc


def login_to_vault(opener, vault_addr: str, auth_mount: str, auth_role: str, jwt_value: str) -> str:
    payload = json_request(
        opener,
        "POST",
        vault_addr.rstrip("/") + f"/v1/auth/{auth_mount.strip('/')}/login",
        payload={"role": auth_role, "jwt": jwt_value},
    )
    token = str((payload.get("auth") or {}).get("client_token", "")).strip()
    if not token:
        raise SystemExit("vault login response did not include auth.client_token")
    return token


def read_credential_material(opener, vault_addr: str, token: str, secret_path: str, field: str) -> str:
    payload = json_request(
        opener,
        "GET",
        vault_addr.rstrip("/") + "/v1/" + secret_path.lstrip("/"),
        headers={"X-Vault-Token": token},
    )
    data = payload.get("data") or {}
    if isinstance(data.get("data"), dict):
        data = data["data"]
    value = str(data.get(field, "")).strip()
    if not value:
        raise SystemExit(f"credential field {field!r} was empty in Vault response")
    return value


def acquire_proof_credential() -> str:
    credential_source = require_env("EXEC_CODEX_CREDENTIAL_SOURCE")
    if credential_source != "workload_vault":
        raise SystemExit(f"unsupported credential source: {credential_source!r}")

    socket_path = parse_identity_endpoint(require_env("EXEC_WORKLOAD_IDENTITY_ENDPOINT"))
    jwt_value = request_identity_jwt(socket_path)
    opener = make_opener()
    token = login_to_vault(
        opener,
        require_env("VAULT_ADDR"),
        require_env("EXEC_WORKLOAD_VAULT_AUTH_MOUNT"),
        require_env("EXEC_WORKLOAD_VAULT_AUTH_ROLE"),
        jwt_value,
    )
    return read_credential_material(
        opener,
        require_env("VAULT_ADDR"),
        token,
        require_env("EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"),
        require_env("EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"),
    )


def split_args(argv):
    if argv and argv[0] == "exec":
        return "exec", argv[1:]
    if argv and argv[0].startswith("-"):
        return "exec", argv
    if argv:
        return argv[0], argv[1:]
    return "exec", []


def parse_exec_args(args):
    cwd = os.getcwd()
    output_last_message = ""
    prompt_parts = []
    read_stdin = False

    valued_options = {
        "--approval-policy",
        "--ask-for-approval",
        "--cd",
        "--config",
        "--cwd",
        "--model",
        "--output-last-message",
        "--profile",
        "--sandbox",
        "-c",
        "-m",
    }
    boolean_options = {
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
        "--skip-git-repo-check",
    }

    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            prompt_parts.extend(args[i + 1 :])
            break
        if token == "-":
            read_stdin = True
            i += 1
            continue
        if token.startswith("--cwd=") or token.startswith("--cd="):
            cwd = token.split("=", 1)[1]
            i += 1
            continue
        if token.startswith("--output-last-message="):
            output_last_message = token.split("=", 1)[1]
            i += 1
            continue
        if token in {"--cwd", "--cd"}:
            if i + 1 >= len(args):
                raise SystemExit(f"{token} requires a value")
            cwd = args[i + 1]
            i += 2
            continue
        if token == "--output-last-message":
            if i + 1 >= len(args):
                raise SystemExit("--output-last-message requires a value")
            output_last_message = args[i + 1]
            i += 2
            continue
        if token in valued_options:
            if i + 1 >= len(args):
                raise SystemExit(f"{token} requires a value")
            i += 2
            continue
        if token in boolean_options or token.startswith("-"):
            i += 1
            continue
        prompt_parts.append(token)
        i += 1

    stdin_prompt = ""
    if read_stdin or not sys.stdin.isatty():
        stdin_prompt = sys.stdin.read()
    prompt = stdin_prompt if stdin_prompt.strip() else " ".join(prompt_parts)
    if not prompt.strip():
        raise SystemExit("proof Codex shim requires a prompt on stdin or argv")
    return pathlib.Path(cwd).resolve(), output_last_message, prompt


def mutate_workspace(cwd: pathlib.Path, prompt: str, credential_material: str) -> dict:
    cwd.mkdir(parents=True, exist_ok=True)
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    proof_dir = cwd / ".codex-proof"
    proof_dir.mkdir(parents=True, exist_ok=True)

    mutation_path = cwd / WORKSPACE_MUTATION
    mutation_path.write_text(
        "\n".join(
            [
                "ES_CONTROL_PLANE_NORMAL_SHELL_PROOF",
                f"profile={PROFILE}",
                f"realization={REALIZATION}",
                f"prompt_sha256={prompt_sha}",
                "credential_material_present=true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = {
        "credential_material_bytes": len(credential_material.encode("utf-8")),
        "credential_material_present": True,
        "credential_source": "workload_vault",
        "profile": PROFILE,
        "prompt_sha256": prompt_sha,
        "realization": REALIZATION,
        "status": "ok",
        "workspace_mutation": WORKSPACE_MUTATION,
    }
    (cwd / WORKSPACE_REPORT).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def write_final_message(path_value: str, cwd: pathlib.Path, message: str):
    if not path_value:
        return
    path = pathlib.Path(path_value)
    if not path.is_absolute():
        path = cwd / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(message + "\n", encoding="utf-8")


def run_exec(args) -> int:
    cwd, output_last_message, prompt = parse_exec_args(args)
    print("CODEX-PROOF-SHIM-START", flush=True)
    credential_material = acquire_proof_credential()
    print("codex-proof-shim: credential material acquired from workload_vault", file=sys.stderr, flush=True)
    report = mutate_workspace(cwd, prompt, credential_material)
    print(f"codex-proof-shim: workspace mutated at {WORKSPACE_MUTATION}", file=sys.stderr, flush=True)
    final_message = (
        "ES control-plane normal-shell proof completed "
        f"prompt_sha256={report['prompt_sha256']} mutation={WORKSPACE_MUTATION}"
    )
    write_final_message(output_last_message, cwd, final_message)
    print(json.dumps(report, sort_keys=True), flush=True)
    print(final_message, flush=True)
    return 0


def main(argv) -> int:
    if argv and argv[0] in {"--version", "version"}:
        print(f"codex-proof-shim {REALIZATION}")
        return 0
    if argv and argv[0] in {"--help", "-h", "help"}:
        print("usage: codex exec [--cwd PATH] [--output-last-message PATH] [-]")
        print("supported-local proof shim for control-plane-normal-shell/v1")
        return 0

    command, args = split_args(argv)
    if command != "exec":
        raise SystemExit(f"unsupported proof Codex shim command: {command!r}")
    return run_exec(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
