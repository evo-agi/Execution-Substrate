# Runbook: Local Runtime Identity Validation (v1)

- Version: `v1`
- Last Updated: `2026-04-02`

## 1. Objective

Validate the current runtime identity plumbing end to end using the existing Go platform plus minimal local infrastructure:

`ES -> mounted endpoint socket -> reference workload -> local identity adapter -> Vault dev mode -> secret read`

This runbook is intentionally local and non-production:

- no SPIRE
- no production Vault
- no TLS added for Vault or the identity adapter
- no platform code changes

It proves plumbing and contract compatibility only.

For a fresh Linux VM, an optional explicit bootstrap helper is available at:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/linux_vm_runtime_identity/setup.sh`

That helper installs dependencies, pauses for GitHub SSH-key setup, clones the repository once, verifies the required tools, and then hands control back to this runbook.

## 2. Prerequisites

The current Go platform must already be up using the existing bring-up flow.

This runbook adds only:

- a local Vault dev server
- one locally generated RSA keypair for JWT signing
- one static RS256 JWT
- one local Unix-socket identity adapter

You also need:

- `vault`
- `openssl`
- `python3`
- `curl`
- `nomad`

Use the existing runtime identity reference workload:

- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/entrypoint`
- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/package.sh`

## 3. Vault Setup Commands

Export local Vault env:

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
```

Start Vault in dev mode:

```bash
vault server -dev \
  -dev-root-token-id=root \
  -dev-listen-address=127.0.0.1:8200
```

Leave that running in its own terminal.

In a second terminal, create a working directory for the local validation material:

```bash
export RI_LOCAL_DIR="/tmp/ri-local-validation"
rm -rf "$RI_LOCAL_DIR"
mkdir -p "$RI_LOCAL_DIR"
```

Generate a local RSA keypair:

```bash
openssl genrsa -out "$RI_LOCAL_DIR/jwt-private.pem" 2048
openssl rsa -in "$RI_LOCAL_DIR/jwt-private.pem" -pubout -out "$RI_LOCAL_DIR/jwt-public.pem"
```

Create one static RS256 JWT with:

- `sub = runtime-identity-reference`
- `aud = vault`

```bash
python3 - <<'PY' "$RI_LOCAL_DIR"
import base64, json, pathlib, sys, time

root = pathlib.Path(sys.argv[1])
header = {"alg": "RS256", "typ": "JWT"}
now = int(time.time())
payload = {
    "sub": "runtime-identity-reference",
    "aud": ["vault"],
    "iat": now,
    "exp": now + 3600,
}

def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

message = (
    f"{b64url(json.dumps(header, separators=(',', ':')).encode())}."
    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
)
(root / "jwt-message.txt").write_text(message)
PY

openssl dgst -sha256 \
  -sign "$RI_LOCAL_DIR/jwt-private.pem" \
  -out "$RI_LOCAL_DIR/jwt-signature.bin" \
  "$RI_LOCAL_DIR/jwt-message.txt"

python3 - <<'PY' "$RI_LOCAL_DIR"
import base64, pathlib, sys

root = pathlib.Path(sys.argv[1])
message = (root / "jwt-message.txt").read_text().strip()
signature = (root / "jwt-signature.bin").read_bytes()
jwt = message + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
(root / "runtime-identity.jwt").write_text(jwt)
print("Wrote", root / "runtime-identity.jwt")
PY
```

Enable Vault JWT auth:

```bash
vault auth enable -path=jwt jwt
```

Configure JWT verification using the generated public key:

```bash
vault write auth/jwt/config \
  jwt_supported_algs=RS256 \
  jwt_validation_pubkeys=@"$RI_LOCAL_DIR/jwt-public.pem"
```

Create a minimal policy allowing the test secret read:

```bash
vault policy write runtime-identity-reference - <<'EOF'
path "secret/data/runtime-identity-reference" {
  capabilities = ["read"]
}
EOF
```

Create the Vault role expected by the workload:

```bash
vault write auth/jwt/role/service_execution \
  role_type=jwt \
  bound_audiences=vault \
  user_claim=sub \
  bound_subject=runtime-identity-reference \
  token_policies=runtime-identity-reference \
  token_ttl=1h
```

Write the test secret:

```bash
vault kv put secret/runtime-identity-reference message=runtime-identity-ok
```

Optional sanity check:

```bash
vault write -field=token auth/jwt/login \
  role=service_execution \
  jwt=@"$RI_LOCAL_DIR/runtime-identity.jwt"
```

If that returns a token, Vault JWT auth is configured correctly for this local validation path.

## 4. Identity Adapter Script

Use the existing minimal adapter:

- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py`

It:

- listens on a Unix socket
- accepts the reference workload JSON-line request
- returns the configured JWT
- stays stateless request -> response only

Start it on the ES host:

```bash
export RI_ENDPOINT_SOCKET="/tmp/endpoint.sock"
rm -f "$RI_ENDPOINT_SOCKET"

python3 /Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py \
  --socket "$RI_ENDPOINT_SOCKET" \
  --audience vault \
  --jwt "$(cat "$RI_LOCAL_DIR/runtime-identity.jwt")"
```

Leave that running in its own terminal.

## 5. ES Config Snippet

The only local runtime identity plumbing change needed in ES config is the host socket path and a base image with `python3`.

Example execution snippet:

```json
{
  "nomad": {
    "base_url": "http://127.0.0.1:4646",
    "datacenter": "dc1",
    "timeout_seconds": 5
  },
  "execution": {
    "staging_root_dir": "/tmp/es-stage",
    "base_image": "python:3.13-alpine",
    "workload_identity_endpoint_host_path": "/tmp/endpoint.sock"
  }
}
```

The local validation path adds no new TLS or certificate requirements beyond whatever your current Go system bring-up already uses.

## 6. Execution Steps

Package the reference workload:

```bash
/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/package.sh
```

Follow the governed publish + submit flow from:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_runtime_identity_reference.md`

Use these important values:

- payload:
  - `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz`
- publish request:
  - `constraints.network_access = true`
- submit env:
  - `REFERENCE_SECRET_PATH=secret/data/runtime-identity-reference`

The workload then runs this real local flow:

1. connect to `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT`
2. receive the static RS256 JWT from the Unix-socket adapter
3. call `POST $VAULT_ADDR/v1/auth/jwt/login`
4. receive a real Vault token from Vault dev mode
5. call `GET $VAULT_ADDR/v1/secret/data/runtime-identity-reference`
6. print the secret value to stdout

## 7. Verification Steps

Inspect allocation logs:

```bash
nomad alloc logs -stdout "$ALLOC_ID"
```

Success must include:

- `IDENTITY-JWT-RECEIVED`
- `VAULT-AUTH-SUCCESS`
- `SECRET-READ-SUCCESS:runtime-identity-ok`

Expected final JSON line:

```text
{"artifact_digest":"sha256:...","secret_message":"runtime-identity-ok","status":"ok"}
```

This proves:

- socket mount worked
- the workload reached the mounted endpoint
- the adapter returned a JWT
- Vault auth worked
- the secret read worked

## 8. Failure Guide

### Socket not reachable

What it means:

- the workload could not use the mounted Unix socket

Common causes:

- `/tmp/endpoint.sock` does not exist
- ES points at the wrong host path
- adapter is not running
- container runtime cannot expose the mounted socket correctly

### JWT not returned

What it means:

- the workload reached the endpoint but did not receive a valid JWT response

Common causes:

- wrong audience
- adapter started with the wrong JWT
- adapter returned malformed JSON

### Vault auth fails

What it means:

- the JWT reached Vault, but Vault rejected it

Common causes:

- `jwt_validation_pubkeys` does not match the signing key
- wrong `bound_audiences`
- wrong `bound_subject`
- wrong Vault role name
- expired JWT

### Secret read fails

What it means:

- Vault login worked, but the token could not read the secret

Common causes:

- missing or wrong policy
- wrong secret path
- secret not written yet
