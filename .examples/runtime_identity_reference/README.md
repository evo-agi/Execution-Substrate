# Runtime Identity Reference Workload

This directory contains a reference `static-script` workload that exercises the current runtime identity contract without changing platform behavior.

## What It Demonstrates

The workload:

- reads `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT`
- reads bounded non-secret Vault auth metadata from the environment
- obtains a JWT from the mounted identity endpoint
- authenticates to Vault locally
- reads one test secret from Vault
- prints success markers and the secret message to stdout

## Reference Identity Endpoint Protocol

This workload expects the mounted endpoint to speak a small JSON-line protocol over a Unix socket.

Request:

```json
{"kind":"jwt_request","audience":"vault"}
```

Response:

```json
{"jwt":"reference-runtime-identity-jwt"}
```

The platform contract remains generic. This protocol exists only for the reference workload and its helper scripts.

## Files

- `entrypoint`: executable Python 3 workload entrypoint
- `package.sh`: packages the artifact as `dist/runtime_identity_reference.tar.gz`
- `helpers/mock_identity_endpoint.py`: optional local helper implementing the reference identity endpoint protocol
- `helpers/mock_vault.py`: optional local helper implementing a tiny Vault-compatible login and secret-read surface

## Packaging

```bash
./.examples/runtime_identity_reference/package.sh
```

This produces:

- `.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz`

## Runtime Requirements

- ES base image must include `python3`
- the workload must receive:
  - `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT`
  - `VAULT_ADDR`
  - `MONOLITH_WORKLOAD_VAULT_AUTH_MODE`
  - `MONOLITH_WORKLOAD_VAULT_AUTH_MOUNT`
  - `MONOLITH_WORKLOAD_VAULT_AUTH_ROLE`
  - `MONOLITH_WORKLOAD_VAULT_JWT_AUDIENCE`

Optional:

- `REFERENCE_SECRET_PATH`
- `REFERENCE_VAULT_INSECURE_SKIP_VERIFY=1`
