# Runtime Identity Reference Workload

This directory contains a reference `static-script` workload that exercises the current runtime identity contract without changing platform behavior.

Everything in this directory is example-level behavior. The platform contract is limited to the reserved runtime-identity workspace, the reserved endpoint path, and the non-secret Vault auth environment variables.

## What It Demonstrates

The workload:

- reads `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT`
- creates a local bridge at the reserved runtime identity path
- reads bounded non-secret Vault auth metadata from the environment
- obtains a JWT from `REFERENCE_IDENTITY_URL` through that local bridge
- authenticates to Vault locally
- reads one test secret from Vault
- prints success markers and the secret message to stdout

## Reference Identity Protocols

This workload creates a Unix-socket endpoint at `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT`.

The local endpoint speaks a small JSON-line protocol:

Request:

```json
{"kind":"jwt_request","audience":"vault"}
```

Response:

```json
{"jwt":"reference-runtime-identity-jwt"}
```

The platform contract remains generic. This protocol exists only for the reference workload and its helper scripts.

The upstream identity URL in `REFERENCE_IDENTITY_URL` is expected to accept:

```json
{"audience":"vault"}
```

and respond with:

```json
{"jwt":"reference-runtime-identity-jwt"}
```

`REFERENCE_IDENTITY_URL`, the upstream helper protocol, and the local bridge protocol are all reference-workload choices. They are not platform requirements.

The current entrypoint also uses permissive local socket permissions as a validation convenience. That is not part of the platform contract or a production recommendation.

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
  - `REFERENCE_IDENTITY_URL`

Optional:

- `REFERENCE_SECRET_PATH`
- `REFERENCE_VAULT_INSECURE_SKIP_VERIFY=1`
