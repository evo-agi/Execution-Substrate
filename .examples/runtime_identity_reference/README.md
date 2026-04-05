# Runtime Identity Reference Workload

This directory contains a legacy reference `static-script` workload that exercises the older workload-authored runtime-identity bridge shape.

Everything in this directory is example-level scaffolding only. It is not the slice-1 platform-owned runtime identity implementation. The platform contract is limited to the reserved runtime-identity workspace, the discovered `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, and the non-secret Vault auth environment variables.

For the current bounded platform-owned proof path, prefer [/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/README.md](/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/README.md).

## What It Demonstrates

The reference workload:

- reads `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- creates its own local bridge at the reserved runtime identity path
- reads bounded non-secret Vault auth metadata from the environment
- obtains a JWT from `REFERENCE_IDENTITY_URL` through that local bridge
- authenticates to Vault locally
- reads one test secret from Vault
- prints success markers and the secret message to stdout

That workload-authored bridge is retained only as example scaffolding. Slice 1 replaces this ownership model with a platform-owned helper launched by the platform supervisor inside the workload task.

## Reference Identity Protocols

This reference workload creates a Unix-socket endpoint at `EXEC_WORKLOAD_IDENTITY_ENDPOINT`.

The local endpoint speaks a small JSON-line protocol:

Request:

```json
{"kind":"jwt_request","audience":"vault"}
```

Response:

```json
{"jwt":"reference-runtime-identity-jwt"}
```

The platform contract does not require this protocol. This request shape exists only for the legacy reference workload and its helper scripts.

The upstream identity URL in `REFERENCE_IDENTITY_URL` is expected to accept:

```json
{"audience":"vault"}
```

and respond with:

```json
{"jwt":"reference-runtime-identity-jwt"}
```

`REFERENCE_IDENTITY_URL`, the upstream helper protocol, and the local bridge protocol are all reference-workload choices. They are not platform requirements and they are not the slice-1 platform-owned endpoint shape.

The current reference entrypoint also uses permissive local socket permissions as a validation convenience. That is not part of the platform contract, not a production recommendation, and not the slice-1 platform-owned runtime boundary.

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
  - `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
  - `VAULT_ADDR`
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`
  - `REFERENCE_IDENTITY_URL`

Optional:

- `REFERENCE_SECRET_PATH`
- `REFERENCE_VAULT_INSECURE_SKIP_VERIFY=1`
