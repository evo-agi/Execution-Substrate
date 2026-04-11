# Runtime Identity Vault Login Workload

This directory contains the bounded platform-owned useful-credential-flow example for the current slice.

It does not create a workload-authored identity bridge. The workload is only a client of the platform-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT`.

## What It Demonstrates

The workload:

- discovers `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- proves the raw SPIRE socket remains helper-private
- requests a bounded real SPIRE-backed JWT-SVID for the `workload_vault` target
- performs `auth/jwt/login` itself against a proof-scoped real Vault dev/test target
- uses the returned Vault token to read one secret
- prints explicit success markers and a final JSON status line
- stays alive briefly after printing success so the operator proof path can capture workload logs before Nomad client log state disappears on this fast-completing example

This is the current bounded usefulness proof for slice `1A` and slice `1B`. It keeps identity delivery platform-owned while keeping Vault login and secret use workload-local.

## Files

- `entrypoint`: executable Python 3 workload entrypoint
- `package.sh`: packages the workload as the generated local artifact `dist/runtime_identity_vault_login.tar.gz`
- repo-owned proof bootstrap now lives in `scripts/72_supported_local_setup.sh` and `scripts/73_supported_local_proof.sh`

## Packaging

From the repository root:

```bash
".examples/runtime_identity_vault_login/package.sh"
```

This produces:

- `.examples/runtime_identity_vault_login/dist/runtime_identity_vault_login.tar.gz`

That `dist/` output is generated proof packaging, not tracked repo authority. Regenerate it with `package.sh` when needed.

## Runtime Requirements

- ES base image must include `python3`
- the workload must receive:
  - `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
  - `VAULT_ADDR`
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`

Optional:

- `WORKLOAD_VAULT_SECRET_PATH`
- `WORKLOAD_VAULT_INSECURE_SKIP_VERIFY=1`

## Expected Markers

Successful runs print:

- `PLATFORM-ENDPOINT-USED`
- `RAW-SPIRE-DENIED`
- `IDENTITY-JWT-RECEIVED`
- `VAULT-LOGIN-SUCCESS`
- `SECRET-READ-SUCCESS:<message>`
