# Runbook: Submit Runtime Identity Vault Login Workload (v1)

- Version: `v1`
- Last Updated: `2026-04-07`

## 1. Objective

Prove the current bounded useful credential flow through the governed execution path:

`AGS publish -> ARS -> ES submit -> Nomad/Docker -> workload uses EXEC_WORKLOAD_IDENTITY_ENDPOINT -> workload performs Vault auth/jwt/login -> workload reads one secret`

This runbook is the current platform-owned proof path for useful credential flow completion. It does **not** use the legacy workload-authored bridge.

The downstream target in this runbook is a proof-scoped real Vault dev/test server. That is a realism upgrade for the bounded proof path, not a claim of full production Vault integration.

On the current supported local reference host on this Mac, the canonical repo-owned path for this proof is now:

```bash
scripts/73_supported_local_proof.sh run
```

That wrapper records the proof under `.out/es-proof-<id>/`, runs supported-host qualification first, then runs this useful credential-flow workload through the real operator path. The manual sections below remain the lower-level breakdown for debugging or for non-wrapper environments.

## 2. Proof Asset

The workload artifact lives at:

- [/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/entrypoint](/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/entrypoint)

Package it with:

```bash
"/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/package.sh"
```

The resulting archive is:

- `/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/dist/runtime_identity_vault_login.tar.gz`

The operator execute-loop input for this workload is:

- [/Users/ds/Repositories/Execution Substrate/.examples/execution_loop/runtime_identity_vault_success.input.json](/Users/ds/Repositories/Execution Substrate/.examples/execution_loop/runtime_identity_vault_success.input.json)

## 3. What This Flow Proves

The workload:

- consumes only `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- proves the raw SPIRE socket remains helper-private
- requests the bounded JWT-SVID for `workload_vault`
- performs `POST /v1/auth/<mount>/login` itself as a client
- uses the returned Vault token to read one secret
- remains alive briefly after printing success markers so the normal operator polling path can capture workload logs before Nomad client log state disappears for this fast-completing proof workload

This slice deliberately does **not**:

- expose raw SPIRE to the workload
- introduce platform-owned Vault token brokerage
- broaden helper requests beyond the bounded `workload_vault` JWT-SVID target
- claim X.509, multi-host, or broader workload compatibility

## 4. Preconditions

All prerequisites from [/Users/ds/Repositories/Execution Substrate/.runbooks/system/v1_bringup.md](/Users/ds/Repositories/Execution Substrate/.runbooks/system/v1_bringup.md) still apply.

In particular, before continuing:

- the standard operator bring-up path must report `submit-ready: true`
- ES config must already point at a workload-zone Vault blob in ARS
- that blob must use the bounded fields ES already consumes:
  - `vault_config.address`
  - `vault_config.auth_mount`
  - `vault_config.auth_role`
  - `vault_config.jwt_audience`

For this proof, set that workload-zone Vault blob so `vault_config.address` points at the proof-scoped Vault dev/test target you start below. Do not replace the bounded auth fields with broader or custom ones for this slice.

## 5. Bring Up The Stack

For the current supported local reference host on this Mac, prefer the canonical wrapper above instead of this lower-level sequence.

For lower-level debugging or non-wrapper environments, use the normal bring-up/readiness path that preserves the supported-host truth:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
BRINGUP_PROFILE=full scripts/01_bringup.sh check
```

Do not continue unless the check reports `submit-ready: true`.

## 6. Proof-Scoped Vault Dev/Test Bootstrap

On the current supported local reference host on this Mac, the canonical wrapper already starts and configures the proof-scoped Vault dev/test target through `scripts/72_supported_local_setup.sh setup`, writes the generated bootstrap material to `managed-secrets.conf`, and aligns the workload-zone Vault blob for this proof.

For lower-level debugging or non-wrapper environments, use that same repo-owned bootstrap layer rather than an ad hoc mock:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
source /tmp/execution-substrate-supported-local-proof/managed-secrets.conf
```

That setup script is the authoritative proof bootstrap for this runbook. It:

- starts `vault server -dev -dev-tls` as a proof-scoped process
- configures JWT auth at `auth/<mount>/login` using the repo-owned mock SPIFFE Workload API signing public key
- writes the proof secret used by the workload
- records the generated root token, CA cert path, and JWT validation material in `managed-secrets.conf`

For example, after setup you can inspect the real Vault dev/test target directly:

```bash
VAULT_ADDR="$PROOF_VAULT_LOCAL_ADDR" \
VAULT_CACERT="$PROOF_VAULT_CA_CERT_FILE" \
VAULT_TOKEN="$PROOF_VAULT_ROOT_TOKEN" \
vault status
```

This target is deliberately proof-scoped and dev/test only. It is real Vault, but it does **not** make Execution Substrate a production Vault integrator, a long-lived token broker, or a general infra manager.

## 7. Align The Workload-Zone Vault Blob

Before submitting the workload, ensure the workload-zone Vault blob referenced by `ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest` has these bounded values:

```json
{
  "vault_config": {
    "address": "https://<container-reachable-host>:18200",
    "auth_mount": "jwt",
    "auth_role": "service_execution",
    "jwt_audience": "vault"
  }
}
```

The canonical supported-local wrapper now performs that alignment through the same repo-owned proof setup path. Do not bypass the configured runtime-config reference with workload-owned overrides.

## 8. Execute The Proof Through The Normal Operator Path

Package the workload:

```bash
"/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/package.sh"
```

Run the normal execute-loop helper:

```bash
scripts/60_execute_loop.sh "/Users/ds/Repositories/Execution Substrate/.examples/execution_loop/runtime_identity_vault_success.input.json"
```

## 9. Expected Success Markers

Successful workload logs include:

- `PLATFORM-ENDPOINT-USED`
- `RAW-SPIRE-DENIED`
- `IDENTITY-JWT-RECEIVED`
- `VAULT-LOGIN-SUCCESS`
- `SECRET-READ-SUCCESS:runtime-identity-ok`

The final log line is a JSON status object containing:

- `"status": "ok"`
- `"secret_message": "runtime-identity-ok"`
- the governed `artifact_digest`

## 10. What This Does Not Prove

This runbook does **not** prove:

- host qualification by itself; use [/Users/ds/Repositories/Execution Substrate/.docs/system_overview/supported_linux_host_qualification.md](/Users/ds/Repositories/Execution Substrate/.docs/system_overview/supported_linux_host_qualification.md) and [/Users/ds/Repositories/Execution Substrate/.runbooks/system/v1_bringup.md](/Users/ds/Repositories/Execution Substrate/.runbooks/system/v1_bringup.md) to distinguish `supported` from `bounded-fallback`
- arbitrary or root workload compatibility
- X.509 SVID delivery
- multi-host topology
- the final control-plane network model
- full production Vault integration
