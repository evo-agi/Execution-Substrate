# Runbook: Submit Runtime Identity Vault Login Workload (v1)

- Version: `v1`
- Last Updated: `2026-04-05`

## 1. Objective

Prove the current bounded useful credential flow through the governed execution path:

`AGS publish -> ARS -> ES submit -> Nomad/Docker -> workload uses EXEC_WORKLOAD_IDENTITY_ENDPOINT -> workload performs Vault-compatible auth/jwt/login -> workload reads one secret`

This runbook is the current platform-owned proof path for useful credential flow completion. It does **not** use the legacy workload-authored bridge.

The downstream target in this runbook is a bounded Vault-compatible HTTPS mock endpoint, not a claim of full Vault integration.

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

For this proof, set that workload-zone Vault blob so `vault_config.address` points at the HTTPS mock endpoint you start below. Do not replace the bounded auth fields with broader or custom ones for this slice.

## 5. Bring Up The Stack

Use the normal full bring-up path:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
scripts/01_bringup.sh check
```

Do not continue unless the check reports `submit-ready: true`.

## 6. Start The Vault-Compatible HTTPS Mock

Generate a bounded local certificate for the HTTPS mock:

```bash
WORKDIR="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORKDIR/mock-vault-key.pem" \
  -out "$WORKDIR/mock-vault-cert.pem" \
  -subj "/CN=mock-vault.internal"
```

Choose a host address reachable from bridge-networked workload containers. On a standard Docker bridge host, this is usually the bridge gateway:

```bash
export VAULT_HOST="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
export VAULT_PORT="18200"
export VAULT_ADDR_VALUE="https://${VAULT_HOST}:${VAULT_PORT}"
```

Start the bounded Vault-compatible HTTPS mock:

```bash
python3 "/Users/ds/Repositories/Execution Substrate/.examples/runtime_identity_vault_login/helpers/mock_vault.py" \
  --bind 0.0.0.0 \
  --port "${VAULT_PORT}" \
  --auth-mount jwt \
  --role service_execution \
  --bound-audience vault \
  --secret-path secret/data/runtime-identity-vault-login \
  --secret-value runtime-identity-ok \
  --cert-file "$WORKDIR/mock-vault-cert.pem" \
  --key-file "$WORKDIR/mock-vault-key.pem"
```

This target is deliberately only a compatibility/mock endpoint. It validates the bounded JWT claims shape enough for this proof, returns one client token, and serves one secret path.

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

This runbook assumes that referenced ARS blob has already been updated through the same configuration path your environment normally uses. Do not bypass the configured runtime-config reference with workload-owned overrides.

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

- natural schedulability without the bounded `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` workaround on the current proof VM
- arbitrary or root workload compatibility
- X.509 SVID delivery
- multi-host topology
- the final control-plane network model
- full production Vault integration
