# Governed Execution ES Submit Runtime Identity Vault Login Workload

## What is it?

This runbook proves the current bounded useful credential flow through the governed execution path: a workload logs in to Vault with the identity the platform gives it, and reads one secret.

`AGS publish -> ARS -> ES submit -> Nomad/Docker -> workload uses EXEC_WORKLOAD_IDENTITY_ENDPOINT -> workload performs Vault auth/jwt/login -> workload reads one secret`

This runbook is the current platform-owned proof path for useful credential flow completion. It does **not** use the legacy workload-authored bridge.

The downstream target in this runbook is a proof-scoped real Vault dev/test server. That is a realism upgrade for the bounded proof path, not a claim of full production Vault integration.

## What does it prove?

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

This runbook does **not** prove:

- host qualification by itself; use [.docs/system_overview/supported_linux_host_qualification.md](../../.docs/system_overview/supported_linux_host_qualification.md) and [.runbooks/system/Governed Execution ES System Bring-Up.md](../system/Governed%20Execution%20ES%20System%20Bring-Up.md) to distinguish `supported` from `bounded-fallback`
- arbitrary or root workload compatibility
- X.509 SVID delivery
- multi-host topology
- the final control-plane network model
- full production Vault integration

## What do I need?

All prerequisites from [.runbooks/system/Governed Execution ES System Bring-Up.md](../system/Governed%20Execution%20ES%20System%20Bring-Up.md) still apply.

In particular, before continuing:

- the standard operator bring-up path must report `submit-ready: true`
- ES config must already point at a workload-zone Vault blob in ARS
- that blob must use the bounded fields ES already consumes:
  - `vault_config.address`
  - `vault_config.auth_mount`
  - `vault_config.auth_role`
  - `vault_config.jwt_audience`

For this proof, set that workload-zone Vault blob so `vault_config.address` points at the proof-scoped Vault dev/test target you start in step 3. Do not replace the bounded auth fields with broader or custom ones for this slice.

The workload artifact lives at:

- [.examples/runtime_identity_vault_login/entrypoint](../../.examples/runtime_identity_vault_login/entrypoint)

The operator execute-loop input for this workload is:

- [.examples/execution_loop/runtime_identity_vault_success.input.json](../../.examples/execution_loop/runtime_identity_vault_success.input.json)

## How to use it?

Run command examples from the repository root unless a step says otherwise. The output to expect is taken from the scripts in this repository; Test Evidence says what has been run.

### 1. On the supported local reference host: run the canonical wrapper

On the current supported local reference host on this Mac, the canonical repo-owned path for this proof is now:

```bash
scripts/73_supported_local_proof.sh run
```

That wrapper records the proof under `.out/es-proof-<id>/`, runs supported-host qualification first, then runs this useful credential-flow workload through the real operator path. Before bootstrap it explicitly removes stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs, stages a fresh snapshot of the current host worktree into guest bootstrap scratch, and preserves the host `.out/es-proof-<id>/` evidence record as the canonical proof output.

Expect it to exit with status 0 and leave its evidence under `.out/es-proof-<id>/`. A failing phase prints `supported-local proof phase failed:` and the phase's name.

With the wrapper, you are done. Steps 2 to 6 remain the lower-level breakdown for debugging or for non-wrapper environments.

### 2. Bring up the stack

For the current supported local reference host on this Mac, prefer the canonical wrapper in step 1 instead of this lower-level sequence.

For lower-level debugging or non-wrapper environments, use the normal bring-up/readiness path that preserves the supported-host truth:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
BRINGUP_PROFILE=full scripts/01_bringup.sh check
```

Expect `bring-up complete` from `up`, then the readiness report from `check`. Do not continue unless the check reports `submit-ready: true`.

### 3. Start the proof-scoped Vault dev/test target

On the current supported local reference host on this Mac, the canonical wrapper already starts and configures the proof-scoped Vault dev/test target through `scripts/72_supported_local_setup.sh setup`, writes the generated bootstrap material to `managed-secrets.conf`, aligns the workload-zone Vault blob for this proof, and treats guest `/tmp/es-proof-*` as transient proof-owned scratch rather than as canonical evidence.

For lower-level debugging or non-wrapper environments, use that same repo-owned bootstrap layer rather than an ad hoc mock:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
source /tmp/execution-substrate-supported-local-proof/managed-secrets.conf
```

That setup script is the authoritative proof bootstrap for this runbook. It:

- boots a proof-scoped real SPIRE server/agent path and real Workload API socket used by the helper-private ES runtime mount
- starts `vault server -dev -dev-tls` as a proof-scoped process
- explicitly ensures the proof JWT auth mount exists at `auth/<mount>/login` and configures it with proof-only JWT validation material derived from the real SPIRE bundle
- explicitly enables or verifies the proof KV v2 mount backing `proof-secrets/data/...` before writing the bounded proof secret
- writes the proof secret used by the workload
- records the generated root token, CA cert path, JWT validation material, and proof secret mount details in `managed-secrets.conf`

For example, after setup you can inspect the real Vault dev/test target directly:

```bash
VAULT_ADDR="$PROOF_VAULT_LOCAL_ADDR" \
VAULT_CACERT="$PROOF_VAULT_CA_CERT_FILE" \
VAULT_TOKEN="$PROOF_VAULT_ROOT_TOKEN" \
vault status
```

Expect Vault's status table, with `Sealed` `false`.

This target is deliberately proof-scoped and dev/test only. It is real Vault, but it does **not** make Execution Substrate a production Vault integrator, a long-lived token broker, or a general infra manager. Long-lived Vault ownership still belongs to the larger ecosystem outside this bounded proof tooling. The proof still relies on the dev root token plus Vault's built-in system mounts for bootstrap, but the workload-facing JWT auth path and KV v2 secret mount are now established explicitly by the repo-owned proof setup.

### 4. Align the workload-zone Vault blob

Before submitting the workload, ensure the workload-zone Vault blob referenced by `ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest` has these bounded values:

```json
{
  "vault_config": {
    "address": "https://<container-reachable-host>:18200",
    "auth_mount": "jwt",
    "auth_role": "service_execution",
    "jwt_audience": "vault",
    "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

The canonical supported-local wrapper now performs that alignment through the same repo-owned proof setup path. Do not bypass the configured runtime-config reference with workload-owned overrides.

### 5. Execute the proof through the normal operator path

Package the workload:

```bash
".examples/runtime_identity_vault_login/package.sh"
```

The resulting archive is:

- `.examples/runtime_identity_vault_login/dist/runtime_identity_vault_login.tar.gz`

Run the normal execute-loop helper:

```bash
scripts/60_execute_loop.sh ".examples/execution_loop/runtime_identity_vault_success.input.json"
```

Expect `workdir=` and the run's work directory, `publish: success artifact_digest=sha256:…`, `prepare: success`, `submit: accepted run_id=run-…`, and last `execution: success run_id=run-… exit_code=0`. The work directory holds a structured summary and the captured logs.

### 6. Check the success markers

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

## Notes

- The workload archive is a generated local proof artifact, not tracked repo authority. Rebuild it with `package.sh` when needed.
- The repo also carries a native-Linux bootstrap validation at `go test ./es/app -run TestSupportedLocalSetupScriptBootstrapsRealSPIREAndVaultDevTarget -count=1`, but on this Mac the wrapper remains the canonical supported-local validation path because it stages and exercises a fresh host-worktree snapshot inside the guest and records the proof evidence under `.out/es-proof-<id>/`.
- For the canonical wrapper on this Mac:
  - stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs is cleaned automatically before a new proof starts
  - the current run's guest `/tmp/es-proof-*` scratch is removed after a successful host evidence copy
  - host `.out/es-proof-<id>/` remains the preserved canonical proof record and is not auto-deleted
  - old Nomad `exec-*` job history is left alone because fresh `run_id` values isolate new proof submissions from that dead history

## Test Evidence

- **Automated, in CI on every pull request:** the Linux job "build, vet and test" runs `TestSubmitFlowUsesPlatformOwnedIdentityForVaultLoginAndSecretRead`, which submits this runbook's workload, `.examples/runtime_identity_vault_login/entrypoint`, through ES to a real Nomad agent and Docker, with a mock Vault-compatible server in place of the Vault dev/test target. It also runs `TestSupportedLocalSetupScriptBootstrapsRealSPIREAndVaultDevTarget`, the native-Linux bootstrap validation named in Notes.
- **Not run:** the wrapper and the manual steps above, as written, were not run end to end when this runbook was restructured into this layout on 2026-11-25; no step's commands changed then.

## History

- **2026-04-07:** version `v1` of this runbook, last updated on this date before it came into this repository (from its former header).
- **2026-04-19:** came into this repository as `v1_submit_runtime_identity_vault_login.md` (PR #1).
- **2026-11-23:** renamed to its current name (PR #37).
- **2026-11-25:** restructured into the layout of the project's other runbooks (What is it?, What do I need?, How to use it? with numbered steps and the output to expect, Notes, Test Evidence, History), with the former sections "What This Flow Proves" and "What This Does Not Prove" under "What does it prove?"; the bring-up runbook was renamed to `Governed Execution ES System Bring-Up.md`. No command changed.
