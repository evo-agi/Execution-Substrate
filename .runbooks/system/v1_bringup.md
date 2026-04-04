# Runbook: Governed System Bring-up (v1)

- Version: `v1`
- Last Updated: `2026-04-04`
- Compatible System Version: `Execution-Platform current working tree`

## 1. Objective

Bring up the current bounded governed system through one operator path and verify the live execution slice:

`AGS publish -> ARS -> ES prepare -> ES submit -> Nomad -> Docker -> ES lifecycle`

The preferred operator path is now:

- `scripts/01_bringup.sh up`
- `scripts/01_bringup.sh check`
- `scripts/60_execute_loop.sh`
- `scripts/01_bringup.sh down`

The lower-level `scripts/02_start_*.sh` through `scripts/06_start_nomad.sh` helpers remain available as manual fallback, but they are no longer the primary documented bring-up flow.

The readiness vocabulary for that primary path is now:

- `service health`: the public health surfaces for ARS, EGS, AGS, and ES are up and reporting ready
- `prepare-ready`: service health plus successful workload-zone Vault runtime-config blob verification through ARS
- `submit-ready`: prepare-ready plus ES submit config present, Docker available, Nomad leader present, and at least one ready Nomad client node

## 2. Prerequisites

### Required software

- Go `1.22.x`
- `curl`
- `python3`
- `tar`
- `gzip`
- `nomad`
- `docker`

### Required environment

- Docker daemon running
- runtime CA, service certificates, and client certificates already provisioned
- service config files prepared as JSON

### Required config files

Export absolute paths:

```bash
export ARS_CONFIG="/abs/path/ars.json"
export EGS_CONFIG="/abs/path/egs.json"
export AGS_CONFIG="/abs/path/ags.json"
export ES_CONFIG="/abs/path/es.json"
export NOMAD_CONFIG="/abs/path/nomad.hcl"
```

Build these from the current validators and the configuration matrix in [configuration.md](/Users/ds/Repositories/Execution-Platform/.docs/system_overview/configuration.md). Example templates live under [/Users/ds/Repositories/Execution-Platform/.examples/config](/Users/ds/Repositories/Execution-Platform/.examples/config), but they are templates only.

### Required TLS material for API calls and bring-up verification

Export a CA bundle and a client cert/key that authenticate as:

- `spiffe://execution.internal/operator`

```bash
export CA_CERT="/abs/path/runtime-ca.pem"
export OPERATOR_CERT="/abs/path/operator-client.pem"
export OPERATOR_KEY="/abs/path/operator-client-key.pem"
```

If your ARS read policy does not allow the operator identity, also export a separate ARS read client:

```bash
export ARS_READ_CERT="/abs/path/execution-client.pem"
export ARS_READ_KEY="/abs/path/execution-client-key.pem"
```

`scripts/01_bringup.sh` and `scripts/10_health_check.sh` use the ARS read client only to verify the configured workload-zone Vault blob exists and has the expected JSON shape before first execution. If `ARS_READ_CERT` and `ARS_READ_KEY` are omitted, those checks fall back to `OPERATOR_CERT` and `OPERATOR_KEY`.

### Required service URLs

Adjust these to match your environment:

```bash
export ARS_URL="https://127.0.0.1:8442"
export EGS_URL="https://127.0.0.1:8443"
export AGS_URL="https://127.0.0.1:8444"
export ES_URL="https://127.0.0.1:8445"
export NOMAD_ADDR="http://127.0.0.1:4646"
```

Optional local hostname overrides for `curl --resolve`:

```bash
export ARS_RESOLVE="server.artifact-registry.internal:8442:127.0.0.1"
export EGS_RESOLVE="server.execution-governance.internal:8443:127.0.0.1"
export AGS_RESOLVE="server.artifact-governance.internal:8444:127.0.0.1"
export ES_RESOLVE="server.execution.internal:8445:127.0.0.1"
```

### Required data assumptions

The current bounded system still assumes:

- ES startup config includes `runtime_config.workload_zone_vault_config_ref.digest`
- ARS already contains the workload-zone Vault JSON blob referenced by that digest
- EGS TrustModel `allowed_signers` includes the AGS signer key ID
- ES verification keys match EGS and AGS signing keys
- ES `workload_vault_auth.default_mode` is `vault_identity_jwt`
- ES `nomad` and `execution` sections are configured for real `:submit`
- Nomad Docker bind mounts are enabled
- the configured ES base image is available or pullable

CGS is not required for this bring-up runbook because it is not part of the current ES hot path.

## 3. Primary Bring-up Path

Run all commands from:

`/Users/ds/Repositories/Execution-Platform`

### Full execution profile

Use this for the current real execution slice:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
```

What this does:

- starts ARS, verifies ARS health, and verifies the configured workload-zone Vault blob through ARS
- starts EGS and AGS and waits for their public health surfaces to report `"ready": true`
- starts ES and waits for its admission-oriented health surface to report `"ready": true`
- verifies Docker readiness
- starts Nomad and waits for a leader plus at least one ready node
- runs the unified readiness check once more before reporting success as both prepare-ready and submit-ready

Successful output ends with:

```text
bring-up complete
```

The script writes PID files and logs under:

```bash
${BRINGUP_DIR:-/Users/ds/Repositories/Execution-Platform/.tmp/bringup}
```

### Prepare-only profile

If you want only bounded preflight `:prepare` and not real submit/lifecycle:

```bash
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
```

This still starts ARS, EGS, AGS, and ES, and it still verifies the workload-zone Vault blob. It intentionally skips Nomad and Docker readiness.

In this profile, successful bring-up proves `prepare-ready` only. `submit-ready` is intentionally skipped because `:submit` and lifecycle are out of scope for `prepare-only`.

## 4. Readiness Verification

Re-run readiness checks at any time with:

```bash
scripts/01_bringup.sh check
```

Or directly:

```bash
VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh
```

For the full profile, `scripts/01_bringup.sh check` now reports three layers:

- service health
- prepare-ready
- submit-ready

For the full profile, `submit-ready: true` means:

- ARS, EGS, AGS, and ES each return `200` with `"ready": true`
- Nomad has a leader and at least one ready node
- `docker info` succeeds
- ES submit config still includes `nomad.base_url`, `nomad.datacenter`, `execution.staging_root_dir`, and `execution.base_image`
- the workload-zone Vault blob named by `runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and validates structurally

For ES specifically, `/health` still confirms:

- server started
- trust model loaded
- ARS healthy

It still does **not** imply Nomad is reachable, which is why the bring-up path verifies Nomad separately.

For `prepare-only`, success still means:

- ARS, EGS, AGS, and ES each return `200` with `"ready": true`
- the workload-zone Vault blob named by `runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and validates structurally
- `submit-ready` is reported as skipped for that profile

## 5. Failure Guidance

Use the current bounded failure classes when operator-facing helpers fail:

- caller authorization / credential failure
  - check `OPERATOR_CERT` and `OPERATOR_KEY`
  - confirm the client identity is `spiffe://execution.internal/operator`
- trust / evidence / admission failure
  - check the published artifact, aggregate evidence, and EGS trust model inputs
- runtime-config reference or blob failure
  - re-run `scripts/01_bringup.sh check`
  - confirm `ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest` points at a readable ARS blob with the expected JSON shape
- service health / readiness failure
  - re-run `scripts/01_bringup.sh check`
  - restore service health or prepare-ready before retrying publish / prepare / submit
- substrate failure (Docker / Nomad / runtime availability)
  - re-run `scripts/01_bringup.sh check`
  - confirm Docker is reachable and Nomad has a leader plus a ready client
- execution failure after successful submit
  - inspect `scripts/50_lifecycle.sh` output and workload logs
  - in this slice, failed, canceled, lost, or otherwise ambiguous runs retain host staging under `execution.staging_root_dir/<run_id>` for debugging
- operator misuse / invalid input
  - validate request JSON, env vars, readable file paths, and `run_id`

Later helpers still rely on this bring-up/check path as the readiness source of truth. They should not be treated as a replacement readiness probe.

## 6. First Execution Verification

After bring-up succeeds, the preferred bounded end-to-end smoke test is:

```bash
scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json
```

That helper drives:

- AGS publish
- ES `:prepare`
- ES `:submit`
- ES `status`
- ES `logs`

and writes a structured summary plus captured logs to a per-run work directory.

Because that helper waits for terminal status and then reads logs, it also exercises the current successful-submit staging cleanup policy: ES keeps `execution.staging_root_dir/<run_id>` while the workload may still depend on it, then best-effort removes that staging root after terminal success is observed. Failed, canceled, lost, or otherwise ambiguous outcomes intentionally retain staging for debugging.

If you want the manual publish/prepare/submit breakdown instead, use:

- [/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_static_script.md](/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_static_script.md)
- [/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_runtime_identity_reference.md](/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_runtime_identity_reference.md)

## 7. Shutdown

Stop all managed processes with:

```bash
scripts/01_bringup.sh down
```

This stops, in order:

- Nomad
- ES
- AGS
- EGS
- ARS

## 8. Manual Fallback

If you need foreground manual startup for one service at a time, the direct wrappers remain available:

- `scripts/02_start_ars.sh`
- `scripts/03_start_egs.sh`
- `scripts/04_start_ags.sh`
- `scripts/05_start_es.sh`
- `scripts/06_start_nomad.sh`

Those scripts still require the same explicit config env vars, but they no longer define the primary operator path for the current slice.
