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

## 5. Operator Troubleshooting Matrix

Use this matrix after an operator-facing helper already surfaced one of the bounded failure categories. Keep `scripts/01_bringup.sh check` and `scripts/10_health_check.sh` as the readiness source of truth. Later helpers should point back here rather than inventing a second readiness story.

Managed bring-up logs live under:

```bash
${BRINGUP_DIR:-/Users/ds/Repositories/Execution-Platform/.tmp/bringup}/logs
```

The current one-path bring-up writes:

- `ars.log`
- `egs.log`
- `ags.log`
- `es.log`
- `nomad.log` for `BRINGUP_PROFILE=full`

Docker daemon logs are outside this repo and are only a useful next step for substrate trouble.

| Failure class | Usually means | Source of truth | Most relevant logs | Retained staging useful? | Most useful next action |
| --- | --- | --- | --- | --- | --- |
| caller authorization / credential failure | The helper reached AGS or ES, but the caller cert/key was wrong for that operation or TLS auth failed before the request was accepted. | The failing helper itself (`scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, or `scripts/50_lifecycle.sh`). This is not a bring-up readiness failure. | `ags.log` for publish; `es.log` for prepare / submit / lifecycle. | No. There is no admitted run to inspect. | Verify `OPERATOR_CERT` and `OPERATOR_KEY`, confirm the caller is `spiffe://execution.internal/operator`, then retry. |
| trust / evidence / admission failure | The published artifact, aggregate evidence, signer policy, or admission inputs were rejected after auth succeeded. | The failing publish / prepare / submit helper. | `ags.log` for publish-side evidence handling, `es.log` for prepare / submit rejection, `egs.log` when signer or artifact trust policy is the likely cause. | No. The failure is before runtime handoff. | Check the published artifact digest, aggregate evidence, and EGS trust inputs before retrying. |
| runtime-config reference or blob failure | ES runtime-config points at a missing, unreadable, or structurally invalid workload-zone Vault blob in ARS. | `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh`. | `es.log` and `ars.log`. | No. Fix the referenced blob first. | Re-run `scripts/01_bringup.sh check`, then confirm `ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest` still points at a readable ARS JSON blob with the expected shape. |
| service health / readiness failure | A required service is down, unhealthy, or not ready enough to claim service health or prepare-ready. | `scripts/01_bringup.sh check` or `scripts/10_health_check.sh`. | The failing service log under `logs/`; if ES health is failing because an upstream dependency is sick, inspect that upstream log too. | No. Readiness must be restored first. | Re-run `scripts/01_bringup.sh check`, restore service health or prepare-ready, then retry publish / prepare / submit. |
| substrate failure (Docker / Nomad / runtime availability) | ES submit wiring, Docker availability, Nomad leadership, or Nomad client readiness is missing for the full submit path. | `scripts/01_bringup.sh check` or `scripts/10_health_check.sh` in `BRINGUP_PROFILE=full`. | `nomad.log`, `es.log`, and Docker daemon logs if `docker info` fails. | Usually no. If `:submit` was never accepted, there is no run staging to inspect. | Re-run `scripts/01_bringup.sh check`, then verify Docker, Nomad leader/client readiness, and ES submit config before retrying. |
| execution failure after successful submit | `:submit` returned a `run_id`, but the workload later failed, was canceled, got lost, or otherwise ended non-successfully. | `scripts/50_lifecycle.sh` or `scripts/60_execute_loop.sh`. | Workload logs from `scripts/50_lifecycle.sh` or the per-run `logs.txt` from `scripts/60_execute_loop.sh`, plus `es.log` and `nomad.log` if the runtime handoff itself looks suspicious. | Yes, but only for non-success outcomes with a real `run_id`. | Inspect lifecycle status/logs for the `run_id`, then inspect retained host staging under `execution.staging_root_dir/<run_id>` if the run failed, was canceled, was lost, or never reached clean success. |
| operator misuse / invalid input | The helper caught missing env vars, unreadable files, malformed JSON, or an invalid `run_id`, or the service returned a bounded input-validation error. | The failing helper itself. | Usually none. If the malformed request reached a service, inspect `ags.log` or `es.log` for the matching `400`. | No. Fix the input first. | Validate request JSON, env vars, readable file paths, and `run_id`, then retry. |

Staging inspection guidance in this slice:

- staging is only useful after a successful `:submit` already returned a real `run_id`
- failed, canceled, lost, or otherwise ambiguous outcomes intentionally retain `execution.staging_root_dir/<run_id>`
- terminal success may remove `execution.staging_root_dir/<run_id>` best-effort once ES observes success through `status` or `logs`
- if publish, prepare, or submit failed before a `run_id` existed, staging is the wrong next step

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
