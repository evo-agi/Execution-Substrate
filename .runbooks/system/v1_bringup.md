# Runbook: Governed System Bring-up (v1)

- Version: `v1`
- Last Updated: `2026-04-07`
- Compatible System Version: `Execution Substrate current working tree`

## 1. Objective

Bring up the current bounded governed system through one operator path and verify the live execution slice:

`AGS publish -> ARS -> ES prepare -> ES submit -> Nomad -> Docker -> ES lifecycle`

The preferred operator path is now:

- repo-owned supported-local proof environment setup inside the guest: `scripts/72_supported_local_setup.sh setup`
- canonical supported-local proof wrapper on this Mac: `scripts/73_supported_local_proof.sh run`
- inside that wrapper, clean supported-host qualification still happens first: `BRINGUP_PROFILE=prepare-only scripts/01_bringup.sh up`, then `BRINGUP_PROFILE=full scripts/01_bringup.sh check`
- inside that wrapper, the canonical higher-value proof workload is now the bounded runtime-identity Vault-login path through `scripts/60_execute_loop.sh`
- bounded local fallback bootstrap when the repo must manage Nomad itself: `BRINGUP_PROFILE=full scripts/01_bringup.sh up`
- teardown of repo-managed services: `scripts/01_bringup.sh down`

The lower-level `scripts/02_start_*.sh` through `scripts/06_start_nomad.sh` helpers remain available as manual fallback, but they are no longer the primary documented bring-up flow.

The readiness vocabulary for that primary path is now:

- `service health`: the public health surfaces for ARS, EGS, AGS, and ES are up and reporting ready
- `prepare-ready`: service health plus successful workload-zone Vault runtime-config blob verification through ARS
- `submit-ready`: prepare-ready plus ES submit config present, Docker available, Nomad leader present, and at least one ready Nomad client node with positive `cpu.totalcompute` and a healthy Docker driver

## 2. Prerequisites

### Required software

- `curl`
- `python3`
- `tar`
- `gzip`
- `nomad`
- `docker`

### Required environment

- one Linux host/VM for the actual slice-0 topology proof
- Docker daemon running
- runtime CA, service certificates, and client certificates already provisioned
- service config files prepared as JSON
- Docker host networking must be able to reach host loopback from a container
  - `scripts/01_bringup.sh up` probes this behavior before starting services
  - this host networking use is temporary slice-0 compatibility scaffolding only, not the final control-plane network model

For a fresh Linux workload-zone VM, use `/Users/ds/Repositories/Execution Substrate/scripts/70_linux_setup.sh` as the bounded bootstrap helper.

Before treating any Linux host or VM as the repo's clean `supported` environment, apply the host qualification boundary in [supported_linux_host_qualification.md](/Users/ds/Repositories/Execution Substrate/.docs/system_overview/supported_linux_host_qualification.md).

That helper currently:

- installs the base packages used by the operator path
- writes the single-node `/etc/nomad.d/nomad.hcl` used for the one-host workload-zone baseline
- enables Docker
- tries to enable and start the root-managed non-`-dev` `nomad.service`
- exits nonzero if the VM still cannot qualify the supported substrate baseline

That helper does **not** override host-admin reality:

- it still relies on `sudo` for package and service management
- it does not silently accept leftover user-started Nomad processes as equivalent to a supported pre-managed service
- it does not normalize `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` as part of the supported profile
- if it had to add the current user to the `docker` group, log out and back in before treating the host as ready for repo scripts
- if `nomad.service` still cannot start cleanly or natural `cpu.totalcompute` remains `0`, treat the VM as not yet supported and investigate at the host/service layer before using the main operator path
- if the root-managed non-`-dev` service is up but the node still reports `cpu.totalcompute=0`, inspect host capability by behavior: no readable `cpufreq` sysfs files, no `/proc/cpuinfo` `cpu MHz`, and SMBIOS processor `Current Speed: Unknown` means the guest is not exposing the CPU-frequency data Nomad needs for natural schedulability
- on the current Apple Silicon Mac, Lima `qemu` + Ubuntu 24.04 arm64 now qualifies under the real `nomad.service` path without override, while the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain unsupported because natural `cpu.totalcompute` stays `0`

### Required config files

Export absolute paths:

```bash
export ARS_CONFIG="/abs/path/ars.json"
export EGS_CONFIG="/abs/path/egs.json"
export AGS_CONFIG="/abs/path/ags.json"
export ES_CONFIG="/abs/path/es.json"
export NOMAD_CONFIG="/abs/path/nomad.hcl"
```

Build these from the current validators and the configuration matrix in [configuration.md](/Users/ds/Repositories/Execution Substrate/.docs/system_overview/configuration.md). Example templates live under [/Users/ds/Repositories/Execution Substrate/.examples/config](/Users/ds/Repositories/Execution Substrate/.examples/config), but they are templates only.

For the clean supported-host path, use `BRINGUP_PROFILE=prepare-only scripts/01_bringup.sh up` for the control plane and `BRINGUP_PROFILE=full scripts/01_bringup.sh check` against the already-running pre-managed Nomad endpoint.

On the current supported local reference host on this Mac, you do not need the earlier out-of-repo `/tmp` harnesses. The canonical supported-local proof path is now:

```bash
scripts/73_supported_local_proof.sh run
```

That repo-owned wrapper creates the canonical proof workspace under `.out/es-proof-<id>/`, packages the bounded runtime-identity Vault-login workload, removes stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs, invokes the guest-side `scripts/72_supported_local_setup.sh setup`, runs the supported-host qualification sequence, runs the higher-value useful credential-flow proof, and collects the resulting guest evidence back into that canonical workspace.

On this Mac, the wrapper still uses a guest `/tmp/es-proof-<id>` workspace internally because Lima mounts the repo tree read-only inside the current `qemu` guest. That guest scratch is proof-owned transient implementation detail: the wrapper cleans stale proof-owned guest scratch before a new run and removes the current guest scratch after a successful host evidence copy. The canonical proof workspace is the host-side `.out/es-proof-<id>/`.

The repo also carries a native-Linux bootstrap validation at `go test ./es/app -run TestSupportedLocalSetupScriptBootstrapsRealSPIREAndVaultDevTarget -count=1`, but that test is not the canonical supported-local validation path on this Mac. The supported-local closure proof here is the wrapper run above because it stages the current host working tree into the guest and records the canonical evidence under `.out/es-proof-<id>/`.

For the current full-profile script path, `scripts/01_bringup.sh up` still starts Nomad itself from `NOMAD_CONFIG`. Treat that path as bounded fallback/troubleshooting scaffolding, not as the clean supported-environment story for Linux.

Optional bounded slice-0 override for proof hosts where Nomad CPU fingerprinting fails:

```bash
export NOMAD_CLIENT_CPU_TOTAL_COMPUTE="2000"
```

Use this only when Nomad otherwise reports `cpu.totalcompute=0` on the proof node. `scripts/06_start_nomad.sh` converts it into a transient client override for the current bring-up run; it is deployment troubleshooting, not a new platform contract.

When this override is active, the current operator path surfaces that explicitly:

- `scripts/01_bringup.sh up` and `scripts/01_bringup.sh check` report `submit-ready-mode: bounded-override (...)`
- successful execution in that mode is still a bounded slice-0 proof, not evidence that the host is naturally schedulable without the override

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

`scripts/01_bringup.sh` and `scripts/10_health_check.sh` use a runtime-issued client certificate for all service health checks because `/health` is now behind strict mTLS. They use the ARS read client only for the workload-zone Vault blob read when the operator identity is not sufficient. If `ARS_READ_CERT` and `ARS_READ_KEY` are omitted, those checks fall back to `OPERATOR_CERT` and `OPERATOR_KEY`.

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
- single-node loopback Nomad configs set explicit `advertise` addresses for `http`, `rpc`, and `serf`
- the configured ES base image is available or pullable

CGS is not required for this bring-up runbook because it is not part of the current ES hot path.

## 3. Primary Bring-up Path

Run all commands from:

`/Users/ds/Repositories/Execution Substrate`

### Supported-host qualification path

Use this when Nomad is already running as the packaged pre-managed non-`-dev` service and you want the repo proof path to preserve that fact:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
BRINGUP_PROFILE=full scripts/01_bringup.sh check
```

Pass only if the check reports:

- `nomad-startup-mode: pre-managed`
- `submit-ready-mode: natural`
- `supported-environment: supported`
- `submit-ready: true`

On the current Apple Silicon Mac, Lima `qemu` + Ubuntu 24.04 arm64 is the known supported local reference profile for this path. The previously investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain unsupported on this Mac because natural `cpu.totalcompute` stays `0`.

The current guest-side helper is intentionally narrow:

- it prepares the bounded supported-local proof environment used by both qualification and the canonical useful credential-flow proof
- it boots the proof-scoped real SPIRE server/agent path that backs the helper-private Workload API socket used by ES submit config
- it seeds the bounded workload-zone Vault runtime fields used by ES, including the proof-scoped real Vault dev/test target for the current runtime-identity Vault-login workload
- it does not broaden the slice beyond the bounded workload-vault login and one-secret-read proof

### Full execution profile

Use this when you intentionally want the repo to manage a local Nomad process for the current real execution slice:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
```

What this does:

- regenerates `.out/Dockerfile` through `scripts/generate_control_plane_dockerfile.sh`, then rebuilds the shared service image used by the current bring-up path; that image currently bundles `ars`, `ags`, `egs`, `es`, `es-runtime-support`, and `cgs` even though the minimal operator path starts only ARS, EGS, AGS, and ES
- proves that Docker host networking can actually reach host loopback from a container before continuing
- starts ARS, verifies ARS health, and verifies the configured workload-zone Vault blob through ARS
- starts EGS and AGS and waits for their public health surfaces to report `"ready": true`
- starts ES and waits for its admission-oriented health surface to report `"ready": true`
- records the ES same-path staging proof at `${BRINGUP_DIR}/staging-invariant.json`
- verifies Docker readiness
- starts Nomad from `NOMAD_CONFIG` as a bounded local fallback/troubleshooting path, then waits for a leader plus at least one ready node with positive `cpu.totalcompute` and a healthy Docker driver
- runs the unified readiness check once more before reporting success as both prepare-ready and submit-ready

Note:

- in the current slice, `submit-ready` now rejects zero-compute or Docker-unhealthy Nomad nodes, but it still does not prove every later placement constraint; a job can still fail on memory, device, or other scheduler limits after bring-up is green
- on hosts where Nomad reports `cpu.totalcompute=0`, the natural bring-up path now fails explicitly with a bounded troubleshooting message instead of claiming submit-ready and leaving the first workload stuck in `submitted`
- a green `submit-ready` result is not the whole support claim by itself; the operator output also reports `nomad-startup-mode`, `supported-environment`, and `submit-ready-mode`
- because this profile starts Nomad itself, it remains bounded fallback even when it becomes submit-ready

Successful output ends with:

```text
bring-up complete
```

The script writes PID files and logs under:

```bash
"${BRINGUP_DIR:-/Users/ds/Repositories/Execution Substrate/.tmp/bringup}"
```

### Prepare-only profile

If you want only bounded preflight `:prepare` and not real submit/lifecycle:

```bash
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
```

This still starts ARS, EGS, AGS, and ES, and it still verifies the workload-zone Vault blob. It intentionally skips Nomad and Docker readiness.

Prepare-only still requires Docker because the hot-path control plane now runs in containers.

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

It also reports:

- `nomad-startup-mode`
- `supported-environment`
- `submit-ready-mode`

For the full profile, `submit-ready: true` means:

- ARS, EGS, AGS, and ES each return `200` with `"ready": true`
- those health checks succeeded with a valid client certificate at the TLS boundary
- Nomad `GET /v1/agent/self` does not report `config.DevMode=true`
- Nomad has a leader and at least one ready node with positive `cpu.totalcompute` and a healthy Docker driver
- `docker info` succeeds
- ES submit config still includes `nomad.base_url`, `nomad.datacenter`, `execution.staging_root_dir`, and `execution.base_image`
- the workload-zone Vault blob named by `runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and validates structurally
- the current ES same-path staging invariant has already been recorded at `${BRINGUP_DIR}/staging-invariant.json`

Current limitation:

- this readiness result now rejects `cpu.totalcompute=0` and Docker-unhealthy nodes, but it still does not guarantee successful placement for every workload shape; later memory, device, or other constraint failures remain possible
- if the host requires `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` to become schedulable, that remains bounded fallback rather than clean evidence of natural substrate support
- the current script-managed local Nomad path also remains bounded fallback/troubleshooting even when Nomad is schedulable; the supported-environment story for this slice is still a pre-managed non-`-dev` Nomad service on the Linux host/VM plus natural schedulability
- a pre-managed `nomad agent -dev` environment is unsupported for that support claim even if it looks healthy and exposes positive compute
- on the current Apple Silicon Mac, the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain ruled out for the supported-profile claim because the real root-managed non-`-dev` service still reports `cpu.totalcompute=0`

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
"${BRINGUP_DIR:-/Users/ds/Repositories/Execution Substrate/.tmp/bringup}/logs"
```

The current one-path bring-up writes:

- `ars.log`
- `egs.log`
- `ags.log`
- `es.log`
- `nomad.log` for `BRINGUP_PROFILE=full`
- `control-plane-image-build.log`
- `staging-invariant.json`

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

Companion diagnostics helper for the same matrix:

- `scripts/70_diagnostics.sh --category auth|trust|runtime-config|readiness|substrate|execution|input`
- `scripts/70_diagnostics.sh --run-id run-0123456789abcdef`
- `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>`

The collector accepts either the short category aliases above or the surfaced failure labels from the operator-facing scripts. It gathers only the checks, logs, lifecycle output, and staging inspection signals already called out in this matrix. It prints both `bundle_dir=` and `bundle_json=` so the summary helper can render the collected bundle without re-running diagnostics.

## 6. First Execution Verification

After bring-up succeeds, the preferred bounded end-to-end proof on the current supported local reference host on this Mac is:

```bash
scripts/73_supported_local_proof.sh run
```

This path still proves the one-host Linux substrate and same-path staging contract directly, and it now makes the bounded useful credential flow the canonical higher-value governed proof on that already-qualified host. The first platform-owned runtime identity boundary remains active through the real ES -> Nomad -> Docker path: same-container supervisor/helper, helper-private SPIRE channel, fixed non-root workload launch, and helper-death/task-fatal behavior are all active in the current slice.

For the underlying credential-flow details, use [/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_runtime_identity_vault_login.md](/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_runtime_identity_vault_login.md).

That bounded proof has now also been exercised on a supported local host on the current Apple Silicon Mac through Lima `qemu` + Ubuntu 24.04 arm64 under a pre-managed non-`-dev` Nomad service with natural `cpu.totalcompute`. The previously investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain unsupported on this Mac because the real service path still leaves natural `cpu.totalcompute=0`.

On Linux, keep the supported-environment story narrow and explicit:

- `supported`: pre-managed non-`-dev` Nomad already running on the host/VM, Docker healthy, and at least one ready node exposes positive `cpu.totalcompute` without override; on this Mac, Lima `qemu` + Ubuntu 24.04 arm64 is the known supported local reference profile
- `bounded-fallback`: the current script-managed local Nomad path, or any run that needs `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`
- `unsupported`: Docker unhealthy, Nomad `DevMode=true`, no Nomad leader, no ready Docker-capable node, or `cpu.totalcompute=0` without explicit bounded override; on this Mac, the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles are currently in this bucket

That helper drives:

- AGS publish
- ES `:prepare`
- ES `:submit`
- ES `status`
- ES `logs`

and writes a structured summary plus captured logs to a per-run work directory.

Because that helper waits for terminal status and then reads logs, it also exercises the current successful-submit staging cleanup policy: ES keeps `execution.staging_root_dir/<run_id>` while the workload may still depend on it, then best-effort removes that staging root after terminal success is observed. Failed, canceled, lost, or otherwise ambiguous outcomes intentionally retain staging for debugging.

Keep host qualification and smoke proof distinct:

- if `scripts/60_execute_loop.sh` fails but `BRINGUP_PROFILE=full scripts/01_bringup.sh check` still reports `supported-environment: supported`, treat that first as workload/runtime troubleshooting rather than as proof that the host lost qualification
- only relabel the host itself if the supported-host checks regress
- the current supported local proof path is repo-owned; no out-of-repo `/tmp` harness is required for the qualification or the canonical useful credential-flow proof sequence

If you want the manual publish/prepare/submit breakdown instead, use:

- [/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_static_script.md](/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_static_script.md)
- [/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_runtime_identity_reference.md](/Users/ds/Repositories/Execution Substrate/.runbooks/execution/v1_submit_runtime_identity_reference.md)

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
