# Runbook: Governed System Bring-up (v1)

- Version: `v1`
- Last Updated: `2026-04-13`
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
- `prepare-ready`: service health plus successful workload-zone Vault runtime-config blob verification through ARS, including structural validation of any supplied Vault CA bundle
- `submit-ready`: prepare-ready plus ES submit config present, Docker available, required enabled runtime-profile images present, Nomad leader present, and at least one ready Nomad client node with positive `cpu.totalcompute` and a healthy Docker driver
- for enabled local runtime-profile images, `submit-ready` also requires Nomad Docker image cleanup to be disabled through `docker.cleanup.image=false`, because the supported-local CP normal-shell proof image is local runtime material rather than a pullable product registry image

For the ES-side supported-local Control Plane consumer story, including the real CP-facing API surface, `control-plane-normal-shell/v1`, workload-visible identity/Vault/trust-material handoff, retained-result meaning, and ownership boundaries, use [supported_local_cp_consumer_runbook.md](../../.docs/supported_local_cp_consumer_runbook.md).

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

For a fresh Linux workload-zone VM, use `scripts/70_linux_setup.sh` as the bounded bootstrap helper.

Before treating any Linux host or VM as the repo's clean `supported` environment, apply the host qualification boundary in [supported_linux_host_qualification.md](../../.docs/system_overview/supported_linux_host_qualification.md).

That helper currently:

- installs the base packages used by the operator path
- writes the single-node `/etc/nomad.d/nomad.hcl` used for the one-host workload-zone baseline
- disables Nomad Docker image cleanup in that config so locally built runtime-profile images survive completed allocations for repeated supported-local client runs
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

Build these from the current validators and the configuration matrix in [configuration.md](../../.docs/system_overview/configuration.md). Example templates live under [.examples/config](../../.examples/config), but they are templates only.

For the clean supported-host path, use `BRINGUP_PROFILE=prepare-only scripts/01_bringup.sh up` for the control plane and `BRINGUP_PROFILE=full scripts/01_bringup.sh check` against the already-running pre-managed Nomad endpoint.

Before a configured Submit setup or supported-local proof, provide stable
`SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID` and
`SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID` identifiers and
`SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE`, a reference to an already
provisioned key on the machine running ES. Through the proof wrapper, this is
a guest-local path, not a Mac file to upload. The file must be in an external
private directory outside staging, results, the replaceable proof workspace,
and guest bootstrap/scratch cleanup scopes. The helpers validate metadata and
lexical placement but do not read, generate, copy, repair, or qualify key bytes;
ES startup performs its own file checks. Fresh-store example identifiers are
placeholders. Existing retained data requires the original stable identifiers
and key; no automatic lost-key recovery, rotation, or old-result adoption is
provided.

On the current supported local reference host on this Mac, you do not need the earlier out-of-repo `/tmp` harnesses. The canonical supported-local proof path is now:

```bash
scripts/73_supported_local_proof.sh run
```

That repo-owned wrapper creates the canonical proof workspace under `.out/es-proof-<id>/`, packages the bounded runtime-identity Vault-login workload, removes stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs, stages a fresh snapshot of the current host worktree into guest proof bootstrap scratch, invokes the guest-side `scripts/72_supported_local_setup.sh setup` from that staged snapshot, runs the supported-host qualification sequence, runs the higher-value useful credential-flow proof, and collects the resulting guest evidence back into that canonical workspace.

On this Mac, the wrapper still uses guest `/tmp/es-proof-<id>` plus `/tmp/es-proof-<id>.bootstrap` internally because Lima mounts the repo tree read-only inside the current `qemu` guest and that mounted view is not the repo-owned proof source of truth. Those guest paths are proof-owned transient implementation detail: the wrapper stages a fresh repo snapshot into the bootstrap scratch before the run, cleans stale proof-owned guest scratch before a new run, and removes the current guest scratch after a successful host evidence copy. The canonical proof workspace is the host-side `.out/es-proof-<id>/`.

The repo also carries a native-Linux bootstrap validation at `go test ./es/app -run TestSupportedLocalSetupScriptBootstrapsRealSPIREAndVaultDevTarget -count=1`, but that test is not the canonical supported-local validation path on this Mac. The supported-local closure proof here is the wrapper run above because it stages and exercises a fresh host-worktree snapshot inside the guest and records the canonical evidence under `.out/es-proof-<id>/`.

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

The current repo-owned AGS and ES configs keep `authorization.allowed_spiffe_path_prefixes=["operator"]`, so the operator identity above remains the right credential for the documented helper path even though those services now authorize callers from configured SPIFFE path prefixes rather than from hard-coded caller checks.

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
- any enabled `control-plane-normal-shell/v1` profile image is present in the Docker daemon used by Nomad before submit-ready is claimed
- Nomad Docker image cleanup is disabled for local runtime-profile image durability when that profile is enabled

CGS is not required for this bring-up runbook because it is not part of the current ES hot path.

## 3. Primary Bring-up Path

Run all commands from:

`.`

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
- `runtime profile image durability: nomad docker.cleanup.image=false`
- `submit-ready: true`

On the current Apple Silicon Mac, Lima `qemu` + Ubuntu 24.04 arm64 is the known supported local reference profile for this path. The previously investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain unsupported on this Mac because natural `cpu.totalcompute` stays `0`.

The current guest-side helper is intentionally narrow:

- it prepares the bounded supported-local proof environment used by both qualification and the canonical useful credential-flow proof
- it boots the proof-scoped real SPIRE server/agent path that backs the helper-private Workload API socket used by ES submit config
- it seeds the bounded workload-zone Vault runtime fields used by ES, including the proof-scoped real Vault dev/test target for the current runtime-identity Vault-login workload
- it does not broaden the slice beyond the bounded workload-vault login and one-secret-read proof

For CP consumer-specific diagnosis, do not infer extra ES ownership from this helper. Use the canonical ES-side CP consumer runbook linked above.

### Full execution profile

Use this when you intentionally want the repo to manage a local Nomad process for the current real execution slice:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
```

What this does:

- regenerates `.out/Dockerfile` through `scripts/generate_control_plane_dockerfile.sh`, then rebuilds the shared service image used by the current bring-up path; that image currently bundles `ars`, `ags`, `egs`, `es`, `es-runtime-support`, and `cgs` even though the minimal operator path starts only ARS, EGS, AGS, and ES
- proves that Docker host networking can actually reach host loopback from a container before continuing; on a user-namespace-remapped Docker daemon, Docker refuses host networking (`cannot share the host's network namespace when user namespaces are enabled`), so bring-up stops here before starting any service. Rootless Docker is untested and unsupported for bring-up
- starts ARS, verifies ARS health, and verifies the configured workload-zone Vault blob through ARS; ARS runs in its container as your numeric UID and primary GID, with no supplementary groups. Before any service starts, bring-up checks ARS's storage and refuses unless:
  - `storage.root_dir` and `storage.index_file` are absolute paths written in normal form: no `.` or `..` component, no repeated or trailing slash, no leading or trailing whitespace (the form Python's `os.path.normpath` writes). ARS opens both exactly as written while its mounts use the normal form, so the refusal prints the form to write instead. A missing storage root is created as you
  - the index file already exists as a regular file, not a symbolic link
  - ARS itself could use the storage: the check runs a short-lived container exactly as ARS will run (the same image, your numeric UID and primary group with no supplementary groups, the same mounts, and ARS's container name), and in it searches every directory on the way to the storage root and the index directory, creates and removes a file in the index directory and in every storage directory, finds its file again by listing each storage directory, reads the index and every stored file, refuses any symbolic link or special file below the storage root (ARS never creates one), and last rewrites the index the way ARS writes it (a new `0600` file with the same content, renamed over it). Access that only one of your supplementary groups grants therefore does not count, and ACLs and the sticky bit count exactly as they will for ARS. After a passing check, the index is a `0600` file owned by you, as after ARS's first write. The check takes seconds even when ARS's storage holds all 65,794 directories its `sha256/xx/yy` layout can create, and ARS's readiness wait (`READY_TIMEOUT_SECONDS`, 30 s by default) starts only once ARS's launcher has passed its own run of the check
  - no ARS container exists: the check uses ARS's container name, so Docker refuses it while one still exists; run `scripts/01_bringup.sh down` first
  - storage that an earlier bring-up wrote as root, or that is shared through another group, fails this check, and the refusal prints the `sudo chown` command that hands it back to you; a storage root or index file that you cannot reach at all, or a directory above the storage that ARS cannot search, is refused with its path
- starts EGS and AGS and waits for their public health surfaces to report `"ready": true`; both run as your numeric UID and primary GID too
- ARS, EGS and AGS read their config file and every file it names in a `*_file` setting (TLS certificate, key and client CA, and for AGS its ARS client certificate, key and root CA) as you, so each must be readable by your UID or your primary group; and because no service runs as root, every configured port must be 1024 or higher (the defaults are 8442 to 8445) unless your host allows unprivileged processes to bind lower ports
- starts ES and waits for its admission-oriented health surface to report `"ready": true`; without a supported-local roots profile, ES runs in its container as your numeric UID and primary GID (what `id -u` and `id -g` print), with no supplementary groups. ES refuses to start unless:
  - the configured staging and results roots are owned by your UID and your primary group; roots whose group was set directly to another group, for example a shared project group, are refused. Roots that inherit another group from a setgid parent directory are not refused: ES passes its startup checks and reports ready, and then every submission fails with `stage artifact payload failed`, reported as a substrate failure. Keep the bring-up workspace out of setgid directories whose group is not your primary group
  - the retained-result key file is owned by you, has mode `0400` or `0600` and sits outside both roots
  - the ES config file and every other file it names in a `*_file` setting (TLS certificate, key and client CA, the ARS and EGS client certificates, keys and root CA) are readable by your UID or your primary group; a file readable only by root, or only through another group you belong to, stops ES when it loads that file
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
"${BRINGUP_DIR:-.tmp/bringup}"
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
- ES submit config still includes `nomad.base_url`, `nomad.datacenter`, `execution.staging_root_dir`, `execution.results_root_dir`, and `execution.base_image`
- required enabled runtime-profile images are present according to `docker image inspect`
- enabled local runtime-profile images are protected from Nomad stopped-task image cleanup by `docker.cleanup.image=false`
- the workload-zone Vault blob named by `runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and validates structurally, including any `vault_config.ca_bundle_pem` certificate material
- the current ES same-path staging invariant has already been recorded at `${BRINGUP_DIR}/staging-invariant.json`

Current limitation:

- this readiness result now rejects `cpu.totalcompute=0` and Docker-unhealthy nodes, but it still does not guarantee successful placement for every workload shape; later memory, device, or other constraint failures remain possible
- the image-durability check only covers Nomad's Docker driver cleanup. Manual `docker image rm`, Docker daemon reset, or external pruning still makes the profile image absent and must be followed by a rebuild or refresh before another submit-ready claim.
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
- the workload-zone Vault blob named by `runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and validates structurally, including any supplied Vault CA bundle
- `submit-ready` is reported as skipped for that profile

## 5. Operator Troubleshooting Matrix

Use this matrix after an operator-facing helper already surfaced one of the bounded failure categories. Keep `scripts/01_bringup.sh check` and `scripts/10_health_check.sh` as the readiness source of truth. Later helpers should point back here rather than inventing a second readiness story.

Managed bring-up logs live under:

```bash
"${BRINGUP_DIR:-.tmp/bringup}/logs"
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
| caller authorization / credential failure | The helper reached AGS or ES, but the caller cert/key was wrong for that operation or TLS auth failed before the request was accepted. | The failing helper itself (`scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, or `scripts/50_lifecycle.sh`). This is not a bring-up readiness failure. | `ags.log` for publish; `es.log` for prepare / submit / lifecycle. | No. There is no admitted run to inspect. | Verify `OPERATOR_CERT` and `OPERATOR_KEY`, confirm the caller SPIFFE path is allowed by the current `authorization.allowed_spiffe_path_prefixes` in AGS or ES config, and remember that the repo-owned operator path keeps those allowlists operator-only by default. Then retry. |
| trust / evidence / admission failure | The published artifact, aggregate evidence, signer policy, or admission inputs were rejected after auth succeeded. | The failing publish / prepare / submit helper. | `ags.log` for publish-side evidence handling, `es.log` for prepare / submit rejection, `egs.log` when signer or artifact trust policy is the likely cause. | No. The failure is before runtime handoff. | Check the published artifact digest, aggregate evidence, and EGS trust inputs before retrying. |
| runtime-config reference or blob failure | ES runtime-config points at a missing, unreadable, or structurally invalid workload-zone Vault blob in ARS, including malformed Vault CA bundle material when supplied. | `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh`. | `es.log` and `ars.log`. | No. Fix the referenced blob first. | Re-run `scripts/01_bringup.sh check`, then confirm `ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest` still points at a readable ARS JSON blob with the expected address/auth shape and valid optional CA bundle. |
| service health / readiness failure | A required service is down, unhealthy, or not ready enough to claim service health or prepare-ready. | `scripts/01_bringup.sh check` or `scripts/10_health_check.sh`. | The failing service log under `logs/`; if ES health is failing because an upstream dependency is sick, inspect that upstream log too. | No. Readiness must be restored first. | Re-run `scripts/01_bringup.sh check`, restore service health or prepare-ready, then retry publish / prepare / submit. |
| substrate failure (Docker / Nomad / runtime availability) | ES submit wiring, Docker availability, required runtime-profile image availability, Nomad image-cleanup guardrail, Nomad leadership, or Nomad client readiness is missing for the full submit path. | `scripts/01_bringup.sh check` or `scripts/10_health_check.sh` in `BRINGUP_PROFILE=full`. | `nomad.log`, `es.log`, and Docker daemon logs if `docker info`, `docker image inspect`, or Nomad Docker client-option checks fail. | Depends on the failure boundary. There is no staging only when failure preceded both run assignment and exclusive run-root creation. A failed or ambiguous Submit after claim may retain partial or complete staging without returning a receipt or run ID. | Re-run `scripts/01_bringup.sh check`, then verify Docker, required runtime-profile images, Nomad Docker image cleanup config, Nomad leader/client readiness, and ES submit config before retrying. Treat any retained post-claim root as sensitive diagnostic state, not as proof of Nomad acceptance. |
| execution outcome after successful submit | `:submit` returned a `run_id` and the workload later reached any observable outcome. | `scripts/50_lifecycle.sh` or `scripts/60_execute_loop.sh`. | Workload logs from `scripts/50_lifecycle.sh` or the per-run `logs.txt` from `scripts/60_execute_loop.sh`, plus `es.log` and `nomad.log` if the runtime handoff itself looks suspicious. | Yes. Successful, failed, canceled, lost, and ambiguous outcomes all retain the same root. | Inspect lifecycle status/logs for the `run_id`, then inspect retained host staging under `execution.staging_root_dir/<run_id>` when needed. |
| operator misuse / invalid input | The helper caught missing env vars, unreadable files, malformed JSON, or an invalid `run_id`, or the service returned a bounded input-validation error. | The failing helper itself. | Usually none. If the malformed request reached a service, inspect `ags.log` or `es.log` for the matching `400`. | No. Fix the input first. | Validate request JSON, env vars, readable file paths, and `run_id`, then retry. |

Staging inspection guidance in this slice:

- staging may exist after any post-claim Submit return, including a partial or ambiguous failure that did not return a receipt
- retained post-claim state may contain sensitive payload, trust, runtime-support, or mount material; restrict operator access accordingly
- retained staging is not proof that Nomad accepted the job, and absence of staging is not proof that no provider effect occurred
- successful, failed, canceled, lost, ambiguous, and unknown outcomes all retain `execution.staging_root_dir/<run_id>`
- terminal observation and retained-result capture from `/execution/run/result` never authorize staging deletion
- staging is relevant after a successful run-root claim, even if a later Submit
  response fails or is ambiguous; no run tree exists before claim
- every successfully claimed `execution.staging_root_dir/<run_id>` remains
  retained through materialization error, registration failure or ambiguity,
  and terminal success/failure/cancel/loss
- terminal result capture from `/execution/run/result` is separate from
  staging retention; descriptor close does not delete the run root
- retained terminal result bundles, when present, live under `execution.results_root_dir/<run_id>/result.tar.gz` and are fetched through `GET /v1/executions/{run_id}/result`
- the no-staging case is limited to failure before both run assignment and exclusive run-root creation; receipt absence alone does not establish that boundary
- the former blanket heuristic, "if publish, prepare, or submit failed before a `run_id` existed, staging is the wrong next step", is obsolete for Submit: it remains safe for publish/prepare, but a Submit without a receipt may still have crossed exclusive claim and retained sensitive staging
- no current automatic whole-run-root reclamation path exists

Companion diagnostics helper for the same matrix:

- `scripts/70_diagnostics.sh --category auth|trust|runtime-config|readiness|substrate|execution|input`
- `scripts/70_diagnostics.sh --run-id run-0123456789abcdef`
- `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>`

The collector accepts either the short category aliases above or the surfaced failure labels from the operator-facing scripts. It gathers only the checks, logs, lifecycle output, and staging inspection signals already called out in this matrix. It prints both `bundle_dir=` and `bundle_json=` so the summary helper can render the collected bundle without re-running diagnostics.

The legacy surfaced label `execution failure after successful submit` remains
an accepted alias for the execution category. The category now covers every
observable post-submit outcome; the legacy label does not imply that only
failed executions retain staging.

## 6. First Execution Verification

After bring-up succeeds, the preferred bounded end-to-end proof on the current supported local reference host on this Mac is:

```bash
scripts/73_supported_local_proof.sh run
```

This path still proves the one-host Linux substrate and same-path staging contract directly, and it now makes the bounded useful credential flow the canonical higher-value governed proof on that already-qualified host. The first platform-owned runtime identity boundary remains active through the real ES -> Nomad -> Docker path: same-container supervisor/helper, helper-private SPIRE channel, fixed non-root workload launch, and helper-death/task-fatal behavior are all active in the current slice.

For the underlying credential-flow details, use [.runbooks/execution/v1_submit_runtime_identity_vault_login.md](../execution/v1_submit_runtime_identity_vault_login.md).

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

Because that helper waits for terminal status and then reads logs, it also
exercises retained staging: ES attempts retained-result capture from
`/execution/run/result` while leaving `execution.staging_root_dir/<run_id>` in
place. Result success, absence, conflict, or failure has no staging-mutation
consequence.
Because that helper waits for terminal status and then reads logs, it can
exercise retained-result capture from `/execution/run/result`. The isolated
candidate retains every successfully claimed staging root after terminal
success as well as failure, cancellation, loss, or ambiguous registration.
This interim rule increases disk use and sensitive-material residence; no
reclamation authority is selected.

Keep host qualification and smoke proof distinct:

- if `scripts/60_execute_loop.sh` fails but `BRINGUP_PROFILE=full scripts/01_bringup.sh check` still reports `supported-environment: supported`, treat that first as workload/runtime troubleshooting rather than as proof that the host lost qualification
- only relabel the host itself if the supported-host checks regress
- the current supported local proof path is repo-owned; no out-of-repo `/tmp` harness is required for the qualification or the canonical useful credential-flow proof sequence

If you want the manual publish/prepare/submit breakdown instead, use:

- [.runbooks/execution/v1_submit_static_script.md](../execution/v1_submit_static_script.md)
- [.runbooks/execution/v1_submit_runtime_identity_reference.md](../execution/v1_submit_runtime_identity_reference.md)

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
