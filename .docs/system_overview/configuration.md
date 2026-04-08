# Configuration Matrix

## Purpose

This document lists the current configuration surface for the bounded Go system.

It is an operator reference, not an orchestration design. It describes what each service needs today so the system can be started manually and explicitly.

## Shared Conventions

All current services use JSON config files loaded via `-config /absolute/path/to/file.json`.

All current services require:

- `http.bind_address`
- `http.port`
- `http.read_timeout_seconds`
- `http.write_timeout_seconds`
- `http.shutdown_timeout_seconds`
- `tls.cert_file`
- `tls.key_file`
- `tls.client_ca_file`

All path values are expected to be explicit local filesystem paths.

For the current slice-0 operator path, ARS, EGS, AGS, and ES run as containers. Their config files, referenced TLS files, and any writable host state are mounted into those containers at the same absolute paths named in config. Relative paths are therefore not valid for the primary bring-up path.

All hot-path control-plane listeners now require a verified client certificate at the TLS boundary, including `/health`. Bring-up and readiness checks must present a runtime-issued client certificate rather than relying on handler-only rejection.

This repository does not ship ready-to-run service config examples. Operators must provide explicit JSON config files that satisfy the current validators.

## Workload-Zone Vault Runtime Config

### Required config groups

- none as a standalone service
- the current required installation point is `ES.runtime_config`

### Required fields

- `runtime_config.workload_zone_vault_config_ref.digest`

### Required external dependencies

- the workload-zone Vault config blob must be stored in ARS under the referenced digest

### Minimal valid configuration

- `runtime_config.workload_zone_vault_config_ref.digest` must contain the digest of the named workload-zone Vault config blob
- the current workload-zone Vault blob must satisfy `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`

Minimal reference example:

```json
{
  "runtime_config": {
    "workload_zone_vault_config_ref": {
      "digest": "sha256:<workload-zone-vault-digest>"
    }
  }
}
```

## ARS

### Required config groups

- `http`
- `tls`
- `security`
- `authorization`
- `storage`

### Required fields

- `security.bootstrap_issuer_common_name`
- `authorization.allowed_spiffe_path_prefixes`
- `storage.root_dir`
- `storage.index_file`

### Required external dependencies

- local filesystem storage for blobs
- local filesystem index file for artifact registration

### Minimal valid configuration

- `storage.root_dir` must point to a writable directory
- `storage.index_file` must point to a writable file path
- `security.bootstrap_issuer_common_name` must name the legacy/bootstrap issuer that ARS rejects on both read and write paths
- `authorization.allowed_spiffe_path_prefixes` must allow ES and other intended readers
- AGS writes use the dedicated `service/artifact-governance` writer identity

## AGS

### Required config groups

- `http`
- `tls`
- `security`
- `dependencies`
- `signer`

### Required fields

- `security.bootstrap_issuer_common_name`
- `dependencies.artifact_registry.base_url`
- `dependencies.artifact_registry.server_name`
- `dependencies.artifact_registry.client_cert_file`
- `dependencies.artifact_registry.client_key_file`
- `dependencies.artifact_registry.root_ca_file`
- `dependencies.artifact_registry.timeout_seconds`
- `signer.algorithm`
- `signer.key_id`
- `signer.private_key_hex`
- `signer.public_key_hex`

### Required external dependencies

- ARS write boundary over HTTPS
- Ed25519 signer key material

### Minimal valid configuration

- `signer.algorithm` must be `ed25519`
- `dependencies.artifact_registry.base_url` must be an absolute `https://` URL
- signer key material must match the public key ES verifies and the signer key ID EGS allows

AGS no longer exposes a legacy-signing compatibility control. The current publish path is evidence-native only.

## EGS

### Required config groups

- `http`
- `tls`
- `security`
- `signer`
- `runtime_trust`
- `publication`

### Required fields

- `security.bootstrap_issuer_common_name`
- `signer.algorithm`
- `signer.key_id`
- `signer.private_key_hex`
- `signer.public_key_hex`
- `publication.version`
- `publication.update_revision`

### Required external dependencies

- none for runtime calls
- signer key material for runtime-trust signing

### Minimal valid configuration

- `signer.algorithm` must be `ed25519`
- `publication.update_revision` must be greater than `0`
- `runtime_trust.signer_policy.allowed_signers` and `revoked_signers` must not contain duplicates or empty values
- `runtime_trust.artifact_policy.revoked_artifacts`, if present, must contain labeled SHA-256 digests

For a minimal active system, `runtime_trust.signer_policy.allowed_signers` must include the AGS signer key ID used for provenance.

## ES

### Required config groups

- `http`
- `tls`
- `security`
- `dependencies`
- `verification`
- `workload_vault_auth`
- `nomad` for `:submit`
- `execution` for `:submit`

### Required fields

- `security.bootstrap_issuer_common_name`
- `dependencies.artifact_registry.*`
- `dependencies.execution_governance.*`
- `runtime_config.workload_zone_vault_config_ref.digest`
- `verification.trust_model.*`
- `verification.provenance.*`
- `verification.derivation_attestation.*`
- `verification.workload_identity_binding.*`
- `workload_vault_auth.default_mode`
- `nomad.base_url`, `nomad.datacenter`, `nomad.timeout_seconds` when submit is enabled
- `execution.staging_root_dir`, `execution.base_image` when submit is enabled

### Required external dependencies

- ARS over HTTPS
- EGS over HTTPS
- Nomad for real execution submit
- Docker under Nomad for container runtime
- workload-zone Vault config reference installed in ES startup config, with the blob available through ARS
- the current workload-zone Vault blob must satisfy the `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob` schema

### Minimal valid configuration

- all verifier algorithms must be `ed25519`
- verifier key IDs and public keys must match the active EGS and AGS signers
- all dependency base URLs must be absolute `https://` URLs
- `workload_vault_auth.default_mode` must be `vault_identity_jwt`
- `workload_vault_auth` no longer carries per-workload selectors in the current slice; ES consumes workload-zone vault runtime fields directly and applies only the configured default auth mode
- `runtime_config.workload_zone_vault_config_ref.digest` must point at the current workload-zone Vault config blob in ARS
- if `nomad` and `execution` are omitted, ES can still support `:prepare` but not `:submit`
- for full end-to-end execution verification, include:
  - `nomad.base_url`
  - `nomad.datacenter`
  - `execution.staging_root_dir`
  - `execution.base_image`
  - `execution.runtime_support_binary`
  - `execution.spire_workload_api_socket_path`
  - optionally `execution.runtime_identity_tmpfs_size`
- `execution.staging_root_dir` is a writable host-local staging root
  - the current slice-0 operator path requires that host path to be mounted into the ES container at the exact same absolute path with no translation
  - it backs run-scoped payload, run, and mount staging while the workload may still depend on those bind mounts
  - ES best-effort removes `<staging_root>/<run_id>` after it observes terminal success for that run through the current lifecycle path
  - failed, canceled, lost, or otherwise ambiguous outcomes retain `<staging_root>/<run_id>` for debugging in the current slice
  - `/execution/run` remains a host-backed writable execution workspace and is not guaranteed non-sensitive
  - `/execution/staged` and caller-visible `/execution/mounts/...` remain host-backed copies of governed artifact content
  - ES does not semantically inspect payloads or mount contents for secrecy
- the runtime identity contract no longer requires ES-local identity plumbing configuration
- ES currently backs the injected runtime identity endpoint with a memory-backed tmpfs workspace under a run-scoped subtree rooted at `/run/es-runtime-identity/`
  - this backing workspace is not persisted to host staging
  - `execution.runtime_identity_tmpfs_size` controls that ES-owned backing workspace and defaults to `1048576` bytes (`1 MiB`); it must not exceed `8388608` bytes (`8 MiB`)
- slice `1A` and `1B` additionally require:
  - `execution.runtime_support_binary`: absolute path to the platform-owned runtime supervisor/helper binary staged into the workload task
  - `execution.spire_workload_api_socket_path`: absolute path to the local SPIRE Workload API Unix socket that ES bind-mounts into the helper-private runtime path
- for the containerized operator bring-up path:
  - the default generated control-plane image now bundles `/usr/local/bin/es-runtime-support`
  - the bring-up path must mount `execution.spire_workload_api_socket_path` into the ES container at that same absolute path so ES can validate the socket before serving and later hand the same host path to Nomad
- for fresh Linux workload-zone VMs, `scripts/70_linux_setup.sh` now installs Docker, Nomad, Vault, and Go, writes the current single-node `/etc/nomad.d/nomad.hcl`, and then tries to qualify the root-managed `nomad.service` baseline
  - that helper does not silently claim success if the host still needs manual root investigation, cannot start `nomad.service`, reports `DevMode=true`, or still leaves `cpu.totalcompute=0`
  - if the helper had to add the current operator user to the `docker` group, the user must log out and back in before treating the VM as qualified for repo scripts
  - a nonzero exit from that helper means the VM is not yet a supported substrate baseline for this slice
  - if that helper reaches a root-managed non-`-dev` Nomad service but the ready node still reports `cpu.totalcompute=0`, qualify the host by behavior rather than by platform label: inspect whether the guest actually exposes CPU-frequency data through `cpufreq` sysfs, `/proc/cpuinfo` `cpu MHz`, or SMBIOS processor `Current Speed`
  - on the current Apple Silicon Mac, Lima `qemu` + Ubuntu 24.04 arm64 now qualifies under the real `nomad.service` path without override, while the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles still expose no usable natural-compute inputs there; `dmidecode` and `cpufrequtils` only confirm that gap and do not make those profiles supported
- slice `1A` and `1B` intentionally narrow workload compatibility:
  - the helper runs as `0:0`
  - the workload runs as fixed UID:GID `10000:10000`
  - the workload gets no supplemental groups and no privilege-escalation path
  - root workloads and arbitrary image-user execution are out of scope for this slice
- workloads should rely on `EXEC_WORKLOAD_IDENTITY_ENDPOINT` for endpoint discovery rather than on any fixed socket path
- ES `/health` does not include Nomad readiness in the current slice; Nomad availability is verified separately during bring-up and submit/lifecycle checks
- The primary bring-up/check path distinguishes:
  - service health: ARS, EGS, AGS, and ES public health surfaces
  - prepare-ready: service health plus successful workload-zone Vault runtime-config blob verification through ARS
  - submit-ready: prepare-ready plus ES submit config present, Docker available, Nomad leader present, and at least one ready Nomad client node that exposes positive `cpu.totalcompute` and a healthy Docker driver

Minimal vault-auth example:

```json
{
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt"
  }
}
```

## CGS

### Required config groups

- `http`
- `tls`
- `policy`
- `security`

### Required fields

- `policy.id_conf_path`
- `security.bootstrap_issuer_common_name`

### Required external dependencies

- local policy file

### Minimal valid configuration

- `policy.id_conf_path` must point to a valid policy file
- the repo includes a minimal checked-in subject-policy baseline at `cgs/policy/id.conf`
- that checked-in file is a current baseline only
  - it is derived from current Go-repo tests/examples
  - it is not documented as complete production policy or final long-term grammar
- the current `id.conf` grammar uses explicit `subject` records with:
  - `type`
  - `principal`
  - `role`

CGS is not required for the current ES hot path and is not part of the minimal governed execution bring-up runbook.

## Nomad And Docker

These are not configured through the Go service config files, but they are required for the current bounded execution slice.

### Nomad requirements

The current host-qualification boundary for the supported Linux environment is defined in [supported_linux_host_qualification.md](/Users/ds/Repositories/Execution Substrate/.docs/system_overview/supported_linux_host_qualification.md).

- reachable at the `es.nomad.base_url`
- configured for the target datacenter in `es.nomad.datacenter`
- Docker driver available
- client bind mounts enabled through `client.options["docker.volumes.enabled"] = "true"`
- explicit local data directory for repeatable manual bring-up
- when the current slice-0 single-node topology binds Nomad to `127.0.0.1`, the Nomad config must also set explicit loopback `advertise` addresses for `http`, `rpc`, and `serf`
- for the supported Linux environment story in this slice, Nomad should already be running as a pre-managed non-dev service on the host/VM before `scripts/01_bringup.sh up`; the local script-managed Nomad startup path remains bounded fallback/troubleshooting scaffolding
- the operator readiness path now inspects `GET /v1/agent/self` and rejects `config.DevMode=true`; `nomad agent -dev` is unsupported for the slice-0 supported-environment claim even if it reports healthy Docker and positive compute
- when Nomad uses the Docker driver on Linux, HashiCorp's Docker driver guidance treats root-managed Nomad as the compatible mode for CPU-core / NUMA-aware behavior; user-managed Nomad startup may still be useful for bounded proof and troubleshooting, but it is not the supported-environment baseline
- if a Linux proof host exposes `cpu.totalcompute=0` because Nomad CPU fingerprinting fails, the bounded slice-0 operator path can provide `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` as a temporary client override for that host; this is deployment troubleshooting, not a new cross-service contract
  - when this override is active, the operator path must surface that host as `submit-ready-mode: bounded-override (...)` rather than implying natural schedulability
  - if the override is absent and the host remains at `cpu.totalcompute=0`, the current bring-up path now fails explicitly instead of claiming submit-ready

### Docker requirements

- daemon running
- bind mounts enabled for Nomad Docker tasks
- ES execution base image available or pullable

## Practical Minimal Stack

For the current bounded governed execution path, the practical minimum is:

- ARS
- EGS
- AGS
- ES
- Nomad
- Docker

CGS remains implemented but is not required for the current ES admission or execution path.

For local operator bring-up against this practical minimum:

- on the current supported local reference host on this Mac, `scripts/72_supported_local_setup.sh setup` is the guest-side repo-owned proof-environment helper; it writes the current Dockerfile/TLS/config/blob assets, installs the `es-runtime-support` binary path used by ES submit config, boots a proof-scoped real SPIRE server/agent path and real Workload API socket, derives proof-only Vault JWT validation material from the SPIRE bundle, starts and configures the proof-scoped real Vault dev/test target, writes `managed-secrets.conf`, writes `env.sh`, and replaces the earlier out-of-repo `/tmp` harnesses
- `scripts/73_supported_local_proof.sh run` is the canonical host-side supported-local proof wrapper on this Mac; it records proof workspaces under `.out/es-proof-<id>/`, packages the bounded runtime-identity Vault-login workload, cleans stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs, runs the supported-host qualification path, runs the higher-value useful credential-flow proof, and copies the resulting guest evidence back into that canonical workspace
- on this Mac, the wrapper may still use guest `/tmp/es-proof-<id>` internally because the Lima-mounted repo tree is read-only inside the `qemu` guest; that guest scratch is proof-owned transient implementation detail, not the canonical proof workspace, and successful current-run guest scratch is removed after host evidence has been preserved
- use `BRINGUP_PROFILE=prepare-only scripts/01_bringup.sh up`, then `BRINGUP_PROFILE=full scripts/01_bringup.sh check`, as the clean supported-host proof path when Nomad is already running as a pre-managed non-dev service at `NOMAD_ADDR`
- use `BRINGUP_PROFILE=full scripts/01_bringup.sh up` when you intentionally want the repo to manage a local Nomad process as bounded bootstrap/troubleshooting scaffolding
- for `BRINGUP_PROFILE=full`, the current script-managed Nomad startup path remains bounded fallback/troubleshooting even when submit-ready passes; the supported-environment path for this slice is a pre-managed non-dev Nomad client/server already running at `NOMAD_ADDR`
- use `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh` to re-run readiness checks
- use `BRINGUP_PROFILE=prepare-only` only when you intentionally want ARS + EGS + AGS + ES preflight without Nomad submit
- the current slice-0 bootstrap path targets one Linux host/VM and fails fast unless Docker host networking can actually reach host loopback from a container
- that bounded path has now been functionally proved on Linux through the real ES -> Nomad -> Docker flow, and the current supported local reference profile on this Mac is Lima `qemu` + Ubuntu 24.04 arm64 with pre-managed non-dev Nomad and positive natural `cpu.totalcompute`
- `scripts/01_bringup.sh up` regenerates `.out/Dockerfile` through `scripts/generate_control_plane_dockerfile.sh`, then rebuilds the shared service image used by the current bring-up path (currently bundling `ars`, `ags`, `egs`, `es`, and `cgs`) and records the ES same-path staging proof at `${BRINGUP_DIR}/staging-invariant.json`
- `CONTROL_PLANE_DOCKERFILE` remains an explicit operator override, but the default bring-up source of truth is the generated `.out/Dockerfile`
- `.out/` is the current repo-local generated-artifact area: `.out/Dockerfile` remains the tracked control-plane image input, kept integration harness workspaces such as `es-submit-*` are created under `.out/`, and the canonical supported-local proof workspaces on this Mac now live under `.out/es-proof-<id>/`; those host proof workspaces are preserved evidence, not transient scratch
- top-level `scripts/*.sh` remain the operator-facing entrypoints and manual fallback commands; `scripts/internal/*.sh` is the sourced-only helper layer behind those entrypoints
- Docker host networking in that path is temporary slice-0 compatibility scaffolding, not the final control-plane network model
- use an operator SPIFFE client cert/key for AGS and ES operator-facing helpers:
  - `CA_CERT`
  - `OPERATOR_CERT`
  - `OPERATOR_KEY`

The current unified health check verifies:

- ARS, EGS, AGS, and ES all report `ready=true`
- those health checks succeeded with a real client certificate at the TLS boundary
- Nomad has a leader and at least one ready node with positive `cpu.totalcompute` and a healthy Docker driver when `BRINGUP_PROFILE=full`
- `docker info` succeeds when `BRINGUP_PROFILE=full`
- ES submit config still includes `execution.runtime_support_binary` and `execution.spire_workload_api_socket_path`, and the configured SPIRE socket path is present as a local Unix socket, when `BRINGUP_PROFILE=full`
- the workload-zone Vault blob referenced by `ES.runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and structurally valid before first execution
- the operator path now also surfaces Nomad bring-up mode and the current environment-support classification so a green submit-ready result cannot be misread as the same support claim in pre-managed-supported and managed-local/override fallback modes
- the operator path also rejects Nomad `-dev` mode as unsupported rather than letting it appear as a supported pre-managed environment

Current limitation:

- `submit-ready` is now honest about zero-compute or Docker-unhealthy Nomad nodes, but it still does not prove every workload/resource shape can place successfully; later memory, device, or placement-constraint failures remain possible
- a host that needs `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` remains only a bounded fallback environment for slice-0 proof, not evidence that the substrate is naturally self-honest there
- the script-managed local Nomad path also remains bounded fallback even when it is schedulable; the supported-environment story for this slice is a pre-managed non-dev Nomad service with natural schedulability
- a pre-managed Nomad `-dev` agent is unsupported even if it reports positive `cpu.totalcompute`
- a host profile that still reports `cpu.totalcompute=0` under the root-managed non-`-dev` service and also exposes no usable CPU-frequency data through `cpufreq` sysfs, `/proc/cpuinfo`, or SMBIOS `Current Speed` should currently be treated as unsupported for the slice-0 supported-environment claim rather than as a script/service-mode mistake
- on the current Apple Silicon Mac, the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain in that unsupported bucket because natural `cpu.totalcompute` still stays `0`

Readiness still does **not** prove useful downstream credential use by itself. The workload-identity boundary now exists, and the bounded workload-vault login plus secret-read proof now sits directly on top of the supported-local qualification path as the canonical higher-value proof on this Mac.

Slice `1A` and `1B` now prove platform-owned runtime identity delivery for platform-controlled non-root workloads. In this first workload-identity slice, the platform launches the runtime identity helper as `0:0` and launches the workload as fixed UID:GID `10000:10000` with no supplemental groups and no privilege-escalation path. Root workloads, arbitrary image-user execution, and any mode that gives the workload direct access to raw SPIRE channels are out of scope for this slice. This is a bounded runtime compatibility constraint required to preserve platform-owned identity delivery; it is not a reduction of the workload-identity claim.

Useful credential flow is now also proved on top of that slice: one workload uses `EXEC_WORKLOAD_IDENTITY_ENDPOINT` to fetch a bounded real SPIRE-backed JWT-SVID for `workload_vault`, performs `auth/jwt/login` itself against a proof-scoped real Vault dev/test target, and reads one secret without reintroducing workload-authored identity bridging or platform-owned Vault token brokerage.

Supported-host qualification is now achieved on the current local reference host, and the current supported local proof path is now repo-owned through `scripts/72_supported_local_setup.sh`, `scripts/73_supported_local_proof.sh run`, and the existing bring-up and execute-loop helpers. Supported vs bounded-fallback vs unsupported states must remain explicit in bring-up/readiness output.

For operator diagnostics in the current bounded slice:

- `scripts/01_bringup.sh check` and `scripts/10_health_check.sh` remain the authoritative readiness baseline for service health, prepare-ready, and submit-ready
- later helpers such as `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, `scripts/50_lifecycle.sh`, and `scripts/60_execute_loop.sh` must not redefine readiness; they should direct operators back to that baseline when they detect readiness or substrate trouble
- `scripts/70_diagnostics.sh` is the bounded diagnostics companion for the same current slice; it collects only the logs/checks already named by the troubleshooting matrix, keyed by category or `run_id`
- `scripts/71_diagnostics_summary.sh` is the tiny rendering companion for those bundles; it reads `bundle.json` from `scripts/70_diagnostics.sh` and prints a compact operator-facing summary without collecting extra data
- the bounded operator failure classes are:
  - caller authorization / credential failure
  - trust / evidence / admission failure
  - runtime-config reference or blob failure
  - service health / readiness failure
  - substrate failure (Docker / Nomad / runtime availability)
  - execution failure after successful submit
  - operator misuse / invalid input
- the compact operator troubleshooting matrix for those classes now lives in `/Users/ds/Repositories/Execution Substrate/.runbooks/system/v1_bringup.md`; it maps each surfaced category to the authoritative check, the most relevant service logs, when retained staging is actually useful, and the next operator action
