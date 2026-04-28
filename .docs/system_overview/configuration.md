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
- the current workload-zone Vault blob must satisfy `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`

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
- `authorization`
- `dependencies`
- `signer`

### Required fields

- `security.bootstrap_issuer_common_name`
- `authorization.allowed_spiffe_path_prefixes`
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
- `authorization.allowed_spiffe_path_prefixes` must contain the SPIFFE path prefixes allowed to call `POST /v1/artifacts:publish`
- signer key material must match the public key ES verifies and the signer key ID EGS allows
- the current repo-owned runbooks, proofs, and generated helper configs keep this allowlist operator-only, but the caller allowlist is now deployment-configured rather than hard-coded in AGS
- the first repo-owned non-operator caller activation path uses `service/control-plane`; prefer a narrow allowlist such as `["operator", "service/control-plane"]` over a broad `service/` prefix
- the current repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`
- the companion example templates for that path are `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- the default templates `ags.json` and `es.json`, plus the operator runbooks, remain operator-only by default

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
- `authorization`
- `dependencies`
- `verification`
- `workload_vault_auth`
- `nomad` for `:submit`
- `execution` for `:submit`

### Required fields

- `security.bootstrap_issuer_common_name`
- `authorization.allowed_spiffe_path_prefixes`
- `dependencies.artifact_registry.*`
- `dependencies.execution_governance.*`
- `runtime_config.workload_zone_vault_config_ref.digest`
- `verification.trust_model.*`
- `verification.provenance.*`
- `verification.derivation_attestation.*`
- `verification.workload_identity_binding.*`
- `workload_vault_auth.default_mode`
- `nomad.base_url`, `nomad.datacenter`, `nomad.timeout_seconds` when submit is enabled
- `execution.staging_root_dir`, `execution.results_root_dir`, `execution.base_image` when submit is enabled
- `execution.runtime_profiles.control_plane_normal_shell.*` only when the bounded Control Plane normal-shell runtime profile is enabled

### Required external dependencies

- ARS over HTTPS
- EGS over HTTPS
- Nomad for real execution submit
- Docker under Nomad for container runtime
- local filesystem storage for retained result bundles outside the staging root
- workload-zone Vault config reference installed in ES startup config, with the blob available through ARS
- the current workload-zone Vault blob must satisfy the `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob` schema

### Minimal valid configuration

- all verifier algorithms must be `ed25519`
- verifier key IDs and public keys must match the active EGS and AGS signers
- all dependency base URLs must be absolute `https://` URLs
- `authorization.allowed_spiffe_path_prefixes` must contain the SPIFFE path prefixes allowed to call the ES execution and lifecycle APIs
- `workload_vault_auth.default_mode` must be `vault_identity_jwt`
- `workload_vault_auth` no longer carries per-workload selectors in the current slice; ES consumes workload-zone vault runtime fields directly and applies only the configured default auth mode
- `runtime_config.workload_zone_vault_config_ref.digest` must point at the current workload-zone Vault config blob in ARS
- if `nomad` and `execution` are omitted, ES can still support `:prepare` but not `:submit`
- the current repo-owned runbooks, proofs, and generated helper configs keep this allowlist operator-only, but the caller allowlist is now deployment-configured rather than hard-coded in ES
- the first repo-owned non-operator caller activation path uses `service/control-plane`; prefer a narrow allowlist such as `["operator", "service/control-plane"]` over a broad `service/` prefix
- the current repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`
- the companion example templates for that path are `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- the default templates `ags.json` and `es.json`, plus the operator runbooks, remain operator-only by default
- for full end-to-end execution verification, include:
  - `nomad.base_url`
  - `nomad.datacenter`
  - `execution.staging_root_dir`
  - `execution.results_root_dir`
  - `execution.base_image`
  - `execution.runtime_support_binary`
  - `execution.spire_workload_api_socket_path`
  - optionally `execution.runtime_identity_tmpfs_size`
- to enable the bounded Control Plane normal-shell runtime profile, include:
  - `execution.runtime_profiles.control_plane_normal_shell.enabled=true`
  - `execution.runtime_profiles.control_plane_normal_shell.image`
  - `execution.runtime_profiles.control_plane_normal_shell.codex_cli_path`
  - `execution.runtime_profiles.control_plane_normal_shell.credential_vault_secret_path`
  - `execution.runtime_profiles.control_plane_normal_shell.credential_vault_secret_field`
- `execution.staging_root_dir` is a writable host-local staging root
  - the current slice-0 operator path requires that host path to be mounted into the ES container at the exact same absolute path with no translation
  - that same-path requirement is a current deployment constraint of the bounded Nomad/Docker slice, not a client-facing governed-execution contract
  - it backs run-scoped payload, run, and mount staging while the workload may still depend on those bind mounts
  - ES best-effort removes `<staging_root>/<run_id>` after it observes terminal success for that run through the current lifecycle path
  - failed, canceled, lost, or otherwise ambiguous outcomes retain `<staging_root>/<run_id>` for debugging in the current slice
  - `/execution/run` remains a host-backed writable execution workspace and is not guaranteed non-sensitive
  - `/execution/staged` and caller-visible `/execution/mounts/...` remain host-backed copies of governed artifact content
  - ES does not semantically inspect payloads or mount contents for secrecy
  - a future infra manager may replace the current host-path backing with named volumes or other managed attachment semantics if it preserves the ES-local runtime contract inside the task
- `execution.results_root_dir` is a writable ES-owned retained-results root
  - it must be an absolute local filesystem path
  - it must be separate from `execution.staging_root_dir`
  - future non-root-required readiness and service-user migration check-only require `execution.staging_root_dir` and `execution.results_root_dir` to resolve to the same target owner UID:GID
  - ES stores retained terminal result bundles under `<results_root>/<run_id>/result.tar.gz`
  - when validated ownership-normalization evidence exists for a completed run, ES preserves it under `<results_root>/<run_id>/ownership-normalization.json` before successful cleanup can remove the staging copy
  - retained-result packaging and repeat retained-result reads may perform only narrow retained-artifact owner reconciliation on `<results_root>/<run_id>/`, `result.tar.gz`, and the preserved normalization-evidence sidecar so those retained artifacts stay readable to the future ES service owner
  - retained bundles survive best-effort cleanup of `<staging_root>/<run_id>`
  - retained bundles are opaque to ES callers and are fetched through `GET /v1/executions/{run_id}/result`
  - this is a bounded current-slice terminal output contract, not a general runtime-output platform or Control Plane state store
- the runtime identity contract no longer requires ES-local identity plumbing configuration
- ES currently backs the injected runtime identity endpoint with a memory-backed tmpfs workspace under a run-scoped subtree rooted at `/run/es-runtime-identity/`
  - this backing workspace is not persisted to host staging
  - `execution.runtime_identity_tmpfs_size` controls that ES-owned backing workspace and defaults to `1048576` bytes (`1 MiB`); it must not exceed `8388608` bytes (`8 MiB`)
- slice `1A` and `1B` additionally require:
  - `execution.runtime_support_binary`: absolute path to the platform-owned runtime supervisor/helper binary staged into the workload task
  - `execution.spire_workload_api_socket_path`: absolute path to the local SPIRE Workload API Unix socket source that ES records and later bind-mounts into the helper-private runtime path
- the bounded `control-plane-normal-shell/v1` profile additionally requires:
  - `execution.runtime_profiles.control_plane_normal_shell.image`: the Docker image ES selects for opt-in requests instead of `execution.base_image`
  - `execution.runtime_profiles.control_plane_normal_shell.codex_cli_path`: an absolute container path where the profile image provides Codex CLI
  - `execution.runtime_profiles.control_plane_normal_shell.credential_vault_secret_path`: the workload-zone Vault API path containing Codex credential material
  - `execution.runtime_profiles.control_plane_normal_shell.credential_vault_secret_field`: the field inside that Vault response data object the workload should read
  - `network_access=true` on the published workload, because Codex and workload-side Vault login need network reachability in this profile
  - the configured profile image must be present in the Docker daemon used by Nomad before the repo-owned full-profile readiness helper claims `submit-ready`; the supported-local setup helper builds this repo-owned image before proof execution
  - ES injects only non-secret metadata for the secret path/field and does not read or broker the credential
- for the containerized operator bring-up path:
  - the default generated control-plane image now bundles `/usr/local/bin/es-runtime-support`
  - the long-lived ES process keeps `execution.spire_workload_api_socket_path` as a submit/runtime input, may validate only its config shape at startup, and does not need direct raw-socket traversal or `stat(2)` authority there
  - operator bring-up, submit-readiness, and service-user migration check-only flows must still validate that the configured host SPIRE socket path exists as a local Unix socket before they claim submit-ready or apply-ready
  - runtime-helper failure to validate or reach that helper-private raw SPIRE path remains explicit and fail closed; the workload must not receive raw SPIRE socket access
  - that host socket path is current ES deployment input, not workload-visible contract; future infra-managed attachment can replace the bind form if it preserves the helper-private raw SPIRE boundary
- for fresh Linux workload-zone VMs, `scripts/70_linux_setup.sh` now installs Docker, Nomad, Vault, and Go, writes the current single-node `/etc/nomad.d/nomad.hcl` with bind mounts enabled and Nomad Docker image cleanup disabled for local runtime-profile durability, and then tries to qualify the root-managed `nomad.service` baseline
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
  - prepare-ready: service health plus successful workload-zone Vault runtime-config blob verification through ARS, including structural validation of any supplied Vault CA bundle
  - submit-ready: prepare-ready plus ES submit config present, Docker available, required enabled runtime-profile images present, Nomad leader present, and at least one ready Nomad client node that exposes positive `cpu.totalcompute` and a healthy Docker driver

Minimal vault-auth example:

```json
{
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt"
  }
}
```

### Remote Alpha ES service-user migration helper

For the bounded Option B service-user migration surface, the preferred
repo-side/operator helper is:

- `scripts/remote_alpha_migrate_es_service_user.sh`

Its sourced internal implementation is:

- `scripts/internal/remote_alpha_migrate_es_service_user.sh`

Operator rules for that helper are:

- `--check-only` is the default and must remain non-mutating
- `--apply` must be explicit and must re-run the check-only gates immediately
  before any mutation
- the default staged-wrapper path must use noninteractive `sudo -n` preflight
  and fail cleanly with structured `sudo_unavailable` evidence before helper
  upload or root-owned staging when passwordless sudo is unavailable
- `--interactive-sudo` may be used only from a visible terminal when a
  bounded password handoff is explicitly authorized; staged batch execution
  must still use bounded remote commands rather than a forced-PTY heredoc path,
  and tty-backed staged outputs must be fetched from remote artifact files
  rather than redirected directly into the local evidence files; interactive
  check-only should keep the privileged staged-install, stage-stat, and helper
  execution inside one visible sudo-backed SSH session
- when `--ssh-target` is used, the default local evidence directory should be
  `.out/remote-alpha-m75q`
- remote staging must copy only the migration helper plus the existing
  writable-state readiness checker helper files; a full repo checkout is not
  required on the remote host
- the helper must not claim full ES/runtime de-root
- the helper must leave the root-start runtime helper, Nomad task
  `User: "0:0"`, helper-private SPIRE traversal, broad root selector scope,
  and workload-zone Vault handoff semantics labeled as bounded compatibility
  edges

The default host-local apply-summary path for that helper is:

- `/var/tmp/execution-substrate-remote-alpha/es-service-user-migration-summary.json`

The required local staged-wrapper artifacts for that helper are:

- `es-service-user-migration-check-only.json`
- `es-service-user-migration-helper-staging-record.json`
- `es-service-user-migration-apply-summary.json` when `--apply` is used
- `es-service-user-migration-apply-stdout.txt` when `--apply` is used

The helper staging record for that wrapper must distinguish:

- `sudo_unavailable`
- `wrapper_tooling_error`
- whether staging occurred
- whether the check-only helper ran
- whether transient staging was removed

Check-only for that helper must emit machine-readable JSON and must not create
users or groups, call `chown` or `chmod` on live writable state, rewrite
systemd units, restart services, delete staging/results, or run governed
proof. Check-only must not create the host-local apply summary file; it emits
JSON to stdout only. Apply may change only the bounded `es.service` account
drop-in needed to set `User=es`, `Group=es`, and the documented `UMask=0027`,
after readiness gates pass and a pre-mutation backup is created.

The current live bounded state after that later helper apply is now:

- the long-lived `es.service` runs as `User=es`, `Group=es`, `UMask=0027`
- ES config/TLS prep is applied
- ES stable writable-state roots are prepared
- post-apply `/health`, `GET /v1/executions:contract`, the retained-result
  fetch/materialization flow, and the current lowest-cost existing happy path
  all passed
- future writable-state readiness passed
- this still does not claim full ES/runtime de-root because the root-start
  runtime helper, Nomad task `User: "0:0"`, helper-private SPIRE traversal,
  broad selector posture, and Vault/workload-zone handoff remain bounded
  compatibility edges
- old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by the migration

For bounded rollback rehearsal after that completed service-user change, the
repo now carries the local-only checker
`scripts/remote_alpha_es_service_user_rollback_rehearsal.sh`. Its default
input is `.out/remote-alpha-m75q`, and it emits:

- `es-service-user-rollback-rehearsal.json`
- `es-service-user-rollback-rehearsal.md`

That rehearsal is non-mutating and local-evidence-only. It must not SSH, use
`sudo`, mutate the live host, execute rollback, run ES apply, run governed
proof, or do PR/merge prep. It must classify findings as `pass`, `warning`, or
`blocker` while verifying that the service-user backup path is recorded, the
previous service unit/drop-in state is recorded, the bounded drop-in remains
limited to `User=es`, `Group=es`, and `UMask=0027`, rollback notes exist, the
binary-deployment backup plus writable-state backup/quarantine paths are
referenced, old root-era staging/results roots remain preserved as
rollback/debug/evidence state, and no recorded rollback instruction requires
recursive chown or broad deletion.

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

The current host-qualification boundary for the supported Linux environment is defined in [supported_linux_host_qualification.md](supported_linux_host_qualification.md).

- reachable at the `es.nomad.base_url`
- configured for the target datacenter in `es.nomad.datacenter`
- Docker driver available
- client bind mounts enabled through `client.options["docker.volumes.enabled"] = "true"`
- when enabled local runtime-profile images are part of the supported-local proof/runtime surface, Nomad Docker image cleanup disabled through `client.options["docker.cleanup.image"] = "false"` so Nomad does not remove the configured local profile image after a stopped allocation
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
- when `control-plane-normal-shell/v1` is enabled, the configured profile image must already be present in the Docker daemon used by Nomad before repo-owned readiness claims submit readiness
- when that configured profile image is local-only, repo-owned submit-readiness also requires the supported-local Nomad Docker image-cleanup guardrail above; otherwise a green image-present check can drift after Nomad observes terminal allocations

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

- on the current supported local reference host on this Mac, `scripts/72_supported_local_setup.sh setup` is the guest-side repo-owned proof-environment helper; it writes the current Dockerfile/TLS/config/blob assets, installs the `es-runtime-support` binary path used by ES submit config, builds the repo-owned Control Plane normal-shell runtime-profile image, boots a proof-scoped real SPIRE server/agent path and real Workload API socket, derives proof-only Vault JWT validation material from the SPIRE bundle, starts and configures the proof-scoped real Vault dev/test target, explicitly ensures the proof JWT auth mount plus the proof-owned KV v2 secret mount needed by the bounded credential-flow and Codex credential-material proofs, writes `managed-secrets.conf`, writes `env.sh`, and replaces the earlier out-of-repo `/tmp` harnesses
- `scripts/73_supported_local_proof.sh run` is the canonical host-side supported-local proof wrapper on this Mac; it records proof workspaces under `.out/es-proof-<id>/`, packages the bounded runtime-identity Vault-login workload and the Control Plane normal-shell runtime-contract workload, stages a fresh snapshot of the current host worktree into guest bootstrap scratch, cleans stale proof-owned guest `/tmp/es-proof-*` scratch from earlier wrapper runs, runs the supported-host qualification path, runs the higher-value useful credential-flow proof, runs the bounded Control Plane normal-shell runtime-profile proof, fetches and validates the retained result bundle, and copies the resulting guest evidence back into that canonical workspace
- on this Mac, the wrapper may still use guest `/tmp/es-proof-<id>` plus `/tmp/es-proof-<id>.bootstrap` internally because the Lima-mounted repo tree is read-only inside the `qemu` guest; those guest paths are proof-owned transient implementation detail, not the canonical proof workspace, and successful current-run guest scratch is removed after host evidence has been preserved
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
  - the current repo-owned examples, proofs, and bring-up configs keep `authorization.allowed_spiffe_path_prefixes=["operator"]` for AGS and ES, even though caller authorization is now deployment-configured rather than hard-coded in those services

The current unified health check verifies:

- ARS, EGS, AGS, and ES all report `ready=true`
- those health checks succeeded with a real client certificate at the TLS boundary
- Nomad has a leader and at least one ready node with positive `cpu.totalcompute` and a healthy Docker driver when `BRINGUP_PROFILE=full`
- `docker info` succeeds when `BRINGUP_PROFILE=full`
- any enabled `control-plane-normal-shell/v1` runtime-profile image is present according to `docker image inspect` in the Docker daemon used by Nomad when `BRINGUP_PROFILE=full`
- when an enabled runtime-profile image is present, the Nomad Docker driver client options report `docker.cleanup.image=false`, so Nomad will not remove that local image after stopped tasks as part of the supported-local runtime surface
- ES submit config still includes `execution.runtime_support_binary` and `execution.spire_workload_api_socket_path`, and the configured SPIRE socket path is present as a local Unix socket, when `BRINGUP_PROFILE=full`
- the workload-zone Vault blob referenced by `ES.runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and structurally valid before first execution
- if that blob supplies `vault_config.ca_bundle_pem`, the readiness check validates that it contains PEM certificate material; submit then stages it for workloads as `VAULT_CACERT` and as part of the runtime `SSL_CERT_FILE` bundle
- the operator path now also surfaces Nomad bring-up mode and the current environment-support classification so a green submit-ready result cannot be misread as the same support claim in pre-managed-supported and managed-local/override fallback modes
- the operator path also rejects Nomad `-dev` mode as unsupported rather than letting it appear as a supported pre-managed environment

Current limitation:

- `submit-ready` is now honest about zero-compute or Docker-unhealthy Nomad nodes, but it still does not prove every workload/resource shape can place successfully; later memory, device, or placement-constraint failures remain possible
- the local runtime-profile image durability guardrail only prevents Nomad's Docker driver from removing images after stopped tasks; manual Docker pruning, daemon reset, or an operator-deleted image still invalidates submit-readiness and must be refreshed before the next run
- a host that needs `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` remains only a bounded fallback environment for slice-0 proof, not evidence that the substrate is naturally self-honest there
- the script-managed local Nomad path also remains bounded fallback even when it is schedulable; the supported-environment story for this slice is a pre-managed non-dev Nomad service with natural schedulability
- a pre-managed Nomad `-dev` agent is unsupported even if it reports positive `cpu.totalcompute`
- a host profile that still reports `cpu.totalcompute=0` under the root-managed non-`-dev` service and also exposes no usable CPU-frequency data through `cpufreq` sysfs, `/proc/cpuinfo`, or SMBIOS `Current Speed` should currently be treated as unsupported for the slice-0 supported-environment claim rather than as a script/service-mode mistake
- on the current Apple Silicon Mac, the investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain in that unsupported bucket because natural `cpu.totalcompute` still stays `0`

Readiness still does **not** prove useful downstream credential use by itself. The workload-identity boundary now exists, and the bounded workload-vault login plus secret-read proof now sits directly on top of the supported-local qualification path as the canonical higher-value proof on this Mac.

Slice `1A` and `1B` now prove platform-owned runtime identity delivery for platform-controlled non-root workloads. In this first workload-identity slice, the platform launches the runtime identity helper as `0:0` and launches the workload as fixed UID:GID `10000:10000` with no supplemental groups and no privilege-escalation path. Root workloads, arbitrary image-user execution, and any mode that gives the workload direct access to raw SPIRE channels are out of scope for this slice. This is a bounded runtime compatibility constraint required to preserve platform-owned identity delivery; it is not a reduction of the workload-identity claim.

On the current Remote Supported-Host Alpha helper proof slice, that `0:0` helper start identity also explains the current persistent SPIRE workload registration shape: the helper proof uses `unix:uid:0` plus `unix:gid:0` for `spiffe://execution.internal/workload` so the installed helper can fetch locally through `/run/spire/sockets/agent.sock` without widening the workload-facing contract. That selector set is broad across root-owned processes and must be treated as Alpha-only proof scope, not product posture. Product hardening must narrow or replace that registration before a broader remote runtime identity claim is accepted, while preserving the current helper-private raw SPIRE boundary and the fixed workload UID:GID `10000:10000` non-exposure rule.

Useful credential flow is now also proved on top of that slice: one workload uses `EXEC_WORKLOAD_IDENTITY_ENDPOINT` to fetch a bounded real SPIRE-backed JWT-SVID for `workload_vault`, performs `auth/jwt/login` itself against a proof-scoped real Vault dev/test target using the proof Vault CA bundle carried through the workload-zone runtime config, and reads one secret without reintroducing workload-authored identity bridging or platform-owned Vault token brokerage.

For the current Remote Supported-Host Alpha service hardening tranche, scoped
honestly as `AGS sealed + ARS de-root + EGS de-root`:

- AGS is already de-rooted and sealed.
- ARS is already de-rooted.
- EGS is the only service being moved off root in this slice.
- ES remains on root in this tranche.
- ES public contracts, the current SPIRE selector posture, current Control
  Plane/Infrastructure Manager ownership boundaries, and the direct
  no-bridge/no-shared-filesystem remote path facts remain unchanged.

For the landed AGS seal step within that current tranche, the active
repo-derived AGS runtime inputs remain:

- binary path `/usr/local/lib/execution-substrate/bin/ags`
- config path `/etc/execution-substrate/ags.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- AGS bind `https://192.168.1.156:8444`
- AGS server cert `/etc/execution-substrate/tls/ags-server-cert.pem`
- AGS server key `/etc/execution-substrate/tls/ags-server-key.pem`
- AGS client CA bundle `/etc/execution-substrate/tls/combined-service-ca-bundle.pem`
- ARS base URL `https://127.0.0.1:8442`
- AGS client cert `/etc/execution-substrate/tls/ags-client-cert.pem`
- AGS client key `/etc/execution-substrate/tls/ags-client-key.pem`
- ARS root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- signer material location `/etc/execution-substrate/ags.json`
- no AGS-local state directory
- journald/stdout logging only
- systemd unit path `/etc/systemd/system/ags.service`
- systemd drop-in dir `/etc/systemd/system/ags.service.d`
- systemd drop-in path `/etc/systemd/system/ags.service.d/10-account.conf`
- ARS as the only AGS runtime dependency in this slice
- no EGS dependency on the AGS runtime path
- no ES dependency on the AGS runtime path

The repo-owned host-local hardening command for that landed AGS step is
`scripts/remote_alpha_harden_ags_service.sh`. It must be run as root,
typically through `sudo`, because the live Alpha posture keeps AGS config and
TLS material root-owned before the slice is applied and `ds` must still not
rely on passwordless sudo for this path.

That hardening command must reconfigure only `ags.service` to run as dedicated
`ags:ags`, must not introduce a shared `execution-substrate` account model,
must not change ES public contracts, must not change the SPIRE selector model,
and must leave `ars.service`, `egs.service`, and `es.service` in their
then-current posture for that step.

For this sealed AGS step within the current hardening tranche, the host-local
hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the landed AGS step away
from the repo-owned AGS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

The AGS-readable ownership model for that slice is:

- config file `/etc/execution-substrate/ags.json` owned as `root:ags` mode
  `0640`
- TLS directory `/etc/execution-substrate/tls` traversable for AGS as
  `root:ags` mode `0710`
- AGS-readable TLS files owned as `root:ags` mode `0640`:
  - `/etc/execution-substrate/tls/ags-server-cert.pem`
  - `/etc/execution-substrate/tls/ags-server-key.pem`
  - `/etc/execution-substrate/tls/combined-service-ca-bundle.pem`
  - `/etc/execution-substrate/tls/ags-client-cert.pem`
  - `/etc/execution-substrate/tls/ags-client-key.pem`
  - `/etc/execution-substrate/tls/runtime-ca.pem`
- a systemd drop-in or equivalent unit configuration setting `User=ags` and
  `Group=ags`

The host-local summary for that slice is
`execution-substrate.remote-alpha.ags-service-hardening-summary.v1` at
`/var/tmp/execution-substrate-remote-alpha/ags-service-hardening-summary.json`.
It is a hardening slice record, not a new happy-path proof. It must record the
AGS service user, AGS ownership model, preserved direct HTTPS/mTLS plus
no-bridge/no-shared-filesystem facts, local AGS health and publish-probe
results, and explicit non-claim fields:

- `not_claimed.es_runtime_hardening`
- `not_claimed.submit_runtime_profile_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

For the landed ARS de-root step within that same current tranche, the active
repo-derived ARS runtime inputs remain:

- binary path `/usr/local/lib/execution-substrate/bin/ars`
- config path `/etc/execution-substrate/ars.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- ARS bind `https://127.0.0.1:8442`
- current source server cert `/etc/execution-substrate/tls/ars-server-cert.pem`
- current source server key `/etc/execution-substrate/tls/ars-server-key.pem`
- current source client CA / runtime root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- dedicated ARS-readable TLS dir `/etc/execution-substrate/ars-tls`
- ARS-readable server cert `/etc/execution-substrate/ars-tls/ars-server-cert.pem`
- ARS-readable server key `/etc/execution-substrate/ars-tls/ars-server-key.pem`
- ARS-readable client CA / runtime root CA `/etc/execution-substrate/ars-tls/runtime-ca.pem`
- blob storage root `/var/lib/execution-substrate/ars/blobs`
- index file `/var/lib/execution-substrate/ars/index.json`
- journald/stdout logging only
- no ARS runtime dependency on AGS, EGS, or ES
- AGS remains the current downstream runtime dependency on ARS
- systemd unit path `/etc/systemd/system/ars.service`
- systemd drop-in dir `/etc/systemd/system/ars.service.d`
- systemd drop-in path `/etc/systemd/system/ars.service.d/10-account.conf`

The repo-owned host-local hardening command for that landed ARS de-root step is
`scripts/remote_alpha_harden_ars_service.sh`. It must be run as root,
typically through `sudo`, because the live Alpha posture keeps ARS config, the
current source TLS material, and ARS writable state root-owned before the slice
is applied and `ds` must still not rely on passwordless sudo for this path.

That hardening command must reconfigure only `ars.service` to run as dedicated
`ars:ars`, must preserve the current ARS loopback-only listener posture, must
preserve the current AGS `ags:ags` posture plus AGS publish path through ARS,
must not widen `/etc/execution-substrate/tls`, must not introduce a shared
`execution-substrate` account model, must not change ES public contracts, must
not change the SPIRE selector model, and must leave `egs.service` and
`es.service` in their then-current posture for that step.

For this sealed ARS de-root step within the current hardening tranche, the
host-local hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the ARS de-root step away
from the repo-owned ARS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

Because the current shared `/etc/execution-substrate/tls` directory is already
owned as `root:ags` for the landed AGS seal in the same tranche, ARS must not
reuse that shared directory as its readable runtime TLS path. The ARS-readable
ownership model for this step is:

- config file `/etc/execution-substrate/ars.json` owned as `root:ars` mode
  `0640`
- dedicated TLS directory `/etc/execution-substrate/ars-tls` owned as
  `root:ars` mode `0710`
- ARS-readable TLS files owned as `root:ars` mode `0640`:
  - `/etc/execution-substrate/ars-tls/ars-server-cert.pem`
  - `/etc/execution-substrate/ars-tls/ars-server-key.pem`
  - `/etc/execution-substrate/ars-tls/runtime-ca.pem`
- writable state root `/var/lib/execution-substrate/ars` owned as `ars:ars`
  mode `0750`
- writable blob root `/var/lib/execution-substrate/ars/blobs` owned as
  `ars:ars` mode `0750`
- writable index file `/var/lib/execution-substrate/ars/index.json` owned as
  `ars:ars` mode `0600`
- a systemd drop-in or equivalent unit configuration setting `User=ars`,
  `Group=ars`, and `UMask=0027`

The host-local summary for that slice is
`execution-substrate.remote-alpha.ars-service-hardening-summary.v1` at
`/var/tmp/execution-substrate-remote-alpha/ars-service-hardening-summary.json`.
It is a hardening slice record, not a new happy-path proof. It must record the
ARS service user, ARS config/TLS/state ownership model, preserved direct
HTTPS/mTLS plus no-bridge/no-shared-filesystem facts, local ARS health plus
local AGS health and publish-probe results, and explicit non-claim fields:

- `not_claimed.es_or_egs_hardening`
- `not_claimed.es_public_contract_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

That summary must not persist JWT-SVIDs, Vault tokens, TLS private-key PEM
bodies, API keys, private keys, or secret payloads. Its output is not ES
`/health`, not runtime-profile readiness, not submit readiness, and not a new
happy-path proof.

For the EGS de-root step within that same current tranche, the active
repo-derived EGS runtime inputs remain:

- binary path `/usr/local/lib/execution-substrate/bin/egs`
- config path `/etc/execution-substrate/egs.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- EGS bind `https://127.0.0.1:8443`
- current source server cert `/etc/execution-substrate/tls/egs-server-cert.pem`
- current source server key `/etc/execution-substrate/tls/egs-server-key.pem`
- current source client CA / runtime root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- dedicated EGS-readable TLS dir `/etc/execution-substrate/egs-tls`
- EGS-readable server cert `/etc/execution-substrate/egs-tls/egs-server-cert.pem`
- EGS-readable server key `/etc/execution-substrate/egs-tls/egs-server-key.pem`
- EGS-readable client CA / runtime root CA `/etc/execution-substrate/egs-tls/runtime-ca.pem`
- signer material location `/etc/execution-substrate/egs.json`
- runtime-trust policy location `/etc/execution-substrate/egs.json`
- publication metadata location `/etc/execution-substrate/egs.json`
- no EGS-local writable state paths
- journald/stdout logging only
- no EGS runtime dependency on AGS, ARS, or ES
- ES remains the current downstream runtime dependency on EGS
- systemd unit path `/etc/systemd/system/egs.service`
- systemd drop-in dir `/etc/systemd/system/egs.service.d`
- systemd drop-in path `/etc/systemd/system/egs.service.d/10-account.conf`

The repo-owned host-local hardening command for that EGS de-root step is
`scripts/remote_alpha_harden_egs_service.sh`. It must be run as root,
typically through `sudo`, because the live Alpha posture keeps EGS config, the
current source TLS material, and the inline signer material in that config
root-owned before the slice is applied and `ds` must still not rely on
passwordless sudo for this path.

Because the current shared `/etc/execution-substrate/tls` directory remains
narrowed for the landed AGS seal at `root:ags`, this EGS de-root step must not
reuse or widen that shared TLS directory and must not introduce a shared
Unix-account model. Instead, it stages only the EGS server cert, EGS server
key, and runtime root CA into dedicated EGS-readable paths under
`/etc/execution-substrate/egs-tls`.

That hardening command must reconfigure only `egs.service` to run as dedicated
`egs:egs`, must preserve the current EGS loopback-only listener posture, must
preserve the landed AGS `ags:ags` and ARS `ars:ars` service postures, must
preserve local AGS `/health` plus focused AGS publish through ARS, must
preserve local ES `/health` plus `GET /v1/executions:contract`, must not widen
`/etc/execution-substrate/tls`, must not change ES public contracts, must not
change the SPIRE selector model, and must leave `es.service` in its current
root posture for this slice.

If a pre-existing `egs` user/group already exists on the host, the helper must
prove that the account remains acceptably narrow for this slice before it is
reused. At minimum, that proof must confirm primary group `egs`, no
supplementary groups, and no unexpected extra members in the `egs` group
itself; otherwise the helper must fail instead of silently claiming a
dedicated narrow account/group.

For this sealed EGS de-root step within the current hardening tranche, the
host-local hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the EGS de-root step away
from the repo-owned EGS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

The EGS-readable ownership model for this step is:

- config file `/etc/execution-substrate/egs.json` owned as `root:egs` mode
  `0640`
- dedicated TLS directory `/etc/execution-substrate/egs-tls` owned as
  `root:egs` mode `0710`
- EGS-readable TLS files owned as `root:egs` mode `0640`:
  - `/etc/execution-substrate/egs-tls/egs-server-cert.pem`
  - `/etc/execution-substrate/egs-tls/egs-server-key.pem`
  - `/etc/execution-substrate/egs-tls/runtime-ca.pem`
- no EGS-local writable state paths
- a systemd drop-in or equivalent unit configuration setting `User=egs`,
  `Group=egs`, and `UMask=0027`

The host-local summary for that slice is
`execution-substrate.remote-alpha.egs-service-hardening-summary.v2` at
`/var/tmp/execution-substrate-remote-alpha/egs-service-hardening-summary.json`.
It is a hardening slice record, not a new happy-path proof. It must record the
EGS service user, EGS config/TLS ownership model, the fact that signer,
runtime-trust, and publication material remain config-local, that EGS has no
dedicated writable state, preserved direct HTTPS/mTLS plus
no-bridge/no-shared-filesystem facts, local EGS health plus preserved local AGS
health/publish and local ES health/contract results, and explicit non-claim
fields:

- `not_claimed.es_de_root`
- `not_claimed.es_public_contract_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

For that EGS summary:

- `validation.service_account_narrowness` must record the actual primary group
  seen for `egs`, the supplementary groups seen for `egs`, and the effective
  `egs` group members derived from the host group/passwd view, including
  `group_members` and `unexpected_group_members`. It must pass before the
  summary describes the account/group as narrow/dedicated.
- `preserved_remote_path.direct_https_mtls` must be an inference record
  derived from current AGS/ES host config and the host-local HTTPS+mTLS probes,
  not a hardcoded pass boolean and not a Mac-side reachability proof.
- `preserved_remote_path.no_bridge` and
  `preserved_remote_path.no_shared_filesystem` must be explicit operator
  assertion records unless a later slice adds proof inputs that can validate
  them directly.
- `security.shared_unix_account_model_introduced` must be derived from the
  service-account narrowness check and must not report `false` unless that
  check proves the account remained narrow for this slice.

That summary must not persist signer private-key bytes, TLS private-key PEM
bodies, JWT-SVIDs, Vault tokens, API keys, private keys, secret payloads, or
raw retained-result bundles. Its output is not ES `/health`, not
runtime-profile readiness, not submit readiness, and not a new happy-path
proof.

Remote Supported-Host Alpha may also extend that current bounded hardening work
with one separate ES config/TLS ownership prep slice.

`Bounded slice rule`: this slice prepares only ES-readable config/TLS
ownership for a later non-root ES step.

Current live bounded ES state on Remote Alpha is now:

- ES config/TLS prep is applied.
- ES stable writable-state roots are prepared.
- the current live long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`.
- post-apply `/health`, `GET /v1/executions:contract`, the retained-result
  fetch/materialization flow, and the current lowest-cost existing happy path
  all passed.
- future writable-state readiness passed.
- this does not claim full ES/runtime de-root.
- the root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad selector posture, and Vault/workload-zone handoff
  remain bounded compatibility edges.
- old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by the migration.

The config/TLS, binary-deployment, and writable-state subsections below still
describe earlier bounded slices whose own apply summaries intentionally record
`root(default)` at those earlier steps. That historical wording remains true
for those slice-specific artifacts and should not be read as the current live
service posture after the later bounded `User=es` service-user migration.

`Temporary compatibility edge`: at that earlier step, the live `es.service`
user/group remained `root(default)` while the ES config file and dedicated ES
TLS directory were prepared under `root:es` readability for a later de-root
slice. That bridge existed only to keep runtime behavior unchanged while future
ES de-root work stayed explicit.

This slice must:

- introduce dedicated ES-readable config ownership and a dedicated ES-readable
  TLS directory
- keep the live `es.service` user/group posture unchanged
- preserve the current AGS, ARS, and EGS service postures
- preserve the current direct HTTPS/mTLS ES `/health` plus
  `GET /v1/executions:contract` path
- preserve current SPIRE selector posture, SPIRE socket traversal, and
  Vault/runtime-helper semantics
- preserve the current Nomad task user model
- leave staging and retained-results ownership untouched
- avoid broader proof reruns

The active repo-derived ES runtime inputs for this prep slice remain:

- binary path `/usr/local/lib/execution-substrate/bin/es`
- config path `/etc/execution-substrate/es.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- systemd unit path `/etc/systemd/system/es.service`
- current source server cert `/etc/execution-substrate/tls/es-server-cert.pem`
- current source server key `/etc/execution-substrate/tls/es-server-key.pem`
- current source client CA `/etc/execution-substrate/tls/runtime-ca.pem`
- current source ARS client cert `/etc/execution-substrate/tls/es-client-cert.pem`
- current source ARS client key `/etc/execution-substrate/tls/es-client-key.pem`
- current source ARS root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- current source EGS client cert `/etc/execution-substrate/tls/es-client-cert.pem`
- current source EGS client key `/etc/execution-substrate/tls/es-client-key.pem`
- current source EGS root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- dedicated ES-readable TLS dir `/etc/execution-substrate/es-tls`
- ES-readable server cert `/etc/execution-substrate/es-tls/es-server-cert.pem`
- ES-readable server key `/etc/execution-substrate/es-tls/es-server-key.pem`
- ES-readable server client CA `/etc/execution-substrate/es-tls/server-client-ca.pem`
- ES-readable ARS client cert `/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`
- ES-readable ARS client key `/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`
- ES-readable ARS root CA `/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`
- ES-readable EGS client cert `/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`
- ES-readable EGS client key `/etc/execution-substrate/es-tls/execution-governance-client-key.pem`
- ES-readable EGS root CA `/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`
- the current `execution.staging_root_dir`, `execution.results_root_dir`, and
  `execution.spire_workload_api_socket_path` remain whatever
  `/etc/execution-substrate/es.json` already carries; this slice must not move
  or re-own them

The preferred repo-side operator wrapper for that slice is
`scripts/remote_alpha_stage_es_config_tls_prep.sh`.

That productized wrapper runs from the operator repo, stages only the minimal
helper tree onto the remote host, defaults to non-mutating check-only, records
the required staging provenance, executes only from the root-owned staged
helper path, and requires `--apply` before any live mutation is attempted.

The remote staged helper entrypoint for that slice remains
`scripts/remote_alpha_prepare_es_config_tls.sh`.

The remote host does not need a full Execution Substrate repo checkout for
this slice. The current accepted live-host invocation model is transient
helper staging from the operator repo into a root-owned staging tree under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/`.

At minimum, the operator must stage the repo-owned wrapper
`scripts/remote_alpha_prepare_es_config_tls.sh` and its sourced helper
`scripts/internal/remote_alpha_prepare_es_config_tls.sh`, preserving their
relative layout under that staging tree so the staged wrapper path is
`/var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`.

Execution must run from that root-owned staged tree, not from a user-writable
upload path. Any user-scoped upload directory is transport only and must not
be used as the execution path for the live helper invocation.

The staged wrapper must still be run as root, typically through `sudo`,
because the live Alpha posture keeps ES config and shared TLS material
root-owned before the slice is applied and `ds` must still not rely on
passwordless sudo for this path.

The required operator-staged provenance record for that transient helper tree
must include:

- the local git commit when available
- the sha256 of each staged helper file
- the remote staged path
- the remote owner/mode proving the staged tree is root-owned rather than a
  user-writable upload path

The required operator-staged flow for this slice is:

1. Prefer the repo-side wrapper
   `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host>`
   for the default non-mutating check-only path. That wrapper must stage only
   the minimal helper tree from the local operator repo snapshot; a full
   remote repo checkout is not required.
   Copy only the minimal helper tree from the local operator repo snapshot; a
   full remote repo checkout is not required.
2. Install that helper tree into
   `/var/tmp/execution-substrate-remote-alpha/helper-staging/` as a root-owned
   staged tree, record the required provenance above, and execute the staged
   wrapper from that location.
3. Run the staged wrapper with `--check-only` before any live apply.
4. Review the `--check-only` JSON report. Apply may proceed only when
   `result.ok=true`, `plan.blockers` is empty,
   `plan.service_identity_would_remain_root_default=true`, and
   `validation.config_rewrite_scope.status=pass`; the planned writes must stay
   limited to `/etc/execution-substrate/es.json`,
   `/etc/execution-substrate/es-tls`, the files beneath that dedicated TLS
   directory, and the configured summary path.
5. Run the staged wrapper without `--check-only` only after those gates pass.
6. Preserve the apply summary, backup path, rollback notes, live
   `es.service` identity, and post-apply `/health` plus
   `GET /v1/executions:contract` status as the bounded post-apply evidence
   set.
7. Remove the transient helper staging tree after that bounded evidence is
   collected, while preserving the apply backup and summaries under
   `/var/tmp/execution-substrate-remote-alpha/`.
8. Do not run governed proof as part of this staged operator flow.

This operator-staged flow is ownership prep only. It is not ES de-rooting.

The preferred productized operator commands are:

- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host>`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --apply`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q --apply`

The wrapper's default invocation above must remain check-only. The second form
must run apply only after the wrapper's repo-side gate validation accepts the
check-only JSON report for this slice.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local evidence
artifacts with the filenames Infrastructure Manager consumes directly:

- `es-config-tls-check-only.json`
- `es-config-tls-helper-staging-record.json`
- `es-config-tls-apply-summary.json` when `--apply` is used
- `es-config-tls-apply-stdout.txt` when `--apply` is used

Those local artifacts are hardening evidence/provenance only. They are not a
new governed proof, they do not authorize a wider ES prep slice, and they do
not change the host-local apply summary contract under
`/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`.

The required first step before any live apply is:

- `sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`

`--dry-run` is an accepted alias for that same non-mutating repo-side check.
That check-only path must perform discovery and validation only. It must emit a
machine-readable JSON plan/report to stdout and must not create users or
groups, call `chown` or `chmod`, rewrite `/etc/execution-substrate/es.json`,
create or replace `/etc/execution-substrate/es-tls`, create a backup directory
under `/var/tmp/execution-substrate-remote-alpha/`, or restart
`es.service`. It may inspect current service posture, current config and
dependency paths, existing owner/mode state, and the planned ES config rewrite
scope. The live apply step
`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`
may be run only after
that check-only report is reviewed and accepted.

Before any apply-mode mutation primitive runs, the helper must create a
timestamped backup directory under
`/var/tmp/execution-substrate-remote-alpha/`. That backup directory must
contain a copied pre-apply `es.json` plus a `pre-apply-snapshot.json` record
covering the pre-apply source TLS path, size, owner, group, mode, and sha256
for each current ES TLS/dependency input path, whether the `es` prep user and
group existed before apply, the current `es.service` `User`, `Group`,
`ActiveState`, and `SubState`, and rollback notes for restoring the pre-apply
ES config/TLS posture.

If the target host already has an `es` user/group, the helper must prove that
the pre-existing prep account is still acceptably narrow for this slice before
it is reused. At minimum, that check must confirm primary group `es` and no
supplementary groups; otherwise the helper must fail instead of silently
claiming a dedicated narrow account/group.

For this sealed ES config/TLS prep slice, the host-local helper must not
accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_PREP_USER`,
`REMOTE_ALPHA_PREP_GROUP`, `REMOTE_ALPHA_BINARY_PATH`,
`REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`,
`REMOTE_ALPHA_SERVICE_UNIT_PATH`, `--service-name`, `--prep-user`,
`--prep-group`, `--binary-path`, `--config-path`,
`--healthcheck-env-path`, or `--service-unit-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the slice away from the
repo-owned ES posture. Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH`
may vary for output placement.

The ES-readable ownership model for this prep slice is:

- prep account `es:es`, proved narrow before reuse
- config file `/etc/execution-substrate/es.json` owned as `root:es` mode
  `0640`
- dedicated TLS directory `/etc/execution-substrate/es-tls` owned as
  `root:es` mode `0710`
- ES-readable TLS files owned as `root:es` mode `0640`:
  - `/etc/execution-substrate/es-tls/es-server-cert.pem`
  - `/etc/execution-substrate/es-tls/es-server-key.pem`
  - `/etc/execution-substrate/es-tls/server-client-ca.pem`
  - `/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`
  - `/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`
  - `/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`
  - `/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`
  - `/etc/execution-substrate/es-tls/execution-governance-client-key.pem`
  - `/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`
- at that earlier step, live `es.service` continued to run as `root(default)`
  in this slice
- current staging and retained-results ownership remain unchanged in this
  slice

The host-local apply summary for that prep slice is
`execution-substrate.remote-alpha.es-config-tls-prep-summary.v1` at
`/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`.
Apply mode writes that file. Check-only must not create it; instead it must
emit the same schema shape as stdout JSON with `mode.output` set to
`stdout_json` and the configured summary path recorded under
`plan.paths_written`. This is a host-local ownership-prep record, not a new
happy-path proof. It must record the live ES service posture, the dedicated ES
config/TLS ownership model, preserved direct HTTPS/mTLS plus
no-bridge/no-shared-filesystem facts, post-apply ES `/health` and
producer-contract probe results, and explicit non-claim fields:

- `not_claimed.es_de_root`
- `not_claimed.es_public_contract_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.spire_socket_traversal_changes`
- `not_claimed.nomad_task_user_model_changes`
- `not_claimed.vault_runtime_helper_changes`
- `not_claimed.staging_or_results_ownership_changes`
- `not_claimed.new_remote_happy_path_proof`

For that ES prep summary:

- `slice.classification`, `slice.not_a_new_happy_path_proof`, and
  `slice.temporary_compatibility_edge` must keep the ownership-prep slice,
  non-proof posture, and live `root(default)` service-user bridge explicit in
  machine-readable form.
- `service.live_user`, `service.live_group`, `service.binary_path`,
  `service.config_path`, `service.health_url`, and `service.contract_url`
  must describe the live ES service identity plus the repo-derived runtime and
  probe endpoints this slice preserves.
- `dependencies.server_tls.cert_file`, `dependencies.server_tls.key_file`,
  `dependencies.server_tls.client_ca_file`,
  `dependencies.artifact_registry.base_url`,
  `dependencies.artifact_registry.client_cert_file`,
  `dependencies.artifact_registry.client_key_file`,
  `dependencies.artifact_registry.root_ca_file`,
  `dependencies.execution_governance.base_url`,
  `dependencies.execution_governance.client_cert_file`,
  `dependencies.execution_governance.client_key_file`,
  `dependencies.execution_governance.root_ca_file`,
  `dependencies.local_state_paths`, and `dependencies.log_sink` must describe
  the current ES dependency inputs that the helper inspects and preserves.
- `mode.name`, `mode.non_mutating`, and `mode.output` must explicitly label
  whether the record came from non-mutating check-only or live apply mode.
- `plan.paths_read` must enumerate the current ES config/dependency/service
  inputs and the ownership-inspection paths read by this slice.
- `plan.paths_written` must enumerate the config, dedicated ES TLS paths, and
  configured summary path that apply mode would write.
- `plan.ownership_changes` must describe current owner/mode state plus planned
  `root:es` owner/mode targets for the config file and dedicated ES TLS paths.
- `plan.prep_account` must say whether `es:es` already exists or would be
  created in apply mode.
- `plan.service_identity_would_remain_root_default` must state whether the
  current `es.service` posture would remain `root(default)` through this slice.
- `plan.restart_required_in_apply_mode` must remain `true` because the live
  apply path still restarts `es.service` once after rewriting the config/TLS
  ownership slice.
- `plan.warnings` and `plan.blockers` must capture advisory host-posture facts
  plus any reasons the current host is not ready for a bounded live apply.
- `ownership_model.prep_account`, `ownership_model.config_file`,
  `ownership_model.tls_directory`, `ownership_model.tls_files`,
  `ownership_model.live_service_posture`, and
  `ownership_model.writable_state` must describe the bounded ES-readable
  ownership model, the unchanged live `root(default)` service posture, and the
  fact that writable state remains outside this prep slice.
- `backup.status`, `backup.parent_dir`, and `backup.path` must label whether
  apply created the timestamped backup and where it lives.
- `backup.pre_apply_config_copy` and `backup.snapshot_manifest_path` must point
  to the copied pre-apply config and the snapshot manifest inside the backup
  directory.
- `backup.pre_apply_source_tls` must record the pre-apply source TLS path,
  size, owner, group, mode, and sha256 for each source file.
- `backup.pre_apply_prep_account` must record whether the `es` prep user and
  group existed before apply.
- `backup.pre_apply_service` must record the pre-apply `es.service` `User`,
  `Group`, `ActiveState`, and `SubState`.
- `backup.rollback_notes` must record rollback notes for restoring the
  pre-apply ES config/TLS posture without changing `es.service` `User=` or
  `Group=`.
- `validation.prep_account_narrowness` must prove the `es` prep account
  remains narrow for this slice before the summary may describe it as
  dedicated.
- `validation.config_rewrite_scope` must prove that only ES config/TLS path
  fields changed and that `execution.staging_root_dir`,
  `execution.results_root_dir`, and
  `execution.spire_workload_api_socket_path` remained unchanged.
- `validation.es_service_posture` must show the live service still runs as
  `root(default)` after the prep apply.
- `preserved_remote_path.direct_https_mtls` must be an inference record
  derived from current ES host config plus the host-local HTTPS+mTLS probes,
  not a hardcoded pass boolean and not a Mac-side reachability proof.
- `preserved_remote_path.no_bridge` and
  `preserved_remote_path.no_shared_filesystem` must be explicit operator
  assertion records unless a later slice adds proof inputs that can validate
  them directly.
- `security.ds_not_in_docker_group` and
  `security.passwordless_sudo_for_ds` are host-posture observations recorded
  in the summary. They must not, by themselves, turn an otherwise-valid ES
  config/TLS ownership prep apply into a failed slice result.
- `security.shared_unix_account_model_introduced` must be derived from
  `validation.prep_account_narrowness`. It must not report `false` unless that
  check proves the dedicated `es` prep account remained narrow for this slice.
- `result.status`, `result.ok`, and `result.non_mutating` must summarize the
  machine-readable outcome without implying that check-only performed any live
  mutation.

That summary must not persist TLS private-key PEM bodies, client-cert private
keys, JWT-SVIDs, Vault tokens, API keys, private keys, secret payloads, or raw
retained-result bundles. Its output is not ES `/health`, not submit
readiness, not runtime-profile readiness, and not a new happy-path proof.

Remote Supported-Host Alpha may now also extend that current bounded hardening
work with one separate ES binary-parity deployment slice.

`Bounded slice rule`: this earlier slice resolved only live ES/runtime-helper
binary parity against the repo snapshot before the later writable-state and
service-user steps.

`Temporary compatibility edge`: at that earlier step, the live `es.service`
user/group remained `root(default)` while only the binaries at the accepted
live paths were updated to a repo-built linux/amd64 snapshot. This slice must
not rewrite ES config, TLS ownership, staging/results ownership, or the
accepted runtime-helper design.

This slice must:

- build or locate the repo-owned linux/amd64 `es` and `es-runtime-support`
  artifacts through the established repo build path only
- compare those local artifact hashes and sizes to the live host binaries
- treat a live hash mismatch as `deployment_needed`, not as a host failure by
  itself
- keep the then-live `es.service` posture at `root(default)` through this
  earlier slice
- preserve the current AGS, ARS, and EGS service postures
- preserve the current direct HTTPS/mTLS ES `/health` plus
  `GET /v1/executions:contract` path
- preserve the current staging/results ownership and service-user posture
- avoid broader proof reruns

The active repo-derived inputs for this slice remain:

- service name `es`
- binary path `/usr/local/lib/execution-substrate/bin/es`
- runtime helper binary path `/usr/local/bin/es-runtime-support`
- config path `/etc/execution-substrate/es.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- systemd unit path `/etc/systemd/system/es.service`

The preferred repo-side/operator wrapper for that slice is:

- `scripts/remote_alpha_deploy_es_binaries.sh`

Its sourced implementation is:

- `scripts/internal/remote_alpha_deploy_es_binaries.sh`

When the wrapper stages through `--ssh-target`, it must upload only the
minimal helper tree and payload files needed by this bounded slice, and it
must preserve the exact relative paths the root-owned install step later
consumes:

- `<upload-root>/scripts/remote_alpha_deploy_es_binaries.sh`
- `<upload-root>/scripts/internal/remote_alpha_deploy_es_binaries.sh`
- `<upload-root>/payload/es`
- `<upload-root>/payload/es-runtime-support`
- `<upload-root>/payload/build-provenance.json`

If any required staged helper or payload path is missing from the local upload
tree, the wrapper must fail as structured `wrapper_tooling_error` evidence
before remote root-owned install is attempted. It must not surface a raw
`install: cannot stat` failure from the root-owned staging step.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local evidence
artifacts with the filenames Infrastructure Manager consumes directly:

- `es-binary-deployment-check-only.json`
- `es-binary-deployment-helper-staging-record.json`
- `es-binary-deployment-apply-summary.json` when `--apply` is used

The summary schema for this host-local deployment record is:

- `execution-substrate.remote-alpha.es-binary-deployment-summary.v1`

The current host-local non-secret apply summary for that deployment step is:

- `/var/tmp/execution-substrate-remote-alpha/es-binary-deployment-summary.json`

Check-only must not create that file; instead it must emit stdout JSON in the
same schema family with `mode.name=check_only`, `mode.non_mutating=true`,
`proof.check_only_is_not_proof=true`, `proof.host_mutation_performed=false`,
and a boolean `plan.deployment_needed`. Apply may change only:

- `/usr/local/lib/execution-substrate/bin/es`
- `/usr/local/bin/es-runtime-support`

Apply must install both binaries atomically as `root:root` mode `0755`, create
a pre-mutation backup, restart `es.service` at most once, keep
`validation.es_service_posture` at `root(default)`, and validate `/health`
plus `GET /v1/executions:contract` afterward. This is a bounded binary
deployment record only; it is not governed proof, not writable-state evidence,
and not service-user migration evidence.

Before any apply-mode mutation primitive runs, the helper must create a
timestamped backup directory under
`/var/tmp/execution-substrate-remote-alpha/`. That backup directory must:

- copy the pre-apply `es` binary and record its sha256
- copy the pre-apply `es-runtime-support` binary and record its sha256
- write `pre-apply-snapshot.json`

Transient remote staging for this wrapper is limited to the user-owned upload
root, the user-owned artifact root, and the root-owned helper staging root
under `/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`.
Unless `--keep-staging-on-failure` is explicitly requested, deferred cleanup
must remove all three transient roots when they were created for the run.
- record the pre-apply `es.service` `ExecStart`, `User`, `Group`,
  `ActiveState`, and `SubState`
- record the pre-apply `es.json` sha256
- record rollback notes for restoring the old binaries and restarting
  `es.service` once

Remote Supported-Host Alpha may now also extend that current bounded hardening
work with one separate ES stable writable-state ownership slice.

`Bounded slice rule`: this earlier slice prepared only the stable
staging/results root ownership needed before the later non-root
`es.service` step.

`Temporary compatibility edge`: at that earlier step, the live `es.service`
user/group remained `root(default)` while only the stable writable-state roots
moved to the documented `es:es` model. This slice must not recursively re-owner
retained run trees and must not rewrite ES config/TLS inputs. Default
empty-root apply must not restart `es.service`; a separate explicit non-empty-
root maintenance window may stop/start `es.service` once while keeping the
service identity at `root(default)`.

This slice must:

- inspect only `execution.staging_root_dir` and `execution.results_root_dir`
  from `/etc/execution-substrate/es.json`
- target owner `es:es` mode `0750` for both stable roots
- block by default when either stable root is non-empty
- advertise explicit maintenance-window rotation only when the helper can rule
  out active or unknown runs safely
- classify legacy run directories read-only through the existing configured
  Nomad connection only when retained-result or normalization-marker evidence
  is absent
- require explicit `--accept-stale-orphaned-runs` before rotating non-empty
  roots whose legacy directories are scheduler-terminal or stale/orphan
  candidates without retained-result or normalization-marker evidence
- inspect the minimal common parent traversal directory or directories needed
  to reach the live staging/results roots
- preserve the existing parent owner and change only the parent group and mode
  needed for ES traversal; under the current Remote Alpha host layout that
  means `root:es` `0750` for `/var/lib/execution-substrate/es`
- refuse recursive `chown` of arbitrary retained run/debug trees
- keep the then-live `es.service` posture at `root(default)` through this
  earlier slice
- preserve the current direct HTTPS/mTLS ES `/health` plus
  `GET /v1/executions:contract` path
- preserve current SPIRE selector posture, SPIRE socket traversal,
  Vault/runtime-helper semantics, and the current Nomad task user model
- avoid broader proof reruns

The preferred repo-side/operator wrapper for that slice is:

- `scripts/remote_alpha_prepare_es_writable_state_ownership.sh`

Its sourced implementation is:

- `scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local evidence
artifacts with the filenames Infrastructure Manager consumes directly:

- `es-writable-state-ownership-check-only.json`
- `es-writable-state-ownership-helper-staging-record.json`
- `es-writable-state-ownership-apply-summary.json` when `--apply` is used

The summary schema for this host-local ownership record is:

- `execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1`

The current host-local non-secret apply summary for that ownership step is:

- `/var/tmp/execution-substrate-remote-alpha/es-writable-state-ownership-summary.json`

Check-only must not create that file; instead it must emit stdout JSON in the
same schema family with `mode.name=check_only`, `mode.non_mutating=true`,
`proof.check_only_is_not_proof=true`, `proof.host_mutation_performed=false`,
a boolean `plan.apply_ready`, and a boolean
`plan.roots_nonempty_block_apply`. When non-empty roots are observed, that
check-only record may still report a separate explicit
`--rotate-nonempty-roots` maintenance-window path as available, but default
apply readiness must remain blocked. Apply may change only:

- `execution.staging_root_dir` from `/etc/execution-substrate/es.json`
- `execution.results_root_dir` from `/etc/execution-substrate/es.json`

Apply must change only those two stable roots to owner `es:es` mode `0750`,
must not recursively re-owner retained run/debug trees, must not delete
staging/results contents, and must preserve `validation.es_service_posture` as
`root(default)`. Empty-root apply may re-owner the two live roots in place
without a service restart. The separate explicit `--rotate-nonempty-roots`
maintenance-window path may stop `es.service`, move the old non-empty
configured roots aside to timestamped root-owned quarantine paths, create
fresh live roots at the original configured paths, start `es.service` again,
and require post-start `/health` plus `GET /v1/executions:contract`
validation. That maintenance-window rotation must preserve the old contents
without recursive `chown` or deletion, must record that old retained results
may no longer be available through the normal ES API after rotation, and must
not claim to be service-user migration or full ES/runtime de-root. This is a
bounded writable-state ownership record only; it is not governed proof and not
a service-user migration record.
When legacy run directories lack retained-result or normalization-marker
evidence, the helper must classify them read-only via the configured Nomad
connection and may advertise explicit apply readiness only with both
`--rotate-nonempty-roots` and `--accept-stale-orphaned-runs`. Active,
unknown, or scheduler-unavailable classifications remain hard blockers.
When the live roots already match the documented `es:es` model but a shared
parent directory still blocks future non-root traversal, the helper may offer
an additional explicit parent-traversal preparation flag such as
`--fix-parent-chain`. That parent-only apply must preserve the existing owner
of the traversal parent, change only the group/mode needed for ES traversal,
must not revisit root rotation unless drift is detected, must not mutate
quarantined old roots, and should avoid any `es.service` restart unless a
measured host proves it is required.

Before any apply-mode mutation primitive runs, the helper must create a
timestamped backup directory under
`/var/tmp/execution-substrate-remote-alpha/`. That backup directory must:

- write `pre-apply-snapshot.json`
- record the pre-apply `es.json` sha256
- record current staging/results owner, group, mode, size, and immediate
  contents summary
- record current `es.service` `User`, `Group`, `ActiveState`, and `SubState`
- record any active-run or drain evidence the helper could discover
- record rollback notes for restoring the pre-apply root owner/mode state
- record any quarantined old-root paths created by a maintenance-window
  rotation

For the separate Remote Supported-Host Alpha host-local Vault/workload-auth
slice, the active repo-derived workload-auth values remain:

- JWT auth mount: `jwt`
- JWT auth role: `service_execution`
- JWT audience: `vault`
- bound subject: `spiffe://execution.internal/workload`
- bound issuer: `spiffe://execution.internal`

That remote slice may use a single-node Alpha/internal Vault system service
instead of the supported-local proof-scoped Vault dev/test target, but any
root-token, unseal, or other privileged bootstrap material must remain root-only
on the remote host and must not be copied into repo proof workspaces,
support-bundle summaries, Control Plane artifacts, or Infrastructure Manager
`.out`.

The repo-owned host-local check path for that remote slice is
`scripts/remote_alpha_vault_workload_auth_check.sh`. It must be run as root,
typically through `sudo`, and it writes the bounded host-local summary
`execution-substrate.remote-alpha.vault-workload-auth-summary.v1` to
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`.
That check validates the current workload-zone Vault config file at
`/etc/execution-substrate/vault/workload-zone-vault-config.json` against the
repo-owned workload-zone Vault config shape, records only bounded metadata, and
must not print or persist JWT-SVIDs, Vault client tokens, root tokens, unseal
keys, private keys, or secret payloads. Its output is not ES `/health`, not
submit readiness, and not a producer-contract or retained-result claim.
The current required auth smoke in that host-local check is JWT fetch, Vault
JWT login, Vault token self-lookup over the documented `GET
/auth/token/lookup-self` path, one bounded proof read at
`proof-secrets/data/runtime-identity-vault-login`, one exact proof-runtime
secret read at `proof-secrets/data/codex-runtime-profile` for field `api_key`,
and self-revoke. The exact proof-runtime secret check records only bounded
metadata such as path, field name, field presence, field non-empty status, and
field shape; it must not print or persist the field value. The check records
those requirements explicitly in summary metadata so a passing
`vault_workload_auth_smoke` cannot silently ignore a failed or skipped required
step.

For the separate Remote Supported-Host Alpha host-local normal-shell runtime
image slice, the active repo-derived values remain:

- image ref `execution-substrate/control-plane-normal-shell:supported-local`
- repo-owned build recipe `scripts/remote_alpha_build_normal_shell_runtime_image.sh`
- configured Codex CLI path `/usr/local/bin/codex`
- no-real-credential realization `proof`

The exact repo-owned build recipe for that slice is
`sudo scripts/remote_alpha_build_normal_shell_runtime_image.sh`. It pins the
current repo-owned recipe and invokes
`scripts/build_control_plane_normal_shell_image.sh` with:

- `CONTROL_PLANE_NORMAL_SHELL_IMAGE=execution-substrate/control-plane-normal-shell:supported-local`
- repo-owned Dockerfile `es/runtimeprofiles/control_plane_normal_shell/Dockerfile`
  resolved under the current repo root
- `CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH=/usr/local/bin/codex`
- `CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION=proof`

Conflicting caller overrides for those recipe-defining variables are outside
this slice. The wrapper must fail fast instead of silently honoring a different
image ref, Dockerfile, Codex CLI path, or Codex realization.

The repo-owned host-local check path for that slice is
`scripts/remote_alpha_normal_shell_runtime_image_check.sh`. It must be run as
root, typically through `sudo`, because the current M75q posture intentionally
keeps `ds` out of the Docker group while the check still needs Docker image and
bounded container-smoke access. It writes the bounded host-local summary
`execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1` to
`/var/tmp/execution-substrate-remote-alpha/normal-shell-runtime-image-summary.json`.
That check records only bounded non-secret recipe, image, service, and bounded
container-smoke metadata; it does not build or rebuild the image by default,
does not install or start ES, AGS, ARS, or EGS, and does not change ES public
contracts. Its output is not ES `/health`, not runtime-profile readiness, not
submit readiness, not producer-contract compatibility, and not retained-result
proof. The required non-claim vocabulary for that summary is
`readiness_not_claimed.runtime_profile_ready`,
`readiness_not_claimed.submit_ready`,
`readiness_not_claimed.es_services_healthy`,
`readiness_not_claimed.producer_contract_compatible`, and
`readiness_not_claimed.retained_result_fetch`. The bounded minimal container
smoke must prove `build.codex_realization = proof`; `placeholder` is not the
current repo-owned slice posture.

For this sealed Remote Alpha slice, the host-local checker must not accept
slice-defining overrides through `REMOTE_ALPHA_RUNTIME_IMAGE_REF`,
`REMOTE_ALPHA_CODEX_CLI_PATH`, `REMOTE_ALPHA_BUILD_SCRIPT`, `--image-ref`, or
`--codex-cli-path`. Those values are fixed to the repo-owned image ref, Codex
CLI path, and recipe wrapper above; the checker must fail fast instead of
silently honoring a non-slice posture.

The summary's build-recipe evidence is current repo-snapshot evidence only. It
must verify the expected repo-owned wrapper for this slice and record that
evidence honestly; it must not claim to prove historical build invocation
unless separate build-time evidence exists.

The bounded Control Plane normal-shell runtime profile is proved as an end-to-end supported-local runtime-contract proof on top of the same path: the profile image is built from the repo-owned reference recipe with a proof-only Codex shim at the configured `EXEC_CODEX_CLI_PATH`, ES selects it only for `invocation.annotations["execution_substrate.runtime_profile"]="control-plane-normal-shell/v1"`, the workload verifies Python, git, narrow shell tooling, obtains proof-scoped Codex credential material through workload-side Vault login using staged CA trust material, invokes the proof Codex shim with stdin prompt input, creates a deterministic workspace mutation, writes runner-style final-message, diff, stdout/stderr, and workspace-archive artifacts, and fetches plus validates the retained ES result bundle. The proof does not prove real upstream Codex service behavior because this repo cannot own a non-sensitive production Codex credential or external Codex service availability.

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
- the compact operator troubleshooting matrix for those classes now lives in `.runbooks/system/v1_bringup.md`; it maps each surfaced category to the authoritative check, the most relevant service logs, when retained staging is actually useful, and the next operator action
