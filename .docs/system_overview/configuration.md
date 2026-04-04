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
- `authorization`
- `storage`

### Required fields

- `authorization.allowed_spiffe_path_prefixes`
- `storage.root_dir`
- `storage.index_file`

### Required external dependencies

- local filesystem storage for blobs
- local filesystem index file for artifact registration

### Minimal valid configuration

- `storage.root_dir` must point to a writable directory
- `storage.index_file` must point to a writable file path
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
  - optionally `execution.runtime_identity_tmpfs_size`
- `execution.staging_root_dir` is a writable host-local staging root
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
- workloads should rely on `EXEC_WORKLOAD_IDENTITY_ENDPOINT` for endpoint discovery rather than on any fixed socket path
- ES `/health` does not include Nomad readiness in the current slice; Nomad availability is verified separately during bring-up and submit/lifecycle checks
- The primary bring-up/check path distinguishes:
  - service health: ARS, EGS, AGS, and ES public health surfaces
  - prepare-ready: service health plus successful workload-zone Vault runtime-config blob verification through ARS
  - submit-ready: prepare-ready plus ES submit config present, Docker available, Nomad leader present, and at least one ready Nomad client node

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

- reachable at the `es.nomad.base_url`
- configured for the target datacenter in `es.nomad.datacenter`
- Docker driver available
- client bind mounts enabled through `client.options["docker.volumes.enabled"] = "true"`
- explicit local data directory for repeatable manual bring-up

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

- use `BRINGUP_PROFILE=full scripts/01_bringup.sh up` as the primary bootstrap path
- use `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh` to re-run readiness checks
- use `BRINGUP_PROFILE=prepare-only` only when you intentionally want ARS + EGS + AGS + ES preflight without Nomad/Docker submit
- use an operator SPIFFE client cert/key for AGS and ES operator-facing helpers:
  - `CA_CERT`
  - `OPERATOR_CERT`
  - `OPERATOR_KEY`

The current unified health check verifies:

- ARS, EGS, AGS, and ES all report `ready=true`
- Nomad has a leader and at least one ready node when `BRINGUP_PROFILE=full`
- `docker info` succeeds when `BRINGUP_PROFILE=full`
- the workload-zone Vault blob referenced by `ES.runtime_config.workload_zone_vault_config_ref.digest` is readable through ARS and structurally valid before first execution

For operator diagnostics in the current bounded slice:

- `scripts/01_bringup.sh check` and `scripts/10_health_check.sh` remain the authoritative readiness baseline for service health, prepare-ready, and submit-ready
- later helpers such as `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, `scripts/50_lifecycle.sh`, and `scripts/60_execute_loop.sh` must not redefine readiness; they should direct operators back to that baseline when they detect readiness or substrate trouble
- the bounded operator failure classes are:
  - caller authorization / credential failure
  - trust / evidence / admission failure
  - runtime-config reference or blob failure
  - service health / readiness failure
  - substrate failure (Docker / Nomad / runtime availability)
  - execution failure after successful submit
  - operator misuse / invalid input
