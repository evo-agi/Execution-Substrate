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

## ACS

### Required config groups

- `http`
- `tls`
- `authorization`
- `catalog`
- `audit`

### Required fields

- `authorization.allowed_spiffe_path_prefixes`
- `audit.mode`

### Required external dependencies

- none for runtime calls
- local seed data for governed assignment lookup

### Minimal valid configuration

- `audit.mode` must be `noop`
- `authorization.allowed_spiffe_path_prefixes` must contain at least one non-empty SPIFFE path prefix
- for the governed execution system, `catalog.seed_artifact_digests` must include the required workload-zone Vault assignment

Minimal seed example:

```json
{
  "catalog": {
    "seed_artifact_digests": {
      "sha256:<workload-zone-vault-digest>": {
        "identity_kind": "workload_zone_vault"
      }
    }
  },
  "audit": {
    "mode": "noop"
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

## EGS

### Required config groups

- `http`
- `tls`
- `security`
- `signer`
- `trust_model`

### Required fields

- `security.bootstrap_issuer_common_name`
- `signer.algorithm`
- `signer.key_id`
- `signer.private_key_hex`
- `signer.public_key_hex`
- `trust_model.version`
- `trust_model.update_revision`

### Required external dependencies

- none for runtime calls
- signer key material for TrustModel signing

### Minimal valid configuration

- `signer.algorithm` must be `ed25519`
- `trust_model.update_revision` must be greater than `0`
- `trust_model.signer_policy.allowed_signers` and `revoked_signers` must not contain duplicates or empty values
- `trust_model.artifact_policy.revoked_artifacts`, if present, must contain labeled SHA-256 digests

For a minimal active system, `trust_model.signer_policy.allowed_signers` must include the AGS signer key ID used for provenance.

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
- `dependencies.artifact_catalog.*`
- `dependencies.artifact_registry.*`
- `dependencies.execution_governance.*`
- `verification.trust_model.*`
- `verification.provenance.*`
- `verification.derivation_attestation.*`
- `verification.workload_identity_binding.*`
- `workload_vault_auth.default_mode`
- `nomad.base_url`, `nomad.datacenter`, `nomad.timeout_seconds` when submit is enabled
- `execution.staging_root_dir`, `execution.base_image` when submit is enabled

### Required external dependencies

- ACS over HTTPS
- ARS over HTTPS
- EGS over HTTPS
- Nomad for real execution submit
- Docker under Nomad for container runtime
- workload-zone Vault config available through ACS -> ARS

### Minimal valid configuration

- all verifier algorithms must be `ed25519`
- verifier key IDs and public keys must match the active EGS and AGS signers
- all dependency base URLs must be absolute `https://` URLs
- `workload_vault_auth.default_mode` must be `vault_identity_jwt`
- if `nomad` and `execution` are omitted, ES can still support `:prepare` but not `:submit`
- for full end-to-end execution verification, include:
  - `nomad.base_url`
  - `nomad.datacenter`
  - `execution.staging_root_dir`
  - `execution.base_image`
  - optionally `execution.runtime_identity_tmpfs_size`
- `execution.staging_root_dir` is a writable host-local staging root
  - it backs successful-submit payload/run staging in the current slice unless removed externally
  - `/monolith/run` remains a host-backed writable execution workspace and is not guaranteed non-sensitive
  - `/monolith/staged` and caller-visible `/monolith/mounts/...` remain host-backed copies of governed artifact content
  - ES does not semantically inspect payloads or mount contents for secrecy
- the runtime identity contract no longer requires ES-local identity plumbing configuration
- ES reserves `/monolith/runtime-identity/` inside the workload container for topology-neutral identity plumbing
  - this reserved workspace is memory-backed tmpfs and is not persisted to host staging
  - `execution.runtime_identity_tmpfs_size` defaults to `1048576` bytes (`1 MiB`) and must not exceed `8388608` bytes (`8 MiB`)
  - `/monolith/runtime-identity/vault-token` remains reserved for future use in the current slice
- ES `/health` does not include Nomad readiness in the current slice; Nomad availability is verified separately during bring-up and submit/lifecycle checks

Minimal vault-auth example:

```json
{
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt",
    "selectors": []
  }
}
```

## CGS

### Required config groups

- `http`
- `tls`
- `policy`
- `vault_runtime`
- `security`
- `action_proof`

### Required fields

- `policy.id_conf_path`
- `vault_runtime.address`
- `vault_runtime.auth_mount`
- `vault_runtime.auth_role`
- `vault_runtime.jwt_audience`
- `vault_runtime.expected_spiffe_id`
- `vault_runtime.client_cert_file`
- `vault_runtime.client_key_file`
- `vault_runtime.client_ca_file`
- `vault_runtime.timeout_seconds`
- `security.bootstrap_issuer_common_name`
- `action_proof.secret_key`
- `action_proof.hash_function`

### Required external dependencies

- local policy file
- Vault runtime connection details and client TLS

### Minimal valid configuration

- `action_proof.hash_function` must be `sha256` or `sha512`
- `vault_runtime.expected_spiffe_id` must be a valid SPIFFE URI
- `policy.id_conf_path` must point to a valid policy file

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

- ACS
- ARS
- EGS
- AGS
- ES
- Nomad
- Docker

CGS remains implemented but is not required for the current ES admission or execution path.
