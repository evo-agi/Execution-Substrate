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

The Workstream E E0 ownership decision is recorded in
`.docs/system_overview/runtime_config_ownership.md`. Runtime-config semantics
live in the runtime-config contract surface; the current typed shared schema is
`internal/contracts/runtimeconfig/v1`.

ARS owns blob storage/read by digest only. ES is the current runtime-config
consumer and lookup orchestrator during prepare and submit. ES startup config
currently carries the required reference as compatibility/config residue on a
reopened ownership seam.

There is no ACS hop in the runtime-config path.

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
- the required typed runtime-config reference must be configured and validated
  before ES serves governed execution traffic; this is a reference-availability
  startup guarantee, not a startup blob-fetch guarantee
- the digest-only ref shape is active as a temporary compatibility edge and
  bounded current surface, not final runtime-config architecture
- optional `ca_bundle_pem` remains non-secret TLS trust material for standard
  TLS/env-based verification, not runtime-config authority or token truth
- runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff

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

## Runtime Identity Handoff

The Workstream F F0 ownership decision is recorded in
`.docs/system_overview/runtime_identity_handoff.md`.

Runtime identity handoff is currently ES-selected and platform-delivered. ES
owns handoff selection, env injection, reserved path layout, mounts, and Nomad
job construction for the current slice. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is
the bounded workload-visible discovery contract; it is not raw SPIRE socket
exposure, Vault token brokerage, runtime-config authority, or a secret payload.

The runtime supervisor/helper owns the in-task endpoint implementation,
helper-private SPIRE traversal, readiness-before-workload, and the
root-to-workload privilege boundary for the current implementation. SPIRE owns
JWT-SVID issuance. Vault owns token, secret, and lease issuance after
workload-side login.

Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces are
bounded or compatibility-heavy, not final generalized architecture. F0 does
not claim full ES/runtime de-root, rootless Nomad client, production
readiness, production Vault readiness, or generalized remote deployment
architecture.

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
- in bring-up, ARS runs as the operator's UID and primary GID; before starting ARS, `scripts/02_start_ars.sh` (and `scripts/01_bringup.sh up`, before any service) refuses unless `storage.root_dir` and `storage.index_file` are absolute and in normal form (ARS opens them exactly as written, while its mounts use the normal form), creates a missing storage root as the operator, refuses unless the index file exists as a regular file, not a symbolic link, and then does what ARS does with its storage in a short-lived container that runs exactly as ARS will: the same image, the same UID:GID with no supplementary groups, the same mounts, and ARS's container name, so Docker refuses the check while an ARS container still exists. In it, the check searches every directory on the way to the storage root and the index directory, creates and removes a file in the index directory and in every storage directory, finds its file again by listing each storage directory, reads the index and every stored file, refuses any symbolic link or special file below the storage root (ARS never creates one), and last rewrites the index the way ARS does (a new `0600` file with the same content, renamed over it), so the kernel decides each step for that identity. The check starts no process per directory and takes seconds even at ARS's full `sha256/xx/yy` fan-out of 65,794 directories, and `scripts/01_bringup.sh up` starts ARS's readiness wait only once ARS's launcher has passed its own run of the check
- `security.bootstrap_issuer_common_name` must name the legacy/bootstrap issuer that ARS rejects on both read and write paths
- `authorization.allowed_spiffe_path_prefixes` must allow ES and other intended readers
- ARS validates each allowed SPIFFE path prefix at startup with the same rule as AGS and ES (see the ES section below and `contracts.md` section 3A)
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
- AGS validates each allowed SPIFFE path prefix at startup with the same rule as ARS and ES (see the ES section below and `contracts.md` section 3A)
- signer key material must match the public key ES verifies and the signer key ID EGS allows
- the current repo-owned runbooks, proofs, and generated helper configs keep this allowlist operator-only, but the caller allowlist is now deployment-configured rather than hard-coded in AGS
- the first repo-owned non-operator caller activation path uses `service/control-plane`; prefer a narrow allowlist such as `["operator/local", "service/control-plane"]` over a broad `service/` prefix
- the current repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`
- the companion example templates for that path are `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- the default templates `ags.json` and `es.json`, plus the operator runbooks, remain operator-only by default
- the three Submit-enabled `.examples/config/es*.json` templates use a syntactically valid all-zero runtime-config digest only as an inert placeholder; replace it with the actual ARS blob digest, along with the retained-result auth placeholders, before real startup

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
- `publication.version` and `publication.update_revision` configure
  EGS-owned publication metadata. They are not trust-contract/schema/API
  versioning for the current EGS v1 surface.
- `publication` config remains outside the signed `runtime_trust` payload.
  D1c is design-only and docs/tests-only; it does not introduce EGS v2
  config, alter the signed runtime-trust payload shape, or change the current
  `GET /v1/trust-model` route/wrapper/payload compatibility surface.
- `GET /v1/trust-model` currently accepts only
  `spiffe://execution.internal/service/execution` and the narrow operator
  identity `spiffe://execution.internal/operator/local`; single-segment
  `spiffe://execution.internal/operator` is not an accepted EGS caller.

For a minimal active system, `runtime_trust.signer_policy.allowed_signers` must include the AGS signer key ID used for provenance.

## ES

### Required config groups

- `http`
- `tls`
- `security`
- `authorization`
- `dependencies`
- optional `admission_policy`
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
- `nomad.base_url`, `nomad.server_name`, `nomad.root_ca_file`, `nomad.server_spki_sha256`, `nomad.datacenter`, `nomad.timeout_seconds`, `nomad.token_file` when submit is enabled (see [Nomad HTTPS](#nomad-https))
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
- ES validates each allowed SPIFFE path prefix as a relative path prefix with
  at least two non-empty segments, no leading or trailing slash, and no `.`,
  `..`, or empty segment. Prefixes such as `service/control-plane` and
  `operator/local` are accepted; `service`, `operator`, `/`, `.`, `..`,
  `service//control-plane`, `service/./control-plane`, and
  `service/../control-plane` are rejected.
- Every segment must use only `A-Z`, `a-z`, `0-9`, `.`, `-`, and `_`, the
  SPIFFE ID path characters, so white space, a full
  `spiffe://execution.internal/...` ID, a query, or percent encoding is also
  rejected: no authenticated caller path could match such a prefix. ARS, AGS,
  and ES share this rule through `internal/callerallowlist`.
- ES authorization keeps exact-or-subpath matching after config validation:
  `service/control-plane` authorizes `service/control-plane` and
  `service/control-plane/provider`, but not `service/control-plane-evil`.
- `workload_vault_auth.default_mode` must be `vault_identity_jwt`
- `workload_vault_auth` no longer carries per-workload selectors in the current slice; ES consumes workload-zone vault runtime fields directly and applies only the configured default auth mode
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract
- optional `admission_policy.configured_static_script_literal_deny` is ES
  deployment/admin configuration for one built-in ES admission policy only
  - supported `mode` values are `disabled` and `enforce`
  - entries are bounded literal deny entries only; each entry has a safe `id`,
    `input_class`, and `literal`
  - `enforce` mode requires at least one entry; `disabled` mode does not
    enforce entries
  - the only supported `input_class` is `static_script_payload_text`
  - current validation limits are at most 32 entries, at most 256 bytes per
    literal, and at most 64 bytes per entry ID
  - entry IDs must be unique, start and end with an ASCII letter or digit, and
    contain only ASCII letters, digits, dot, underscore, or hyphen
  - literals must be non-empty, not whitespace-only, valid UTF-8 printable text
    and must not contain NUL, control, format/invisible, or other non-printable
    characters
  - regex-looking text is treated as literal text; there is no regex, glob,
    shell expression, Boolean policy language, OPA/Rego, DSL, customer policy
    bundle, external evaluator service, user-defined reason code,
    user-defined API message, request-supplied policy entry, CP-supplied policy
    input, or CGS `id.conf` reuse
  - configured literals and matched content must not be exposed through API
    responses, the producer contract, logs, retained bundles, support bundles,
    docs examples other than harmless placeholder markers, or test output
- `verification.derivation_attestation.*` and `verification.workload_identity_binding.*` remain required because the current ES startup path still constructs those verifier shapes
- those two verifier config groups are current configuration/startup-verifier residue, not active shared-kernel authorization meaning, not CGS policy truth, and not a settlement of Workstream E runtime-config ownership or Workstream F runtime-identity handoff
- `runtime_config.workload_zone_vault_config_ref.digest` must point at the current workload-zone Vault config blob in ARS
- if `nomad` and `execution` are omitted, ES can still support `:prepare` but not `:submit`
- the current repo-owned runbooks, proofs, and generated helper configs keep this allowlist operator-only, but the caller allowlist is now deployment-configured rather than hard-coded in ES
- the first repo-owned non-operator caller activation path uses `service/control-plane`; prefer a narrow allowlist such as `["operator/local", "service/control-plane"]` over a broad `service/` prefix
- the current repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`
- the companion example templates for that path are `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- the default templates `ags.json` and `es.json`, plus the operator runbooks, remain operator-only by default
- `.examples/config/es.configured_literal_policy_demo.json` is a separate
  non-default full ES config template for the harmless configured-literal
  prepare-denial demo. Its configured literal is a public inert replace-me
  placeholder; real filming/demo literals must be installed only in the actual
  ES runtime config selected by `$ES_CONFIG` for supported-local runs or
  `/etc/execution-substrate/es.json` on Remote Alpha/systemd hosts.
- for full end-to-end execution verification, include:
  - `nomad.base_url` (`https://<loopback IP>:<port>`)
  - `nomad.server_name`, `nomad.root_ca_file` and `nomad.server_spki_sha256`
  - `nomad.datacenter`
  - `nomad.token_file`
  - `execution.staging_root_dir`
  - `execution.results_root_dir`
  - `execution.retained_result_auth.store_id`, `key_id`, and `key_file`
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
  - submit-enabled startup creates missing directory components without
    following symlinks, reopens the configured root under descriptor custody,
    probes staging for exclusive run-root creation and actual no-follow refusal,
    and separately probes results for exclusive temporary creation and
    no-replace publication; failure is a startup error with no fallback
  - each new run root is created exclusively, held by parent/root descriptors,
    and never adopted or reopened from a pre-existing path
  - it backs run-scoped payload, run, and mount staging, and the same visible
    root remains retained on every post-claim return
  - failed, partial, ambiguous, accepted, terminal, canceled, lost, unknown,
    and result-publication outcomes all retain `<staging_root>/<run_id>`
  - ES does not quarantine, rename, scan, or recursively delete a run root;
    automatic whole-root reclamation is not implemented
  - it backs run-scoped payload, run, and mount staging while the workload may still depend on those bind mounts
  - in the isolated resolved-plan/custody candidate, every successfully claimed `<staging_root>/<run_id>` is retained, including materialization failure, ambiguous registration and terminal success; no whole-run-root reclamation authority exists yet
  - this interim rule increases disk use and sensitive-material residence; before environment-bound operational/rollout acceptance, accumulated-root/result/probe capacity and residence bounds must be selected and enforced with an explicit reclamation owner and authority or an enforceable bounded operating disposition; development-source acceptance selects none of these
  - for the selected supported-local `service-root-v1` profile only, canonical setup exclusively provisions the two fresh configured roots as UID:GID `0:0`, exact directory mode `0755`; this is a static root-service provision, not permission to widen the private `0750` per-run staging or result directories
  - prepare-only bring-up, ES launch, and full-profile submit-readiness share a read-only proof-binding, owner/mode, service-image/config, and exact same-path read-write mount check for that profile; the ordinary operator needs inspection access rather than write authority to those service-owned roots; generic no-profile readiness still checks caller writability and does not create missing roots
  - the bounded setup helper retains each initialized root's no-follow descriptor through a final visible pair check; it refuses name/identity drift without repair, while `mkdir` and later descriptor acquisition under the operator-owned proof parent do not establish an atomic creation identity against arbitrary concurrent interference
  - setup retains a fixed, path-free safe projection of that static root owner/mode check in proof evidence; the projection explicitly does not claim the future container's identity or behavioral capability
  - `/execution/run` remains a host-backed writable execution workspace and is not guaranteed non-sensitive
  - `/execution/staged` and caller-visible `/execution/mounts/...` remain host-backed copies of governed artifact content
  - ES does not semantically inspect payloads or mount contents for secrecy
  - a future infra manager may replace the current host-path backing with named volumes or other managed attachment semantics if it preserves the ES-local runtime contract inside the task
- `execution.results_root_dir` is a writable ES-owned retained-results root
  - it must be an absolute local filesystem path
  - it must be separate from `execution.staging_root_dir`; lexical separation
    is only an early non-mutating configuration check, not physical proof
  - staging and results are qualified together as one operation-local root
    set before startup provisioning, Submit claim, and every named result-side
    mutation; descriptor-held canonical objects and topology, not configured
    spelling, must prove that neither root aliases or contains the other
  - Linux uses complete `statx` identity including mount ID, no-follow
    canonical `/proc/self/fd` rewalk, and a bounded mount-ID-selected
    `/proc/self/mountinfo` record to compare source coordinates; Darwin uses
    `F_GETPATH`, descriptor identity, `fstatfs`, and bounded `getfsstat`, and
    rejects same-FSID distinct presentations as unprovable
  - Linux keeps complete valid `nsfs` namespace-object records in the bounded
    mount snapshot but classifies their source-grounded `kind:[decimal-inode]`
    roots as opaque, never as pathname coordinates; only canonical pathname
    roots are coordinate-eligible, and a descriptor-selected opaque root fails
    before effects rather than using its mountpoint or configured spelling
  - supported opaque namespace kinds are exactly `mnt`, `net`, `uts`, `ipc`,
    `pid`, `user`, `cgroup`, and `time`; malformed labels, child-view aliases,
    and other non-path root classes fail closed, and this record recognition
    does not support `nsfs` as an execution-root filesystem
  - ambiguous dual-missing roots under one deepest existing lookup object
    fail closed; startup creates at most one missing component per proof and
    requalifies before the next component or other effect
  - an existing retained bundle may still be served when staging or its run
    is absent; a read never provisions a missing results root, and topology
    refusal never falls through to Nomad
  - submit requires `execution.staging_root_dir` and `execution.results_root_dir` to resolve to the same target owner UID:GID; the retired Remote Alpha readiness and service-user helpers no longer inspect or certify that property
  - submit-enabled startup and retained-result operations qualify every path
    component without symlink traversal and keep the configured root plus the
    run-scoped result directory under descriptor-held identity custody
  - ES stores retained terminal result bundles under `<results_root>/<run_id>/result.tar.gz` by syncing a complete temporary object and publishing it with the existing platform no-replace rename primitive
  - when validated ownership-normalization evidence exists for a completed run, ES preserves it under `<results_root>/<run_id>/ownership-normalization.json`; this has no staging-mutation consequence
  - retained-result packaging and repeat reads fail closed on an existing final bundle whose owner, mode, link count, size, digest, identity, or stable path is wrong; an existing final bundle is never owner- or mode-reconciled in place
  - newly constructed unpublished result objects receive their governed modes; existing run directories, final bundles, and normalization evidence are validated without in-place metadata repair
  - retained bundles and retained staging are independent current surfaces
  - retained bundles are opaque to ES callers and are fetched through `GET /v1/executions/{run_id}/result`
  - this is a bounded current-slice terminal output contract, not a general runtime-output platform or Control Plane state store

The physical-separation implementation is candidate behavior until the
required running-deployment observation, repaired-helper mounted alias
fixtures, native linux/amd64 and linux/arm64 validation, and fresh independent
audit complete. Those gates were deferred until after local implementation;
they were not passed or waived.
- `execution.retained_result_auth` is a configured-Submit prerequisite for the isolated R1 candidate
  - `store_id` and `key_id` are stable non-secret 1–32 byte ASCII identifiers matching `[a-z][a-z0-9_-]{0,31}`
  - `key_file` is a clean absolute path with a non-root parent directory, outside the staging/results roots, to an externally provisioned regular file containing exactly 32 raw HMAC-SHA-256 key bytes; `/key` and `/` are outside the supported placement contract; no default, generator, fallback, reuse of an existing service key, or automatic rotation exists
  - exclusion compares the key path with the effective `Clean(TrimSpace(root))` staging/results roots; no-follow key lookup preserves every component of the canonical configured key path, including a space in a parent component
  - supported-local setup requires the two stable non-secret identifiers and the key-file reference through trusted operator inputs `SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID`, `SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID`, and `SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE`; the proof wrapper forwards these as guest-local metadata and never transfers a Mac key file
  - the key reference must be lexically outside the setup proof workspace and, through the wrapper, outside guest proof/bootstrap/repository and `/tmp/es-proof-*` cleanup scopes; this lexical check does not prove physical alias isolation or safety against a same-UID process
  - supported-local owned proof, bootstrap, repository, host collection and cleanup path scopes must be clean, single-leading-slash absolute non-root spellings; root, equality, and either ancestor/descendant overlap with the key reference fail closed before wrapper mutation or finalizer registration, while distinct sibling components remain distinct
  - the setup script dispatches a requested action once when run as a file or through the wrapper's `bash -s -- setup` stdin transport with explicit `EXECUTION_SUBSTRATE_REPO_ROOT`; sourcing it exposes production functions without dispatching setup
  - ES loads and privately owns the key once at configured-Submit service initialization. `BRINGUP_PROFILE=prepare-only` changes bring-up/readiness sequencing, not `Config.SubmitConfigured()`; this canonical setup retains Submit configuration, so key loading and execution-root capability qualification still run before ES listens. Only genuinely Submit-disabled service configuration avoids those startup prerequisites
  - the file and its parent are opened without symlink traversal and checked for owner/access/identity and stable 32-byte content; failure stops configured Submit without repair or key-path/value diagnostics
  - trusted operator inputs and generated ES configuration may carry only the identifiers and key-file reference; raw key bytes are forbidden from environment variables, argv, logs, generated proof assets, manifests and archives. Neither key bytes nor the key path enters workload environment, execution plan, captured material, Nomad, runtime mount, authority handoff or public diagnostic
  - static key-file checks and separate storage do not prove isolation from an arbitrary same-UID process or physical alias; actual deployment isolation/exposure, key loss and rotation remain environment-bound operational/rollout acceptance gates, not facts established or requirements removed by development-source acceptance; no recovery or rotation behavior is selected here
  - authenticated `result.commit.v1` is private result-byte eligibility evidence, not execution success, lifecycle truth, caller authorization or reliable-submit state; legacy unmarked finals stay unavailable
- The bounded private codec-3 synthetic replay fixture injects a separate
  32-byte PB1 binding key and a separate 32-byte envelope key in tests only.
  They are not retained-result authentication keys and are not read from or
  added to ES configuration, startup, environment, argv or production files.
  Future operator-provisioned key custody and state-path configuration need a
  separately governed decision; this private source does not enable runtime.
- the isolated candidate qualifies staging and results roots as one normalized
  pair from one configuration snapshot: absolute, component-wise no-symlink,
  distinct non-overlapping backing objects with a matching owner model
- configured-submit startup proves required local root and no-replace capabilities
  by behavior; failure stops startup without fallback
- a Submit-disabled service does not create run staging; a prepare-only bring-up profile does not itself disable Submit in the generated ES configuration

- the runtime identity contract no longer requires ES-local identity plumbing configuration
- ES currently backs the injected runtime identity endpoint with a memory-backed tmpfs workspace under a run-scoped subtree rooted at `/run/es-runtime-identity/`
  - this backing workspace is not persisted to host staging
  - `execution.runtime_identity_tmpfs_size` controls that ES-owned backing workspace and defaults to `1048576` bytes (`1 MiB`); it must not exceed `8388608` bytes (`8 MiB`)
- slice `1A` and `1B` additionally require:
  - `execution.runtime_support_binary`: absolute path to the platform-owned runtime supervisor/helper binary staged into the workload task
  - `execution.spire_workload_api_socket_path`: absolute path to the local SPIRE Workload API Unix socket source that ES records and later bind-mounts into the helper-private runtime path
  - the runtime-support source must be a stable, no-follow, single-link regular
    file of at most 32 MiB at startup validation and submit capture
  - normalized workload-zone Vault CA and selected system CA inputs are each
    limited to 256 KiB; the combined workload TLS bundle is limited to 524,289
    bytes. These are explicit compatibility/security bounds and add no config
    fields.
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
  - operator bring-up and submit-readiness must still validate that the configured host SPIRE socket path exists as a local Unix socket before claiming submit-ready; the retired Remote Alpha service-user route makes no apply-ready claim
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
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains bounded workload-visible
  discovery only. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- runtime-config refs, `authority_handoff.runtime_config_refs`, ARS blob
  storage/read mechanics, digest-only runtime-config refs, and
  `workload_vault_auth.default_mode` remain Workstream E surfaces or config
  residue; they are not runtime-identity or credential authority.
- ES `/health` does not include Nomad readiness in the current slice; Nomad availability is verified separately during bring-up and submit/lifecycle checks
- The primary bring-up/check path distinguishes:
  - service health: ARS, EGS, AGS, and ES public health surfaces
  - prepare-ready: service health plus successful workload-zone Vault runtime-config blob verification through ARS, including structural validation of any supplied Vault CA bundle
  - submit-ready: prepare-ready plus ES submit config present (including a `nomad.token_file` that is a regular 0400/0600 file), Nomad presenting the pinned certificate over TLS 1.3 with at least 14 days of validity left, Docker available, required enabled runtime-profile images present, Nomad leader present, Nomad enforcing ACLs with no anonymous policy (read with the observer token named by `NOMAD_TOKEN_FILE`), and at least one ready Nomad client node that exposes positive `cpu.totalcompute`, a healthy Docker driver and a host-mode network

Minimal vault-auth example:

```json
{
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt"
  }
}
```

### Retired Remote Alpha existing-host ES helpers

The Remote Alpha ES writable-state readiness, readiness staging, ES service-user
migration, ownership preparation, rollback-generation, and old-root planning
implementations are retired. Their public wrappers remain compatibility
delegators to fixed exit-2 tombstones that emit only the prescribed two-line
stderr notice and create no artifact. No check-only, apply, discovery,
inspection, staging, backup, JSON, Markdown, or migration simulation remains.

Archived v1 files remain historical evidence only. No live operator route
parses or projects the retired readiness, staging, or ES service-user schemas,
and they do not establish current host state or authorize deployment,
readiness, migration, drain, reclamation, or mutation. No v2 replacement
exists for that retired ES writable-state/service-user migration family. The
unrelated current EGS hardening v2 schema and current Vault service-user family
remain outside this retirement. Future infrastructure recovery requires a
separately selected fresh-host setup contract, but a
complete supported fresh-host ES provisioner is not currently implemented.
Reuse of an old or nonempty host remains blocked without a separately governed
existing-host migration contract. One such contract exists, for one host:
`scripts/remote_alpha_upgrade_es.sh` moves the Remote Alpha box's ES to one
named commit with Nomad's gossip encrypted. From the `16cbf739` build that ES
PR #54's upgrade installed, it issues Nomad's TLS material, puts Nomad's API
and RPC behind TLS 1.3, adds the Nomad TLS keys to its `es.json` and gives
Nomad a gossip keyring. From a later build with Nomad already on HTTPS, it
leaves the TLS material, `nomad.hcl` and `es.json` as they are and gives
Nomad a gossip keyring if it has none. It moves ES only forward along the
clone's history, unless root names a move that is not forward on the
command line (`--allow-downgrade <installed>..<commit>`), which it records;
`rollback` puts back only the backup of the apply that left the installed
ES builds as they are, and records that too.
On a box it already moved it only verifies; it refuses any other host shape
and names what each part looks like; see `.docs/system_overview/remote_supported_host_alpha.md`,
section "Remote ES Upgrade And Nomad HTTPS".

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
- that checked-in file and `policy.id_conf_path` are current-CGS-v1 compatibility/config residue for the current authorize surface
  - they are not documented as transport/schema/API versioning or final repo-wide policy language
  - D1b does not rewrite the current `id.conf` grammar or evaluation and does not promote `id.conf` into repo-wide future policy language
- `policy.id_conf_path` remains a CGS-local current-v1 configuration pointer
  only. It is not a repo-wide policy registry, runtime-config owner surface,
  or runtime-identity handoff input.
- the current `id.conf` grammar and checked-in baseline remain local to
  current CGS v1 evaluation only
  - they are not ES admission policy truth
  - they are not EGS trust truth
  - they are not Control Plane review/approval/checkpoint/finalization policy truth
  - they are not Infrastructure Manager readiness/profile/support-bundle authority truth
  - D1d does not move `id.conf` into Workstream E runtime-config ownership or Workstream F runtime-identity handoff
- the current `id.conf` grammar uses explicit `subject` records with:
  - `type`
  - `principal`
  - `role`

CGS is not required for the current ES hot path and is not part of the minimal governed execution bring-up runbook.

## Nomad And Docker

These are not configured through the Go service config files, but they are required for the current bounded execution slice.

### Nomad requirements

The current host-qualification boundary for the supported Linux environment is defined in [supported_linux_host_qualification.md](supported_linux_host_qualification.md).

- reachable over HTTPS (TLS 1.3 only) at `es.nomad.base_url`, presenting the certificate ES pins; see [Nomad HTTPS](#nomad-https) below
- configured for the target datacenter in `es.nomad.datacenter`
- Docker driver available, and the only driver the client enables: `client.options["driver.allowlist"] = "docker"` (every ES task runs through its runtime helper on the Docker driver)
- an explicit `plugin "docker"` block that refuses privileged containers (`allow_privileged = false`) and allows only the capabilities ES's runtime helper uses to prepare a run and drop to the workload user: `allow_caps = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]` (each one is needed: removing any one fails the real Nomad and Docker submit tests)
- bind mounts enabled in that block through `volumes { enabled = true }`
- when enabled local runtime-profile images are part of the supported-local proof/runtime surface, Nomad Docker image garbage collection disabled in that block through `gc { image = false }` so Nomad does not remove the configured local profile image after a stopped allocation (the supported config no longer writes the older `client.options` keys `docker.cleanup.image` and `docker.volumes.enabled`, and readiness reads the plugin block instead, which Nomad 2.1 reports as an object and Nomad 2.0 as a list holding one object; both are accepted)
- Nomad's configuration directory and its data directory (Raft state and keyring) owned by root (`/etc/nomad.d` 0755 with `nomad.hcl` root:root 0640, data directory 0700), because Nomad runs as root
- readiness (`scripts/10_health_check.sh`, bring-up and supported-local setup) refuses a Nomad whose agent does not report the Docker-only allowlist, `allow_privileged = false` and capabilities within the list above (`nomad: drivers=docker docker_privileged=refused docker_caps=...`)
- explicit local data directory for repeatable manual bring-up
- when the current slice-0 single-node topology binds Nomad to `127.0.0.1`, the Nomad config must also set explicit loopback `advertise` addresses for `http`, `rpc`, and `serf`
- the client's host network pinned to loopback: `client { network_interface = "lo" }` (`scripts/70_linux_setup.sh` and `.examples/config/nomad.hcl` write it). ES's jobs (Docker with `network_mode` `none`, or `bridge` when the execution has network access, no Nomad network block, no ports) can be placed only on a node with a host-mode network, which Nomad takes from the interface `network_interface` names, or from the default route's interface when it names none. Loopback exists whether the host is on Wi-Fi or a cable, so the supported setup works on either and assumes neither: pinned to a wired port, the node has no host network while the cable is out and every plan fails with `missing network`; unpinned, Nomad does not start while there is no default route (Wi-Fi not up yet). Readiness refuses a node without a host-mode network (`<node>=no-host-network`), and `sudo scripts/nomad_acl_setup.sh placement`, run after every Nomad start, plans ES's job shapes with ES's token (see [Nomad access control](#nomad-access-control))
- for the supported Linux environment story in this slice, Nomad should already be running as a pre-managed non-dev service on the host/VM before `scripts/01_bringup.sh up`; the local script-managed Nomad startup path remains bounded fallback/troubleshooting scaffolding
- the operator readiness path now inspects `GET /v1/agent/self` and rejects `config.DevMode=true`; `nomad agent -dev` is unsupported for the slice-0 supported-environment claim even if it reports healthy Docker and positive compute
- when Nomad uses the Docker driver on Linux, HashiCorp's Docker driver guidance treats root-managed Nomad as the compatible mode for CPU-core / NUMA-aware behavior; user-managed Nomad startup may still be useful for bounded proof and troubleshooting, but it is not the supported-environment baseline
- access control (ACLs) enabled with `acl { enabled = true }` and bootstrapped, with no anonymous policy; see [Nomad access control](#nomad-access-control) below
- readiness also refuses a Nomad whose agent does not serve HTTP and RPC over TLS 1.3 with server names verified (`tls=1.3` on the posture line)
- gossip encrypted: without a gossip key, Nomad's serf port accepts any process that reaches it as a peer, so a local account could start its own Nomad server and join this one as a member and a raft non-voter. `scripts/70_linux_setup.sh` writes a keyring holding one random 32-byte key to `<data_dir>/server/serf.keyring` (`/opt/nomad/data/server/serf.keyring`, root, 0600) before Nomad starts. Nomad reads that keyring when it starts, so `nomad.hcl` names no key and the keyring is the key's only copy. Later runs keep a sound keyring (a regular file of root's, 0600, holding a JSON list of base64 32-byte keys). Otherwise they write a new one and restart Nomad: a single server has no peer that needs the old key. Readiness and the setup's qualification refuse an agent whose `/v1/agent/self` does not report `stats.serf.encrypted` as `"true"` (`gossip=encrypted` on the posture line). Remote Supported-Host Alpha's box does not run this setup: its upgrade (`scripts/remote_alpha_upgrade_es.sh`) writes the keyring with the setup's `nomad_gossip_issue` and rolls back unless Nomad then reports its gossip encrypted; until that upgrade has run there, the box's gossip stays unencrypted
- if a Linux proof host exposes `cpu.totalcompute=0` because Nomad CPU fingerprinting fails, the bounded slice-0 operator path can provide `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` as a temporary client override for that host; this is deployment troubleshooting, not a new cross-service contract
  - when this override is active, the operator path must surface that host as `submit-ready-mode: bounded-override (...)` rather than implying natural schedulability
  - if the override is absent and the host remains at `cpu.totalcompute=0`, the current bring-up path now fails explicitly instead of claiming submit-ready

### Nomad HTTPS

ES, the operator scripts and the nomad CLI reach Nomad only over TLS 1.3, and
ES sends its token only to the Nomad whose server key it pins.

- **Nomad config**: a `tls` block with `http = true`, `rpc = true`,
  `tls_min_version = "tls13"`, `verify_server_hostname = true` and
  `verify_https_client = false` (clients authenticate with ACL tokens, not
  certificates), naming `ca_file`, `cert_file` and `key_file` in
  `/etc/nomad.d/tls`. `scripts/70_linux_setup.sh` writes it, and
  `.examples/config/nomad.hcl` shows it.
- **Certificate**: `scripts/70_linux_setup.sh` issues it into
  `/etc/nomad.d/tls` (root-owned, 0755): `ca.pem` and `server.pem` 0644,
  `server-key.pem` 0600. Keys are ECDSA P-256. The server certificate names
  `server.global.nomad`, `localhost`, `127.0.0.1` and `::1`, is valid for 825
  days, and is signed by a CA (path length 0) whose key is deleted right
  after signing, so no other certificate can chain to `ca.pem`. Later runs
  keep sound material with at least 30 days left; otherwise they issue a new
  CA, key and certificate, restart Nomad and print the new pin.
- **ES config**: `nomad.base_url` is `https://<loopback IP>:<port>` (an IP
  literal, no user, path, query or fragment); `nomad.server_name` is the DNS
  name in the certificate (`server.global.nomad`); `nomad.root_ca_file` is
  the absolute path of `ca.pem`; `nomad.server_spki_sha256` is the lowercase
  hex SHA-256 of the server certificate's SubjectPublicKeyInfo. At startup ES
  reads the CA file (a regular file of at most 1 MiB holding only PEM
  certificates). On every connection it requires TLS 1.3, verifies the chain
  against that CA alone for `nomad.server_name`, and then requires the pinned
  key: any other certificate, even one the same CA signed, fails the
  handshake before ES sends its token, and submit refuses with `503
  execution_runtime_unavailable` ("execution runtime is unavailable"),
  creating no run. The setup script prints all four
  values; `python3 scripts/internal/nomad_tls_identity.py pin
  https://127.0.0.1:4646 /etc/nomad.d/tls/ca.pem server.global.nomad` prints
  the pin of the running Nomad.
- **Scripts**: `NOMAD_ADDR=https://127.0.0.1:4646` and
  `NOMAD_CACERT=/etc/nomad.d/tls/ca.pem`. The shell helpers and the Python
  tools refuse an address that is not `https://` and a CA file that is
  missing or a symbolic link, require TLS 1.3, and trust only that CA (no
  system CAs), with no proxy and no redirects. The nomad CLI reads the same
  two variables.
- **Readiness**: submit readiness runs `nomad_tls_identity.py check` once
  Nomad is ready. It makes ES's own checks against the running Nomad (TLS
  1.3, CA, name, pin), sends no request, requires `nomad.base_url` to be
  `NOMAD_ADDR`, and refuses a certificate with fewer than 14 days left
  (`nomad tls: tls=1.3 server_name=... key=pinned expires=...
  days_left=...`).
- **After a new certificate**: set `nomad.server_spki_sha256` to the new pin
  and restart ES. `scripts/72_supported_local_setup.sh` observes the pin from
  the running Nomad (after its certificate verified under
  `SUPPORTED_LOCAL_NOMAD_CACERT`) and writes it into `es.json`.

### Nomad access control

Without ACLs any local process that reaches Nomad's API can register a job and
bypass ES admission. ES therefore submits only to a Nomad that enforces them.

- **Nomad config**: `acl { enabled = true }`. `scripts/70_linux_setup.sh`
  writes it into the managed `/etc/nomad.d/nomad.hcl`, restarts Nomad when
  the config changed, and bootstraps the ACL system.
- **Management token**: Nomad's bootstrap token. `scripts/70_linux_setup.sh`
  generates its secret, writes it root-only (0600) to
  `/etc/execution-substrate/nomad-acl/management-token` before the bootstrap
  call, and reuses it on later runs. It bootstraps only once Nomad names a
  leader. If a bootstrap never took effect (no leader yet, a lost
  response), a rerun of either script offers the saved secret again; Nomad
  accepts it only while its ACLs are not bootstrapped. Only that script and
  `scripts/nomad_acl_setup.sh` (as root) read it. It is never given to ES or
  to an operator check. If Nomad is already bootstrapped and the file is
  lost or holds another token, both scripts refuse and leave an existing
  file as it is; recovery is Nomad's ACL bootstrap reset procedure, done by
  hand.
- **Port holder guard (second guard)**: while Nomad is down, any local
  account can listen on its port. HTTPS stops such a holder from passing
  for Nomad: it has no certificate from Nomad's CA and cannot read Nomad's
  server key, and ES also pins that key. As a second guard, before the
  setup script and the ACL tool send a token or a bootstrap secret, they
  check in the kernel's TCP tables that the socket belongs to Nomad's user:
  root for `nomad.service`; `NOMAD_USER` for `scripts/nomad_acl_setup.sh`,
  `SUPPORTED_LOCAL_NOMAD_USER` for supported-local setup, and the current
  user for full-profile bring-up, which starts Nomad itself. Otherwise they
  send nothing. The tool checks the socket that accepted its own
  connection, before the TLS handshake. The setup script checks the
  listener just before each request or batch of requests, which leaves a
  short window for a restart in between, and TLS covers that window.
  `provision` also waits up to 30 s for Nomad to name a leader before it
  bootstraps. ES's own requests and the observer token's readiness requests
  rely on TLS (and, for ES, the pin) alone.
- **ES token** (`nomad.token_file`): a client token with only policy
  `es-submit-v1` (`submit-job`, `read-job`, `read-logs` in namespace
  `es-submit-v1`). It cannot read nodes or the agent, write policies or
  tokens, or act in any other namespace. ES reads the file once at startup,
  before it provisions any execution root, and refuses to start unless it is
  a regular file (not a symbolic link, one hard link) owned by ES's user,
  mode 0400 or 0600, in a directory owned by ES's user or root that is not
  group- or world-writable, holding one canonical lower-case Nomad token with
  an optional trailing newline. The file must lie outside ES's staging and
  results roots and outside the directory of
  `execution.spire_workload_api_socket_path` (workloads mount those), and must
  differ from the retained-result key file. No error names the path or the
  token. ES sends the token only in the `X-Nomad-Token` header, uses no proxy
  for Nomad and follows no redirect from it. A test fails the build if any
  Go code names a Nomad API path outside the request builder that sets the
  token.
- **Per-submit check**: before every submit ES confirms that its token is a
  client token, that ACLs are enabled and that no anonymous policy exists;
  otherwise it refuses with `503 execution_runtime_unavailable` ("execution
  runtime access control check failed").
- **Observer token**: a read-only client token (policy `es-observer-v1`:
  agent and node read, `list-jobs`, `read-job` and `read-logs` in
  `es-submit-v1`) for readiness and evidence checks. It can list and inspect
  ES's jobs and read their logs, and cannot submit, plan, stop or scale
  them. `check` requires these exact rules, so on a host provisioned before
  `list-jobs` was added, `check` refuses until `provision` runs again and
  rewrites the policy (the tokens are kept). Operator scripts read it from the file named
  by `NOMAD_TOKEN_FILE` and pass it to curl through a configuration on a file
  descriptor, to Python by file, and to the nomad CLI through its
  environment, never on a command line. The observer token cannot submit.
- **Provisioning**: `sudo scripts/nomad_acl_setup.sh` creates the namespace,
  both policies and both token files in
  `/etc/execution-substrate/nomad-acl/` (`es-token` 0400 owned by `ES_USER`,
  default root; `observer-token` 0400 owned by `OBSERVER_USER`, default the
  sudo caller), then runs the lock check. It is idempotent: a working token
  is kept. `check` verifies the lock (an anonymous plan in `es-submit-v1`,
  ES's token in `default` or on `/v1/nodes`, and the observer token planning
  are all refused; ES's token can plan in `es-submit-v1`; the ES and
  observer tokens are client tokens with only their own policy and no roles;
  the ES and observer policies have exactly the tool's rules and no job ACL,
  which would give their capabilities to the workloads of the job it names),
  and `rotate` issues new
  ES and observer tokens and deletes the old ones. Only ES may submit or
  change jobs in `es-submit-v1`, and only the read-only observer may read
  them: the tool asks Nomad itself, by issuing a short-lived (5 minute) probe
  token for each other policy and for each role, and with it reading the
  `es-submit-v1` namespace (Nomad allows that for any job capability there, so
  `scale-job`, `dispatch-job`, `alloc-lifecycle`, `alloc-exec` and
  `read-job` grants all count) and planning a job there; any answer other
  than 403 to either counts as a grant and is refused. So every policy
  syntax (HCL, JSON, escaped names, namespace globs) and every role is
  covered, and a glob grant shadowed by a `deny` on `es-submit-v1` passes.
  Variables capabilities are not job capabilities and are not judged; ES's
  jobs read no Nomad variables. The observer policy is exempt only while its
  rules are exactly the tool's and it has no job ACL.
  It also refuses when any ACL auth method exists (its binding rules could
  issue tokens), when a live management token other than the one in the
  management token file exists (every management token can submit
  anywhere), when a live token other than the ES or observer token holds
  their policy, when an anonymous policy exists, or when ACLs are off.
  Provision writes the two policies before these probes, so a widened copy
  is restored and a job ACL cleared, replaces an ES or observer token that
  has a role, and deletes other tokens with ES's or the observer's policy.
  `scripts/nomad_acl_setup.sh check` runs all of this with the management
  token; that part writes to Nomad (it creates and deletes the probe
  tokens). `nomad_acl.py check` without `--management-token-file` checks
  only what ES's and the observer's tokens can do and their policies' rules.
  Grants outside namespaces stay operator power the check does not judge:
  for example `node` write can drain the node and so stop ES's allocations.
  The tool behind it is `scripts/internal/nomad_acl.py`; it talks only to a
  loopback Nomad HTTPS address over TLS 1.3, trusting only the CA given by
  `--ca-file` (`NOMAD_CACERT` in the wrapper), with no proxy and no
  redirects.
- **Placement check**: `sudo scripts/nomad_acl_setup.sh placement` proves
  what no ACL check sees: that Nomad can place ES's jobs. With the observer
  token it waits (`NOMAD_PLACEMENT_WAIT_SECONDS`, default 60) for a ready,
  eligible client node with a healthy Docker driver and a host-mode
  network. With `NOMAD_STARTED_AT`, the Unix time just before the latest
  Nomad start, a node counts only once the restarted client registered
  again, because for about half a minute after a restart the servers can
  serve the node as it was before. With ES's token it then plans each job
  shape ES submits (Docker, `network_mode` `none` and `bridge`, no network
  block, no ports) in `es-submit-v1` and in the datacenter that
  `nomad.datacenter` names in ES's config (`ES_CONFIG`, default
  `/etc/execution-substrate/es.json`); each plan must place its one
  allocation. A plan registers nothing, and the check never uses the
  management token. Like `check` and `rotate`, it needs the `ES_USER` and
  `OBSERVER_USER` that provisioned the tokens, because it refuses token
  files owned by anyone else. The Remote Alpha upgrade script runs it after
  it restarts Nomad.
- **Rotation needs an ES restart**: ES reads its token only at startup, and a
  container bind mount keeps the old file, so restart ES after `rotate`.
- **Bring-up and proof paths**: `BRINGUP_PROFILE=full scripts/01_bringup.sh
  up` starts its own Nomad with ACLs, provisions it before ES starts (ES needs
  its token at startup), and exports the observer token for its checks.
  `scripts/72_supported_local_setup.sh` refuses before any effect unless the
  host's Nomad presents a certificate from `SUPPORTED_LOCAL_NOMAD_CACERT`
  (default `/etc/nomad.d/tls/ca.pem`) and enforces ACLs, then runs
  `scripts/nomad_acl_setup.sh` through `sudo -n` (ES token owned by root,
  because ES runs as root in the `service-root-v1` profile), writes
  `nomad.token_file` and Nomad's HTTPS identity (server name, CA file and the
  observed pin) into `es.json`, and exports `NOMAD_TOKEN_FILE` and
  `NOMAD_CACERT` in `env.sh`. The directory is
  `SUPPORTED_LOCAL_NOMAD_ACL_DIR`, which must lie outside the proof, staging,
  results and SPIRE socket directories. `SUPPORTED_LOCAL_NOMAD_PORT` (default
  4646) names the loopback port of the host's Nomad.

Known limits of this lock:

- A local process that binds `127.0.0.1:4646` while Nomad is down gets no
  token: without Nomad's server key it cannot complete a handshake ES or the
  scripts accept. Root can read that key, and root is trusted on the host.
- The lock governs Nomad's API, not Docker. Root and members of the `docker`
  group can start containers directly and are outside it.
- ES's submit token still controls job shape within the Docker limits. The
  supported Nomad refuses only privileged containers, capabilities beyond the
  seven above, and drivers other than Docker. Checked on Nomad 2.1.1 and
  2.0.0, it still runs, for any holder of ES's token (audit INF-02):
  - bind mounts of host paths, `/` included, with the task user `0:0`;
  - `network_mode = "host"` (the container shares the host's network,
    including loopback services such as Nomad's API);
  - `devices` (host device nodes mapped into the container);
  - `security_opt`, for example `seccomp=unconfined`;
  - on Nomad 2.0.0 only, `pid_mode = "host"`, `ipc_mode = "host"` (the
    container joins the host IPC namespace) and `userns_mode = "host"`
    (Nomad 2.1.1 refuses all three).

  Nomad's Docker plugin has no setting that refuses these options. ES's own
  admission decides job shape; a stricter design for job shape and the task
  user is tracked separately.

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
- `CONTROL_PLANE_DOCKERFILE` remains an explicit operator override, but the default bring-up Dockerfile authority is `scripts/generate_control_plane_dockerfile.sh`; `.out/Dockerfile` is its checked-in generated projection and build input
- `.out/` is the current repo-local generated-artifact area: `.out/Dockerfile` remains the tracked control-plane image projection, kept integration harness workspaces such as `es-submit-*` are created under `.out/`, and the canonical supported-local proof workspaces on this Mac now live under `.out/es-proof-<id>/`; those host proof workspaces are preserved evidence, not transient scratch
- top-level `scripts/*.sh` remain the operator-facing entrypoints and manual fallback commands; `scripts/internal/*.sh` is the sourced-only helper layer behind those entrypoints
- Docker host networking in that path is temporary slice-0 compatibility scaffolding, not the final control-plane network model
- use an operator SPIFFE client cert/key for AGS and ES operator-facing helpers:
  - `CA_CERT`
  - `OPERATOR_CERT`
  - `OPERATOR_KEY`
  - the current repo-owned examples, proofs, and bring-up configs keep `authorization.allowed_spiffe_path_prefixes=["operator/local"]` for AGS and ES, even though caller authorization is now deployment-configured rather than hard-coded in those services

The current unified health check verifies:

- ARS, EGS, AGS, and ES all report `ready=true`
- those health checks succeeded with a real client certificate at the TLS boundary
- Nomad has a leader and at least one ready node with positive `cpu.totalcompute`, a healthy Docker driver and a host-mode network when `BRINGUP_PROFILE=full`
- `docker info` succeeds when `BRINGUP_PROFILE=full`
- any enabled `control-plane-normal-shell/v1` runtime-profile image is present according to `docker image inspect` in the Docker daemon used by Nomad when `BRINGUP_PROFILE=full`
- when an enabled runtime-profile image is present, the Nomad Docker plugin reports `gc.image = false`, so Nomad will not remove that local image after stopped tasks as part of the supported-local runtime surface
- Nomad enables only the Docker driver and its Docker plugin refuses privileged containers and allows only ES's runtime-helper capabilities
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
and on any current rerun must preserve the current ARS `ars:ars`, EGS
`egs:egs`, and ES `User=es`, `Group=es`, `UMask=0027` service postures.

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
not change the SPIRE selector model, and on any current rerun must preserve
the current EGS `egs:egs` and ES `User=es`, `Group=es`, `UMask=0027`
service postures.

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

For the landed EGS de-root step within that same current tranche, the active
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
change the SPIRE selector model, and on any current rerun must preserve the
current ES `User=es`, `Group=es`, `UMask=0027` posture.

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

Remote Supported-Host Alpha retains unrelated config/TLS helper history as a
bounded support surface. It does not reactivate the retired ES writable-state
or service-user routes.

`Bounded slice rule`: this slice prepares only ES-readable config/TLS
ownership for a later non-root ES step.

Archived v1 evidence recorded the following earlier host state:

- ES config/TLS prep is applied.
- ES stable writable-state roots are prepared.
- the observed long-lived `es.service` ran as `User=es`,
  `Group=es`, `UMask=0027`.
- post-apply `/health`, `GET /v1/executions:contract`, the retained-result
  fetch/materialization flow, and the current lowest-cost existing happy path
  all passed.
- the then-current writable-state check passed.
- this does not claim full ES/runtime de-root.
- the root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad selector posture, and Vault/workload-zone handoff
  remain bounded compatibility edges.
- old root-era staging/results roots remain preserved as rollback/debug/evidence
  state in that historical record.

Those facts are not current host truth or authority. The v1 readiness,
service-user, ownership, rollback, staging, and cleanup-planning producers are
retired and cannot refresh them. An old or nonempty host remains blocked without
a separately governed migration contract.

The config/TLS, binary-deployment, and writable-state subsections below still
describe earlier bounded slices whose own apply summaries intentionally record
`root(default)` at those earlier steps. All such wording is historical artifact
context and must not be read as current service posture or apply authority.

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

`Current invariant`: binary-parity refresh must preserve the accepted live
`es.service` identity for the current host slice and must not change
`User=`, `Group=`, or `UMask=` while only the binaries at the accepted live
paths are updated to a repo-built linux/amd64 snapshot.

`Historical bounded evidence`: the earlier live-host-evidenced apply for this
slice happened before the later bounded service-user migration, so those
earlier apply summaries honestly record `root(default)` at that step. Current
post-migration reruns must instead preserve the accepted `User=es`,
`Group=es`, `UMask=0027` posture and must not treat that accepted service
identity as drift.

`Current invariant`: this helper no longer accepts a root-like live
`es.service` identity. If operators ever need to return to a root-era service
posture, that must happen through a separate rollback/service-user surface
rather than through binary deployment.

This slice must:

- build or locate the repo-owned linux/amd64 `es` and `es-runtime-support`
  artifacts through the established repo build path only
- compare those local artifact hashes and sizes to the live host binaries
- treat a live hash mismatch as `deployment_needed`, not as a host failure by
  itself
- preserve the accepted live `es.service` identity for the current host slice
  through the binary refresh
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
a pre-mutation backup, restart `es.service` at most once, preserve the
accepted live `es.service` identity for the current host slice, and validate
`/health` plus `GET /v1/executions:contract` afterward. Historical earlier
apply evidence may still show `root(default)` because that slice ran before
service-user migration; current post-migration apply evidence must preserve
`User=es`, `Group=es`, `UMask=0027` instead of treating it as drift. This is
a bounded binary deployment record only; it is not governed proof, not
writable-state evidence, and not service-user migration evidence.

Check-only and apply summaries for the current helper should expose
`plan.service_identity_matches_current_supported_posture=true` when the live
service remains `User=es`, `Group=es`. Root-like service identity must block
the helper instead of being treated as an accepted posture.

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

The former Remote Alpha ES stable writable-state ownership slice is retired.
Its wrapper delegates to a fixed tombstone and performs no inspection, Nomad
classification, rotation, ownership change, staging, backup, or evidence
production. Historical v1 ownership files may remain archived but cannot
authorize current readiness, migration, drain, reclamation, or mutation. No
replacement v2 schema or current existing-host ownership contract exists for
that retired ES family. The unrelated current EGS hardening v2 schema is not
part of this statement.

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

For the separate Remote Supported-Host Alpha host-local Vault service-user
migration slice, the repo-owned public wrapper is
`scripts/remote_alpha_migrate_vault_service_user.sh`, with sourced
implementation `scripts/internal/remote_alpha_migrate_vault_service_user.sh`.
Default behavior is `check_only`, non-mutating, and writes
`execution-substrate.remote-alpha.vault-service-user-migration-summary.v1` to
`/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-check-only.json`
unless the operator overrides the summary path. The bounded apply path requires
explicit `--apply`, requires a successful check-ready preflight artifact or
equivalent rerun of the same checks, writes
`/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-apply-summary.json`
by default, creates backup plus rollback evidence before any mutation, applies
only the minimum Vault service-account or drop-in or path-owner changes needed
for Vault, and then runs honest post-apply Vault `/v1/sys/health` or
equivalent local health, ES `/health`, and ES `GET /v1/executions:contract`
checks. Lowest-cost governed execution smoke must run only when the operator
supplies the documented smoke profile plus command; otherwise the apply summary
must record that smoke as `skipped`, not passed. This helper must preserve
workload-side Vault JWT login through `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, must
keep `es_vault_token_brokerage=false`, must fail closed if its summary would
persist Vault tokens, root tokens, unseal keys, JWT-SVIDs, PEM private keys,
API keys, Codex credentials, or raw secret payloads, and must keep explicit
non-claims as labels such as `not_vault_production_ready`,
`not_governed_execution_proof`, `not_full_es_runtime_deroot`,
`not_full_nomad_client_deroot`, and `not_spire_redesign`.

For the separate Milestone 1 runtime/security boundary posture surface, the
repo-owned host-local checker is
`scripts/remote_alpha_runtime_security_boundary_check.sh`, with sourced
implementation
`scripts/internal/remote_alpha_runtime_security_boundary_check.sh`. Default
behavior is `check_only`, non-mutating, and writes
`execution-substrate.remote-alpha.runtime-security-boundary-check.v1` to stdout
or to a caller-selected artifact path such as
`runtime-security-boundary-check.json`. That checker must not SSH by default,
mutate services, change ownership, restart services, archive files, or delete
anything. It must classify the current Nomad server/client posture, the
accepted MVP Nomad-client root dependency, the current Nomad task
`User: "0:0"` edge, the root-start runtime helper/supervisor posture, the
helper-private raw SPIRE traversal boundary, the broad root selector posture,
the workload-visible `EXEC_WORKLOAD_IDENTITY_ENDPOINT` contract, Vault service
account posture, Vault root/unseal/client-token leakage checks, the
workload-zone handoff posture, the no-ES-Vault-token-brokerage rule, and the
non-authority status of support/evidence artifacts. It may also emit
non-secret host/runtime/CVE inventory evidence, including kernel, OS release,
package versions, service users, Docker/Nomad runtime chain observations,
Docker storage-driver observation status, FUSE/fuse-overlayfs/rootless
storage observation status, Podman/crun/idmapped or `mount_setattr` path
observation status, and evidence-only CVE-2026-31431 and CVE-2026-31465
classifications of `fixed`, `vulnerable`, `not_affected`,
`mitigated_not_fixed`, or `unknown`. CVE-2026-31431 may be classified as
`mitigated_not_fixed` only when vendor/package evidence remains vulnerable and
non-mutating local evidence proves `algif_aead` is currently not loaded while
modprobe policy blocks autoload. That is a module-disable mitigation, not a
kernel patch and not proof of production safety; it remains a blocker unless the
checker is run with the explicit
`--accept-cve-31431-mitigation-risk-for-internal-alpha` flag for bounded
internal Remote Alpha proof. Vendor status checks are direct evidence only
when observed from the host; otherwise CVE patch status remains `unknown` and
the artifact must include `not_cve_patch_authority`. Even when vendor status
or module-disable mitigation evidence is directly observed, the artifact
remains evidence only and not patch authority. Missing local tools or
unavailable observations must become honest `blockers` or `not_evaluated`
entries rather than false pass output. The checker must fail closed if its
summary would persist JWT-SVIDs, Vault tokens, root tokens, unseal keys, PEM
private keys, API keys, Codex credentials, raw secret payloads, or overclaim
text such as `full ES/runtime de-root`. Nomad server/client posture reporting
must stay role-aware and honest: one combined `nomad.service` observation is
not separate server/client proof by itself. When the checker uses one combined
service unit as the privilege evidence path for both surfaces, it must record
`independently_evaluated=false`, set
`evaluation_source=combined_nomad_systemd_unit`, and explain that one combined
service unit does not prove separate server/client posture. Stable Nomad
posture fields may include `nomad_roles_detected`, `evaluation_source`,
`independently_evaluated`, `combined_single_node_service`, and
`role_evidence`. CVE/runtime inventory fields remain evidence/projection only:
they are not service health, submit readiness, runtime-profile readiness,
governed execution proof, full ES/runtime de-root, rootless Nomad client proof,
support-bundle authority, or CVE patch authority.

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
- the compact operator troubleshooting matrix for those classes now lives in `.runbooks/system/Governed Execution ES System Bring-Up.md`; it maps each surfaced category to the authoritative check, the most relevant service logs, when retained staging is actually useful, and the next operator action
