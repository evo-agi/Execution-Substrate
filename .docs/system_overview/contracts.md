# Cross-Service Contracts

## 1. Purpose And Authority

This document inventories the current cross-service contracts in the Go repository.

A system contract, for this document, is any rule, DTO, route, shared payload, or ownership boundary that crosses service or runtime boundaries and that another component can rely on.

Authoritative sources, in order, are:

1. `PLANS.md`
2. `.docs/system_overview/`
3. `.docs/execution_lifecycle/`
4. current Go code and tests

This document describes the repo's active cross-service behavior in the current bounded platform phase. A contract may be active today without being treated as a permanent endpoint.

When existing prose disagrees with code or tests, prefer code and tests.

## 2. How To Read This Document

This file uses four status labels.

| Label | Meaning |
| --- | --- |
| `Observed current contract` | A behavior, surface, or payload shape enforced by the current Go code and tests. |
| `Current invariant` | An active cross-service rule that other components currently depend on and that must not change silently during redesign. |
| `Temporary compatibility edge` | An active field, shape, or behavior retained for continuity or consumer compatibility, but not treated as a long-term architectural endpoint. |
| `Reopened redesign seam` | A currently active surface that `PLANS.md` explicitly reopens for redesign. Its present shape must not be mistaken for settled architecture. |

The labels are intentionally different:

- `Observed current contract` says what exists now.
- `Current invariant` says what must remain explicit and aligned while redesign is underway.
- `Temporary compatibility edge` says the system still uses it, but future work must not preserve it by inertia.
- `Reopened redesign seam` says the surface is live today and also explicitly under architectural review.

## 3. Shared Cross-Service Kernel

### Purpose

Describe the current shared kernel that multiple services use directly today.

### Current producers / consumers

- `AGS` produces aggregate artifact evidence using `contracts/evidence/v1` for the publish path.
- `ES` treats the `contracts/evidence/v1` artifact record as the canonical admission input.
- `ARS` stores and serves the evidence record as the first-class artifact representation, and ARS does not interpret signing semantics.
- `EGS` does not use either package; it has its own runtime-trust signing surface.

### Public surface

`Observed current contract`

- The repo now has one active shared artifact kernel:
  - `contracts/evidence/v1`
- `contracts/evidence/v1` defines one aggregate `ArtifactEvidence` record with these top-level sections:
  - `claims`
  - `seal`
- The `claims` section currently carries:
  - `schema_version`
  - `package`
  - `admission`
- The `package` section currently carries:
  - `identity`
  - `publication`
- The aggregate evidence claims carry explicit `artifact_digest` and `payload_digest` fields inside `claims.package.identity`.
### Current invariants

`Current invariant`

- AGS signs canonical aggregate evidence bytes and ES reconstructs those bytes before verifying the evidence `seal`.
- When ES uses `contracts/evidence/v1`, it verifies:
  - `claims.schema_version == "v1"`
  - expected `algorithm`
  - expected `key_id`
  - recomputed `content_digest`
  - signature over canonical aggregate bytes
- The aggregate evidence canonicalization is typed and normalizes current set-like collections such as:
  - publication `policy_decisions`
  - runtime allowlists and capability lists
- EGS runtime-trust signing is a separate contract and must not be conflated with either artifact kernel.

### Ownership boundary

- `AGS` owns aggregate evidence production.
- `ES` owns verification of the aggregate evidence record that now drives its first-class admission path.
- `ARS` owns storage and retrieval, not signature semantics.
- Shared packages are transport for jointly owned contract logic, not owners of broader system policy.

### Temporary compatibility edges

- The current ES evidence verification path reuses the AGS artifact signer trust settings already configured for provenance verification. That reuse is a first-cut compatibility choice, not a statement that the two verifier surfaces are permanently identical.

### Reopened seams

`Reopened redesign seam`

- The shared-kernel role of `contracts/evidence/v1` remains explicitly reopened by `PLANS.md`.
- The new aggregate evidence record is active today, but it is still a first migration cut rather than the declared end-state kernel.

## 4. Workload-Zone Vault Runtime-Config Contract

### Purpose

Define the shared reference and blob schema ES uses to resolve workload-zone Vault runtime settings.

### Current producers / consumers

- Startup config installs the required `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`.
- `ES` consumes that reference directly from its validated startup config.
- `ARS` serves the blob addressed by the reference digest.

### Public surface

`Observed current contract`

- `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`
- `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`
- `contracts/runtimeconfig/v1.WorkloadZoneVaultConfig`

### Current invariants

`Current invariant`

- The workload-zone Vault config reference is explicit and typed rather than being an anonymous digest string.
- The workload-zone Vault blob schema is defined by `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`.
- ES consumes the typed `WorkloadZoneVaultConfig` derived from that blob rather than owning ad hoc local parsing of the blob shape.
- ARS remains the blob storage and read authority after the digest is known.

### Ownership boundary

- `contracts/runtimeconfig/v1` owns the shared schema surface for the reference and blob meaning.
- ES startup validation currently owns the guarantee that a workload-zone Vault config reference has been installed before ES serves traffic.
- ARS owns blob storage and retrieval by digest.

### Temporary compatibility edges

`Temporary compatibility edge`

- The current reference still identifies the blob by digest. That is an active bounded choice, not a statement that all future runtime-config discovery must remain digest-only.

### Reopened seams

`Reopened redesign seam`

- The long-term owner of the workload-zone Vault runtime-config surface remains explicitly reopened in `PLANS.md`.
- The current startup-configured replacement surface is active today, but it is not yet the declared end-state config ownership model.

## 5. AGS Publication Contract

### Purpose

Accept bounded publication input, assemble the canonical aggregate evidence record, and publish the resulting artifact package through ARS.

### Current producers / consumers

- Current allowed callers are:
  - `spiffe://execution.internal/operator`
- `AGS` consumes the ARS write boundary.
- `ES` later consumes AGS output indirectly through ARS reads.

### Public surface

`Observed current contract`

- `POST /v1/artifacts:publish`

Current request shape:

- `artifact_payload_b64`
- `artifact`
- `publication`
- `admission`

Current response shape:

- `published`
- `artifact_digest`
- `discovery_digest`
- `descriptor_digest`
- `evidence_digest`
- `manifest_digest`
- `payload_digest`

### Current invariants

`Current invariant`

- AGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers.
- AGS only allows publish callers from the operator identity above in the current bounded slice.
- AGS computes `payload_digest` from payload bytes.
- AGS derives `artifact_digest` separately from deterministic package identity inputs: `payload_digest`, `artifact_type`, and `intent_digest`. Artifact identity is no longer equal to payload identity by shortcut, and it is no longer derived from admission/runtime claim material.
- AGS now also assembles and signs one aggregate `contracts/evidence/v1` record whose `claims` section is deliberately split between:
  - `claims.package` for publication/discoverability-facing meaning
  - `claims.admission.authorization` for derivation request-binding meaning only
  - `claims.admission.execution` for the smaller shared runtime contract ES currently consumes:
    - runtime env allowlist
    - required runtime capabilities
    - `target_platform`
    - `network_access`
- AGS assembles and uploads:
  - payload bytes
  - aggregate artifact evidence
  - manifest
  - runtime-facing artifact discovery record
  - artifact descriptor as secondary publication/support data
- AGS signs aggregate artifact evidence using `contracts/evidence/v1`.
- AGS derives publication caller binding from the authenticated caller and always emits `claims.package.publication.builder_service = "artifact-governance"` in aggregate evidence.
- AGS now rejects non-docker `admission.workload.target_platform` values at publish time because the active shared runtime contract only admits empty or `docker` target platforms.
- AGS publish requests currently carry execution access at `admission.access.network_access`; that runtime-facing input is emitted into `claims.admission.execution.access` rather than into shared authorization claims.
- Non-runtime workload metadata such as `artifact_class`, `workload_type`, `service_name`, `workload_identity_id`, and `description` no longer live inside the shared execution/runtime evidence claims.
- `policy_decisions` are caller-supplied and are normalized structurally for signing, but AGS does not semantically evaluate them.
- AGS publishes only through ARS:
  - `PUT /v1/blobs/{digest}`
  - `POST /v1/artifacts:register`
  - registration is now discovery-centered rather than tuple-centered, with optional secondary descriptor support

### Ownership boundary

- AGS owns artifact-fact assembly, signing, upload, and registration.
- AGS does not own EGS runtime-trust publication, runtime admission, scheduler behavior, or runtime credential delivery.

### Temporary compatibility edges

`Temporary compatibility edge`

- None on the current AGS publish path.

### Reopened seams

`Reopened redesign seam`

- The AGS publish contract and fact-assembly model are explicitly reopened in `PLANS.md`.
- The current runtime-facing discovery record, secondary descriptor support data, and caller-binding model are live today, but they are not automatically the target end-state.

## 6. ARS Storage And Discoverability Contract

### Purpose

Provide content-addressed blob storage, integrity enforcement, artifact registration, and runtime-facing artifact discoverability.

### Current producers / consumers

- `AGS` is the fixed writer for the current ARS write boundary.
- `ES` consumes ARS for runtime-facing discovery, evidence and payload blob reads, manifest support reads when needed, and workload-zone vault blob reads.
- Other read callers may access ARS if their SPIFFE path matches configured allowed prefixes.

### Public surface

`Observed current contract`

Write surface:

- `PUT /v1/blobs/{digest}`
- `POST /v1/artifacts:register`

Read surface:

- `HEAD /v1/blobs/{digest}`
- `GET /v1/blobs/{digest}:bytes`
- `GET /v1/blobs/{digest}:json`
- `GET /v1/artifacts/{artifact_digest}/discovery`
- `GET /v1/artifacts/{artifact_digest}/descriptor`
- `GET /v1/artifacts/{artifact_digest}/evidence`
- `GET /v1/artifacts/{artifact_digest}/manifest`

Current registration record is discovery-centered:

- `artifact_digest`
- `discovery_digest`
- `descriptor_digest`
- discovery `artifact` identity
- discovery references for evidence and payload
- optional secondary descriptor support data for publication-only reads such as manifest

### Current invariants

`Current invariant`

- ARS is the only current publication and retrieval boundary for published artifacts.
- Write access is limited to SPIFFE caller path `service/artifact-governance`.
- `PUT /v1/blobs/{digest}` recomputes the digest from received bytes.
- Upload is idempotent for identical content.
- `HEAD /v1/blobs/{digest}` is an integrity check, not a mere presence check.
- `GET /v1/blobs/{digest}:bytes` and `GET /v1/blobs/{digest}:json` both re-read and re-verify blob integrity on the read path.
- `GET /v1/blobs/{digest}:json` additionally requires the blob bytes to be valid JSON.
- Artifact reads become visible only after successful registration.
- ARS serves the registered discovery record as the first-class artifact discoverability surface at `/v1/artifacts/{artifact_digest}/discovery`.
- ARS requires `discovery_digest` for artifact registration.
- `descriptor_digest` is optional secondary support data for descriptor and manifest reads.
- ARS resolves `/evidence` reads through the registered discovery record and `/manifest` reads through the secondary descriptor support path when present.
- Registration validates every referenced digest by:
  - checking digest syntax
  - validating discovery structure and identity fields
  - reading the referenced blob through the storage layer
  - rejecting missing or corrupted blobs
  - requiring JSON validity for the discovery, evidence, and any secondary descriptor/manifest blobs the registration includes
- Registration is idempotent for the same discovery/descriptor tuple and a conflict for a different tuple under the same `artifact_digest`.
- ARS read paths treat referenced blob corruption as a storage failure, not as valid discoverability.

### Ownership boundary

- ARS owns storage correctness, read integrity, and discoverability.
- ARS does not own signature verification, trust enforcement, or policy evaluation.

### Temporary compatibility edges

`Temporary compatibility edge`

- None on the current ARS artifact contract.

### Reopened seams

`Reopened redesign seam`

- The ARS registration and index model are explicitly reopened in `PLANS.md`.
- The current runtime-facing discovery record and secondary descriptor support shape are active, but must not be assumed long-term solely because ES currently consumes them.

## 7. ES Admission And Execution Contract

### Purpose

Compose startup-owned runtime-config references, ARS, and EGS into governed admission and one bounded execution submit path, then project lifecycle state from Nomad.

### Current producers / consumers

- Current allowed callers are:
  - `spiffe://execution.internal/operator`
- ES consumes:
  - the configured workload-zone Vault config reference
  - ARS artifact evidence, manifest support data when needed, and payload/blob reads
  - EGS runtime-trust publication
  - Nomad job and allocation APIs

### Public surface

`Observed current contract`

- `POST /v1/executions:prepare`
- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- `POST /v1/executions/{run_id}:cancel`

### Current integration-facing note

`Observed current contract`

- The current programmatic governed-execution surface is the HTTPS API boundary, not the shell helpers:
  - `POST /v1/artifacts:publish` through AGS
  - the ES execution and lifecycle endpoints above
- `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, `scripts/50_lifecycle.sh`, and `scripts/60_execute_loop.sh` are operator/proof helpers over those APIs; they are not a separate client contract.
- Host staging paths, current bind-mount sources, and the helper-private SPIRE source attachment are ES/operator deployment implementation details, not part of the client-facing execution contract.
- A future infra manager may satisfy those internal attachment needs with named volumes or other managed attachment semantics without changing the current HTTPS API, `run_id` lifecycle lookup contract, or workload-visible endpoint discovery contract.
- The current client-authorization shape is still operator-centric:
  - AGS publish and ES execution/lifecycle calls accept `spiffe://execution.internal/operator`
  - a broader Control Plane or multi-client governed-execution caller model is not yet an implemented public contract

Current prepare request shape:

- `schema_version`
- `invocation`
- `mode`
- `timeout_seconds`
- `resources`

Current invocation shape:

- `schema_version`
- `artifact_digest`
- `derivation_spec_digest`
- `output_id`
- `argv`
- `env`
- `mounts`
- `annotations`

Current lifecycle lookup policy:

- `run_id` must match `run-[0-9a-f]{16}`
- ES owns one explicit internal execution-locator policy for lifecycle lookup
- the current locator resolves `nomad_job_id = exec-<run_id>`

Current successful response shapes:

- `:prepare`
  - `success`
- `:submit`
  - `success`
  - `submitted`
  - `run_id`
  - `status`
- `status`
  - `success`
  - `run_id`
  - `status`
  - optional `exit_code`
  - `terminal`
- `cancel`
  - `success`
  - `run_id`
  - `status`

### Current invariants

`Current invariant`

- ES requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers.
- ES admits only the operator caller identity today on its public execution and lifecycle entry surfaces.
- `:prepare` validates request shape, fetches the artifact discovery record from ARS, follows that record to aggregate evidence and payload references, verifies the evidence record with `contracts/evidence/v1`, enforces the current EGS runtime-trust payload against the evidence signer key, reads the configured workload-zone Vault blob from ARS through `contracts/runtimeconfig/v1`, derives the bounded workload-vault handoff directly from that runtime config plus ES `workload_vault_auth.default_mode`, and returns bounded preflight success only.
- `:prepare` does not create run IDs, scheduler metadata, durable execution state, or public composition detail.
- ES verifies and consumes these current ARS artifact surfaces:
  - artifact discovery record at `/v1/artifacts/{artifact_digest}/discovery`
  - aggregate evidence blob referenced by that discovery record
  - payload bytes at `/v1/blobs/{payload_digest}:bytes`
- ES currently interprets EGS `runtime_trust.signer_policy.allowed_signers` as artifact publication evidence signer key IDs.
- ES verifies and enforces only the signed EGS runtime-trust payload and does not surface EGS publication metadata in `:prepare` results.
- `:submit` reuses the full `:prepare` path first.
- `:submit` is async-only in the current execution slice.
- `:submit` currently supports only:
  - `static-script` artifacts
  - Docker target platform when a target platform is present
  - no required runtime capabilities
- `:submit` is the primary public execution handoff in the current slice and its successful receipt is centered on `run_id`, not backend-specific scheduler IDs.
- ES currently fetches payload bytes via the explicit payload reference carried in the ARS discovery record and cross-checks that reference against aggregate evidence.
- ES now localizes submit-time payload staging, mount staging, and runtime-ready package assembly behind one internal execution-package layout rather than letting that contract drift across submit, mount, and handoff helpers.
- Runtime network mode is derived directly from signed execution access claims:
  - `network_access=false -> network_mode=none`
  - `network_access=true -> network_mode=bridge`
- Caller runtime mounts are currently limited to governed artifact-backed mounts that are:
  - read-only
  - absolute
  - already cleaned
  - under `/execution/mounts`
  - non-overlapping
- Each runtime mount artifact is revalidated through ARS and runtime-trust enforcement before staging.
- Failed submit staging is cleaned immediately.
- Successful submit payload, run, and mount staging remain under `execution.staging_root_dir/<run_id>/` only while the workload may still depend on those bind mounts.
- Once ES observes terminal success for the run through the current lifecycle path, it best-effort removes `execution.staging_root_dir/<run_id>/`.
- Failed, canceled, lost, or otherwise ambiguous terminal outcomes retain their staging root for operator debugging in the current slice.
- Lifecycle is Nomad-backed only:
  - ES does not persist run state
  - ES resolves status, logs, and cancel through Nomad
  - ES derives the minimal public lifecycle `status` value from Nomad-backed state as `submitted`, `running`, or `terminal`
  - logs are stdout-only for task `task`
  - ES uses one explicit projected-allocation policy that currently chooses the latest allocation in the current no-retry, no-reschedule slice

### Ownership boundary

- ES owns request validation, cross-service composition, Nomad submission, and Nomad-backed lifecycle projection.
- ES does not own:
  - trust policy
  - artifact publication
  - storage semantics
  - scheduler state
  - durable lifecycle state

### Temporary compatibility edges

`Temporary compatibility edge`

- `POST /v1/executions:prepare` is an active milestone surface, not a declared long-term public execution API.
- The current container path conventions under `/execution/...` and the current runtime environment variable names are active today, but should not be treated as permanent by default.
- The current internal execution-locator policy (`run_id -> exec-<run_id>`) and projected-allocation model are current slice mechanics, not a general scheduler abstraction.

### Reopened seams

`Reopened redesign seam`

- The ES public request model is explicitly reopened in `PLANS.md`.
- The current prepare/submit split, payload-resolution path, runtime mount model, and scheduler handoff shape are live today but not treated as settled architecture.

## 8. EGS Policy Contract

### Purpose

Publish the signed runtime-trust payload that ES enforces at admission time.

### Current producers / consumers

- `EGS` publishes the runtime-trust payload plus separate publication metadata.
- Current allowed callers are:
  - `spiffe://execution.internal/service/execution`
  - `spiffe://execution.internal/operator`
- `ES` is the current runtime consumer.

### Public surface

`Observed current contract`

- `GET /v1/trust-model`

Current response shape:

- `runtime_trust`
- `algorithm`
- `key_id`
- `payload_digest`
- `signature`
- `publication`

Current `runtime_trust` payload shape:

- `signer_policy.allowed_signers`
- `signer_policy.revoked_signers`
- `artifact_policy.revoked_artifacts`

Current `publication` metadata shape:

- `version`
- `update_revision`

### Current invariants

`Current invariant`

- EGS signs the canonical runtime-trust payload, not artifact facts.
- Current canonical runtime-trust signing covers:
  - `signer_policy`
  - `artifact_policy`
- Runtime-trust list fields are normalized deterministically before digest and signature generation.
- `payload_digest` and `signature` are the authoritative trust signals in the current contract.
- ES verifies the EGS signature and then enforces:
  - provenance signer allow-list
  - provenance signer revocation
  - artifact revocation

### Ownership boundary

- EGS owns runtime-trust publication and signing.
- EGS does not own artifact signing, artifact retrieval, runtime execution, or lifecycle state.

### Temporary compatibility edges

`Temporary compatibility edge`

- The route remains `GET /v1/trust-model` even though the shared runtime contract is now the narrower `runtime_trust` payload plus separate EGS-owned publication metadata.

### Reopened seams

`Reopened redesign seam`

- The current runtime-trust form and response wrapper are explicitly reopened in `PLANS.md`.
- The current EGS surface is live, but its exact payload and wrapper shape must not be treated as frozen architecture.

## 9. CGS Authorization Contract

### Purpose

Provide a separate authorization decision boundary for credential-related access.

### Current producers / consumers

- Callers invoke CGS directly with their own authenticated SPIFFE identity.
- The caller identity must match `workload.workload_identity_id`.
- ES is not a current CGS consumer in the active ES hot path.

### Public surface

`Observed current contract`

- `POST /v1/credential/authorize`

Current request shape:

- `workload`
- `requested_capabilities`

Current response shape:

- `allowed`
- `request_id`
- `decision_id`
- `decision` on allow
- `audit`
- optional `reason` on deny

### Current invariants

`Current invariant`

- CGS exposes only `POST /v1/credential/authorize` in the current Go contract.
- CGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers.
- The authenticated caller identity must equal `workload.workload_identity_id`.
- CGS currently depends only on:
  - `workload.type`
  - `workload.workload_identity_id`
- Removed location-convenience fields such as `module_path`, `file_path`, and `service_name` are not part of the active request contract.
- `requested_capabilities` currently allows only `vault:read`.
- `id.conf` is loaded at startup, parsed into explicit subject records, and used to:
  - validate workload principals
  - derive subject IDs from explicit policy records
  - evaluate allow or deny decisions
- The current supported `id.conf` grammar is:
  - `subject "<id>" {`
  - `type: "service" | "script"`
  - `principal: "spiffe://..."`
  - `role: "<role>"`
  - `}`
- The repo now carries a minimal checked-in baseline at `cgs/policy/id.conf`.
  - It is grounded in current Go-repo tests/examples only.
  - It must not be mistaken for a complete production policy file or final long-term policy grammar.
- Allow and deny both return `200` in the current boundary.
- Allow responses currently return:
  - `role`
  - optional decision constraints
- Current authorize responses include no secret material and no runtime auth-plan payload.

### Ownership boundary

- CGS owns the current authorization decision surface only.
- CGS does not own artifact publication, EGS runtime-trust publication, scheduler state, or the current ES admission path.

### Temporary compatibility edges

`Temporary compatibility edge`

- `id.conf` is an active local policy input, but it should not be mistaken for a permanent repo-wide policy architecture just because it is currently in use.

### Reopened seams

`Reopened redesign seam`

- The CGS authorize DTO and `id.conf` policy-input model are explicitly reopened in `PLANS.md`.
- CGS remains live today, but its current wire and policy-input shape must not be treated as the final core authorization contract.

## 10. Runtime Identity Handoff Contract

### Purpose

Describe the current ES-to-runtime identity boundary used during submission and execution.

### Current producers / consumers

- `ES` provisions the backing runtime-identity workspace and environment marker at submit time.
- The workload container consumes the discovered endpoint and the resulting non-secret runtime inputs.
- Nomad and Docker carry the mounts, but they do not own the handoff semantics.

### Public surface

`Observed current contract`

Current workload-visible handoff:

- canonical `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://<ES-owned run-scoped endpoint>`
- non-secret workload-vault environment inputs derived from the resolved workload-vault auth plan

Current ES-owned implementation details behind that handoff:

- ES currently backs the discovered endpoint with a writable tmpfs workspace under a run-scoped subtree rooted at `/run/es-runtime-identity/`
- ES currently protects the workspace subtree and the endpoint path from caller mount overlap
- the bounded slice-1 implementation target stages platform-owned runtime support assets under `/execution/run/platform/` and keeps workload content under `/execution/run/work`

Current runtime rules:

- ES adds exactly one writable tmpfs-backed workspace to back the discovered runtime-identity endpoint.
- The backing workspace is not caller-controlled.
- Caller mounts must not overlap the ES-owned runtime subtree that backs the discovered endpoint.
- ES also injects non-secret Vault auth metadata through environment variables.
- ES does not apply per-workload selector overrides when shaping that Vault auth metadata in the current slice.
- the slice-1 first implementation slice narrows workload runtime compatibility to platform-controlled non-root workloads:
  - helper runs as `0:0`
  - workload runs as fixed `10000:10000`
  - workload receives no supplemental groups and no privilege-escalation path
- the helper-private SPIRE channel is bounded to `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`
- the public workload-visible endpoint remains `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix:///run/es-runtime-identity/<run_id>/endpoint`
- the public endpoint is platform-bounded and must not become a raw SPIRE passthrough

### Current invariants

`Current invariant`

- ES reserves the runtime-identity workspace and validates that caller mount targets do not overlap it.
- The workspace backing the discovered runtime-identity endpoint is tmpfs-backed, writable, and not persisted into host staging.
- ES does not fetch, mint, or store identity material.
- ES derives the workload-vault auth plan from workload-zone vault runtime fields plus the locally configured default auth mode.
- ES does not treat endpoint creation failure, workload identity failure, or Vault auth failure as ES lifecycle state.
- Capability-sensitive behavior in this area must not rely on OS-based branching or fallback behavior.
- The first platform-owned runtime-identity slice must fail closed unless the workload can be launched as fixed non-root `10000:10000` with no supplemental groups and no privilege-escalation path.
- The raw SPIRE channel must remain helper-private and must not be exposed to workload env, workload mounts, or workload-authored code.

### Ownership boundary

- ES owns workspace reservation and boundary enforcement.
- The workload owns use of the discovered endpoint inside the container and remains only a client of that endpoint.
- The checked-in workload-authored reference bridge is example scaffolding only and does not define final ownership of runtime identity delivery.
- The platform-owned runtime helper owns:
  - raw SPIRE access
  - endpoint serving
  - JWT-SVID retrieval and refresh
  - endpoint-local runtime failure
- ES does not own:
  - token minting
  - Vault token storage
  - runtime identity material delivery
  - post-submit identity lifecycle

### Temporary compatibility edges

`Temporary compatibility edge`

- The endpoint URI is ES-chosen and run-scoped rather than a fixed `/execution/runtime-identity/endpoint` contract.
- The `/run/es-runtime-identity/...` backing layout is current ES implementation, not a broader workload contract.

### Reopened seams

`Reopened redesign seam`

- The runtime identity handoff surface is explicitly reopened in `PLANS.md`.
- The current reserved paths, env var, and ES/runtime division of responsibility are active now, but must not be preserved automatically.
- The current bounded planning target is to keep the workload-visible discovery contract explicit while moving the implementation behind it into a platform-owned injected runtime companion/bridge rather than a workload-authored shim.
- The accepted bounded runtime shape for slice `1A` and `1B` is now the same-container helper launched by a platform-owned supervisor; reconsider sidecar/task only if that shape cannot keep the raw SPIRE channel helper-private or cannot enforce the non-root workload boundary without compromise.

## 11. Temporary Compatibility Edges

The following active edges are compatibility-heavy enough to keep in one place:

- `ES` currently uses `/v1/executions:prepare` as an active milestone surface rather than a declared long-term public execution API.
- `contracts/evidence/v1` now separates signed `claims` content from the `seal` envelope, but the package still remains the active shared artifact kernel and therefore still concentrates substantial cross-service meaning.
- `ES` currently uses `/execution/staged`, `/execution/run`, `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, and the current ES-owned runtime-identity backing layout as active runtime conventions.
- `CGS` currently uses `id.conf` as a local policy input format.

## 12. Reopened Redesign Seams

The following cross-service seams are active today and explicitly not fixed architectural endpoints:

- The shared-kernel role of `contracts/evidence/v1`.
- The ARS registration and index model.
- The workload-zone Vault runtime-config ownership surface.
- The AGS publish grammar and fact-assembly model.
- The ES request model, payload-resolution path, and scheduler handoff shape.
- The EGS runtime-trust form and response wrapper.
- The CGS authorize DTO and `id.conf` policy-input model.
- The ES/runtime identity handoff surface, including reserved path conventions.

This section is not a proposal for replacements. It exists to prevent future readers from preserving the current choreography by accident.

## 13. Decision Rules For Future Edits

Future edits to cross-service contracts must follow these rules:

- Code and tests outrank stale prose.
- Structural coupling must be documented before being preserved.
- Compatibility-only edges must be labeled as such.
- A shared kernel must not grow casually.
- No contract becomes "fixed" merely because it is already implemented.
- No contract becomes "fixed" unless it is named explicitly as such in `PLANS.md` and aligned docs.
- If cross-service behavior changes, update `PLANS.md`, the relevant `.docs/` pages, and tests before treating the change as complete.
