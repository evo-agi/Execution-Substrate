# Service Boundary Map

## 1. Purpose and scope

A boundary in this repository is an ownership line: which service is authoritative for a behavior, which other services consume that behavior, and which responsibilities remain explicitly outside that service.

This document records the repository's current service ownership in the bounded platform phase described in `PLANS.md`. The boundaries below are real and active today, but they are not automatically permanent architecture. Where the current split is serving a bounded slice, compatibility need, or inherited choreography, that is called out explicitly.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

When prose and code disagree, code and tests win.

## 2. How to read this document

- **Observed current boundary**: A service split or responsibility line that is implemented and visible in the current Go repo.
- **Current ownership**: Behavior or data the service is currently authoritative for.
- **Explicit non-ownership**: Behavior the service currently must not be treated as owning, even if it collaborates closely with the owning service.
- **Temporary compatibility edge**: An active boundary behavior retained to keep the current slice coherent or interoperable. It should not be treated as settled architecture without being named again elsewhere.
- **Reopened redesign seam**: A boundary that is active today but explicitly reopened in `PLANS.md` and related design docs. The current shape is descriptive, not final.

## 3. Boundary map overview

| Service | Observed current boundary | Current ownership summary |
| --- | --- | --- |
| ARS | Storage and artifact discoverability service | Blob storage, integrity enforcement, evidence-centered artifact registration, and canonical artifact retrieval |
| AGS | Artifact publication service | Evidence-first publication assembly, caller-bound publication claims, and publication into ARS |
| EGS | Trust model publication service | Signed signer/artifact runtime-trust publication plus separate EGS-owned publication metadata |
| CGS | Authorization service | Direct authorize-only decision surface backed by caller/workload identity checks and explicit `id.conf` subject policy |
| ES | Admission, submission, and lifecycle projection service | Execution request validation, composition across upstream services, Nomad submission, and bounded execution status/log projection |

Important absences in the current Go repo:

- There is no standalone Deployment service boundary in this repository.
- There is no standalone IGS service boundary in this repository.
- There is no separate lifecycle-state service boundary beyond ES projecting Nomad state.

Those absences are current facts, not design commitments.

## 4. Boundary interaction rules

- ES is the main composition boundary. It consumes startup-owned runtime-config references, ARS artifact evidence/records and blobs, and EGS trust policy during admission and submission.
- AGS depends on ARS as the publication sink. AGS publishes through ARS rather than owning artifact storage or discoverability itself.
- EGS publishes signed signer/artifact trust policy; ES consumes that policy.
  Separate EGS-owned publication metadata remains outside the signed
  runtime-trust payload. EGS does not sit in the runtime execution path after
  ES has loaded and verified the trust model.
- CGS is a direct authorize-only boundary. It is active today, but it is not
  part of the current ES hot path.
- ARS is the storage and discoverability authority, not the governance or execution authority. Other services must not rely on ARS to make trust or policy decisions for them.
- `internal/contracts/runtimeconfig/v1` is the shared schema surface for the workload-zone Vault config reference and blob. It is not a standalone service boundary.
- The Workstream E E0 runtime-config ownership decision lives in
  `runtime_config_ownership.md`: runtime-config semantics live in the
  runtime-config contract surface, ARS owns blob storage/read by digest only,
  and ES is the current consumer and lookup orchestrator.
- `internal/contracts/evidence/v1` is now the active shared cross-service kernel for the primary AGS-published artifact path into ES. It is not itself a standalone service boundary.
- The Workstream A classification of what is kernel-level shared meaning versus service-owned contract lives in `shared_kernel.md`.
- The shared evidence package is not a cross-service semantic dumping ground.
  Package placement does not make AGS publication claims, ARS
  discoverability/index/support shapes, ES lifecycle/runtime-profile grammar, CP
  attempt semantics, or generated evidence/projection outputs shared-kernel
  owned.
- The Workstream B classification of AGS publication ownership, ARS
  storage/discoverability authority, canonical runtime-discoverable surfaces,
  and secondary publication/support detail lives in
  `artifact_publication_storage.md`.
- In the current evidence record, `claims.package.identity`, narrow derivation request-binding authorization, the narrow execution/runtime claims ES actually enforces, and `seal` verification are the kernel-level shared surface. `claims.package.publication` remains AGS-owned publication meaning carried inside the signed record.
- `claims.package.identity` is the shared-kernel identity surface ES consumes:
  `payload_digest` identifies payload bytes or payload content identity, while
  `artifact_digest` identifies artifact/package identity as currently derived
  and documented.
- ARS runtime-facing discovery, descriptor, and index shapes are ARS-owned discoverability contracts. ES may consume them, but they are not the shared kernel and must not become ES public grammar by reuse.
- Descriptor/manifest/index/support tuples are compatibility/support or
  implementation-only surfaces unless explicitly migrated, and ES must consume
  artifacts through a designed discoverability surface rather than inheriting
  ARS support tuple grammar as ES public grammar.
- ES-owned admission, submission, lifecycle projection, runtime-profile, runtime-identity, retained-result, and readiness semantics are defined by this repository's planning and boundary docs.
- ES Admission Policy Layer v0 is ES-owned final admission policy for ES-bound
  executions. It is local to ES admission and does not make CP the final ES
  gate, make IM policy/run/runtime authority, or import CGS `id.conf`,
  OPA/Rego, a DSL, customer regex config, signed policy bundles, an external
  policy service, or durable policy-decision storage into ES.
- For Workstream C0, ES owns the public admission model, prepare model, submit
  model, Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- The Workstream F F0 runtime-identity handoff ownership decision lives in
  `runtime_identity_handoff.md`: runtime identity handoff is currently
  ES-selected and platform-delivered, `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the
  bounded workload-visible discovery contract, the runtime supervisor/helper
  owns the in-task endpoint implementation and helper-private SPIRE traversal,
  SPIRE owns JWT-SVID issuance, and Vault owns token/secret/lease issuance
  after workload-side login.
- Control Plane is a consumer of accepted AGS and ES surfaces, not an owner of ES core contracts. CP documents, examples, probes, or proof-harness expectations must be treated as consumer compatibility inputs unless `PLANS.md` explicitly promotes a rule into ES-owned semantics.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
- Generated evidence, `.out` workspaces, support bundles, retained bundles,
  reports, traces, logs, summaries, and proof artifacts remain
  evidence/projection/diagnostics only. They are not service-boundary authority
  and do not define shared-kernel meaning.
- Generated evidence, `.out`, reports, traces, logs, summaries, support
  bundles, retained bundles, proof artifacts, and maintenance summaries remain
  non-authoritative evidence/projection.

## 4A. Proof Bootstrap Ownership

**Purpose**

Keep the bounded supported-local proof honest about what this repo bootstraps for proof execution versus what still belongs to the larger ecosystem.

**Current ownership**

- Repo-owned proof tooling under `scripts/72_supported_local_setup.sh` and `scripts/73_supported_local_proof.sh`
- Proof-scoped SPIRE dev/test bootstrap needed to exercise the helper-private workload identity path
- Proof-scoped Vault dev/test bootstrap needed to exercise the bounded workload JWT login and secret-read proof
- Proof-scoped non-secret Vault CA trust material needed to verify that dev/test Vault TLS endpoint from workloads
- Proof-scoped guest scratch cleanup and canonical host evidence capture under `.out/es-proof-<id>/`

**Explicit non-ownership**

- Long-lived Nomad, Vault, or SPIRE lifecycle management for a real environment
- Production Vault policy, secrets-engine, auth-method, or token lifecycle management
- General machine orchestration, shared ecosystem infra reconciliation, or cross-repo environment ownership

**Boundary note**

- The larger ecosystem still has to own long-lived infrastructure bootstrap and lifecycle somewhere; this repo only owns the bounded proof-scoped bootstrap it needs to prove the current Execution Substrate slice honestly.

## 5. Workload-zone Vault runtime-config surface

**Purpose**

Provide the explicit shared reference and config schema ES uses to resolve workload-zone Vault runtime settings.

**Current ownership**

- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`
- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`
- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfig`
- ES startup validation that `runtime_config.workload_zone_vault_config_ref` exists before ES serves traffic
- Runtime-config semantics for the current workload-zone Vault reference/blob
  surface

**Explicit non-ownership**

- Blob storage or blob integrity enforcement after a digest is known
- Runtime lookup networking or a standalone service hop
- ARS blob mechanics as semantic ownership of workload-zone Vault config
- Runtime-config authority from CGS authorize output, `id.conf`,
  `policy.id_conf_path`, `audit.policy_version`, EGS `publication.version`,
  EGS unsigned publication metadata, AGS `policy_decisions`, ES retained
  bundles, ES `outcome_evidence`, ES `authority_handoff`, IM profiles,
  support bundles, logs, traces, reports, `.out` artifacts, or CP
  review/approval/checkpoint/finalization state
- Artifact publication
- Execution admission or scheduler submission
- Trust model publication or enforcement
- Runtime identity minting or runtime credential delivery
- Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material,
  or runtime identity handoff
- General configuration authority beyond the current workload-zone Vault reference/blob surface

**Current consumers / collaborators**

- ES consumes the configured `WorkloadZoneVaultConfigRef` during preparation and submission
- ARS serves the blob named by that reference
- Test fixtures and startup config install the required reference
- No ACS hop exists in the current runtime-config path

**Boundary pressure points**

- The repo now has an explicit shared runtime-config surface, but the long-term owner of that surface is still under review.
- ES currently remains the only live consumer, so future changes must not let consumer-local convenience become de facto schema ownership again.

**Temporary compatibility edges**

- The current runtime-config surface remains intentionally small and workload-zone-specific rather than becoming a generic config platform by drift.
- ES startup-config placement of
  `runtime_config.workload_zone_vault_config_ref` is compatibility/config
  residue on a reopened ownership seam. It is active today, but it is not the
  final runtime-config owner by inertia.
- The digest-only ref shape is an active temporary compatibility edge and
  bounded current surface.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority or live credential truth.

**Reopened seams**

- Whether the runtime-config surface should remain startup-configured or move behind a different narrow boundary later
- Whether the current config-reference indirection should remain digest-based or evolve once a broader config owner is explicit

## 6. ARS boundary

**Purpose**

Provide artifact blob storage plus the registration and read surfaces that make published artifacts discoverable.

**Current ownership**

- Content-addressed blob write, read, and integrity verification
- Registration of evidence-centered artifact records through `/v1/artifacts:register`
- Fact retrieval through `/v1/artifacts/{artifact_digest}/{kind}`
- Current artifact index entry shape in `ars/index/index.go`
- Descriptor, manifest, index, and support read semantics for the current ARS
  compatibility/support surfaces
- Read-time guarantees that referenced blobs exist, are integrity-valid, and are JSON-valid where the contract requires JSON facts

**Explicit non-ownership**

- Publish-time fact assembly
- Trust or policy evaluation
- Runtime execution or lifecycle state
- Authorization semantics beyond the bounded write and read caller checks implemented by ARS itself
- ES public grammar for descriptor/manifest/index/support tuples

**Current consumers / collaborators**

- AGS writes blobs and registers artifacts through ARS
- ES reads blobs and artifact evidence/records through ARS
- ES reads artifacts through designed ARS discoverability outputs rather than
  inheriting ARS support tuple grammar as ES public grammar
- Other configured callers may read through ARS if their SPIFFE path matches allowed prefixes

**Boundary pressure points**

- The current runtime-facing discovery record shapes what AGS must publish and what ES can later discover through ARS.
- The current ARS discovery record is the canonical runtime-discoverable
  surface for the current slice, while descriptor/manifest support data remain
  secondary publication detail.
- Artifact discoverability is not independent of the registration/index model; downstream services still inherit that model.
- AGS now publishes distinct artifact and payload identities. ARS discoverability and ES consumption both depend on the runtime-facing payload reference plus evidence-claim cross-checks rather than on any hidden digest equality.

**Temporary compatibility edges**

- Descriptor read/support path (`GET /v1/artifacts/{artifact_digest}/descriptor`, optional `descriptor_digest`) is a system-visible compatibility edge on the current ARS boundary. Reason: preserve publication/support descriptor reads while the discovery record remains the canonical runtime-discoverable surface. Scope: secondary descriptor registration and support reads only; not ES hot-path admission or ES public grammar. Affected boundary: ARS boundary and ARS storage/discoverability contract. Removal condition: change only with a documented support-surface migration, deprecation path, or explicit versioning plan first. Full Workstream B metadata lives in `artifact_publication_storage.md`.
- Manifest read/support path (`GET /v1/artifacts/{artifact_digest}/manifest` through descriptor `package.supporting[name=manifest]`) is a system-visible compatibility edge on the current ARS boundary. Reason: preserve publication/support manifest reads without promoting manifest into canonical runtime discoverability or ES admission semantics. Scope: secondary manifest support data plus the current descriptor-carried manifest reference only; not ES hot-path admission or ES public grammar. Affected boundary: ARS boundary, the ARS storage/discoverability contract, and the current AGS/ARS support-data choreography. Removal condition: change only with a documented support-surface or descriptor-layout migration, deprecation path, or explicit versioning plan first. Full Workstream B metadata lives in `artifact_publication_storage.md`.

**Reopened seams**

- The long-term role of the current artifact registration/index model
- Whether ARS should continue to expose the current runtime-facing discovery record and secondary descriptor support path
- Whether current artifact read paths are the right ownership split between storage authority and broader choreography

## 7. AGS boundary

**Purpose**

Assemble the publish-time aggregate evidence record, bind publication to the authenticated caller, and publish the resulting artifact package through ARS.

**Current ownership**

- Publish API at `/v1/artifacts:publish`
- Artifact digest derivation from package-facing identity inputs rooted in `payload_digest`, `artifact_type`, and `intent_digest`
- Evidence-native publish request grammar with `artifact`, `publication`, and `admission` sections
- Construction of the aggregate `internal/contracts/evidence/v1` publication record, with package identity/publication claims kept separate from narrow shared derivation request-binding authorization claims and execution/runtime claims
- Construction of manifest as supporting publication data
- Signing of the aggregate artifact-evidence record using `internal/contracts/evidence/v1`
- Bounded publish caller authorization through configured SPIFFE path-prefix allowlists, with the current repo-owned configs remaining operator-only
- Uploading blobs to ARS and registering the evidence-centered artifact record with ARS

**Explicit non-ownership**

- Blob storage or discoverability after publication
- Execution-time trust evaluation
- Runtime admission, submission, or lifecycle projection
- Runtime identity delivery or token minting
- General-purpose signing unrelated to the publish contract

**Current consumers / collaborators**

- The current repo-owned operator path invokes AGS directly, and additional callers may do so if their SPIFFE paths are allowed by AGS config
- The first repo-owned non-operator governed-execution caller activation path is Control Plane at `spiffe://execution.internal/service/control-plane`
- The current repo-owned direct API example for that caller lives at `.examples/control_plane_static_script/run.sh`
- ARS is AGS's publication sink
- ES later consumes the aggregate evidence and payloads AGS published through
  ARS, but not descriptor/manifest support data on the current hot path, and
  ES does not call AGS on the runtime path

**Boundary pressure points**

- AGS currently sits at the seam between caller input and the canonical aggregate evidence record.
- The publication material AGS assembles determines what ES can verify and admit later.
- AGS and ARS are coupled through the current evidence-centered registration record and the runtime-facing discovery object ARS now owns.
- The shared evidence kernel is narrower than before, but AGS still sits at the split between package/publication claims, narrow derivation request-binding authorization, and execution/runtime claims.

**Temporary compatibility edges**

- `policy_decisions` are structurally normalized on publish, but AGS does not semantically validate them as policy.

**Reopened seams**

- Whether AGS should continue to be the publication boundary for the current fact family
- Whether the current fact assembly model should continue to define the shared cross-service package
- Whether `internal/contracts/evidence/v1` should remain the architecture-defining kernel behind AGS publication

## 8. ES boundary

**Purpose**

Own admission, compose upstream contract checks into an execution decision, submit work to Nomad, project execution status/logs, and retain bounded terminal result bundles without taking ownership of underlying lifecycle state or orchestration decisions.

The authoritative Workstream C classification of ES public execution surfaces,
admission composition, scheduler handoff, retained-result ownership,
runtime-profile handling, and compatibility edges lives in
`.docs/execution_lifecycle/es_execution_admission_model.md`.

**Current ownership**

- Public request surfaces:
  - `/v1/executions:contract`
  - `/v1/executions:prepare`
  - `/v1/executions:submit`
  - `/v1/executions/{run_id}/status`
  - `/v1/executions/{run_id}/logs`
  - `/v1/executions/{run_id}/result`
  - `/v1/executions/{run_id}:cancel`
- Admission validation and execution request shaping
- Composition across startup-owned runtime-config references, ARS, and EGS during prepare and submit, with CGS explicitly outside the current hot path
- Current runtime-config consumer and lookup orchestration during prepare and
  submit; the workload-zone Vault runtime-config semantics themselves live in
  `internal/contracts/runtimeconfig/v1`
- Startup-time trust model loading and verification
- Nomad job submission and bounded runtime mount/environment assembly
- Projection of lifecycle and logs from Nomad without synthesizing independent ES lifecycle state, including the bounded status `lifecycle_projection` read-coordination fact
- Bounded retained-result storage for opaque tar.gz bundles captured from `/execution/run/result` in the current `static-script` slice
- Additive outcome/evidence descriptors for current lifecycle observations and retained outputs that ES can directly source: Nomad status projection depth, Nomad task stdout, accepted Nomad stop request receipts, and opaque ES-retained result bundles
- A narrow non-secret producer compatibility declaration for the current governed-execution contract, submit/profile enablement, and mandatory outcome-evidence response carriers
- `GET /v1/executions:contract` remains a narrow producer compatibility
  declaration, not health, submit readiness, run authority, or a general
  capability registry.
- `POST /v1/executions:prepare` remains bounded preflight and creates no run
  object or scheduler handoff.
- `POST /v1/executions:submit` remains the MVP execution handoff surface:
  async, bounded receipt, and Nomad submission through ES.
- Runtime identity endpoint handoff and ES-owned subtree protection for the backing workspace
- Current runtime-identity handoff selection, environment injection, reserved
  path layout, mount assembly, and Nomad job construction for the bounded
  slice
- Consumption of workload-zone vault runtime fields plus the bounded local default auth mode
- Bounded non-secret `authority_handoff` read facts for submitted runs, sourced from ES-selected runtime handoff facts and the submitted runtime spec
- One bounded opt-in runtime profile for Control Plane normal-shell workloads:
  - profile name `control-plane-normal-shell/v1`
  - selected by `invocation.annotations["execution_substrate.runtime_profile"]`
  - realized by an ES-configured Docker image
  - exposes only non-secret Codex credential-location metadata to the workload
  - relies on the existing platform-owned runtime identity endpoint plus workload-side Vault login for credential material acquisition
  - carries workload-zone Vault CA trust material when the runtime config supplies it, without becoming a Vault token broker

**Explicit non-ownership**

- Artifact publication
- Artifact storage
- ARS descriptor/manifest/index/support tuple grammar as ES public grammar
- Trust model publication
- Canonical lifecycle state independent of Nomad
- Control Plane checkpoint, review, accept, revise, fail, hold, resume, reject, escalation, or terminal-run semantics
- Semantic interpretation of workload-authored result bundle contents
- Vault token minting, storage, or rotation
- Runtime identity endpoint implementation inside the task; the current
  supervisor/helper owns endpoint serving, helper-private SPIRE traversal,
  readiness-before-workload, and root-to-workload privilege boundary
- Workload-vault selector policy or workload-specific auth-role/audience override logic
- Runtime-config semantic ownership beyond ES's current consumer/lookup role
- `authority_handoff.runtime_config_refs` as runtime-config authority or live
  credential truth
- Raw SPIRE socket exposure to workloads
- JWT-SVID issuance or payload brokerage
- Vault token, secret, or lease issuance after workload-side login
- Live credential possession, lease, token-expiry, or rich approval-state observation behind the `authority_handoff` read surface
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- Scheduler identifiers, backend allocation/task IDs, global ES run revisions, cancel completion truth, result-content meaning, stdout/stderr completeness, or write-precondition semantics behind the `outcome_evidence` descriptor surface
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- Service health, submit readiness, run authority, credential truth, lifecycle write coordination, policy truth, or scheduler API semantics behind the producer compatibility declaration
- CGS authorize decisions, policy-approval state, or runtime auth-plan truth as ES hot-path admission inputs, `authority_handoff` facts, `outcome_evidence`, or producer-contract truth
- Policy publication or broader governance decisions that belong upstream
- Control Plane normal-shell orchestration, task-attempt progression, review, accept/revise/fail branching, checkpoint promotion, hold/resume/reject semantics, or finalization
- Codex token brokerage, Codex token minting, Codex token rotation, Codex service invocation ownership, or semantic interpretation of Codex outputs
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- ES must not absorb CP attempt/review/checkpoint/finalization semantics.
- ES must not become a Vault token broker, Codex credential broker, IM
  readiness authority, CP run-control authority, or maintenance-agent
  authority.
- Runtime identity or credential authority from CGS authorize output,
  `id.conf`, `policy.id_conf_path`, `audit.policy_version`, CGS v1/v2 design
  docs, EGS `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, runtime-config refs, `authority_handoff.runtime_config_refs`,
  ARS blob mechanics, digest-only runtime-config refs,
  `workload_vault_auth.default_mode`, retained bundles, `outcome_evidence`,
  `authority_handoff`, IM profiles, support bundles, logs, traces, reports,
  `.out` artifacts, or CP review/approval/checkpoint/finalization state

**Current consumers / collaborators**

- The current repo-owned operator path invokes ES directly, and additional callers may do so if their SPIFFE paths are allowed by ES config
- The first repo-owned non-operator governed-execution caller activation path is Control Plane at `spiffe://execution.internal/service/control-plane`
- The current repo-owned direct API example for that caller lives at `.examples/control_plane_static_script/run.sh`
- ES consumes ARS evidence and payloads, EGS trust policy, and the configured workload-zone Vault config reference
- Nomad is the execution backend ES submits to and reads from
- The supported-local CP consumer runbook documents how CP consumes the accepted ES surface; it does not define ES core contracts.

**Boundary pressure points**

- ES currently composes multiple upstream services into one admission path, making it the main cross-boundary choreography point.
- `:prepare` and `:submit` are intentionally bounded current surfaces, not statements that this request shape is settled architecture.
- `:submit` is now the primary public execution handoff, while `:prepare` is a much smaller preflight-success surface.
- ES now requires aggregate artifact evidence for first-class admission and mount preparation; absence or corruption of that evidence fails the ES path instead of reviving the legacy fact family.
- ES submit now consumes the payload reference discovered through ARS and cross-checked against aggregate evidence claims; it does not depend on artifact identity equaling payload identity.
- ES now localizes its current lifecycle lookup and projected-allocation rules inside explicit internal policy code instead of letting those Nomad-shaped assumptions drift across helpers and tests.
- ES status now exposes only the bounded `lifecycle_projection.source` and opaque same-run read-coordination `lifecycle_projection.revision` facts from that projection path; it still does not expose Nomad job IDs, allocation IDs, task-state detail, or scheduler sequencing semantics as public lifecycle contract.
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- C2 is the narrow tests/docs guardrail slice for this submit/lifecycle
  projection boundary. It preserves ES-owned async submit through Nomad,
  bounded submit receipts without Control Plane run-control grammar,
  non-secret `authority_handoff` evidence, status/logs/result/cancel
  compatibility, and `control-plane-normal-shell/v1` compatibility. It does
  not redesign runtime behavior, retained results, runtime identity, Vault
  handoff, Nomad integration, or Control Plane behavior.
- C3 is the focused tests/docs guardrail slice for retained-result and
  `authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
  C3 pins that retained result bundles remain ES-owned opaque output artifacts
  and that CP may materialize, review, checkpoint, and finalize retained result
  contents semantically, but CP does not own the retained bundle as run-control
  state. Retained result references, paths, manifests, archives, `.out`
  copies, and materialized workspaces are evidence/projection or
  implementation detail, not orchestration authority.
  `GET /v1/executions/{run_id}/result` compatibility shape remains unchanged
  unless an explicit migration/versioning plan exists. `authority_handoff`
  remains bounded non-secret runtime handoff evidence only.
  `authority_handoff` never carries or implies live credentials, Vault tokens,
  Codex credentials, leases, approvals, operator authorization, CP workflow
  state, scheduler truth, or retained-result authority. Runtime identity/Vault
  handoff remains workload-side and non-secret; ES does not become a Vault
  token broker or Codex credential broker. `outcome_evidence` remains bounded
  evidence/projection; current labels remain compatibility surfaces.
  `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- C4 is the focused tests/docs guardrail slice for runtime identity and Vault
  handoff boundaries. C4 is guardrail work, not runtime redesign and not live
  helper execution. Runtime identity acquisition is workload-side or
  helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
  non-secret runtime identity and Vault configuration metadata, but ES must
  not mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES
  must not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies,
  private keys, API keys, proof secrets, root tokens, unseal keys, Vault client
  tokens, or secret payloads through public DTOs, lifecycle responses,
  retained-result metadata, summaries, logs, reports, `.out`, support bundles,
  or proof artifacts. `authority_handoff` may include non-secret
  credential-location and configuration metadata only. `authority_handoff`
  must not carry live credentials, leases, approvals, Vault tokens, Codex
  credentials, JWT-SVIDs, API keys, or scheduler truth. Workload-side Vault
  auth remains workload-side; Vault owns token, secret, and lease authority.
  SPIRE owns identity issuance and SVID material. ES must not expose raw SPIRE
  socket access to workloads as public ES grammar.
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the workload-facing identity
  endpoint contract rather than raw SPIRE socket access. Runtime identity and
  Vault handoff evidence remains non-authoritative and redacted. CP may
  consume runtime identity/Vault handoff evidence, but CP does not own
  credential acquisition, Vault tokens, SPIRE identity issuance, or ES runtime
  handoff boundaries. IM and Maintenance Agent may report
  diagnostics/readiness/status, but do not own runtime identity or Vault
  authority. `control-plane-normal-shell/v1` and
  `execution_substrate.runtime_profile` compatibility remain preserved unless
  an explicit migration/versioning plan exists. Existing workload-auth Remote
  Alpha helpers remain bounded operator/support surfaces, not ES token
  brokerage or production Vault readiness.
- C5 is the focused tests/docs guardrail slice for current
  status/logs/result/cancel compatibility and non-authority posture. C5 is
  guardrail work, not runtime redesign, live proof, or remote validation.
  Status remains Nomad-backed lifecycle projection and evidence, not CP
  workflow truth or ES lifecycle-store truth. Logs remain a bounded current
  compatibility/evidence surface, not final log architecture, CP run-control
  truth, or scheduler authority. Result remains opaque ES-retained output
  delivery, not CP checkpoint, finalization, or review state. Cancel remains a
  bounded ES/Nomad cancellation handoff, not CP intervention authority,
  operator approval authority, or Temporal workflow truth. Status/cancel JSON
  envelopes and successful logs/result headers must exclude CP run-control
  grammar and live credential/security fields, while logs/result bodies remain
  payload/output surfaces under the existing compatibility contract and are
  not newly sanitized, interpreted, or promoted into authority.
- ES status/cancel JSON and successful logs/result responses now include additive outcome/evidence descriptors that label what ES observed or retained without promoting the current scheduler lookup, projected-allocation rule, stdout path, or retained-result storage layout into broader public contract.
- ES exposes `GET /v1/executions:contract` so allowed CP/IM consumers can verify the current producer contract and mandatory outcome-evidence carriers before submitting a high-value run, without treating the declaration as readiness, run authority, credential truth, or scheduler API.
- ES submit/status now expose a bounded `authority_handoff` fact for non-secret runtime authority handoff evidence; it still does not expose live credential state or scheduler identifiers.
- ES now localizes payload staging, mount staging, result-directory staging, and runtime-ready package assembly behind one explicit internal execution-package layout; the current `/execution/...` runtime paths, `/execution/run/result`, and runtime-identity backing subtree remain active conventions inside that layout.
- F0 documents the current runtime identity handoff ownership split without
  making helper/root/Nomad task-user/SPIRE traversal/reserved-path surfaces
  final generalized architecture.
- ES retained-result storage closes the current terminal-output gap for real clients without making stdout logs a fake result contract and without making ES a Control Plane state store.
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.
- ES now relies only on the narrower shared execution/runtime inputs it actually enforces: runtime env allowlist, required capabilities, `target_platform`, and `network_access`.
- The current `verification.derivation_attestation.*` and
  `verification.workload_identity_binding.*` config/startup verifier shapes are
  residue from earlier admission forms. They do not add active shared-kernel
  authorization meaning or CGS coupling to the current ES hot path.
- D1 keeps ES consuming no CGS facts. If a later slice adds a CGS-derived ES
  admission input, it must use a separately versioned bounded authorization
  fact such as allow/deny plus opaque decision reference and expiry rather than
  the current CGS v1 request/response shape, subject grammar, role fields,
  `audit.policy_version`, runtime auth-plan material, workload-vault fields,
  runtime-config refs, credential material, or identity-handoff facts.
- D1b keeps that future fact design-only. If a later versioned CGS
  authorization fact is added, it may carry only allow/deny, opaque decision
  reference, expiry or another bounded freshness indicator if justified, and
  audit/evaluation metadata that remains non-authoritative outside CGS.
- That hypothetical future fact must not carry JWT-SVIDs, credential payloads,
  scheduler facts, ES lifecycle/admission facts, workload-zone Vault ownership
  facts, or Control Plane review/approval/checkpoint/finalization semantics.
- D1c keeps ES consuming EGS only for signed signer/artifact runtime trust.
  EGS publication metadata remains outside the signed payload and outside ES
  hot-path admission facts.
- D1c keeps any future EGS versioned runtime-trust wrapper design-only and
  requires explicit wrapper/payload/versioning before implementation.
- D1c does not change the Workstream B AGS/ARS artifact
  publication/storage/discoverability decision, does not change the
  Workstream C ES admission/runtime public model, does not reopen the accepted
  Workstream A/B/C decisions, and does not settle Workstream E runtime-config
  ownership or Workstream F runtime-identity handoff.
- D1d keeps `id.conf`, the current CGS v1 subject grammar, and
  `policy.id_conf_path` outside the ES admission model. They remain
  CGS-local current-v1 compatibility/config residue, not ES admission policy
  truth, runtime-config ownership input, or runtime-identity handoff input.

**Temporary compatibility edges**

- `/v1/executions:prepare` exists as a bounded milestone surface and is explicitly not the permanent public API endpoint.
- `/v1/executions:contract` exists as a bounded producer compatibility declaration for the current CP governed-execution path. It should not grow into a general capability registry by drift.
- Current runtime mount conventions use `/execution/staged`, `/execution/run`, `/execution/run/result`, and the current ES-owned runtime-identity backing layout.
- The workload-visible runtime identity convention currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT`.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract only. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- Helper start as `0:0`, Nomad task `User: "0:0"`, fixed workload
  `10000:10000`, helper-private SPIRE traversal, and current reserved runtime
  paths are bounded or compatibility-heavy first-slice surfaces.
- The `authority_handoff` field layout and evidence labels are current read vocabulary for the bounded handoff slice, not a durable policy or lifecycle model.
- The `outcome_evidence` JSON field layout, successful logs/result evidence headers, and observation labels are current read vocabulary for the bounded Nomad/retained-result slice, not durable scheduler, result, log, cancellation, or lifecycle architecture.
- ES currently supports only async submit mode and only `static-script` artifacts for real execution.
- The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and retained `application/gzip` bundle retrieval shape are active compatibility edges for the bounded retained-result slice, not a broad output platform, raw path reference model, artifact-serving authority, or CP materialization authority.
- `control-plane-normal-shell/v1` is a bounded `static-script` runtime-profile overlay for the CP normal-shell attempt slice. It is not a broad package-kind redesign, a general developer image contract, or a transfer of CP control semantics into ES.
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- Current CP compatibility for publish -> prepare -> submit -> status/logs/result/cancel is a retained consumer edge. Breaking it requires an explicit compatibility, drain, migration, or versioning plan rather than an implied ES boundary change.

**Reopened seams**

- The long-term ES request model and package-resolution shape
- The current division between prepare-time composition and submit-time execution
- The current execution-package layout, retained-result behavior, result-reference vocabulary, and reserved path conventions
- Retained-result route evolution, result payload identity versus artifact identity, CP materialization semantics, and artifact discovery/index long-term shape
- The final owner and vocabulary for the remaining shared execution/runtime inputs
- Whether runtime profiles remain annotation-selected overlays or become part of a later re-derived ES admission model
- The long-term runtime-identity owner, helper/root/task-user model, SPIRE
  selector posture, Vault posture, and reserved-path architecture

## 9. EGS boundary

**Purpose**

Publish a signed trust model that downstream execution logic can verify and enforce.

**Current ownership**

- `GET /v1/trust-model`
- Signed signer/artifact runtime-trust publication plus separate EGS-owned publication metadata
- Current runtime-trust and publication-metadata shape in `egs/model/trustmodel.go`
- Signing the runtime-trust payload returned to consumers, with publication metadata remaining separate and outside the signed payload
- Publication of allowed signers, revoked signers, and revoked artifacts as the signed runtime-trust payload
- Publication of version and update revision as separate EGS-owned metadata

**Explicit non-ownership**

- Artifact signing
- Artifact publication
- Authorization decisions or runtime auth-plan shaping
- Execution request validation
- Runtime lifecycle state
- ES runtime handoff facts
- Runtime credential delivery

**Current consumers / collaborators**

- ES loads and verifies the trust model on startup, then uses it during artifact admission

**Boundary pressure points**

- The current trust model form directly shapes what ES can enforce without further interpretation.
- EGS signs its own runtime-trust payload format rather than reusing the AGS/ES shared signing kernel, which keeps the boundary narrow but makes the EGS contract family distinct.
- D1b does not expand the EGS boundary. EGS remains signer/artifact
  runtime-trust publication plus separate EGS-owned publication metadata only.
- D1c keeps any future EGS versioned trust wrapper design-only. ES continues
  to consume EGS only for signed signer/artifact runtime trust, while EGS
  publication metadata remains unsigned service-owned metadata outside that
  payload.

**Temporary compatibility edges**

- The route remains `GET /v1/trust-model` even though the signed shared payload is now the narrower `runtime_trust` contract plus separate publication metadata.
- The current route plus wrapper/payload shape are the live EGS v1 compatibility surface.
- `publication.version` and `publication.update_revision` are EGS publication metadata, not trust-contract/schema/API versioning for that surface.
- Semantic expansion of the EGS trust surface requires explicit wrapper/payload versioning before implementation; do not widen the current v1 surface in place.
- D1b keeps that surface design-stable at signer/artifact runtime trust only;
  it does not add authorization, runtime-config, runtime-identity, or
  orchestration semantics to EGS.
- D1c is design-only and docs/tests-only. It does not implement EGS v2 or
  change the current `GET /v1/trust-model` route, wrapper, signed
  `runtime_trust` payload, or signing behavior.
- Any future EGS semantic expansion requires explicit
  wrapper/payload/versioning before implementation.
- Any future versioned EGS trust wrapper must distinguish signed runtime-trust
  payload facts, unsigned publication/discovery metadata, compatibility
  routing or API version, and non-authoritative service metadata.
- That future wrapper must not carry CGS authorization decisions, Control
  Plane review/approval/checkpoint/finalization semantics, runtime auth plans,
  Vault token material, JWT-SVIDs, credential payloads, scheduler truth, ES
  lifecycle/admission truth, runtime-config refs, workload-zone Vault
  ownership facts, runtime identity handoff facts, or AGS/ARS
  artifact-publication authority.

**Reopened seams**

- The long-term trust model form exposed by EGS
- Whether the current trust model fields are the right boundary between policy publication and execution enforcement

## 10. CGS boundary

**Purpose**

Provide a separate authorize-only decision surface for workload credential access using caller/workload identity checks and startup-loaded explicit subject policy.

**Current ownership**

- `POST /v1/credential/authorize`
- Direct authorize-only decisions for current requested capabilities
- Policy loading from `id.conf`
- Mapping authenticated callers and workload principals into authorization decisions
- Workload-bound caller/workload identity matching on the live request path

**Explicit non-ownership**

- Artifact publication
- Trust model publication
- ES scheduler submission or lifecycle state
- Scheduler facts or ES lifecycle/admission facts
- General execution admission
- Runtime auth-plan shaping
- ES runtime handoff facts
- Runtime-config refs or workload-zone Vault ownership facts
- Credential material, Vault token material, or JWT-SVID material
- Credential payloads
- Vault token issuance or workload-vault auth-plan shaping
- Control Plane review/approval/checkpoint/finalization semantics

**Current consumers / collaborators**

- External callers can invoke CGS directly if authenticated
- CGS is active today, but it is not part of the current ES hot path

**Boundary pressure points**

- `id.conf` still strongly influences CGS's current explicit subject grammar and policy-input shape.
- CGS's request and decision logic now center on caller/workload identity interpretation instead of path-derived workload location.
- CGS must stay separate from ES-owned workload-vault auth resolution and runtime identity handling.

**Temporary compatibility edges**

- The current request/response shape is the live CGS v1 compatibility surface.
- `audit.policy_version` is CGS audit/evaluation metadata, not transport/schema/API versioning.
- `id.conf` remains current-CGS-v1 compatibility/config residue even while it is active today.
- `id.conf` remains active as the current explicit subject-policy grammar even though its long-term role is reopened.
- The repo ships a minimal checked-in baseline at `cgs/policy/id.conf`.
  - It exists to make the current `id.conf` dependency explicit and testable.
  - It does not expand `id.conf` into a declared complete production policy grammar or final policy architecture.
- D1d keeps `id.conf`, the current CGS v1 subject grammar, and
  `policy.id_conf_path` as CGS-local current-v1 compatibility/config residue
  rather than a shared policy language or repo-wide policy registry.
- D1d keeps those surfaces out of ES admission policy truth, EGS trust truth,
  Control Plane review/approval/checkpoint/finalization policy truth, and
  Infrastructure Manager readiness/profile/support-bundle authority truth.
- D1d keeps `id.conf` out of Workstream E runtime-config ownership and
  Workstream F runtime-identity handoff.
- Semantic expansion of the CGS authorize surface requires explicit versioning before implementation; do not widen the current v1 surface in place.
- D1b is design-only and docs/tests-only. The current `POST /v1/credential/authorize` shape remains CGS v1 compatibility, and any future CGS v2 authorize contract must be explicitly versioned before behavior changes land.
- D1b keeps ES as a non-consumer. Any hypothetical future ES-consumed CGS fact must stay version-gated and limited to allow/deny, opaque decision reference, expiry or another bounded freshness indicator if justified, and audit/evaluation metadata that remains non-authoritative outside CGS.
- That future fact must not become runtime auth plans, scheduler facts, ES lifecycle/admission facts, runtime-config refs, workload-zone Vault ownership facts, identity-handoff facts, or Control Plane review/approval/checkpoint/finalization semantics.
- D1b does not rewrite the current `id.conf` grammar or evaluation and does not expand EGS beyond signer/artifact runtime-trust publication.
- D1d is design-only and docs/tests-only. It does not change current
  `POST /v1/credential/authorize` behavior, does not implement CGS v2, and
  does not change EGS trust semantics, ES admission behavior, Workstream E
  runtime-config ownership, or Workstream F runtime-identity handoff.

**Reopened seams**

- The long-term authorize DTO and policy-input model
- The role of `id.conf` as a continuing architecture-defining contract
- Whether CGS remains a narrow compatibility boundary or becomes part of a redesigned policy/runtime identity split

## 11. Cross-cutting packages that are not service boundaries

| Package / layer | Current role | Boundary note |
| --- | --- | --- |
| `internal/contracts/evidence/v1` | Active shared kernel for the aggregate AGS -> ARS -> ES artifact-evidence path | Cross-service kernel and redesign pressure point, but not a standalone service boundary |
| `internal/httpx` | Cross-cutting transport helper for strict JSON request decoding, text responses, JSON responses, and method negotiation headers | Support layer only; it standardizes low-level HTTP mechanics without owning auth, lifecycle, or domain behavior |
| `internal/observability` | Cross-cutting utility for request tracing, dependency logging, and trace propagation decisions | Support layer only; it does not own business behavior or define service authority |
| service bootstrap / config entrypoints | Service-local startup wiring, config loading, auth setup, and dependency client construction | Support layer; may reveal coupling, but does not by itself define a service boundary |

These layers can create coupling pressure without owning domain responsibilities. Future edits must not let a shared package silently become a de facto new service boundary.

## 12. Boundary leaks and pressure points

- `internal/contracts/evidence/v1` now concentrates the shared artifact-kernel role between AGS, ARS, and ES. That shared-kernel scope is active today and remains a redesign pressure point rather than a declared final boundary split.
- ES, ARS, and the runtime-config surface currently participate in a tight choreography around reference resolution, artifact retrieval, trust validation, and execution preparation. ES carries the composition burden, but the split is still under redesign pressure.
- The ARS runtime-facing discovery record and secondary descriptor support path constrain both AGS publication and ES discoverability. That storage-facing model still reaches further into service interaction than a pure storage boundary would.
- ES runtime identity handoff currently depends on reserved runtime workspace paths and environment conventions, including a temporary legacy alias. Those conventions are real, but they should not be mistaken for a settled ownership split between ES and runtime-side components.
- CGS's authorize surface is narrow, but its DTO and policy inputs remain coupled to compatibility-oriented `id.conf` and caller/workload identity interpretation.
- The workload-zone Vault config reference and blob schema are now explicit, but the long-term owner of that surface is still a redesign pressure point.

## 13. Temporary compatibility-heavy edges

- ES `:prepare` remains an active but bounded compatibility surface rather than the declared long-term execution API.
- ES runtime path conventions under `/execution/staged`, `/execution/run`, and the current ES-owned runtime-identity backing root are active today but should be treated as conventions under review.
- AGS retains request fields such as `builder_service` and `policy_decisions` in forms that help preserve the current publication slice without proving those fields belong in the long-term kernel.
- ARS exposes a smaller runtime-facing discovery record plus a secondary descriptor support path because that is the active bounded choreography, not because that specific split is already frozen as the final storage boundary.

## 14. Reopened redesign seams

- Workload-zone Vault runtime-config ownership, especially the long-term owner of the named config reference
- ARS storage, registration, and discoverability shape, including the current runtime-facing discovery record, secondary descriptor support path, and index contract
- AGS publication responsibility shape and its relationship to shared signed fact assembly
- ES admission surface and runtime package boundary, including prepare/submit partitioning and package-resolution assumptions
- EGS policy-publication shape, especially the current trust model form
- CGS authorize and policy-input shape, especially the role of `id.conf`
- ES runtime identity handoff surface, including reserved runtime workspace conventions
- The role of `internal/contracts/evidence/v1` in cross-boundary coupling

These seams are intentionally open in the redesign phase. Future readers must not treat the current shapes as fixed endpoints without an explicit decision.

## 15. Decision rules for future boundary changes

- Do not preserve a boundary split without naming what that split buys in ownership clarity or risk reduction.
- Document explicit non-ownership, not just ownership.
- Label compatibility-only edges when they are retained.
- Do not let a shared package silently become a new service boundary.
- Keep boundary changes aligned with `PLANS.md` and `.docs/system_overview/contracts.md`.
- If code and tests disagree with this document, update the document to match reality.
- No service boundary becomes "fixed" unless it is named explicitly as such in the authoritative docs.
