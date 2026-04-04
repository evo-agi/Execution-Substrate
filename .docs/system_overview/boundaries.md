# Service Boundary Map

## 1. Purpose and scope

A boundary in this repository is an ownership line: which service is authoritative for a behavior, which other services consume that behavior, and which responsibilities remain explicitly outside that service.

This document records the Go repository's current service ownership during the architecture-reset phase described in `PLANS.md`. The boundaries below are real and active today, but they are not automatically permanent architecture. Where the current split is serving a bounded slice, compatibility need, or inherited choreography, that is called out explicitly.

Authoritative sources for this document are, in order:

1. `PLANS.md`
2. `.docs/system_overview/*`
3. `.docs/execution_lifecycle/*`
4. current Go code and tests

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
| ACS | Lookup and assignment indirection service | Governed lookup routes that resolve assignment-shaped keys to digests and assignment payloads |
| ARS | Storage and artifact discoverability service | Blob storage, integrity enforcement, evidence-centered artifact registration, and canonical artifact retrieval |
| AGS | Artifact publication service | Evidence-first publication assembly, caller-bound publication claims, and publication into ARS |
| EGS | Trust model publication service | Signed trust model publication for execution-time trust decisions |
| CGS | Authorization service | Authorize-only decision surface backed by caller/workload identity checks and explicit `id.conf` subject policy |
| ES | Admission, submission, and lifecycle projection service | Execution request validation, composition across upstream services, Nomad submission, and bounded execution status/log projection |

Important absences in the current Go repo:

- There is no standalone Deployment service boundary in this repository.
- There is no standalone IGS service boundary in this repository.
- There is no separate lifecycle-state service boundary beyond ES projecting Nomad state.

Those absences are current facts, not design commitments.

## 4. Boundary interaction rules

- ES is the main composition boundary. It consumes ACS lookup results, ARS artifact evidence/records and blobs, and EGS trust policy during admission and submission.
- AGS depends on ARS as the publication sink. AGS publishes through ARS rather than owning artifact storage or discoverability itself.
- EGS publishes trust policy; ES consumes that policy. EGS does not sit in the runtime execution path after ES has loaded and verified the trust model.
- CGS is a separate authorization boundary. It is active today, but it is not part of the current ES hot path.
- ACS is a lookup authority, not a storage or execution authority. Its outputs influence ES decisions, but ACS does not own execution admission or runtime state.
- ARS is the storage and discoverability authority, not the governance or execution authority. Other services must not rely on ARS to make trust or policy decisions for them.
- `contracts/evidence/v1` is now the active shared cross-service kernel for the primary AGS-published artifact path into ES. It is not itself a standalone service boundary.

## 5. ACS boundary

**Purpose**

Provide governed lookup routes that map assignment-shaped keys to digests and assignment payloads.

**Current ownership**

- Lookup routes under `/v1/configuration/...`
- Request-to-assignment-key parsing for the ACS lookup family
- Assignment lookup results containing `digest`, `assignment`, and `catalog_snapshot_digest`
- Assignment taxonomy defined in `acs/catalog/assignment.go`

**Explicit non-ownership**

- Blob storage or blob integrity enforcement
- Artifact publication
- Execution admission or scheduler submission
- Trust model publication or enforcement
- Runtime identity minting or runtime credential delivery
- General configuration authority beyond the current lookup surface

**Current consumers / collaborators**

- ES currently consumes ACS for workload-zone and vault lookup during preparation
- Other callers may use ACS if their SPIFFE path is allowed by configured prefixes

**Boundary pressure points**

- ACS route families encode assignment taxonomy directly into cross-service lookup paths.
- ES currently depends on ACS to resolve workload-zone and vault-related configuration before submit.
- The current assignment payload and digest indirection shape influence downstream composition even when only a small subset of assignments is in the ES hot path.

**Temporary compatibility edges**

- Returning both `assignment` and `catalog_snapshot_digest` on lookup keeps more context available to consumers than ES currently requires.
- The broader assignment family remains active even though the execution path currently uses only a narrow subset.

**Reopened seams**

- Whether ACS should remain a first-class assignment/digest indirection boundary
- Whether the current route family should continue to define cross-service configuration lookup shape
- Whether ACS is strictly a lookup service or is drifting toward broader configuration authority

## 6. ARS boundary

**Purpose**

Provide artifact blob storage plus the registration and read surfaces that make published artifacts discoverable.

**Current ownership**

- Content-addressed blob write, read, and integrity verification
- Registration of evidence-centered artifact records through `/v1/artifacts:register`
- Fact retrieval through `/v1/artifacts/{artifact_digest}/{kind}`
- Current artifact index entry shape in `ars/index/index.go`
- Read-time guarantees that referenced blobs exist, are integrity-valid, and are JSON-valid where the contract requires JSON facts

**Explicit non-ownership**

- Publish-time fact assembly
- Trust or policy evaluation
- Runtime execution or lifecycle state
- Authorization semantics beyond the bounded write and read caller checks implemented by ARS itself

**Current consumers / collaborators**

- AGS writes blobs and registers artifacts through ARS
- ES reads blobs and artifact evidence/records through ARS
- Other configured callers may read through ARS if their SPIFFE path matches allowed prefixes

**Boundary pressure points**

- The current descriptor-centered registration record shapes what AGS must publish and what ES can later discover through ARS.
- Artifact discoverability is not independent of the registration/index model; downstream services inherit that model.
- AGS now publishes distinct artifact and payload identities. ARS discoverability and ES consumption both depend on the descriptor payload reference plus evidence-claim cross-checks rather than on any hidden digest equality.

**Temporary compatibility edges**

- None on the current ARS boundary.

**Reopened seams**

- The long-term role of the current artifact registration/index model
- Whether ARS should continue to expose the current descriptor-driven discoverability contract
- Whether current artifact read paths are the right ownership split between storage authority and broader choreography

## 7. AGS boundary

**Purpose**

Assemble the publish-time aggregate evidence record, bind publication to the authenticated caller, and publish the resulting artifact package through ARS.

**Current ownership**

- Publish API at `/v1/artifacts:publish`
- Artifact digest derivation from package-facing identity inputs rooted in `payload_digest`, `artifact_type`, and `intent_digest`
- Evidence-native publish request grammar with `artifact`, `publication`, and `admission` sections
- Construction of the aggregate `contracts/evidence/v1` publication record, with package identity/publication claims kept separate from narrow shared derivation request-binding authorization claims and execution/runtime claims
- Construction of manifest as supporting publication data
- Signing of the aggregate artifact-evidence record using `contracts/evidence/v1`
- Bounded publish caller authorization for trusted deployment and operator identities
- Uploading blobs to ARS and registering the evidence-centered artifact record with ARS

**Explicit non-ownership**

- Blob storage or discoverability after publication
- Execution-time trust evaluation
- Runtime admission, submission, or lifecycle projection
- Runtime identity delivery or token minting
- General-purpose signing unrelated to the publish contract

**Current consumers / collaborators**

- Deployment or operator callers invoke AGS directly
- ARS is AGS's publication sink
- ES later consumes the aggregate evidence and payloads AGS published through ARS, but ES does not call AGS on the runtime path

**Boundary pressure points**

- AGS currently sits at the seam between caller input and the canonical aggregate evidence record.
- The publication material AGS assembles determines what ES can verify and admit later.
- AGS and ARS are coupled through the current evidence-centered registration record.
- The shared evidence kernel is narrower than before, but AGS still sits at the split between package/publication claims, narrow derivation request-binding authorization, and execution/runtime claims.

**Temporary compatibility edges**

- `policy_decisions` are structurally normalized on publish, but AGS does not semantically validate them as policy.

**Reopened seams**

- Whether AGS should continue to be the publication boundary for the current fact family
- Whether the current fact assembly model should continue to define the shared cross-service package
- Whether `contracts/evidence/v1` should remain the architecture-defining kernel behind AGS publication

## 8. ES boundary

**Purpose**

Own admission, compose upstream contract checks into an execution decision, submit work to Nomad, and project execution status/logs without taking ownership of underlying lifecycle state.

**Current ownership**

- Public request surfaces:
  - `/v1/executions:prepare`
  - `/v1/executions:submit`
  - `/v1/executions/{run_id}/status`
  - `/v1/executions/{run_id}/logs`
  - `/v1/executions/{run_id}:cancel`
- Admission validation and execution request shaping
- Composition across ACS, ARS, and EGS during prepare and submit
- Startup-time trust model loading and verification
- Nomad job submission and bounded runtime mount/environment assembly
- Projection of lifecycle and logs from Nomad without synthesizing independent ES lifecycle state
- Reserved runtime workspace and runtime-identity path protection

**Explicit non-ownership**

- Artifact publication
- Artifact storage
- Trust model publication
- Canonical lifecycle state independent of Nomad
- Vault token minting, storage, or rotation
- Runtime identity endpoint implementation inside the workload
- Policy publication or broader governance decisions that belong upstream

**Current consumers / collaborators**

- Deployment and operator callers invoke ES directly
- ES consumes ACS lookup results, ARS evidence and payloads, and EGS trust policy
- Nomad is the execution backend ES submits to and reads from

**Boundary pressure points**

- ES currently composes multiple upstream services into one admission path, making it the main cross-boundary choreography point.
- `:prepare` and `:submit` are intentionally bounded current surfaces, not statements that this request shape is settled architecture.
- ES now requires aggregate artifact evidence for first-class admission and mount preparation; absence or corruption of that evidence fails the ES path instead of reviving the legacy fact family.
- ES submit now consumes the payload reference discovered through ARS and cross-checked against aggregate evidence claims; it does not depend on artifact identity equaling payload identity.
- Runtime staging, mount validation, and reserved `/monolith/...` path handling are part ownership and part current convention.
- ES returns and relies on the current workload identity triad: `type`, `service_name`, and `workload_identity_id`.

**Temporary compatibility edges**

- `/v1/executions:prepare` exists as a bounded milestone surface and is explicitly not the permanent public API endpoint.
- Current runtime mount conventions use `/monolith/staged`, `/monolith/run`, and `/monolith/runtime-identity`.
- The environment contract currently injects `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT=unix:///monolith/runtime-identity/endpoint`.
- ES currently supports only async submit mode and only `static-script` artifacts for real execution.

**Reopened seams**

- The long-term ES request model and package-resolution shape
- The current division between prepare-time composition and submit-time execution
- The current runtime package staging and reserved path conventions
- The role of the workload identity triad in the public admission contract

## 9. EGS boundary

**Purpose**

Publish a signed trust model that downstream execution logic can verify and enforce.

**Current ownership**

- `GET /v1/trust-model`
- Current trust model shape in `egs/model/trustmodel.go`
- Signing the trust-model payload returned to consumers
- Publication of allowed signers, revoked signers, revoked artifacts, version, and update revision

**Explicit non-ownership**

- Artifact signing
- Artifact publication
- Execution request validation
- Runtime lifecycle state
- Runtime credential delivery

**Current consumers / collaborators**

- ES loads and verifies the trust model on startup, then uses it during artifact admission

**Boundary pressure points**

- The current trust model form directly shapes what ES can enforce without further interpretation.
- EGS signs its own payload format rather than reusing the AGS/ES shared signing kernel, which keeps the boundary narrow but makes the trust-model surface its own contract family.

**Temporary compatibility edges**

- `source_digest` may be returned to help consumers correlate source material, but it is explicitly not part of the signed payload.

**Reopened seams**

- The long-term trust model form exposed by EGS
- Whether the current trust model fields are the right boundary between policy publication and execution enforcement

## 10. CGS boundary

**Purpose**

Provide a separate authorize-only decision surface for workload credential access using caller/workload identity checks and startup-loaded explicit subject policy.

**Current ownership**

- `POST /v1/credential/authorize`
- Bounded authorization decisions for current requested capabilities
- Policy loading from `id.conf`
- Mapping authenticated callers and workload principals into authorization decisions

**Explicit non-ownership**

- Artifact publication
- Trust model publication
- ES scheduler submission or lifecycle state
- General execution admission
- Vault token issuance or workload-vault auth-plan shaping

**Current consumers / collaborators**

- External callers can invoke CGS directly if authenticated
- CGS is active today, but it is not part of the current ES hot path

**Boundary pressure points**

- `id.conf` still strongly influences CGS's current explicit subject grammar and policy-input shape.
- CGS's request and decision logic now center on workload principal identity instead of path-derived workload location.
- CGS must stay separate from ES-owned workload-vault auth resolution and runtime identity handling.

**Temporary compatibility edges**

- `id.conf` remains active as the current explicit subject-policy grammar even though its long-term role is reopened.
- The repo ships a minimal checked-in baseline at `cgs/policy/id.conf`.
  - It exists to make the current `id.conf` dependency explicit and testable.
  - It does not expand `id.conf` into a declared complete production policy grammar.

**Reopened seams**

- The long-term authorize DTO and policy-input model
- The role of `id.conf` as a continuing architecture-defining contract
- Whether CGS remains a narrow compatibility boundary or becomes part of a redesigned policy/runtime identity split

## 11. Cross-cutting packages that are not service boundaries

| Package / layer | Current role | Boundary note |
| --- | --- | --- |
| `contracts/evidence/v1` | Active shared kernel for the aggregate AGS -> ARS -> ES artifact-evidence path | Cross-service kernel and redesign pressure point, but not a standalone service boundary |
| `observability` | Cross-cutting utility for request tracing, dependency logging, and trace propagation decisions | Support layer only; it does not own business behavior or define service authority |
| service bootstrap / config entrypoints | Service-local startup wiring, config loading, auth setup, and dependency client construction | Support layer; may reveal coupling, but does not by itself define a service boundary |

These layers can create coupling pressure without owning domain responsibilities. Future edits must not let a shared package silently become a de facto new service boundary.

## 12. Boundary leaks and pressure points

- `contracts/evidence/v1` now concentrates the shared artifact-kernel role between AGS, ARS, and ES. That shared-kernel scope is active today and remains a redesign pressure point rather than a declared final boundary split.
- ACS, ARS, and ES currently participate in a tight choreography around lookup, artifact retrieval, trust validation, and execution preparation. ES carries the composition burden, but the split is still under redesign pressure.
- The ARS descriptor-centered registration record constrains both AGS publication and ES discoverability. That storage-facing model currently reaches further into service interaction than a pure storage boundary would.
- ES runtime identity handoff currently depends on reserved runtime workspace paths and environment conventions under `/monolith/...`. Those conventions are real, but they should not be mistaken for a settled ownership split between ES and runtime-side components.
- CGS's authorize surface is narrow, but its DTO and policy inputs remain coupled to compatibility-oriented `id.conf` and workload vault configuration shapes.
- ACS currently exposes a broader assignment taxonomy than the active ES path needs. That creates pressure between ACS as lookup authority and ACS as a potential broader configuration authority.

## 13. Temporary compatibility-heavy edges

- ES `:prepare` remains an active but bounded compatibility surface rather than the declared long-term execution API.
- ES runtime path conventions under `/monolith/staged`, `/monolith/run`, and `/monolith/runtime-identity` are active today but should be treated as conventions under review.
- AGS retains request fields such as `builder_service` and `policy_decisions` in forms that help preserve the current publication slice without proving those fields belong in the long-term kernel.
- ARS exposes a descriptor-centered registration record because that is the active bounded choreography, not because that specific surface is already frozen as the final storage boundary.

## 14. Reopened redesign seams

- ACS authority shape, especially the current assignment and digest indirection model
- ARS storage, registration, and discoverability shape, including the current descriptor and index contract
- AGS publication responsibility shape and its relationship to shared signed fact assembly
- ES admission surface and runtime package boundary, including prepare/submit partitioning and package-resolution assumptions
- EGS policy-publication shape, especially the current trust model form
- CGS authorize and policy-input shape, especially the role of `id.conf`
- ES runtime identity handoff surface, including reserved runtime workspace conventions
- The role of `contracts/evidence/v1` in cross-boundary coupling

These seams are intentionally open in the redesign phase. Future readers must not treat the current shapes as fixed endpoints without an explicit decision.

## 15. Decision rules for future boundary changes

- Do not preserve a boundary split without naming what that split buys in ownership clarity or risk reduction.
- Document explicit non-ownership, not just ownership.
- Label compatibility-only edges when they are retained.
- Do not let a shared package silently become a new service boundary.
- Keep boundary changes aligned with `PLANS.md` and `.docs/system_overview/contracts.md`.
- If code and tests disagree with this document, update the document to match reality.
- No service boundary becomes "fixed" unless it is named explicitly as such in the authoritative docs.
