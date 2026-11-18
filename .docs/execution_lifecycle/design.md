# Execution Lifecycle Design

## 1. Purpose and status

This document describes the current ES lifecycle design in the repository's bounded platform phase.

The lifecycle slice documented here is real and implemented today. At the same time, some lifecycle rules are intentionally bounded and must not be mistaken for long-term architecture simply because they are active in the current slice.

Foundational ES lifecycle and runtime-boundary clarification is primary Execution Substrate program work, not a secondary architecture-only exercise. Control Plane is an important consumer of the accepted ES lifecycle surface, but CP orchestration, review, checkpoint, hold/resume/reject, finalization, and proof-harness semantics do not define ES lifecycle ownership.

This file stays design-level. Detailed endpoint and response rules belong in `.docs/execution_lifecycle/contracts.md`. Current implementation behavior belongs in `.docs/execution_lifecycle/implementation.md`.

The authoritative Workstream C classification of ES public execution surfaces,
admission composition, scheduler handoff, compatibility edges, and reopened
seams lives in `es_execution_admission_model.md`.

The target submit idempotency, submit correlation, and recovery seam lives in
`submit_idempotency_correlation_and_recovery.md`, with the persistence and
concurrency decision in `reliable_submit_persistence_and_concurrency.md`. Those
records keep public/operational reliable keyed submit as target-only and do not
change current unkeyed submit. Their bounded private codec-3 synthetic custody
is a source rule without runtime/effect permission. They select public
opt-in/versioning posture,
local embedded SQLite as the storage family, the current `CGO_ENABLED=0` build
posture, `modernc.org/sqlite v1.54.0` with exact `modernc.org/libc v1.74.1`
coupling, private same-package persistence hydration in
`es/admission/internal/reliablesubmit`, revision/CAS, and provider-effect intent
before external I/O. The private persistence source remains unwired and does
not implement reliable keyed submit end to end. The unavailable
contract-adapter foundation selects private request-family identifiers,
submit-key syntax, caller/key derivation, composite `ClaimID` construction
through the committed pure-model constructor, and ES-neutral outcome semantics,
but it is not called by current runtime code. The adapter and store tranches
alone selected no plan encoding or witness. The later private v1 admission
producer now selects canonical effective-plan encoding, `PlanBinding`
construction from admitted facts and a complete fourteen-category witness,
but remains runtime-unwired and always not-effect-ready. The later codec-3
private slice seals original intent, effective facts and material under
synthetic scope; it does not select production key custody, state-path config,
TTL, HTTP status/public errors, recovery route, Nomad reconciliation or a
`run_id` strategy. Source-grounded current Submit resolution is
selected separately by the private
`resolved-execution-plan-extraction-foundation` described below; it does not
make reliable keyed submit available.

C0 is the docs and docs-contract-test gate for the ES-owned public
execution/admission/runtime model. It makes no runtime implementation changes,
and Workstream C implementation must not start until C0 docs and docs-contract
tests pass.

C2 is the tests/docs guardrail slice for submit and lifecycle projection. It
pins `:submit` as the ES-owned async Nomad handoff, keeps lifecycle projection
Nomad-backed with `source=nomad` and an opaque same-run read-coordination
revision, preserves current status/logs/result/cancel and
`control-plane-normal-shell/v1` compatibility, and does not redesign runtime
behavior.

C3 is the focused tests/docs guardrail slice for retained-result and
`authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
C3 pins that retained result bundles remain ES-owned opaque output artifacts
and that CP may materialize, review, checkpoint, and finalize retained result
contents semantically, but CP does not own the retained bundle as run-control
state. Retained result references, paths, manifests, archives, `.out` copies,
and materialized workspaces are evidence/projection or implementation detail,
not orchestration authority. `GET /v1/executions/{run_id}/result`
compatibility shape remains unchanged unless an explicit migration/versioning
plan exists. `authority_handoff` remains bounded non-secret runtime handoff
evidence only. `authority_handoff` never carries or implies live credentials,
Vault tokens, Codex credentials, leases, approvals, operator authorization, CP
workflow state, scheduler truth, or retained-result authority. Runtime
identity/Vault handoff remains workload-side and non-secret; ES does not
become a Vault token broker or Codex credential broker. `outcome_evidence`
remains bounded evidence/projection; current labels remain compatibility
surfaces. `control-plane-normal-shell/v1` and
`execution_substrate.runtime_profile` compatibility remain preserved unless an
explicit migration/versioning plan exists.

C4 is the focused tests/docs guardrail slice for runtime identity and Vault
handoff boundaries. C4 is guardrail work, not runtime redesign and not live
helper execution. Runtime identity acquisition is workload-side or
helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
non-secret runtime identity and Vault configuration metadata, but ES must not
mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES must
not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies, private
keys, API keys, proof secrets, root tokens, unseal keys, Vault client tokens,
or secret payloads through public DTOs, lifecycle responses, retained-result
metadata, summaries, logs, reports, `.out`, support bundles, or proof
artifacts. `authority_handoff` may include non-secret credential-location and
configuration metadata only. `authority_handoff` must not carry live
credentials, leases, approvals, Vault tokens, Codex credentials, JWT-SVIDs,
API keys, or scheduler truth. Workload-side Vault auth remains workload-side;
Vault owns token, secret, and lease authority. SPIRE owns identity issuance
and SVID material. ES must not expose raw SPIRE socket access to workloads as
public ES grammar. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the
workload-facing identity endpoint contract rather than raw SPIRE socket
access. Runtime identity and Vault handoff evidence remains non-authoritative
and redacted. CP may consume runtime identity/Vault handoff evidence, but CP
does not own credential acquisition, Vault tokens, SPIRE identity issuance, or
ES runtime handoff boundaries. IM and Maintenance Agent may report
diagnostics/readiness/status, but do not own runtime identity or Vault
authority. `control-plane-normal-shell/v1` and
`execution_substrate.runtime_profile` compatibility remain preserved unless an
explicit migration/versioning plan exists. Existing workload-auth Remote Alpha
helpers remain bounded operator/support surfaces, not ES token brokerage or
production Vault readiness.

C5 is the focused tests/docs guardrail slice for current
status/logs/result/cancel compatibility and non-authority posture. C5 is
guardrail work, not runtime redesign, live proof, or remote validation.
Status remains Nomad-backed lifecycle projection and evidence, not CP workflow
truth or ES lifecycle-store truth. Logs remain a bounded current
compatibility/evidence surface, not final log architecture, CP run-control
truth, or scheduler authority. Result remains opaque ES-retained output
delivery, not CP checkpoint, finalization, or review state. Cancel remains a
bounded ES/Nomad cancellation handoff, not CP intervention authority,
operator approval authority, or Temporal workflow truth. Status/cancel JSON
envelopes and successful logs/result headers exclude CP run-control grammar
and live credential/security fields. Logs/result bodies remain raw
payload/output content under the existing compatibility contract and are not
newly sanitized, interpreted, or promoted into authority.

## 2. How to read this document

- **Observed current lifecycle model**: The phase structure and authority split implemented in the current Go repo.
- **Current lifecycle invariant**: A lifecycle rule the current code and tests rely on and that must not change silently.
- **Bounded slice rule**: A live rule used by the current slice that should be treated as a scoped design choice, not automatically permanent architecture.
- **Deliberate absence**: A lifecycle capability or owner the current Go slice intentionally does not include.
- **Reopened lifecycle seam**: A live lifecycle seam that `PLANS.md` and the redesign-phase system docs intentionally keep open.

These labels are intentionally separate. A rule can be real today, bounded in scope, and still explicitly reopened.

## 3. Lifecycle slice snapshot

**Observed current lifecycle model**

- `POST /v1/executions:prepare`
- `GET /v1/executions:contract`
- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- `GET /v1/executions/{run_id}/result`
- `POST /v1/executions/{run_id}:cancel`

Current slice summary:

- `:contract` is a narrow read-only producer compatibility declaration for the current governed-execution contract and mandatory outcome-evidence response surfaces.
- `GET /v1/executions:contract` remains a narrow producer compatibility
  declaration, not health, submit readiness, run authority, or a general
  capability registry.
- `:prepare` is active today, but it is explicitly a bounded preflight surface.
- `POST /v1/executions:prepare` remains bounded preflight and creates no run
  object or scheduler handoff.
- `:submit` is the real execution-submission surface in the current slice.
- `POST /v1/executions:submit` remains the MVP execution handoff surface:
  async, bounded receipt, and Nomad submission through ES.
- Lifecycle after submission is Nomad-backed.
- Submitted runs can expose a bounded non-secret `authority_handoff` read fact describing the ES-selected runtime authority path and evidence source for that handoff.
- Terminal result retrieval is bounded to an ES-retained opaque bundle for the current `static-script` slice.
- ES is a composition and submission boundary, not a scheduler.

## 4. Authority boundaries across the lifecycle

| Lifecycle stage | Primary authority | Role of other components |
| --- | --- | --- |
| Before submission | ES | ES validates the request, composes startup-owned workload-zone Vault config references, ARS, and EGS inputs, and returns a bounded preflight result. ARS is authoritative for runtime-facing artifact discovery, evidence and payload blob reads, and workload-zone vault blob reads. Descriptor/manifest support data remain secondary publication detail rather than current ES hot-path admission inputs. EGS is authoritative for runtime-trust publication. |
| At submission | ES hands off to Nomad | ES reuses preparation, stages the payload and runtime mounts, reserves runtime-identity workspace, builds one Nomad batch job, and submits it. Nomad becomes the execution backend for the submitted run. |
| After submission | Nomad | Nomad is authoritative for submitted job and allocation state. ES does not become a parallel lifecycle owner. Docker remains the task runtime under Nomad. |
| Runtime identity handoff | ES owns the handoff boundary only | ES reserves runtime paths, injects endpoint-discovery environment conventions, and may expose bounded non-secret `authority_handoff` facts about the submitted handoff. It does not populate token material, implement the workload-side endpoint, or mint runtime credentials. |
| Lifecycle inspection and control | Nomad, accessed through ES | ES validates `run_id`, resolves the current internal execution locator, reads Nomad job and projected-allocation state, reads task stdout, fetches retained terminal result bundles when present, and asks Nomad to stop jobs. ES projects or forwards that state; it does not own a separate lifecycle registry. |
| Terminal result retention | ES for the retained opaque bundle only | The workload may write files under `/execution/run/result` in the current `static-script` slice. ES may package those files into an opaque retained tar.gz bundle under `execution.results_root_dir`. Publication and staging retention are independent; ES does not parse result files into orchestration, checkpoint, or Control Plane semantics. |

## 5. Phase model

### 5.1 Preparation phase

`GET /v1/executions:contract` is a live read-only compatibility declaration in the current repo. It lets allowed clients verify that ES declares the current governed-execution producer contract, submit/profile enablement, and mandatory outcome-evidence carriers before a run starts.

The declaration is intentionally not a health check, readiness proof, artifact-specific prepare result, run authority, credential truth, lifecycle state, write-precondition token, or scheduler API.

`POST /v1/executions:prepare` is a live public surface in the current repo.

At a design level, it currently does four things:

- validates the incoming execution request and runtime constraints
- requires the registered runtime-facing artifact discovery record from ARS and follows it to aggregate evidence for admission
- does not require ARS descriptor or manifest support data on the current hot path
- verifies publish-time evidence and trust requirements using the active shared evidence kernel and the loaded EGS trust model
- resolves workload-zone vault metadata through the configured runtime-config reference and ARS, then returns bounded preflight success

`.docs/system_overview/artifact_publication_storage.md` records the authoritative Workstream B publication/storage/discoverability decision that this lifecycle design consumes. The preparation phase follows ARS discovery plus explicit evidence/payload references, keeps descriptor/manifest support paths as secondary compatibility support rather than current ES hot-path public grammar, and preserves the explicit separation between `artifact_digest` and `payload_digest`.

The result is intentionally bounded. It proves preflight success after admission composition, but it does not create a run ID, scheduler record, proto-execution state, or a public bundle of internal composition detail.

This makes `:prepare` both active and bounded: it is part of the current design, but it is not presented here as the permanent long-term execution API shape.

### 5.2 Submission phase

`POST /v1/executions:submit` is the current real execution surface.

At a design level, it currently:

- reuses the full preparation path first
- resolves the artifact payload through the explicit payload digest carried by aggregate evidence, then stages it locally
- revalidates and stages runtime mount artifacts when mounts are requested
- reserves the runtime-identity workspace and enforces reserved-path exclusions
- resolves the optional bounded runtime profile selection from `invocation.annotations["execution_substrate.runtime_profile"]`
- assembles the bounded non-secret authority handoff facts for the selected runtime path
- constructs one Nomad batch job with one Docker task
- submits that job to Nomad and returns a bounded submission receipt

In the current slice, `:submit` does not become:

- a durable run registry
- a richer execution-state model
- a sync execution API
- an orchestration layer above Nomad

### 5.3 Lifecycle projection phase

After submission, lifecycle is projected from Nomad.

At a design level:

- `status` reads Nomad job and allocation state and returns a minimal mapped view centered on `submitted`, `running`, or `terminal`
- `status` also returns a bounded `lifecycle_projection` read fact whose source is Nomad and whose revision is an opaque same-run read-coordination token
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- `status` also returns additive `outcome_evidence` that labels which current Nomad observation family backed the served projection and references the same opaque lifecycle projection token
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- `status` may also return `authority_handoff` by recovering ES-submitted non-secret runtime handoff facts from the submitted runtime spec
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- `logs` reads stdout for the selected task from Nomad and labels successful bodies as current Nomad task stdout
- `result` returns an ES-retained opaque tar.gz bundle for files the workload wrote under the bounded reserved result directory and labels successful bodies as opaque retained bundles
- `cancel` asks Nomad to stop the job and labels the receipt as an accepted stop request without turning ES into a broader control-plane owner or claiming observed termination
- status/cancel JSON envelopes and successful logs/result headers remain
  evidence/compatibility envelopes; they do not carry CP review, checkpoint,
  finalization, intervention, approval, hold/resume/reject, Temporal,
  workflow, or live credential/security vocabulary
- logs and result bodies remain payload/output surfaces under the existing
  compatibility contract; ES does not sanitize, interpret, or promote raw
  content into scheduler, CP run-control, credential, or policy authority

This is a bounded projection model, not rich execution tracking. ES does not maintain a run store, aggregate multiple allocations into its own timeline, or synthesize lifecycle state from staging side effects.
The lifecycle projection revision lets consumers compare equality or change for the same run without treating Nomad job IDs, allocation IDs, or ES staging side effects as contract. It is not parseable or orderable scheduler state.
The outcome evidence descriptors let consumers distinguish what ES observed or retained for the current response without treating those labels as scheduler IDs, write preconditions, log/result revisions, policy truth, credential truth, or a global ES run revision.
The authority handoff fact lets consumers see the ES-selected runtime authority path without treating it as live credential state, scheduler identity, or Control Plane orchestration truth.

### 5.4 Terminal result materialization phase

The current `static-script` slice now reserves `/execution/run/result` as a workload-authored terminal output directory.

At a design level:

- workload code may write result files there
- ES treats the directory contents as opaque output material
- when ES observes terminal execution through `status`, `logs`, or `result`, it idempotently packages non-empty result contents into a retained tar.gz bundle keyed by `run_id`
- retained bundles live under `execution.results_root_dir`, outside `execution.staging_root_dir`
- result publication success, absence, conflict, or failure never mutates the retained staging root
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.

Every post-claim run root is retained: failed or partial Submit, ambiguous or
accepted Nomad registration, terminal success or failure, cancellation, loss,
unknown provider evidence, and every result-publication outcome all leave the
visible root in place. ES implements exclusive creation and descriptor-relative
materialization, but no automatic whole-root reclamation. Future governed
reclamation is an ES-owned reopened redesign seam and carries explicit disk,
capacity, sensitive-material-residence, and operator costs.

This is intentionally not a general output platform. It does not create callbacks, streaming output, checkpoint promotion, review/accept/revise branching, or an ES-owned terminal decision model.

## 6. Current lifecycle invariants

**Current lifecycle invariants**

- Nomad is authoritative for submitted execution lifecycle after `:submit`.
- ES does not become the scheduler.
- Lifecycle responses are projections of Nomad state, not ES-owned execution state.
- The status `lifecycle_projection.revision` is an opaque same-run read-coordination token derived from Nomad observation, not a write precondition, ordering token, Nomad identifier or index, or an ES lifecycle-state version.
- `outcome_evidence` is read-only response evidence. It does not add scheduler identifiers, result-content interpretation, log completeness guarantees, cancellation completion truth, or write coordination.
- `:submit` returns a bounded submission receipt rather than a durable run model.
- ES does not own lifecycle persistence, lifecycle reconciliation, or a parallel run registry.
- Runtime identity or runtime credential failures remain workload/runtime failures rather than creating a new ES lifecycle phase.
- `authority_handoff` is read-only handoff evidence and does not become lifecycle state, write coordination, or a live credential claim.
- Docker is the task runtime under Nomad for the current submitted execution slice.
- Every post-claim Submit-created host staging root remains retained. Terminal
  success, failure, cancellation, loss, ambiguity, unknown provider evidence,
  and result-publication success, absence, conflict, or failure grant no
  staging deletion authority, and the current slice attempts no whole-run-root
  cleanup.
- Retained result bundles are ES-owned opaque output artifacts, not durable lifecycle records or orchestration state.

## 7. Bounded slice rules

**Bounded slice rules**

- `POST /v1/executions:prepare` is active today as a bounded milestone/public slice surface.
- `GET /v1/executions:contract` is active today as a bounded producer-side compatibility declaration, not as a broad capability registry.
- Submission is currently async-only.
- `control-plane-normal-shell/v1` is one explicit opt-in runtime-profile overlay on the current `static-script` package/runtime path. It exists to give the CP-owned remote normal-shell attempt path a governed ES-owned runtime-profile-selection and runtime-identity-delivery contract without moving CP orchestration or review semantics into ES.
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- The current slice assumes one meaningful allocation per execution.
- ES keeps one explicit internal projected-allocation rule that selects the latest allocation by `ModifyIndex` for detailed status/log lookup only; that internal rule does not define public `lifecycle_projection.revision` semantics.
- The current logs surface is intentionally narrow: task `task`, stdout only, plain text.
- The current result surface is intentionally narrow: a retained tar.gz bundle of `/execution/run/result` for the `static-script` slice.
- The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and opaque tar.gz bundle encoding remain the bounded compatibility retrieval path for that retained bundle surface.
- The current outcome-evidence descriptor vocabulary is intentionally narrow: Nomad status projection depth, Nomad task stdout, accepted Nomad stop request, and ES-retained opaque result bundle labels.
- The current lifecycle model is intentionally minimal rather than a broad orchestration API.
- Retries and reschedule behavior are not part of the current ES slice.

These rules are active today, but they should be treated as scoped slice design choices unless they are later retained explicitly.

## 8. Deliberate absences

**Deliberate absences**

- No ES-owned lifecycle-state store
- No ES-owned run persistence
- No retry or reschedule orchestration in ES
- No allocation aggregation model inside ES
- No richer scheduler abstraction above Nomad
- No runtime token minting owned by ES
- No synthetic ES-specific lifecycle phase model
- No background lifecycle workers or repair loops
- No ES interpretation of retained terminal result bundle semantics
- No ES-owned checkpoint, review, or terminal-finalization model

These absences are part of the current design shape, not missing implementation work.

## 9. Current lifecycle pressure points

**Reopened lifecycle seams under visible pressure**

- `:prepare` is both an active public surface and an explicitly bounded preflight surface, which creates ongoing design tension about its long-term role.
- ES currently depends on aggregate evidence as the only first-class admission input, which means lifecycle admission now rises or falls with the evidence-native publish/store path.
- Lifecycle lookup currently depends on an explicit ES-owned execution-locator policy whose current mapping is `run_id -> exec-<run_id>`.
- Projected-allocation selection is coherent only because the current slice assumes no meaningful retry or reschedule behavior.
- Runtime identity handoff depends on reserved path and workspace conventions that are active but not settled.
- `:submit` now localizes its current staging, result directory, and package-resolution behavior behind one internal execution-package layout, but the current `/execution/...` runtime path conventions, result directory convention, and mount layout remain bounded slice rules rather than settled architecture.
- ES is coherent today as a thin admission and Nomad handoff boundary, but it still carries redesign pressure around how much lifecycle minimalism is fundamental versus merely bounded.

## 9A. Submit Idempotency And Recovery Pressure

**Target-only reliable keyed-submit pressure**

Current unkeyed submit remains the active implementation. It has no submit
idempotency key, no submit correlation key, no exact replay contract, no
conflicting reuse contract, no pending outcome contract, and no recovery lookup
when a caller loses the bounded `202` receipt.

The detailed target contract is
`submit_idempotency_correlation_and_recovery.md`.

The target reliable keyed-submit contract addresses two separate ambiguity
boundaries:

- caller-to-ES response loss, where ES may have accepted a submission and
  produced a `run_id` but the caller or adapter never receives the receipt;
- ES-to-Nomad registration-response uncertainty, where ES may have sent a
  registration request that Nomad accepted but ES cannot confirm because the
  response was lost, malformed, missing, timed out, or otherwise uncertain.

The target design rule is that transport redelivery is not a new semantic
execution. A future reliable keyed submit must converge exact retry on one
authenticated-caller/key claim and exactly one assigned ES `run_id` once the
claim becomes effect-capable; it must not restage or submit a second Nomad job
for the same exact keyed request.

The selected public opt-in/versioning posture has two independent fail-closed
gates. A reliable caller first authenticates and reads the current producer
declaration, then requires the future narrow reliable-submit producer
sub-contract and enabled status. The caller then sends a structurally distinct
reliable request family or envelope on the existing
`POST /v1/executions:submit` route. That reliable body carries an in-band
structural discriminator unknown to the current `PrepareRequest` decoder, so a
current server rejects it through strict body decoding rather than executing it
as current unkeyed submit.

The unavailable contract-adapter foundation now selects the private request
family identifiers for that future path: request schema
`execution-substrate.reliable-submit-request/v1`, reliable contract
`execution-substrate.reliable-submit/v1`, top-level discriminator
`reliable_submit`, nested `contract`, and nested `submit_key`. It also selects
base64url-no-padding 32-byte submit-key syntax, domain-separated SHA-256
caller/key safe-reference derivation from the exact authenticated SPIFFE URI,
composite `ClaimID` construction through the committed pure-model constructor,
and an ES-neutral outcome projection. These are not public runtime DTOs and
current handlers do not call them. This tranche does not implement
source-grounded resolved effective-plan extraction, canonical effective-plan
encoding, effective-plan commitments, complete effective-plan witness
construction, durable replay-envelope custody, or runtime orchestration.

The `resolved-execution-plan-extraction-foundation` now derives one private
resolved execution plan from the actual current ES admission and
runtime-resolution path. That plan is authoritative only for admitted
semantics. The shared admission helper first borrows the caller
request, immediately deep-copies its mutable members, and uses one private
Prepare-versus-Submit intent so the admission-owned working copy is the sole
mutable authority for mode handling, schema defaulting, validation, and
normalization. Successful admission returns one frozen authoritative snapshot;
immutable defensive transfer copies remain permitted. The caller retains
ownership until the initial copy completes and must keep the
request and every reachable mutable member race-free through that copy.
Concurrent unsynchronized mutation during copying is a caller data race, not
an ES synchronization guarantee. After the owned copy completes, later caller
mutation cannot change admitted or submitted state; downstream defensive
copies do not create a second mutable authority. The helper also retains
the exact workload-zone Vault reference used for successful admission. Submit
captures one immutable configuration snapshot, then its effectful resolver
resolves the artifact and profile gates, resources, payload, runtime-support
bytes, governed mount bytes and one archive parse, workload trust material, and
finally the qualified platform-state owner. Successful resolver return freezes
the execution facts before run assignment or staging.

The semantic plan owns admitted execution semantics: request/invocation schema,
mode, timeout, CPU, memory, runtime-profile identity and selected image,
semantic profile/caller environment inputs, one typed command, distinct
artifact/payload/derivation/output identities, ordered mounts, network
permission, current authority inputs, runtime-support digest,
runtime-identity tmpfs size, and the fixed semantic job envelope. Current
authority handoff is structurally present and unconditional; only the Codex
credential-location subcomponent is optional. Raw payload, runtime-support,
mount, and trust bytes live only in separate private owned material.

Captured host context contains only normalized qualified values: the cleaned
absolute staging root, qualified owner UID/GID, cleaned absolute SPIRE source
directory, and trimmed non-empty Nomad datacenter. The results root is trimmed,
cleaned, and required absolute for current ES service/custody qualification,
but remains outside the semantic plan, captured host context, provider-job
projection, and B1 binding. Run/job IDs,
owner/run/endpoint environment, staged paths, host mount sources, endpoint URI,
derived paths, receipts, and Nomad response facts remain outside the semantic
plan. Current legacy `Submit` derives those facts from typed plan, host, and run
projections only. It does not reread request, prepared admission, live config,
service fields, profile maps, sources, owner state, SPIRE source, or datacenter
after freeze.

The semantic plan is admitted semantic truth only. Plan equality across
qualified host contexts proves admitted-semantic equality, not provider-job,
dispatch, replay, restart, safe-host-substitution, or provider-effect identity.
Captured host context and run/provider projection add additional
execution-shaping facts.
The separate private v1 `PlanBinding` producer consumes this source-grounded
plan and captured material, while retaining host placement outside the semantic
binding as later prerequisites. It creates no second resolution authority.
Historical B1 alone selected no encoding, witness, replay, restart, or
host-context binding treatment. One complete direct literal
default-profile expected job, a direct pointer-owned token/template ledger
expanded only in the expected tree, the unmodified actual job tree, and a
separate direct literal handoff expected object through real Submit protect
current successful behavior. A finite package-local direct-call closure and
exact producer, freeze, validation, payload-projection, and metadata
inventories protect this B1 shape; they are not general noninterference proof.
Tranche B2 now completes its bounded provider-body/lifecycle-log privacy work
and public-message refinement without changing the B1 semantic plan or
successful job construction. The public error envelope,
routes, HTTP statuses, codes, field names, precedence, and successful behavior
remain unchanged. The selected operational failures emit only
`workload-zone vault configuration is invalid`,
`derive execution host context failed`,
`stage workload vault trust material failed`,
`derive execution platform state owner failed`, or
`execution submission failed`; underlying causes and Nomad bodies do not become
public or ordinary-log diagnostics. The three governed result-retention log
calls retain only the fixed event `es result retention failed run_id=%s` and a
validated public run ID.

The B2 control-response policy is deliberately non-universal. Submit
registration, projected-allocation list, and allocation detail use the existing
256 KiB acquisition boundary and exactly one unknown-field-compatible JSON
document. Job lookup remains unbounded but one-document because admitted caller
environment aggregates are unbounded and are echoed by Nomad. Successful
authenticated public Logs remain unbounded opaque workload bytes. The private
`preparedAdmission` aggregate gains fixed ordinary-formatting redaction and
ordinary `{}` JSON, and a second complete source-distinct direct literal golden
covers the `control-plane-normal-shell/v1` provider job and handoff as ES
profile-coverage evidence. The rejected 2.9 MB position-indexed B2 guard is not
accepted assurance. Its replacement is behavior-first, uses only local
position-independent structural checks, and makes cancellation non-purging by
private construction with no purge option. The directly authored compact field
inventory fixes current public execution JSON and only the Nomad response
fields production consumes; compatible unknown incoming provider fields remain
accepted. `preparedAdmission` assurance covers ordinary formatting, formatted
standard-library logging, ordinary JSON, marker placement, and field visibility
only. Provenance establishes byte identity only.

Expected-literal authorship and open-world source-flow honesty remain fresh-
audit obligations. No positional record, replacement-output workflow, package
source graph, source fingerprint, generated inventory, or general analyzer is
selected. This model does not claim arbitrary alias/helper-flow detection,
custom logging-sink coverage, arbitrary same-package aggregate conversion,
whole-program noninterference, or whole-runtime reliable-submit nonwiring.
Reliable keyed-submit runtime remains unwired; the private foundation remains
present, public Submit remains unkeyed, and native Linux runtime validation
remains pending.

This foundation does not synthesize `PrepareRequest` or `Manifest` proof from
the plan, create a parallel admission engine, tighten the current empty
environment-allowlist behavior, or introduce canonical encoding, `PlanBinding`,
a witness, durable material custody, host-context replay rules, public reliable
submit, or reconciliation behavior.

Header-only reliable-submit opt-in is rejected because a current server may
ignore an unknown header and run the current unkeyed request. The producer
declaration is compatibility preflight only; it is not authorization, admission,
health, submit readiness, run authority, lifecycle truth, scheduler API, or a
generic capability registry. The reliable request discriminator is also not a
substitute for producer-declaration preflight.

The target contract reserves only narrow ES-owned submit correlation for
recovery across ES restart. That state is protocol recovery evidence, not
Nomad lifecycle truth, not a scheduler, not a runtime status timeline, not
result-content storage, and not Coordinator desired state. Nomad remains
authoritative for submitted execution lifecycle.

The first source-bearing tranche for this seam is the admission-local internal
pure Go package `es/admission/internal/reliablesubmit`. The placement is below
`es/admission` so future admission transport, persistence, and reconciliation
code can consume it, while unrelated ES packages and other repositories cannot
turn it into a shared kernel. The package remains separate from package
`admission` so constructors and private fields enforce phase creation instead
of letting current submit code construct invalid states directly.

That pure model separates claim phases from views and decisions. The claim
phases are pending before assignment, ambiguous before assignment,
effect-capable assigned, pending after assignment, ambiguous after assignment,
accepted, and provably-not-accepted after assignment. Recovered accepted and
exact replay are views over valid state, not new effects. Conflict,
unauthorized, and expired/unavailable correlation are decisions that disclose no
existing claim run or receipt. Accepted and recovered accepted are the only
progression-eligible successful correlation shapes; exact replay follows the
underlying phase.

The pure model uses an opaque `RunRef` rather than the current execution-locator
format or scheduler lookup rule. It also uses an opaque private `PlanBinding`
plus a fixed fourteen-category `EffectivePlanWitness`: request schema or
version, execution mode, timeout semantics, CPU, memory, runtime profile,
artifact identity, derivation-spec identity, output identity, command and
argument vector, environment additions, mounts, network posture, and
authority-handoff applicability. The witness proves category completeness only;
it stores no execution values and does not duplicate ES admission, defaulting,
runtime-profile, resource, environment, mount, or authority-handoff resolution.

The pure model is not a lifecycle store, scheduler, persistence schema, public
DTO, or Coordinator model. It validates one supplied snapshot and one
transition. It cannot stop two stale copied pre-assignment snapshots from being
assigned independently; the later persistence/concurrency layer must provide
one durable winning caller/key claim and one authoritative run assignment with
uniqueness and compare-and-swap or equivalent transaction semantics.

The persistence and concurrency ADR is
`reliable_submit_persistence_and_concurrency.md`. It selects a narrow ES-owned
submit-correlation store, local embedded SQLite as the first storage backend,
the current `CGO_ENABLED=0` build posture, `modernc.org/sqlite v1.54.0` with
the exact `modernc.org/libc v1.74.1` coupling, private same-package persistence
hydration in `es/admission/internal/reliablesubmit`, revision/CAS semantics,
durable provider-effect intent before external I/O, tombstone/no-reuse
retention, and fail-closed corruption behavior. The private source remains
unwired and implements no config, production runtime wiring, public DTO, HTTP
handler, producer declaration field, staging behavior, Nomad behavior, or
runtime behavior.

That ADR now also has a private source implementation for the durable
latest-operation replay repair contract. Exact durable replay is selected only
for the current latest committed mutation descriptor: latest mutation reference,
closed private operation kind, and versioned safe operation-input binding
digest. Mutation-reference-only replay is rejected. A same mutation reference
with different operation kind or input binding is a mutation conflict. An older
operation arriving after a later committed mutation is stale or superseded, not
exact replay, and no historical mutation-result log is selected. Current source
uses SQLite schema v3 for bounded synthetic codec-3 custody while preserving
complete codec-2 descriptors and migrated codec-1 legacy/unbound rows without
inventing old operation or original-intent semantics. This
is a completed source-repair prerequisite before reliable-submit configuration,
store lifecycle wiring, producer enablement, or public runtime enablement.

This document still does not select the state-path config key, TTL, HTTP-code
or public error vocabulary, recovery query route, supplemental header,
deterministic `run_id`, operational replay-envelope/key custody beyond the
bounded synthetic codec-3 path, public provably-not-accepted `RunRef`
disclosure, or Nomad query design.

## 10. Runtime identity and lifecycle interaction

ES currently reserves and/or stages these runtime areas as part of submission:

- `/execution/staged`
- `/execution/run`
- `/execution/run/result`
- the current ES-owned runtime-identity subtree that backs the injected endpoint convention
- the bounded `authority_handoff` read fact that describes the selected non-secret runtime authority path

Design-level meaning:

- ES injects the canonical endpoint-discovery environment convention, currently retains a temporary legacy alias, and backs the discovered endpoint with an ES-owned runtime subtree.
- For `control-plane-normal-shell/v1`, ES also injects non-secret Codex CLI location metadata, workload-vault credential-location metadata, and any configured workload-zone Vault CA trust material. The workload remains responsible for using the existing identity endpoint and workload-vault auth metadata to read the credential material; ES does not become a Vault or Codex token broker.
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- The read-side `authority_handoff` surface may report those same non-secret facts and the selected workload-zone Vault config digest. It does not assert that endpoint use, JWT-SVID retrieval, Vault login, secret read, or token lease state succeeded.
- Caller-provided runtime mounts must not overlap the reserved runtime paths that back that handoff.
- `/execution/run/result` is workload-writable in the current `static-script` slice and is reserved for opaque terminal result files, not for ES-owned runtime identity material.
- The runtime-identity workspace is provisioned as tmpfs in the current submit path.
- ES does not become the long-lived runtime identity owner. The bounded slice-1 implementation target is a platform-owned helper launched by a platform-owned supervisor inside the workload task.
- The first runtime-identity slice deliberately narrows workload runtime compatibility to a fixed non-root workload process while the helper remains root-owned and helper-private access to the raw SPIRE channel is preserved.

Lifecycle implication:

- Failure to use or populate the runtime identity path does not create a separate lifecycle state in ES.
- Those failures remain workload/runtime failures reflected through Nomad-derived lifecycle projection.

The reserved paths and endpoint conventions are active today, but they remain reopened seams rather than settled lifecycle architecture.

## 11. Relationship to other docs

Use the companion documents for detail:

- `.docs/execution_lifecycle/contracts.md` for endpoint-level lifecycle rules and response semantics
- `.docs/execution_lifecycle/implementation.md` for current execution-path behavior
- `.docs/system_overview/contracts.md` for cross-service contract context
- `.docs/system_overview/boundaries.md` for ownership and non-ownership
- `PLANS.md` for redesign sequencing, superseded assumptions, and decision rules

This file should remain the high-level lifecycle design map.

## 12. Reopened lifecycle seams

- The role and future of `:prepare`
- The internal execution-locator policy behind `run_id` lookup
- Latest-allocation lifecycle projection
- The current execution-package layout and `/execution/...` runtime path conventions inside `:submit`
- The current `/execution/run/result` terminal result convention
- Runtime identity reserved-path and endpoint conventions
- The runtime-profile selection vocabulary and whether profile selection remains annotation based
- The extent to which current lifecycle minimalism is a durable invariant versus a bounded slice rule

Cross-repo evidence seams remain outside lifecycle ownership.
Control Plane owns orchestration, Temporal workflow state, review, checkpoint,
finalization, intervention, and operator-facing control semantics.
CP consumes accepted ES surfaces but does not define ES core contracts.
IM readiness/profile/support-bundle/provenance artifacts remain
evidence/projection/diagnostics only; they do not become ES or CP authority.
Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
only and do not define ES route semantics.
Generated evidence, `.out`, reports, traces, logs, summaries, support bundles,
retained bundles, proof artifacts, and maintenance summaries remain
non-authoritative evidence/projection.

These seams are live today and intentionally not fixed.

## 13. Decision rules for future edits

- Keep this file design-level, not field-level.
- Move endpoint specifics into `.docs/execution_lifecycle/contracts.md`.
- Move concrete execution-path behavior into `.docs/execution_lifecycle/implementation.md`.
- Do not present a bounded slice rule as a permanent invariant without support.
- Do not omit active public surfaces from the design description just because they are bounded.
- If code and tests disagree with this file, update this file to match reality.
- Any lifecycle rule treated as fixed must also stay aligned with `PLANS.md`.

## 14. Current root-custody refinement

Staging non-mutation and retained-output independence are a Current invariant.
The paired-root qualification algorithm below is an active Bounded slice rule
pending integrated review. Staging and results are opened as one operation-local
qualified root set; configured strings are only early shape input. Held
descriptor identities, canonical platform presentations, and fresh bounded
topology metadata must prove that neither root aliases or contains the other
before each currently permitted named result access or effect. Missing suffixes
are absence-checked intent, not canonical objects; ambiguous dual-missing
lookup relationships fail closed, and startup requalifies after every
descriptor-relative component creation.

The retained-result route remains retained-first. It may serve an existing
bundle with a missing staging root or run, does not provision a missing results
root on read, and treats topology refusal as a fixed availability failure
rather than a reason to consult Nomad. An existing bundle becomes eligible only
after authenticated final/record checks; an unmarked or invalid pair is refused,
not adopted. Current result-side directory and temporary creation, initialization
of newly created unpublished records and normalization evidence, no-replace
publication, and authenticated read/check use the descriptor-held results root
after pair proof. Existing directories, finals, and normalization evidence are
validated without metadata repair or adoption. Pair proof does not grant
deletion or repair authority: incomplete leaves, uncertain temporaries, and
startup probe fixtures remain retained. Whole-root reclamation remains
unselected. This does not grant staging cleanup, result-content interpretation,
a global root registry, or a namespace lease. The owning eligibility and
retention contract is `.docs/execution_lifecycle/contracts.md`.

Linux source coordinates are derived from a complete `statx` mount identity,
the held descriptor's no-follow canonical `/proc/self/fd` presentation, and
the uniquely selected bounded mountinfo record when its root is a canonical
pathname. Record validity is not coordinate eligibility: source-valid opaque
`nsfs` namespace-object roots remain represented for complete snapshot,
parent/stack, and descendant-mount reasoning, while an opaque selected record
fails before coordinate construction or effects. The design never turns an
object label into a path, substitutes mountpoint/configured spelling, or treats
record recognition as support for `nsfs` execution roots. Darwin uses `F_GETPATH`,
descriptor identity, `fstatfs`, and bounded `getfsstat`, and conservatively
rejects same-FSID distinct presentations. Both reject canonical descendant
mounts and fail closed when proof is unavailable or inconsistent.

Local implementation and modeled tests do not establish mounted or deployment
compatibility. At the pre-PR #8 integration gate, C's selected native
observations were historical exact-C evidence, not executions of the
then-unaccepted integrated tree. PR #8 later completed source publication;
focused independent changed-interaction assessment may still select a new
bounded witness for a concrete operating claim. Running-deployment topology,
key isolation, capacity, residence, reclamation, publication, and native
qualification for claimed architectures remain gates for their operational scope,
not blanket local pre-commit conditions. No integrated native qualification is
claimed here.
