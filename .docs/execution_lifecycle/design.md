# Execution Lifecycle Design

## 1. Purpose and status

This document describes the current ES lifecycle design in the repository's bounded platform phase.

The lifecycle slice documented here is real and implemented today. At the same time, some lifecycle rules are intentionally bounded and must not be mistaken for long-term architecture simply because they are active in the current slice.

Foundational ES lifecycle and runtime-boundary clarification is primary Execution Substrate program work, not a secondary architecture-only exercise. Control Plane is an important consumer of the accepted ES lifecycle surface, but CP orchestration, review, checkpoint, hold/resume/reject, finalization, and proof-harness semantics do not define ES lifecycle ownership.

This file stays design-level. Detailed endpoint and response rules belong in `.docs/execution_lifecycle/contracts.md`. Current implementation behavior belongs in `.docs/execution_lifecycle/implementation.md`.

The authoritative Workstream C classification of ES public execution surfaces,
admission composition, scheduler handoff, compatibility edges, and reopened
seams lives in `es_execution_admission_model.md`.

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
| Terminal result retention | ES for the retained opaque bundle only | The workload may write files under `/execution/run/result` in the current `static-script` slice. ES may package those files into an opaque retained tar.gz bundle under `execution.results_root_dir` before successful staging cleanup. ES does not parse those files into orchestration, checkpoint, or Control Plane semantics. |

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
- successful staging cleanup does not remove retained bundles
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.

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
- Submit-created host staging remains in place only while the workload may still depend on its bind mounts; after ES observes terminal success, the current slice attempts result retention and then cleans that staging best-effort while retaining non-success outcomes for debugging.
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
