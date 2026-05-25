# ES Execution Admission Model Decision

## 1. Purpose and authority

This document records the bounded Workstream C ES public admission/execution
model decision for Milestone 2C.1.

It answers only the questions needed to keep ES public admission, execution
handoff, lifecycle projection, retained-result ownership, runtime handoff, and
current CP compatibility explicit for the current governed execution path. It
does not settle:

- Workstream D policy/authorization redesign
- Workstream E runtime-config ownership redesign beyond the E0
  docs/tests-only ownership decision in
  `.docs/system_overview/runtime_config_ownership.md`
- Workstream F runtime-identity redesign beyond the F0 docs/tests-only
  ownership decision in `.docs/system_overview/runtime_identity_handoff.md`
- Control Plane orchestration, review, checkpoint, escalation, or finalization
  semantics
- Infrastructure Manager bootstrap, readiness, or support-bundle ownership

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
the code and tests win and this document must be realigned.

## 2. Decision summary

- C0 is the docs and docs-contract-test gate only. It makes no runtime
  implementation changes, and Workstream C implementation must not start until
  C0 docs and docs-contract tests pass.
- ES owns admission composition, prepare-time preflight, submit-time execution
  handoff, Nomad-backed lifecycle projection, retained opaque result-bundle
  ownership, and runtime handoff boundary enforcement.
- ES owns the public admission model, prepare model, submit model,
  Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- `GET /v1/executions:contract` and `POST /v1/executions:prepare` remain
  active bounded compatibility surfaces. Neither surface becomes health,
  readiness, run authority, or hidden orchestration.
- `GET /v1/executions:contract` remains a narrow producer compatibility
  declaration, not health, submit readiness, run authority, or a general
  capability registry.
- `POST /v1/executions:prepare` remains bounded preflight and creates no run
  object or scheduler handoff.
- `POST /v1/executions:submit` is the real ES-owned execution handoff surface.
  Its current behavior remains async-only and returns a bounded receipt rather
  than a durable ES lifecycle record.
- `POST /v1/executions:submit` remains the MVP execution handoff surface:
  async, bounded receipt, and Nomad submission through ES.
- Nomad remains authoritative for submitted execution lifecycle. ES projects
  status, logs, and cancel observations from Nomad and serves retained opaque
  result bundles from ES-owned retained storage through the current bounded
  result path.
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- ES admission composition consumes designed ARS discovery plus
  evidence/payload references, aggregate evidence verification, the narrow
  shared execution/runtime claims in `internal/contracts/evidence/v1`, EGS
  runtime-trust output, the configured workload-zone Vault runtime-config
  reference/blob, and caller authentication plus the configured SPIFFE
  allowlist.
- For the workload-zone Vault runtime-config path, E0 records that
  `internal/contracts/runtimeconfig/v1` owns the typed semantics, ARS owns blob
  storage/read by digest only, and ES is the current consumer and lookup
  orchestrator during `:prepare` and `:submit`. There is no ACS hop.
- ES startup-config placement of the required runtime-config ref is
  compatibility/config residue on a reopened Workstream E ownership seam. The
  startup guarantee is that the typed ref is configured and validated before ES
  serves governed execution traffic, not that E0 adds a startup blob-fetch
  behavior.
- ES admission composition remains CGS-independent in the current hot path.
  D1a preserves that ES consumes no CGS facts. Workstream D may later redesign
  policy/authorization ownership, but any later ES-consumed authorization fact
  must be separately versioned and bounded rather than a reuse of the current
  CGS v1 authorize shape, subject grammar, or audit fields. This decision does
  not settle Workstream E runtime-config ownership or Workstream F
  runtime-identity handoff ownership.
- D1b keeps any future CGS v2 authorize contract design-only. That
  hypothetical future fact is limited to allow/deny, opaque decision
  reference, and expiry or another bounded freshness indicator if justified,
  with audit/evaluation metadata remaining non-authoritative outside CGS. It
  must not carry runtime auth plans, scheduler facts, ES lifecycle/admission
  facts, runtime-config refs, workload-zone Vault ownership facts,
  identity-handoff facts, or Control Plane
  review/approval/checkpoint/finalization semantics.
- D1c keeps any future EGS versioned runtime-trust wrapper design-only. ES
  continues to consume EGS only for signed signer/artifact runtime trust, and
  EGS publication metadata remains outside the signed payload and outside ES
  hot-path admission facts.
- Any future EGS semantic expansion must use explicit
  wrapper/payload/versioning before implementation and must not import CGS
  decisions, runtime-config ownership, runtime identity handoff, AGS/ARS
  artifact-publication authority, or Control Plane orchestration semantics
  into the EGS trust surface.
- D1c does not change the accepted Workstream B artifact
  publication/storage/discoverability semantics or the accepted Workstream C
  ES admission/runtime public model. This decision still does not settle
  Workstream E runtime-config ownership or Workstream F runtime-identity
  handoff ownership.
- D1d keeps `id.conf`, the current CGS v1 subject grammar, and
  `policy.id_conf_path` outside the ES admission model. They remain
  CGS-local current-v1 compatibility/config residue, not ES admission policy
  truth, runtime-config ownership input, or runtime-identity handoff input.
- D1d does not implement CGS v2, does not change EGS trust semantics, does
  not change ES admission behavior, and still does not settle Workstream E
  runtime-config ownership or Workstream F runtime-identity handoff
  ownership.
- F0 records that runtime identity handoff is currently ES-selected and
  platform-delivered. ES owns current handoff selection, env injection,
  reserved path layout, mounts, and Nomad job construction; the runtime
  supervisor/helper owns in-task endpoint implementation, helper-private SPIRE
  traversal, readiness-before-workload, and root-to-workload privilege
  boundary; SPIRE owns JWT-SVID issuance; Vault owns token, secret, and lease
  issuance after workload-side login.
- F0 classifies `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the bounded
  workload-visible discovery contract only. It is not raw SPIRE socket
  exposure, Vault token brokerage, runtime-config authority, or a secret
  payload.
- F0 does not change runtime-config ownership from E0/E1, does not consume or
  promote D seams, and does not widen CP, IM, support-bundle, report, trace,
  retained-bundle, profile, log, or `.out` authority.
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- ES does not own AGS publish-time fact assembly/signing, ARS blob
  storage/registration/discoverability authority, EGS trust publication, CP
  orchestration semantics, runtime credential minting/brokerage/storage, or
  semantic interpretation of retained result contents.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- ES must not absorb CP attempt/review/checkpoint/finalization semantics.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
- ES must not become a Vault token broker, Codex credential broker, IM
  readiness authority, CP run-control authority, or maintenance-agent
  authority.
- Generated evidence, `.out`, reports, traces, logs, summaries, support
  bundles, retained bundles, proof artifacts, and maintenance summaries remain
  non-authoritative evidence/projection.
- ES resolves payload bytes through designed ARS discovery and explicit
  evidence/payload relationships. It does not treat `artifact_digest` as the
  payload locator by hidden equality.
- `invocation.annotations["execution_substrate.runtime_profile"]` and the
  bounded `control-plane-normal-shell/v1` profile remain explicit compatibility
  edges on a reopened ES runtime/package seam.
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- `lifecycle_projection`, `authority_handoff`, and `outcome_evidence` remain
  bounded additive read surfaces. They do not become scheduler identity, write
  coordination, credential truth, approval truth, or CP lifecycle state.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only.
  It is not runtime-config authority, live credential truth, or a source of
  workload-zone Vault semantics.
- ES retained results remain opaque output bundles. They do not become CP
  checkpoint, review, finalization, or orchestration state.
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.

## 3. Surface classes used here

| Class | Meaning for Workstream C |
| --- | --- |
| `stable contract` | An ES-owned public or ownership rule that this package now treats as an explicit current invariant and that must not change silently. |
| `bounded slice rule` | Active public behavior that is real today but intentionally narrow and not automatically the long-term architectural endpoint. |
| `temporary compatibility edge` | An active compatibility-heavy surface retained for continuity; it is real today but must not be preserved by inertia. |
| `implementation-only/current-slice detail` | A current runtime, lookup, or storage mechanic that must not be mistaken for ES public contract or ownership truth. |
| `reopened seam` | An active architecture-defining surface that remains intentionally open in `PLANS.md` and is not settled by this decision. |

## 4. Classified current surfaces

### 4A. Public execution surfaces

| Surface | Class | Current rule | Explicit non-claim |
| --- | --- | --- | --- |
| `GET /v1/executions:contract` | `temporary compatibility edge` | Narrow read-only producer compatibility declaration for the current governed-execution consumer path. | Not service health, submit readiness, artifact admission proof, run authority, run existence proof, lifecycle truth, credential truth, policy truth, or scheduler API. |
| `POST /v1/executions:prepare` | `temporary compatibility edge` | Bounded preflight success surface for the current execution request family. | Not run creation, scheduler handoff, proto-execution state, durable ES lifecycle state, or public composition detail. |
| `POST /v1/executions:submit` | `stable contract` | Real ES-owned execution handoff surface that reuses the full prepare path and returns a bounded async receipt. | Not sync execution, durable ES lifecycle ownership, retry/reschedule policy, or backend scheduler ID exposure. |
| `GET /v1/executions/{run_id}/status` | `stable contract` | Nomad-backed lifecycle projection surface centered on `submitted`, `running`, and `terminal`. | Not a parallel lifecycle store, scheduler identifier surface, or richer CP lifecycle model. |
| `GET /v1/executions/{run_id}/logs` | `bounded slice rule` | Current projected-allocation stdout retrieval surface through ES. | Not streaming, pagination, stderr aggregation, multi-allocation merge, or log authority beyond the served bytes. |
| `GET /v1/executions/{run_id}/result` | `temporary compatibility edge` | Current retained-result retrieval route for ES-owned opaque bundles keyed by public `run_id`. | Not a logs wrapper, checkpoint API, finalization record, or semantic result interpretation surface. |
| `POST /v1/executions/{run_id}:cancel` | `bounded slice rule` | Bounded Nomad stop-request receipt through ES. | Not cancel-completion truth, purge authority, or a broad orchestration/cancellation state model. |

### 4B. Admission, handoff, and projection ownership surfaces

| Surface | Class | Current rule |
| --- | --- | --- |
| ES admission composition at `:prepare`/`:submit` | `stable contract` | ES composes ARS discovery plus evidence/payload refs, aggregate evidence verification, narrow shared execution/runtime claims from `internal/contracts/evidence/v1`, EGS runtime-trust output, the configured workload-zone Vault runtime-config reference/blob, and caller authentication plus configured SPIFFE allowlist authorization. CGS authorize remains outside the current hot path. |
| Scheduler handoff after `:submit` | `stable contract` | Successful submit hands execution to Nomad. ES keeps only the bounded receipt and read-through projection responsibilities after that handoff. |
| `lifecycle_projection` | `bounded slice rule` | `source` and `revision` are opaque same-run read-coordination facts derived from Nomad observation only. |
| Payload/runtime package resolution | `stable contract` | ES resolves payload bytes through designed ARS discovery plus explicit evidence/payload relationships, cross-checks those facts against aggregate evidence, and keeps descriptor/manifest support outside ES hot-path public grammar. |
| Workload-zone Vault runtime-config lookup | `bounded slice rule` | ES is the current consumer and lookup orchestrator during `:prepare` and `:submit`: it reads the validated startup ref, fetches the ARS blob by digest, and decodes typed `internal/contracts/runtimeconfig/v1` data. Runtime-config semantics live in that contract surface, ARS owns blob read by digest only, and no ACS hop exists. |
| Current `/execution/...` runtime path conventions | `temporary compatibility edge` | `/execution/staged`, `/execution/run`, `/execution/run/result`, and the run-scoped runtime-identity backing tree remain current runtime/package conventions only. |
| Runtime-profile selection | `temporary compatibility edge` | `invocation.annotations["execution_substrate.runtime_profile"]` plus `control-plane-normal-shell/v1` remains the current opt-in `static-script` runtime overlay. Unsupported or disabled selection fails `:prepare`/`:submit`. |
| `authority_handoff` read surface | `bounded slice rule` | Additive non-secret runtime handoff evidence on submit/status for facts ES selected and handed off. |
| `outcome_evidence` read surface | `bounded slice rule` | Additive response evidence on status/cancel JSON and successful logs/result responses for current Nomad or retained-result observations. |
| Retained opaque result bundles | `stable contract` | ES retains opaque output bundles outside staging and serves them through the current bounded result surface without interpreting their contents as CP state. |
| Current CP governed path consumption | `temporary compatibility edge` | Preserve AGS publish plus ES contract/prepare/submit/status/logs/result/cancel over HTTPS+mTLS for the current CP consumer path without importing CP orchestration grammar into ES. |
| Runtime identity handoff ownership | `bounded slice rule` | Current handoff is ES-selected and platform-delivered. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is bounded workload-visible discovery only; the supervisor/helper implements the endpoint; SPIRE owns JWT-SVID issuance; Vault owns token/secret/lease issuance after workload-side login. |

ES does not own:

- AGS publish-time fact assembly or signing
- ARS blob storage, registration, or discoverability authority
- EGS trust model publication
- CP orchestration, review, checkpoint, hold/resume/reject, escalation, or finalization semantics
- runtime credential minting, brokerage, storage, or lease truth
- semantic interpretation of retained result contents

### 4C. Temporary compatibility edge metadata

| Edge | Reason | Scope | Affected contract or boundary | Visibility | Removal condition |
| --- | --- | --- | --- | --- | --- |
| Current CP governed execution consumer path | Preserve the first repo-owned non-operator governed execution path while Workstream C clarifies ES-owned public semantics. | AGS publish plus ES `GET /v1/executions:contract`, `POST /v1/executions:prepare`, `POST /v1/executions:submit`, `GET /v1/executions/{run_id}/status`, `GET /v1/executions/{run_id}/logs`, `GET /v1/executions/{run_id}/result`, and `POST /v1/executions/{run_id}:cancel` over HTTPS+mTLS for the current CP consumer path only. | ES public execution contract and ES/CP consumer boundary. | `system-visible` | Remove or change only with an explicit compatibility, drain, migration, or versioning plan that documents the replacement consumer path first. |
| `GET /v1/executions:contract` producer declaration | Preserve the current producer-side compatibility gate without promoting it into broad runtime authority. | Read-only declaration of the current governed-execution producer contract, runtime-profile enablement, and mandatory outcome-evidence carriers only. | ES public execution contract and ES/CP/IM compatibility boundary. | `system-visible` | Remove or change only after a replacement compatibility-gate surface or explicit versioning/deprecation plan is documented first. |
| `POST /v1/executions:prepare` bounded preflight surface | Preserve artifact-specific preflight proof without widening it into hidden orchestration or proto-run creation. | Request validation, upstream composition, evidence/trust/runtime-config verification, and bounded preflight success only. | ES public execution contract and ES admission boundary. | `system-visible` | Remove or change only after a documented replacement preparation model, deprecation path, or explicit versioning plan exists. |
| `invocation.annotations["execution_substrate.runtime_profile"]` plus `control-plane-normal-shell/v1` and the current `static-script` overlay | Preserve the accepted CP normal-shell runtime selection path without widening it into a package-kind redesign or CP control-plane transfer. | Annotation-selected ES runtime-profile choice and the bounded `static-script` runtime overlay for the current CP normal-shell attempt slice only. | ES request contract and ES runtime-boundary contract. | `system-visible` | Remove or change only after an ES-owned replacement runtime-profile/package-selection contract and coordinated compatibility/versioning plan are documented first. |
| Current `/execution/staged`, `/execution/run`, `/execution/run/result`, and run-scoped runtime-identity path conventions | Preserve the current execution-package/runtime layout while the runtime/package seam remains reopened. | Current container-visible runtime paths, retained-result directory convention, and runtime-identity backing-tree conventions only. | ES runtime package boundary and ES runtime handoff boundary. | `local-runtime-only` | Remove or change only after a documented runtime-boundary redesign re-derives the execution-package layout and reserved-path conventions first. |
| Current `authority_handoff` field names and evidence-source labels | Preserve the current CP/IM-consumable runtime handoff evidence vocabulary while the request/runtime-identity seam remains open. | Submit/status `authority_handoff` JSON field names, nested shape, and evidence labels only. | ES public execution contract and ES runtime handoff boundary. | `system-visible` | Remove or change only after a documented replacement handoff vocabulary and explicit compatibility/versioning plan exist. |
| Current `authority_handoff.runtime_config_refs` digest evidence | Preserve the non-secret handoff evidence that identifies which workload-zone Vault config digest ES selected without promoting it into authority. | `authority_handoff.runtime_config_refs.workload_zone_vault_config.digest` only. It is evidence, not runtime-config authority, live credential truth, or token/lease truth. | ES public execution contract, Workstream E runtime-config boundary, and ES runtime handoff boundary. | `system-visible` | Remove or change only after a documented replacement handoff-evidence vocabulary and explicit compatibility/versioning plan exist. |
| Current `outcome_evidence` JSON field layout and successful logs/result evidence headers | Preserve the current consumer evidence-parsing vocabulary while lifecycle observation remains bounded to the current Nomad/retained-result slice. | Status/cancel JSON `outcome_evidence`, successful logs/result outcome headers, and the current observation/access-class labels only. | ES public lifecycle contract. | `system-visible` | Remove or change only after a documented replacement observation vocabulary and explicit compatibility/versioning plan exist. |
| Current `GET /v1/executions/{run_id}/result` route plus retained `application/gzip` bundles keyed by public `run_id` | Preserve the current retained-result retrieval path while the longer-term result-materialization seam remains open. | Public result-route path, `run_id`-keyed lookup, `application/gzip` media type, opaque tar.gz result-bundle behavior, and the current CP-consumed result retrieval path only. | ES public result contract, retained-result boundary, and ES/CP consumer boundary. | `system-visible` | Remove or change only after a documented replacement result-retrieval surface or explicit compatibility/versioning plan exists. |

### 4D. Current relationship map

1. An allowed caller may use `GET /v1/executions:contract` as an early
   compatibility gate only.
2. `POST /v1/executions:prepare` validates the request, follows ARS discovery
   to aggregate evidence and payload references, verifies the narrow shared
   execution/runtime claims plus EGS trust/runtime-config inputs, and returns
   bounded preflight success only.
3. `POST /v1/executions:submit` reuses the full prepare path, resolves payload
   bytes, stages the current execution package, assembles bounded
   `authority_handoff` facts, submits one Nomad batch job, and returns a
   bounded receipt.
4. `GET /v1/executions/{run_id}/status`,
   `GET /v1/executions/{run_id}/logs`, and
   `POST /v1/executions/{run_id}:cancel` read through Nomad. `GET
   /v1/executions/{run_id}/result` reads the retained bundle first and
   otherwise uses the same bounded terminal observation model before retention.
5. `lifecycle_projection`, `authority_handoff`, and `outcome_evidence` remain
   additive read surfaces over ES-owned observation/handoff facts only. They do
   not create ES-owned lifecycle authority, scheduler identity, or CP state.

### 4E. Reopened seams

| Surface | Class | What remains open |
| --- | --- | --- |
| Long-term request DTO and submit receipt vocabulary | `reopened seam` | Workstream C settles the ES-owned route roles and authority boundaries, not the final long-term DTO family. |
| Long-term role of `POST /v1/executions:prepare` | `reopened seam` | `:prepare` remains active today, but whether it survives unchanged as part of a later public execution model remains open. |
| Runtime-profile selection vocabulary and whether it remains annotation based | `reopened seam` | The current annotation plus profile name are compatibility edges, not the final ES runtime-selection model. |
| Internal execution-locator and projected-allocation policies | `reopened seam` | `run_id -> exec-<run_id>` and latest-allocation selection remain active current-slice lookup mechanics, not settled lifecycle architecture. |
| Long-term execution-package layout and `/execution/...` conventions | `reopened seam` | The current runtime package layout is localized inside ES, but its long-term path and reserved-directory conventions remain open. |
| Long-term runtime identity handoff owner behind the public endpoint | `reopened seam` | Workstream C preserves the ES-owned handoff boundary only; Workstream F remains the place to settle the final runtime-identity ownership model. |
| Long-term workload-zone Vault runtime-config owner | `reopened seam` | Workstream C preserves consumption of the current runtime-config reference/blob, but Workstream E remains the place to settle the long-term owner. |
| ES startup-config placement of workload-zone Vault runtime-config ref | `reopened seam` | E0 classifies the current placement as compatibility/config residue; a later Workstream E slice must decide whether the startup guarantee moves to another owner. |

## 5. Guardrails for future edits

- Do not widen `GET /v1/executions:contract` into health, readiness, run
  authority, or scheduler API semantics.
- Do not widen `POST /v1/executions:prepare` into hidden orchestration,
  scheduler metadata creation, or proto-run state.
- Do not expose Nomad job IDs, allocation IDs, task IDs, staging paths, result
  filesystem paths, or bundle internals as public lifecycle authority.
- Do not bypass ARS storage/discoverability authority, EGS runtime-trust
  publication, or configured runtime-config ownership to make admission easier.
- Do not treat ARS blob mechanics, ES startup placement, CGS authorize output,
  EGS publication metadata, IM profiles, support bundles, logs, traces,
  reports, retained bundles, `.out` artifacts, CP
  review/approval/checkpoint/finalization state, `authority_handoff`, or
  `outcome_evidence` as runtime-config authority.
- Do not treat CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, runtime-config refs, `authority_handoff.runtime_config_refs`,
  ARS blob mechanics, digest-only runtime-config refs,
  `workload_vault_auth.default_mode`, retained bundles, `outcome_evidence`,
  `authority_handoff`, IM profiles, support bundles, logs, traces, reports,
  `.out` artifacts, or CP review/approval/checkpoint/finalization state as
  runtime-identity or credential authority.
- Do not reinterpret `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as raw SPIRE socket
  exposure, Vault token brokerage, runtime-config authority, or a secret
  payload.
- Do not turn the current runtime-profile compatibility edges into a general
  package-kind redesign or transfer CP control semantics into ES.
- Do not turn retained result bundles into CP checkpoint/review/finalization
  state or ES-owned orchestration state.
- Any change that breaks the current CP path, runtime-profile annotation/path,
  `authority_handoff` vocabulary, `outcome_evidence` vocabulary, or current
  result-route path/lookup/`application/gzip` bundle behavior requires an explicit
  compatibility, drain, migration, or versioning plan first.
