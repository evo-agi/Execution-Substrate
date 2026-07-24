# Hybrid Integration Architecture: Coordinator, Bridge, ES, CP, IM, And Maintenance Boundaries

Status: accepted architecture/status decision; implementation blocked by missing authority contracts; no integration behavior enabled.

This is the canonical cross-repository integration architecture/status decision record for the current Post-Phase-E alignment. It records architecture and implementation status only. It does not enable real write, real Codex execution, remote maintenance, ES submit, CP diagnose, IM refresh, live proof, connector-triggered execution, worker dispatch, scheduler behavior, queue consumption, Coordinator provisioning, receipt provisioning, or publication.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

## ES Classification

This ADR is an accepted architecture/status decision for a reopened cross-repo integration seam. It does not reopen accepted ES Workstream A/B/C planning boundaries, and it does not displace the ES Admission And Runtime Boundary Realignment track.

- ES Workstream A and Workstream B remain gates that keep ES input contracts honest.
- ES Workstream C admission/runtime boundaries remain the delivered ES milestone and a Current invariant.
- `control-plane-normal-shell/v1` remains a bounded compatibility edge.
- ES still owns no parallel scheduler or lifecycle store beyond its documented bounded lifecycle projection and current compatibility lookup behavior.
- Bridge dry-run/no-mutation evidence remains a Bounded slice rule outside ES authority.
- Maintenance leases and coding-work leases remain separate namespaces and are not interchangeable.
- Operator-healthcheck TLS signer/custody remains a Reopened redesign seam and blocked seam.

## Stable Authority Split

| Component | Authority | Non-authority |
| --- | --- | --- |
| ES | admission/runtime authority; lifecycle projection; runtime identity handoff; retained opaque results. | Not CP workflow authority, not Coordinator durable coding-work truth, not Bridge evidence authority, not IM readiness authority, not Maintenance Agent authority, not operator/repo-policy lease issuer. |
| CP | Workflow, progression, review, checkpoint, cancellation decision, intervention, and finalization authority. | Not ES admission/runtime owner; not Coordinator coding-work state owner; not receipt provisioner by inference. |
| Coordinator | Bounded durable coding-work state; transition/global-stop apply; writer fencing; idempotency; CAS; event receipt; commit uncertainty; replay. | Not CP workflow, ES admission/runtime, Bridge adapter, IM readiness, Maintenance Agent maintenance, publication, worker, scheduler, queue, or general orchestration authority. |
| Bridge / Connector | Guarded adapters and evidence/projection only. | Not execution authority, state authority, lease issuer, receipt provisioner, CP workflow truth, ES runtime truth, Coordinator truth, or hidden run truth. Current connector paths do not mutate Coordinator state or invoke real Codex. |
| IM | Readiness, profile, provenance, and diagnostics. | Not CP workflow, ES runtime, Coordinator durable state, Bridge execution, or Maintenance Agent route authority. |
| Maintenance Agent | Maintenance routes under maintenance-specific authority only. | Not coding-work lease authority, not Coordinator state truth, not hidden reconciler, not ES/CP/IM authority. |
| Operator / repo policy | Intended lease issuance; executable authorization; global-stop decisions; operator-decision receipt provisioning. | Not replaced by a digest, report, Bridge ledger, connector state, Symphony, or Coordinator worker/scheduler logic. |

Reports, projections, ledgers, support material, retained bundles, and local proof artifacts remain evidence/projection/diagnostics only. They are not durable state, authorization, acceptance, publication, product workflow truth, or product runtime truth.

## Coordinator Implementation Status

The current Coordinator status is no longer an A2-P1 skeleton-only state and is not a state-store-port-only design.

Implemented in the Coordinator repository:

- internal durable SQLite writer issuance;
- private atomic transition persistence;
- guarded public transition delegation;
- private atomic global-stop persistence;
- guarded public global-stop delegation;
- verification of already-persisted decision receipts;
- fencing, idempotency, replay, CAS, rollback, one COMMIT attempt, commit uncertainty, and retry.

Not implemented or not owned by Coordinator:

- work-item production provisioning;
- coding-work lease issuer;
- executable authorization issuer;
- decision-receipt provisioner;
- worker;
- scheduler;
- queue consumer;
- Codex invocation;
- ES runtime;
- CP workflow;
- publication;
- general orchestration.

Historical A2/P1 terminology remains valid only as historical tranche context. It must not be used as the current whole-repository status for Coordinator.

## Current Integration Decision

Shape A, the CP-authoritative product path, is the enduring architecture target. CP remains the product workflow authority while ES remains the admission/runtime authority and Coordinator remains bounded coding-work durable state authority.

The connector -> Bridge -> Coordinator -> ES route without CP is currently only a bounded coding-work proof candidate. It is not an established compatibility path, not a product workflow, and not an authorized integration implementation. It may not be represented as CP replacement, ES admission authority, Bridge execution authority, or Coordinator general orchestration.

ES Admission And Runtime Boundary Realignment remains a parallel track for a bounded proof using current compatibility surfaces and is required for the enduring architecture. Coordinator integration work does not displace ES planning authority.

## Preserved ES And NWP Boundaries

NWP/autonomy does not redefine ES Workstream C or runtime authority. CP
compatibility remains bounded. There is no TLS/noninteractive route widening in
this ADR. The rule is: no ES admission/runtime, Workstream C, route, TLS, or
noninteractive authority drift is authorized. Economic or financial goals do not alter ES
admission/security contracts. No current unattended execution is claimed.

Maintenance Agent is not optional for reducing infra babysitting, but it must
not become a hidden reconciler. Maintenance work remains governed by
maintenance-specific route authority and leases, not coding-work lease
authority.

## Missing Contract Packages

Implementation is blocked by four missing contract packages. None is claimed implemented by this ADR.

### Authority Issuance

- lease issuance;
- executable authorization;
- operator-decision receipt provisioning;
- expiry/revocation and immutable references.

### Coordinator Ingress

- finite backlog admission;
- work-item provisioning;
- transition/global-stop command producers;
- expected-version, digest, and idempotency rules.

### Worker / Runtime Handoff

- dispatch command/receipt;
- guarded Codex invocation;
- Bridge or dedicated adapter role;
- ES request construction and runtime handback.

### Correlation And Recovery

- separate CP, Coordinator, Bridge, Connector, and ES identifiers;
- duplicate and lost responses;
- cancellation/global-stop propagation;
- restart reconciliation;
- review and finalization recovery.

## Bridge <-> Codex Evidence Boundary

Bridge connector-safe source intake and no-mutation handoff are implemented and
live-tested as Bridge-local evidence/projection. Bridge connector-safe source
intake and no-mutation Codex handoff are implemented and live-tested as
Bridge-local evidence/projection. They do not invoke Codex or mutate repos.
Local real Codex execution and local acceptance remain separate CLI-only and
non-MCP-visible paths.

The implemented Bridge/Codex evidence path is a no-mutation handoff:

1. ChatGPT creates or validates an assignment through Bridge when the sealed packet path is appropriate.
2. When connector dispatch should avoid local paths or sealed raw assignment payloads, ChatGPT may record connector-safe source ledger evidence through `record_no_mutation_codex_handoff_source`.
3. Bridge records assignment/evidence or source evidence under Bridge policy.
4. Bridge may record a sealed no-mutation handoff packet through `record_no_mutation_codex_handoff`.
5. The source evidence and handoff contain safe labels, assignment metadata, non-authority notices, and redacted evidence references only.

This slice has no repository write, no shell execution, no Codex invocation through connector, no push, no PR, no merge, no local acceptance, no Coordinator mutation, and no ES/CP/IM/Maintenance lifecycle authority. Any later Codex invocation through connector/tunnel requires the missing contract packages and a separate accepted design.

## Integration Point Map

| Integration point | Status | Notes |
| --- | --- | --- |
| Bridge <-> Codex | no-mutation source intake and evidence recorder implemented/live-tested | Bridge source ledger evidence/projection and no-mutation handoff packet recording are implemented/live-tested with exact retry reuse and same-source conflict handling only; they are not Codex invocation, repository mutation, ES admission/runtime/lifecycle authority, local runner/acceptance, connector-triggered execution, durable coordination, Coordinator mutation, or A2 durable work-item state. |

## Component Map

| Component | Current evidence | Current authority | Current role | Non-claims | Missing integration points |
| --- | --- | --- | --- | --- | --- |
| ChatGPT | Human-facing review and intent surface is the initiating context for Bridge proposals. | Human/operator intent and review only. | Create or review assignments that Bridge can validate and record. | Not run-control, not ES authority, not repository writer, not hidden execution truth. | Exact connector UX, assignment schema, and review checkpoints. |
| Connector / MCP tunnel | Bridge tunnel docs describe an externally/platform-owned transport path. | Transport/integration path, externally/platform-owned. | Carry guarded Bridge calls when the operator has configured the transport. | Not lifecycle authority, not repo authority, not proof authority, not Codex authority. | Live readiness, deployment ownership, production support model, and platform custody. |
| Bridge | Dry-run lifecycle, assignment/evidence projection, local preflight evidence, connector-safe no-mutation Codex handoff source intake, Bridge-local no-mutation Codex handoff evidence recording, idempotent retry/conflict handling, and separate real-write design gates exist. | Assignment/evidence adapter; local Bridge policy gate. | Record or reuse connector-safe source ledger evidence and no-mutation Codex handoff packets as Bridge-local evidence while preserving future real-write separation. | Does not own ES, CP, IM, Maintenance Agent, tunnel, Coordinator state mutation, repository mutation, shell execution, push, PR, merge, local acceptance, real Codex execution, or live proof. | Worker/runtime handoff package; correlation and recovery package. |
| Codex | Candidate coding worker exists outside this ADR; Bridge docs currently do not enable real Codex through connector/tunnel. | Candidate worker only when separately invoked under its own guardrails. | Potential worker after separate approval and guarded invocation. | Not enabled by this ADR; not invoked by Bridge here; not lifecycle, maintenance, Coordinator, CP, or ES authority. | Guarded invocation, validation, handback, and recovery. |
| NWP Coordinator | Current bounded SQLite mutation authority exists in the Governed Execution Coordinator repository. | Bounded durable coding-work state authority. | Apply transition and global-stop commands through writer-fenced SQLite mutation with idempotency, replay, CAS, receipts, uncertainty, and retry. | Not ES admission, runtime, lifecycle, status, route, TLS, noninteractive, Workstream C, CP workflow, worker, scheduler, queue, Codex invocation, provisioning, receipt provisioning, executable authorization, publication, or general orchestration authority. | Authority issuance; Coordinator ingress; worker/runtime handoff; correlation and recovery. |
| Maintenance Agent | Automation ladder, route eligibility, canonical digest, biometric lease, and verifier designs exist. | Governed maintenance scanner/planner/proposer; route execution only where eligible and approved. | Required governed maintenance planner/proposer and future lease-approved executor for eligible routes. | Not a hidden reconciler; not signer/custody authority; not ES runtime authority; not CP run-control; not IM readiness owner; not coding-work lease authority. | Route-by-route autonomy matrix, owner route contracts, lease verifier implementation, rollback, and stop conditions. |
| ES | Workstream C guardrails and Remote Linux TLS signer/custody blocked decisions exist. | Governed execution substrate: admission, execution lifecycle, route semantics, runtime identity, retained opaque results. | Keep execution substrate authority and define eligible route contracts that Coordinator/CP/Maintenance/Bridge may only consume. | Does not delegate route truth to Bridge, Maintenance Agent, CP, IM, Symphony, ChatGPT, or Coordinator. | ES Admission And Runtime Boundary Realignment and worker/runtime handoff package. |
| IM | Remote profile/readiness/provenance/support-bundle docs and tests exist. | Profile/provenance/readiness/diagnostics owner. | Emit and refresh profile/readiness/provenance facts when separately authorized. | Not ES runtime authority, not CP run-control, not Coordinator state truth, not signer/custody authority, not hidden reconciler. | Profile lineage acceptance for operator-healthcheck TLS metadata after ES source evidence. |
| CP | ES adapter, remote profile diagnostics, intervention/action authority, and long-running operator contract exist. | Run-control, workflow review, intervention, cancellation decision, checkpoint, and operator-facing orchestration. | Enduring product workflow authority for Shape A. | Not ES admission/runtime owner, not IM profile owner, not Coordinator state owner, not TLS renewal executor. | Guarded action-intent handoff, profile diagnostics inputs, and review/finalization recovery. |
| Remote Linux | Proof/execution target exists, but operator-healthcheck TLS path is blocked. | Execution/proof target only through ES/IM/CP-defined routes and diagnostics. | Future proof target once TLS signer/custody and route eligibility are source-grounded. | Not reachable by this ADR; not repaired by Bridge, Maintenance Agent, Coordinator, or Symphony. | Operator-healthcheck TLS signer/custody, profile lineage, noninteractive status, and proof acceptance. |
| Symphony | Source/reference material only. | No current authority. | Possible source material for future worker-supervision mechanics. | Not included in MVP/product architecture; not an experiment now; not durable state owner, queue truth, work-selection authority, finite backlog expansion authority, a repair for TLS, or a substitute for Bridge, Maintenance Agent, ES, CP, IM, Coordinator, or operator/repo policy. | Any future role must wait for the four missing contract packages and a separate architecture decision. |

## Symphony Phase E Decision

Decision: SYMPHONY DEFERRED.

Symphony is useful as source material for worker-supervision mechanics. It is not included in the MVP/product architecture, and no experiment is currently authorized.

The official specification is tracker-generic and language-neutral. The stock/reference implementation still owns scheduler/session/workspace behavior and has no Governed Execution ES admission backend. It operates as a scheduler/runner and tracker reader that owns polling, claims, dispatch, retries, reconciliation, workspaces, and Codex session lifecycle.

The language-neutral specification could inform a future custom governed worker-supervision implementation after the missing contract packages are settled. Future use must be non-authoritative relative to CP, Coordinator, ES, Bridge, IM, Maintenance Agent, and operator/repo policy. Symphony does not solve lease issuance, executable authorization, operator-decision receipt provisioning, Coordinator provisioning/command production, CP workflow truth, ES runtime authority, or governed cross-component recovery.

Do not claim that the specification is Linear-only or inherently impossible to adapt. Do not recommend installing, integrating, cloning, or running Symphony under this decision.

## Canonical Owner Pointers

- Coordinator current status: `Governed Execution Coordinator/.docs/architecture.md`; `Governed Execution Coordinator/.docs/authority-boundaries.md`
- CP workflow authority: `Control Plane/.docs/long-running-operator-mode-contract.md`
- Bridge/Symphony detailed decision: `Governed Execution OpenAI Bridge/docs/symphony-placement.md`
- ES admission/runtime: `Execution Substrate/PLANS.md`; `Execution Substrate/.docs/system_overview/boundaries.md`; `Execution Substrate/.docs/execution_lifecycle/contracts.md`

These pointers do not transfer domain authority. Each repository remains authoritative only for the domain it owns.

## Harness Vs Product Classification

| Surface | Classification | Change condition |
| --- | --- | --- |
| Bridge dry-run lifecycle | integration scaffolding; proof-harness containment | May change when Bridge handoff schema is separately approved without widening Bridge authority. |
| Bridge ES preflight evidence | integration scaffolding; blocked-seam evidence | May change when ES publishes source-grounded route/status evidence for the same concern. |
| Bridge real-write future gates | future-design placeholder | May change only through a separate real-write ADR/design and tests. |
| Coordinator bounded SQLite mutation authority | bounded coding-work durable state authority | May be consumed only after authority issuance, Coordinator ingress, worker/runtime handoff, and correlation/recovery contracts are accepted. |
| Maintenance Agent automation ladder | stable product boundary for maintenance routes | May change only when route owners revise eligibility and docs/tests. |
| Maintenance Agent biometric lease/digest/verifier | future-design placeholder for maintenance routes | May change when implementation design and route-owner contracts are approved; not reusable as coding-work lease authority by implication. |
| ES Workstream C guardrails | stable product boundary | May change only through ES redesign governance. |
| ES TLS signer/custody decision docs | blocked-seam evidence | May change with source-grounded signer/custody evidence or explicit ES product decision. |
| IM remote profile/readiness/support bundle | stable product boundary; integration scaffolding | May change when IM profile/provenance contracts are revised without becoming run-control. |
| CP ES adapter/remote profile diagnostics | stable product boundary; integration scaffolding | May change through CP adapter/profile contracts without widening CP into ES/IM ownership. |
| Remote Alpha helper/status/renewal routes | proof-harness containment; compatibility edge; blocked seam for operator-healthcheck renewal | May change only through ES route contracts and fake/static validation before live use. |
| Symphony source/reference material | deferred source material only | May change only after a separate architecture decision following the four missing contract packages. |

## Over-Constraint Policy

Every future guardrail must declare its class:

- stable product invariant
- compatibility edge
- proof-harness containment
- blocked seam
- future-design placeholder
- accepted blocked integration contract

If the class is not stable product invariant, the guardrail must answer: what would allow this to change?

This prevents integration scaffolding from becoming permanent architecture by inertia, while also preventing blocked seams from being bypassed by convenience.

## Repo-Scoped Codex Subagent Role Definitions

Repo-local Codex custom subagent configs under `.codex/agents/` are auditable project-scoped role definitions only. They are not authority, credentials, approvals, execution capability, or transport configuration. They are not proof that every Codex surface can invoke custom agents by name. If a Codex surface cannot invoke custom agents by name, parent prompts may still instruct generic read-only subagents with copied role instructions.

These configs must remain portable and non-secret. They must not contain endpoint values, connector/tunnel/workspace/org identifiers, local private paths, environment values, certificate material, private key material, raw payloads, provider/auth/base-url/profile overrides, telemetry settings, notification settings, hooks, or behavior-enabling product configuration.

Adding or updating these role definitions does not reopen accepted Workstream C admission/runtime boundaries, does not resolve the operator-healthcheck TLS signer/custody seam, and does not change any ES Current invariant, Bounded slice rule, Temporary compatibility edge, or Reopened redesign seam.

## Static Contract Expectations

Repo-local docs tests should assert:

- ADR exists and is accepted as architecture/status, blocked by missing authority contracts, with no integration behavior enabled;
- Coordinator current status includes bounded durable SQLite mutation authority, transition/global-stop persistence, guarded public delegation, receipt verification, fencing, idempotency, replay, CAS, uncertainty, and retry;
- stale Coordinator skeleton-only, state-store-port-only, and no-durable-backend claims are rejected as current status;
- four missing contract packages remain unimplemented: Authority Issuance, Coordinator Ingress, Worker / Runtime Handoff, and Correlation And Recovery;
- Shape A is the enduring target and no-CP routing is a bounded proof candidate only;
- Symphony is DEFERRED, source/reference material only, and no experiment is authorized;
- ES Workstream A/B/C planning boundaries, `control-plane-normal-shell/v1` compatibility, no parallel ES scheduler/lifecycle store, Bridge dry-run/no-mutation, Maintenance versus coding-lease separation, and all no-secret/raw-material rules remain intact;
- no secret/raw material in ADR;
- repo-scoped Codex agent role definitions remain non-authority.
