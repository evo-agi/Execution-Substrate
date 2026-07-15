# Hybrid Integration Architecture: Bridge/Codex Handoff Plus Maintenance Agent Autonomous Maintenance

Status: proposed / draft

This is architecture discovery / ADR, not implementation. Symphony is optional candidate only. Remote Linux path is currently blocked by operator-healthcheck TLS signer/custody. This ADR does not enable real write, real Codex execution, remote maintenance, ES submit, CP diagnose, IM refresh, or live proof.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

The candidate architecture is Hybrid:

- Bridge handles assignment/evidence and eventual Codex handoff.
- Maintenance Agent handles governed maintenance proposals and future lease-approved execution when eligible.
- ES remains execution substrate.
- CP remains run-control.
- IM remains profile/provenance/readiness.

## ES Classification

This ADR is a bounded planning record for a reopened cross-repo integration seam. It does not reopen accepted ES Workstream C admission/runtime boundaries, and it does not settle operator-healthcheck TLS signer/custody. Within ES terminology:

- ES Workstream C guardrails are a Current invariant for this ADR.
- Bridge dry-run evidence is a Bounded slice rule outside ES authority.
- Remote Alpha helper/status/renewal surfaces are Temporary compatibility edges and proof-harness containment unless ES docs promote them.
- Operator-healthcheck TLS signer/custody remains a Reopened redesign seam and blocked seam.

## Scope

This ADR records the candidate integration architecture across Bridge, Codex, Maintenance Agent, Execution Substrate, Infrastructure Manager, Control Plane, connector/tunnel transport, and the Remote Linux proof target. It is a static contract for the next design tranche only.

It does not implement tools, start runtimes, create certs or profiles, renew material, mutate repositories, invoke shell execution, contact remote systems, invoke Codex, submit to ES, run CP diagnostics, run IM refresh, push, create PRs, or merge.

## NWP v0 And Strategic Autonomy Alignment

Bridge connector-safe source intake and no-mutation handoff are implemented and
live-tested as Bridge-local evidence/projection. They do not invoke Codex or
mutate repos. Local real Codex execution and local acceptance remain separate
CLI-only and non-MCP-visible paths.

Nightly Work Protocol v0 is proposed as a bounded development-harness/evidence
protocol. It is not a stable product contract, not unattended execution, not
durable orchestration authority, and not hidden run truth. Full policy-bounded
autonomy is the long-term target: the operator's target role is strategy,
budgets, periodic reports, and exception handling.

The A2 target durable-state owner is the separate local NWP Coordinator. The
current repository name is Governed Execution Coordinator and is provisional,
not a schema or authority identity. The A2-P1 skeleton exists locally, but no
production storage backend, scheduler, worker loop, repair loop, local commit
behavior, or publication behavior is created here. API and Symphony remain
future optional planning/ingress/reporting or dispatch adapter candidates only.
Neither is implemented for A2, and neither owns durable state or lease
authority. Repo ownership boundaries remain unchanged: Bridge remains
adapter/evidence; CP remains product workflow authority; ES remains
admission/runtime authority; IM remains readiness/provenance/diagnostics; MA
remains owner-contracted maintenance.

NWP/autonomy does not redefine ES Workstream C or runtime authority. CP
compatibility remains bounded. There is no TLS/noninteractive route widening in
this ADR. Economic or financial goals do not alter ES admission/security
contracts. No current unattended execution is claimed.

## Candidate Architecture

| Component | Current evidence | Current authority | Candidate role | Non-claims | Unresolved integration points |
| --- | --- | --- | --- | --- | --- |
| ChatGPT | Human-facing review and intent surface is the initiating context for Bridge proposals. | Human/operator intent and review only. | Create or review assignments that Bridge can validate and record. | Not run-control, not ES authority, not repository writer, not hidden execution truth. | Exact connector UX, assignment schema, and review checkpoints. |
| Connector / MCP tunnel | Bridge tunnel docs describe an externally/platform-owned transport path. | Transport/integration path, externally/platform-owned. | Carry guarded Bridge calls when the operator has configured the transport. | Not lifecycle authority, not repo authority, not proof authority, not Codex authority. | Live readiness, deployment ownership, production support model, and platform custody. |
| Bridge | Dry-run lifecycle, assignment/evidence projection, local preflight evidence, connector-safe no-mutation Codex handoff source intake, Bridge-local no-mutation Codex handoff evidence recording, idempotent retry/conflict handling, and separate real-write design gates exist. | Assignment/evidence adapter; local Bridge policy gate. | Record or reuse connector-safe source ledger evidence and no-mutation Codex handoff packets as Bridge-local evidence while preserving future real-write separation. | Does not own ES, CP, IM, MA, tunnel, repository mutation, shell execution, push, PR, merge, local acceptance, real Codex execution, or live proof. | Any future Codex invocation boundary. |
| Codex | Candidate coding worker exists outside this ADR; Bridge docs currently do not enable real Codex through connector/tunnel. | Candidate worker only when separately invoked under its own guardrails. | Consume a handoff packet after separate approval and perform human-reviewed work in an isolated future path. | Not enabled by this ADR; not invoked by Bridge here; not lifecycle or maintenance authority. | Invocation method, workspace isolation, diff validation, review loop, and audit handback. |
| NWP Coordinator | A2-P1 skeleton exists locally in the current `Governed Execution Coordinator` repository. | Future local coding-work durable state owner; P1 has a state-store port only. | Own future lease-bound finite backlog state, durable work-item state, scheduling, attempt/repair accounting, recovery, reporting, global-stop enforcement, and later local-commit eligibility. P1 provides lease identity parsing/canonicalization, fail-closed unsupported authorization, finite backlog parsing, pure state transitions, global stop checks, and report projections. | Not ES admission, runtime, lifecycle, status, route, TLS, noninteractive, or Workstream C authority; no production store, executable authorization, scheduler, worker loop, sandbox, repair, commit, publication, ES route, or ES runtime behavior exists in this ADR. | Production state backend decision, executable authorization model, sandbox, and first zero-repair/no-commit executable slice outside ES product runtime. |
| Maintenance Agent | Automation ladder, route eligibility, canonical digest, biometric lease, and verifier designs exist. | Governed maintenance scanner/planner/proposer; route execution only where eligible and approved. | Required governed maintenance planner/proposer and future lease-approved executor for eligible routes. | Not a hidden reconciler; not signer/custody authority; not ES runtime authority; not CP run-control; not IM readiness owner. | Route-by-route autonomy matrix, owner route contracts, lease verifier implementation, rollback, and stop conditions. |
| ES | Workstream C guardrails and Remote Linux TLS signer/custody blocked decisions exist. | Governed execution substrate: admission, execution lifecycle, route semantics, runtime identity, retained results. | Keep execution substrate authority and define eligible route contracts that MA/CP/Bridge may only consume. | Does not delegate route truth to Bridge, MA, CP, IM, Symphony, or ChatGPT. | Operator-healthcheck TLS signer/custody, noninteractive status contract, remote proof readiness. |
| IM | Remote profile/readiness/provenance/support-bundle docs and tests exist. | Profile/provenance/readiness/diagnostics owner. | Emit and refresh profile/readiness/provenance facts when separately authorized. | Not ES runtime authority, not CP run-control, not signer/custody authority, not hidden reconciler. | Profile lineage acceptance for operator-healthcheck TLS metadata after ES source evidence. |
| CP | ES adapter, remote profile diagnostics, intervention/action authority, and long-running operator contract exist. | Run-control, workflow review, intervention, and operator-facing orchestration. | Consume ES/IM/MA projections under explicit contracts and retain run-control authority. | Not ES admission/runtime owner, not IM profile owner, not TLS renewal executor. | Guarded action-intent handoff to MA, profile diagnostics inputs, and review checkpoints. |
| Remote Linux | Proof/execution target exists, but operator-healthcheck TLS path is blocked. | Execution/proof target only through ES/IM/CP-defined routes and diagnostics. | Future proof target once TLS signer/custody and route eligibility are source-grounded. | Not reachable by this ADR; not repaired by Bridge, MA, or Symphony. | Operator-healthcheck TLS signer/custody, profile lineage, noninteractive status, and proof acceptance. |
| Symphony | Placement docs identify it as optional external dispatcher/harness candidate. | No current authority. | Optional dispatcher candidate if a future design needs it. | Not required for the hybrid path; not a repair for TLS; not a substitute for Bridge, MA, ES, CP, or IM authority. | Whether it is needed at all, and if so, which non-authoritative dispatch contract it may use. |

## Integration Point Map

| Integration point | Status | Notes |
| --- | --- | --- |
| ChatGPT <-> connector | unknown platform contract | Bridge documents bounded operator-provided/live-tested connector-to-Bridge A0 operational evidence, but ES owns no platform contract; this ADR performs no connector smoke or live call and grants no A2 authority. |
| connector <-> tunnel | unknown | Tunnel readiness is not exercised here. |
| tunnel <-> Bridge | dry-run only | Bridge can expose guarded dry-run/evidence tools; real-write and real Codex remain disabled through this path. |
| Bridge <-> Codex | no-mutation source intake and evidence recorder implemented/live-tested | Bridge source ledger evidence/projection and no-mutation handoff packet recording are implemented/live-tested with exact retry reuse and same-source conflict handling only; they are not Codex invocation, repository mutation, ES admission/runtime/lifecycle authority, local runner/acceptance, connector-triggered execution, durable coordination, or A2 durable work-item state. |
| Bridge <-> repo workspace | dry-run only | Future real-write gates are documented, but this ADR does not enable repository mutation. |
| Bridge <-> ES | dry-run only | Bridge ES preflight evidence is local, non-authoritative, and not ES status truth. |
| Bridge <-> MA | designed only | Future proposal/evidence handoff only; no maintenance execution. |
| MA <-> ES | dry-run only | MA may plan/propose around ES-owned route contracts; autonomous execution remains bounded and future. |
| MA <-> IM | exists and tested | Local evidence/readiness/report consumption exists; live refresh is outside this ADR. |
| MA <-> macOS authorization | designed only | Biometric lease/digest/verifier designs are static and fail-closed. |
| ES <-> Remote Linux | blocked | Operator-healthcheck TLS signer/custody is source-insufficient. |
| ES <-> Nomad/Docker/SPIRE/Vault | exists and tested | Bounded product/proof surfaces exist; they do not resolve operator-healthcheck signer/custody by inference. |
| IM <-> Remote Linux | exists and tested | Readiness/profile/support paths exist when operator-run; no refresh or collection is run here. |
| IM <-> CP profile emission | exists and tested | CP may consume IM profile facts without becoming IM authority. |
| CP <-> ES | exists and tested | CP ES adapter is opt-in consumer integration; ES remains admission/runtime authority. |
| CP <-> IM profiles | exists and tested | CP diagnostics consume profile/provenance facts; they do not create proof or signer authority. |
| Symphony <-> Codex/Bridge | designed only | Optional candidate/harness only, not required and not authority; it may not own durable state, choose work outside coordinator policy, or expand the finite backlog. |

## Message-Bus Reduction Path

The implemented Bridge/Codex evidence path is a no-mutation handoff:

1. ChatGPT creates or validates an assignment through Bridge when the sealed packet path is appropriate.
2. When connector dispatch should avoid local paths or sealed raw assignment payloads, ChatGPT may record connector-safe source ledger evidence through `record_no_mutation_codex_handoff_source`.
3. Bridge records assignment/evidence or source evidence under Bridge policy.
4. Bridge may record a sealed no-mutation handoff packet through `record_no_mutation_codex_handoff`.
5. The source evidence and handoff contain safe labels, assignment metadata, non-authority notices, and redacted evidence references only.

This first slice has no repository write, no shell execution, no Codex invocation through connector, no push, no PR, no merge, no local acceptance, and no ES/CP/IM/MA lifecycle authority. Real Codex execution and local acceptance remain separate CLI-only and non-MCP-visible paths. Any later Codex invocation through connector/tunnel requires a separate design.

Future real-write requires all of these gates before implementation:

- explicit separate tool;
- capability flag;
- repo allowlist;
- path allowlist;
- forbidden sensitive paths;
- dry-run preview;
- worktree isolation;
- clean-tree guard;
- diff guard;
- changed-file validation;
- report redaction;
- no push/PR/merge unless separately enabled;
- audit before and after.

These gates are future-design placeholders until a separate ADR or design tranche promotes them. They do not enable real write today.

## Autonomous Maintenance Path

Maintenance Agent is not optional for reducing infra babysitting. Maintenance Agent must not become a hidden reconciler. It may become a governed autonomous maintenance planner/proposer/executor only under owner-defined route contracts, leases, evidence, rollback, and stop conditions.

| Capability class | Current ADR position |
| --- | --- |
| current ready capabilities | Local scan, classification, evidence summaries, proposals, and bounded operator-approved routes where current docs already allow them. |
| design-ready capabilities | Canonical maintenance plan digest, biometric lease shape, fail-closed verifier shape, and route-matrix documentation. |
| lease-required capabilities | Any future unattended or low-touch execution that mutates material or runs a maintenance action. |
| blocked-by-route-owner capabilities | Routes whose ES/IM/CP owner contract has not declared the action eligible. |
| blocked-by-signing/custody capabilities | Operator-healthcheck TLS renewal or replacement until ES signer/custody is source-grounded or explicitly decided. |
| blocked-by-remote-auth capabilities | Any route requiring remote authorization that has not been made noninteractive and owner-approved. |
| unsafe/not desired capabilities | Hidden reconciliation, broad shell, broad SSH, fallback repair, signer invention, CP run-control bypass, IM profile mutation by inference, Bridge-mediated maintenance execution. |

First MA tranche: route-by-route autonomous maintenance capability matrix plus lease-approved execution design. That tranche should classify each route, define owner approval requirements, identify evidence and rollback, and preserve fail-closed stop conditions. It must not execute maintenance in this ADR tranche.

## TLS/Linux Blocker

The Linux-box path remains blocked by operator-healthcheck TLS. Signer/custody evidence is source-insufficient. No repo can resolve it by execution today.

Bridge cannot repair it. Maintenance Agent cannot repair it without ES signer/custody and route eligibility. Symphony would not repair it. The next TLS step requires source-grounded signer/custody evidence or explicit ES product decision.

Service/governance TLS evidence, profile diagnostics, Bridge preflight evidence, biometric leases, and support bundles must not be used as substitutes for operator-healthcheck signer/custody.

## Harness Vs Product Classification

| Surface | Classification | Change condition |
| --- | --- | --- |
| Bridge dry-run lifecycle | integration scaffolding; proof-harness containment | May change when Bridge handoff schema is separately approved without widening Bridge authority. |
| Bridge ES preflight evidence | integration scaffolding; blocked-seam evidence | May change when ES publishes source-grounded route/status evidence for the same concern. |
| Bridge real-write future gates | future-design placeholder | May change only through a separate real-write ADR/design and tests. |
| MA automation ladder | stable product boundary | May change only when route owners revise eligibility and docs/tests. |
| MA biometric lease/digest/verifier | future-design placeholder | May change when implementation design and route-owner contracts are approved. |
| ES TLS signer/custody decision docs | blocked-seam evidence | May change with source-grounded signer/custody evidence or explicit ES product decision. |
| ES Workstream C guardrails | stable product boundary | May change only through ES redesign governance. |
| IM remote profile/readiness/support bundle | stable product boundary; integration scaffolding | May change when IM profile/provenance contracts are revised without becoming run-control. |
| CP ES adapter/remote profile diagnostics | stable product boundary; integration scaffolding | May change through CP adapter/profile contracts without widening CP into ES/IM ownership. |
| Remote Alpha helper/status/renewal routes | proof-harness containment; compatibility edge; blocked seam for operator-healthcheck renewal | May change only through ES route contracts and fake/static validation before live use. |

## Over-Constraint Policy

Every future guardrail must declare its class:

- stable product invariant
- compatibility edge
- proof-harness containment
- blocked seam
- future-design placeholder

If the class is not stable product invariant, the guardrail must answer: what would allow this to change?

This prevents integration scaffolding from becoming permanent architecture by inertia, while also preventing blocked seams from being bypassed by convenience.

## Implemented Evidence Slice And Remaining Candidates

Implemented first slice: Bridge no-mutation Codex handoff packet/design through connector-safe source intake and no-mutation handoff evidence recording. It remains Bridge-local evidence only and must stay no-write, no-shell, no-push/PR/merge, no-local-runner, no-local-acceptance, and no-Codex-invocation unless separately approved.

Next unimplemented candidates: executable authorization model,
executable-validation sandbox, production state backend, guarded execution linkage, connector-triggered
Codex invocation, autonomous acceptance/publication, and any Symphony or API
adapter remain future-only until separately designed and approved. Parallel MA
candidate: autonomous maintenance capability matrix / lease-approved execution
design. It must remain design-only until owner route contracts, leases,
rollback, evidence, and stop conditions are approved.

No ES implementation is included in this ADR.

## Repo-Scoped Codex Subagent Role Definitions

Repo-local Codex custom subagent configs under `.codex/agents/` are auditable
project-scoped role definitions only. They are not authority, credentials,
approvals, execution capability, or transport configuration. They are not proof
that every Codex surface can invoke custom agents by name. If a Codex surface
cannot invoke custom agents by name, parent prompts may still instruct generic
read-only subagents with copied role instructions.

These configs must remain portable and non-secret. They must not contain
endpoint values, connector/tunnel/workspace/org identifiers, local private
paths, environment values, certificate material, private key material, raw
payloads, provider/auth/base-url/profile overrides, telemetry settings,
notification settings, hooks, or behavior-enabling product configuration.

Adding or updating these role definitions does not reopen accepted Workstream C
admission/runtime boundaries, does not resolve the operator-healthcheck TLS
signer/custody seam, and does not change any ES Current invariant, Bounded
slice rule, Temporary compatibility edge, or Reopened redesign seam.

## Static Contract Expectations

Repo-local docs tests should assert:

- ADR exists;
- hybrid architecture is candidate/proposed, not final;
- Symphony optional/candidate only;
- TLS remains blocked;
- Bridge real-write is not enabled;
- Bridge source intake and no-mutation handoff are implemented evidence-only;
- separate local NWP Coordinator A2-P1 skeleton exists as future A2 durable-state owner; current repository name is Governed Execution Coordinator and is not schema/authority identity;
- no ES admission/runtime, Workstream C, route, TLS, or noninteractive authority drift;
- connector-triggered Codex, production state store, scheduler, repair, acceptance, commit, and publication remain future/unimplemented;
- MA autonomous maintenance is required but bounded;
- no hidden reconciler;
- ES/CP/IM ownership boundaries preserved;
- harness vs product classification exists;
- over-constraint policy exists;
- no secret/raw material in ADR.
