# Milestone 7 First Buyer And Failure Mode

## 1. Purpose and status

This is a Milestone 7 commercialization hypothesis artifact for Governed
Execution. It exists to identify a likely first buyer, a painful failure mode,
buyer-facing promises, GUI implications, demo implications, and validation work
without changing product architecture.

This document does not widen Execution Substrate, Control Plane, or
Infrastructure Manager contracts. It does not make buyer demand, market urgency,
or painful failure frequency repo-validated facts. It does not make a chat
surface, operator console, log, support bundle, readiness report, retained
bundle, workflow report, generated profile, proof artifact, or `.out` material
authoritative.

The primary guardrail is
[`claim-ledger.md`](claim-ledger.md). This document uses that ledger's allowed
and forbidden wording, required qualifiers, evidence classes, and source gaps.
Buyer language here is a working commercialization hypothesis
until validated by external research or customer discovery.

Sources inspected for this artifact include Execution Substrate
`.docs/commercialization/claim-ledger.md`, `.docs/mvp.md`, `PLANS.md`,
`.docs/system_overview/boundaries.md`, and
`.docs/execution_lifecycle/contracts.md`; Control Plane `README.md`,
`.docs/architecture.md`, `.docs/invariants.md`,
`.docs/long-running-operator-mode-contract.md`,
`.docs/governed-execution-console-v1.md`, and
`.docs/execution-substrate-integration.md`; Infrastructure Manager `README.md`,
`.docs/architecture.md`, `.docs/remote-supported-host-alpha.md`, and
`.docs/remote-supported-host-support-bundle.md`.

## 2. One-sentence positioning hypothesis

Governed Execution provides governed execution boundaries for accepted ES-backed
autonomous software work in the current bounded MVP slice.

Draft buyer-facing version:

For security-conscious engineering teams adopting coding agents, Governed
Execution makes high-risk autonomous work admitted, bounded, observable,
interruptible by guarded request, retained, and reviewable without making the
agent, chat surface, logs, support bundle, or workflow report the authority.

Required qualifiers:

- This is positioning, not a production-readiness claim.
- The repo-backed scope is accepted ES-backed governed execution paths in the
  current bounded MVP slice.
- Interruptibility means guarded request plus later observed terminal state, not
  guaranteed immediate stop.
- Reviewability means CP-owned workflow state plus supporting non-authoritative
  evidence, not audit certification.

## 3. Primary buyer hypothesis

The first buyer hypothesis is security-conscious platform, security, or
infrastructure engineering teams adopting coding agents or internal automation
agents for repository work, infrastructure changes, deployment-adjacent
workflows, or regulated operational workflows.

This is a product-positioning hypothesis. The repos support the authority split
and current bounded controls, but they do not prove this buyer profile or market
urgency.

| Role | Job-to-be-done | Current pain | Proof they need | What they will not care about yet | Wording that will create distrust |
| --- | --- | --- | --- | --- | --- |
| Economic buyer | Decide whether autonomous software work can be allowed in higher-risk engineering areas without creating uncontrolled operational or compliance exposure. | Agent adoption pressure is arriving before governance, audit review, and intervention practices are settled. | A bounded demo showing admitted ES-backed work, CP-owned review/finalization, guarded intervention, retained opaque results, and non-authoritative support evidence. | Fine-grained runtime internals, proof harness mechanics, exact UI chrome, or broad model comparisons. | "Production-ready autonomous execution platform", "guaranteed safe agents", "full compliance out of the box", or any claim that every agent action is covered. |
| Technical champion | Prove that governed execution can sit between agents and risky engineering workflows without replacing existing orchestration, IAM, or observability systems. | Existing tools may log activity but do not clearly separate workflow authority, runtime authority, evidence, and presentation surfaces for accepted agent work. | Source-backed authority map: ES owns admission/runtime handoff/lifecycle projection/result retention, CP owns orchestration/review/intervention/finalization, IM owns readiness/provenance/diagnostics. | Pricing packaging, generic marketing claims, or a polished public website before the boundary proof is credible. | "Temporal replacement", "Okta replacement", "LangSmith replacement", or "generic workflow builder." |
| Day-to-day operator | Understand what is happening, why the run is here, what can safely be done, what evidence supports it, what is stale or projection-only, and what happened after intervention. | Run state, provider state, logs, results, reports, and notifications can disagree or arrive at different times, making safe operator action hard. | Console or snapshot evidence with authority/source labels, allowed actions, stale/projection markers, requested-vs-observed intervention state, and redacted evidence refs. | Competitive category theory, market sizing, or full enterprise IAM roadmap details. | "The UI controls the run", "the report is the source of truth", "cancel means stopped", or "logs prove final outcome." |
| Skeptical reviewer | Determine whether the product preserves governance and security boundaries under pressure. | Agent-governance products can blur demos, logs, reports, permissions, and runtime facts into one untrustworthy story. | Negative claims and caveats: no raw secret/log/prompt/diff/workspace exposure, evidence is non-authoritative, CP/ES/IM ownership is explicit, and compatibility edges remain labeled. | Vision-language flourishes, broad TAM claims, or unsupported vendor comparisons. | "Full sandbox", "least privilege solved", "enterprise IAM for agents", "support bundle proves run truth", or "Remote Alpha is production." |
| Likely blocker | Prevent a new tool from adding unclear authority, sensitive evidence exposure, or another unreviewed platform dependency. | They inherit incident risk if an agent path bypasses policy gates, approval workflows, identity boundaries, or artifact controls. | A clear disqualification checklist, explicit non-goals, validation backlog, and a demo that fails closed when required evidence is missing. | Demo polish that hides blockers, high-level category labels, or claims about future integrations. | "Trust us", "automatic remediation", "silent fallback", "raw logs available in the UI", or "we can bypass existing governance." |

## 4. Painful failure mode

Failure-mode hypothesis:

Agents can act faster than existing controls, logs, and human approval processes
can keep up.

This is a commercialization problem statement that needs external validation.
Repo docs justify why governed boundaries exist; they do not prove market
frequency or buyer urgency.

| Scenario | Why it is risky | What existing tools may already cover | What gap remains | Governed Execution demo beat | Claims that must remain qualified |
| --- | --- | --- | --- | --- | --- |
| Risky repo change | A coding agent can touch sensitive files, policy code, build scripts, or dependency surfaces before a human understands the blast radius. | Git history, branch protection, CI, code review, local execution logs, and static reports. | Those tools may show what happened after the fact but not whether the work entered through an admitted ES-backed path with CP-owned review and finalization. | Risky work request, CP workflow entry, ES contract/prepare admission, retained opaque result, CP review/finalization. | Not every agent action is covered; only accepted ES-backed paths in the bounded MVP slice. Reviewability is not audit certification. |
| Infrastructure/configuration change | Agent-authored automation may alter deploy-adjacent config, runtime settings, or host assumptions faster than platform teams can validate ownership boundaries. | IaC review, config repositories, CI checks, deployment approvals, change-management tickets. | Existing approvals may not tie runtime execution evidence, environment provenance, and retained result material back to clear CP/ES/IM ownership. | ES submit/runtime handoff, lifecycle projection, retained opaque result, redacted support evidence. | IM evidence remains readiness/provenance/diagnostics only; Governed Execution is not a general deployment platform. |
| Credential or secret-adjacent operation | An agent path near credentials can create anxiety about token possession, secret exposure, lease state, and who is allowed to see evidence. | IAM systems, Vault, secret scanners, access logs, endpoint controls. | Logs and reports may not clearly prove that ES does not broker tokens and that only non-secret runtime handoff evidence is shown. | Runtime identity handoff evidence, support evidence shown as non-authoritative and redacted. | Bounded workload identity handoff is not full enterprise IAM; no ES token brokerage; no raw secrets, JWT-SVIDs, TLS/SPIFFE/Vault material, API keys, or credential material should be exposed. |
| Deployment or operational runbook action | A fast agent could trigger operational steps before the operator knows whether the action is still safe, stale, or already superseded. | Runbooks, ticket approvals, deployment tools, scheduler state, observability dashboards. | Existing tools may show provider status but not a CP-owned guarded action receipt with requested-vs-observed separation. | Guarded stop request, later observed terminal state, lifecycle projection. | Stop is a request, not a guarantee; later lifecycle evidence proves what happened. ES status is projection, not scheduler truth. |
| Regulated or audit-sensitive workflow | A regulated team may need to explain who authorized, what evidence was reviewed, and which artifacts are non-authoritative. | GRC systems, audit logs, SIEM, change records, ticketing, code review exports. | Audit records may not distinguish authority from evidence or preserve why a bounded action was allowed without exposing sensitive raw material. | CP review/finalization, retained opaque result, redacted support evidence, no raw artifact exposure. | This is not audit certification, not a compliance product claim, and not a LangSmith or observability replacement. External regulatory claims require citations and buyer validation. |

## 5. Why now

This section is a placeholder for current external citations before public use.
Do not use it externally until official or current external research is attached
and dated.

Categories to validate:

- Enterprise agent identity/governance vendors: validate whether buyers are
  actively budgeting for agent identity, policy, approval, and evidence
  boundaries.
- Coding-agent audit/session-log vendors: validate whether session logs and
  replay are perceived as enough, or whether buyers still need admitted,
  interruptible, retained, and reviewable execution boundaries.
- Workflow/orchestration systems: validate where buyers expect Temporal-like,
  runbook, CI/CD, or ticketing systems to remain authority.
- Observability/audit-log systems: validate whether buyers see logs/traces as
  sufficient evidence or as insufficient because they are not control truth.

Unsupported public claims until validated:

- Market size, buyer urgency, adoption rates, incident frequency, regulatory
  demand, competitor gaps, or named-vendor comparisons.
- Claims that enterprises are already standardizing on this category.
- Claims that existing IAM, workflow, or observability products cannot solve any
  part of the problem.

## 6. What we are not

| Non-claim | Why buyers may confuse us with it | Safer explanation |
| --- | --- | --- |
| Not another AI coding agent | The first visible scenario may involve coding-agent work. | Governed Execution provides governed execution boundaries around accepted ES-backed risky autonomous work; it is not the agent intelligence layer. |
| Not a chat UI | Operators may first encounter the system through a browser, app, message, or channel surface. | Chat, browser, app, iMessage, notification, and channel surfaces are presentation or guarded action-adapter surfaces. They are not run truth. |
| Not an Okta or Microsoft Entra replacement | Runtime identity handoff and credential-adjacent evidence sound like identity-platform territory. | Current repo-backed identity claims are bounded workload identity handoff for supported runtime paths, not enterprise IAM replacement. Future identity integrations must preserve ES authority boundaries. |
| Not a Temporal replacement | CP currently uses a Temporal-backed shell, and buyers may focus on workflow state. | CP owns workflow state and run-control semantics in the current architecture; Governed Execution does not replace Temporal as a general workflow engine. |
| Not a LangSmith replacement | Evidence, traces, reports, and review artifacts may look like an observability or model-tracing product. | Logs, traces, reports, and support evidence are non-authoritative evidence/projection unless a contract says otherwise. |
| Not a generic workflow builder | The system has workflow-owned review, intervention, and finalization. | Governed execution workflows are bounded by CP contracts and accepted ES-backed paths; this is not a general workflow-builder surface. |
| Not a full enterprise IAM layer | The buyer pain includes identity and credentials. | The current claim is bounded runtime identity handoff and workload-side credential acquisition where supported, not full IAM lifecycle management. |
| Not a general deployment platform | Infrastructure/configuration scenarios may sound deployment-oriented. | IM owns bootstrap, readiness, provenance, diagnostics, and support evidence. It does not own governed run control or general deployment lifecycle. |

## 7. Buyer-specific promise

Security buyer:

For accepted ES-backed governed execution paths in the current bounded MVP
slice, Governed Execution helps security teams separate admission, runtime
identity handoff evidence, CP-owned review/finalization, guarded intervention,
and non-authoritative logs/support bundles so high-risk agent work can be
reviewed without promoting evidence artifacts into authority.

Required qualifiers:

- Runtime identity handoff is bounded and non-secret; it is not full enterprise
  IAM.
- ES does not broker Vault tokens or expose raw credential material.
- Logs, reports, readiness reports, support bundles, retained bundles, and
  `.out` material are evidence/projection, not run truth.

Platform buyer:

For accepted ES-backed governed execution paths, Governed Execution gives
platform teams a governed path with producer compatibility gates, ES prepare
preflight, bounded runtime-profile selection, repeatable lifecycle projection,
retained opaque outputs when produced, and an explicit CP/ES/IM ownership split
that avoids turning convenience integrations into architecture.

Required qualifiers:

- `control-plane-normal-shell/v1` is the current bounded compatibility path, not
  final general runtime architecture.
- ES status is lifecycle projection, not a parallel scheduler or lifecycle
  store.
- IM profiles, checks, readiness reports, and support bundles are provenance or
  diagnostics only.

Operator:

For operators watching a live or recently terminal run, Governed Execution aims
to answer what is happening, why it is here, what can safely be done, what
evidence supports it, what is stale or projection-only, and what happened after
intervention through CP-owned read and guarded-action contracts.

Required qualifiers:

- The console is a presentation adapter over `ExecutionFlowSnapshot v1`; it is
  not control truth.
- Allowed actions come from CP-owned actionability state and guarded
  intervention routes.
- A guarded stop request is not proof that the workload has stopped; later
  lifecycle observation proves the terminal outcome.

## 8. GUI implications

These are buyer/failure-mode implications for the operator console and demo
story. They do not request implementation changes in this document.

| Console implication | Classification | Requirement intent |
| --- | --- | --- |
| Top-of-page trust summary | Presentation-only | Show the operator the current authority posture first: workflow authority availability, current run status, current attempt state, allowed action summary, and evidence quality. |
| Authority/source labels | Read-model requirement | Every decisive fact should identify owner/source class: CP workflow authority, ES lifecycle/evidence, IM provenance, or projection fallback. |
| "Why this is allowed" panel | Presentation-only | Explain admitted path, producer compatibility, prepare/preflight, runtime-profile selection, and CP actionability in human-readable form without making the panel authority. |
| "What can I safely do" action panel | Guarded-action requirement | Render only actions present in CP-owned allowed-action state and submit through the guarded intervention contract with expected-state guards. |
| Evidence/projection/stale labels | Read-model requirement | Label logs, reports, retained refs, support evidence, readiness reports, profiles, and projections with freshness and non-authority status. |
| Requested-vs-observed intervention state | Read-model requirement | Distinguish accepted/rejected request, pending/applied/no effect status, ES/provider stop-request evidence, and later observed terminal state. |
| Retained-result versus CP finalization separation | Read-model requirement | Show ES-retained opaque result material separately from CP-owned semantic interpretation, review, checkpointing, and finalization. |
| Support evidence shown as non-authoritative | Presentation-only | Present redacted support evidence as supporting narrative only, with no implication that a bundle proves run truth or production readiness. |
| No raw secret/log/prompt/diff/workspace exposure | Guarded-action requirement | Keep critical material behind deny-by-default artifact policy; do not inline raw secrets, logs, prompts, diffs, workspaces, retained bundles, credentials, TLS/SPIFFE/Vault material, API keys, or WebAuthn material. |
| Buyer-facing external market context in-console | Future/not MVP | External market claims, competitor claims, or benchmark context should not appear in the MVP operator console. |

## 9. Demo implications

Buyer-facing demo spine:

| Beat | Buyer question answered | Repo owner of truth | Evidence to show | Caveat to say aloud | Validation needed before external demo |
| --- | --- | --- | --- | --- | --- |
| Risky work request | What risky autonomous work is being governed? | CP for workflow entry and objective/task context | CP workflow entry or run context, with the agent not treated as authority | This is a demo scenario, not proof of market pain or every agent action. | Dry-run selected scenario and verify no unsupported market claim is embedded. |
| CP workflow entry | Who owns progression, review, intervention, and finalization? | CP | Workflow state, task lifecycle, review/finalization refs, operator actionability | CP consumes ES; it does not define ES execution contracts. | Verify workflow state is current and not reconstructed from reports/traces. |
| ES contract/prepare admission | Why was this ES-backed path allowed before submit? | ES | Producer contract declaration summary plus prepare success for the selected artifact/runtime profile | Contract is compatibility metadata, not health or run authority; prepare creates no run. | Collect current contract and prepare evidence for the exact demo path. |
| ES submit/runtime handoff | What boundary receives the accepted work? | ES | Submit receipt, ES run id/provider handle, bounded runtime-profile evidence | Submit is async handoff, not completion or durable ES lifecycle ownership. | Verify successful submit receipt and matching CP attempt manifest. |
| Runtime identity handoff evidence | What identity/credential boundary exists? | ES plus workload-side runtime evidence where validated | Non-secret `authority_handoff` fields and workload-side credential-acquisition proof when available | Bounded handoff evidence only; not full IAM, not ES token brokerage, not live credential truth. | Verify emitted fields and redact sensitive material before showing. |
| Lifecycle projection | What is happening now? | ES for status projection, CP for run-control truth | ES status/lifecycle projection, CP `ExecutionFlowSnapshot v1`, field/source labels | Projection is not scheduler truth or write authority; CP workflow state remains run-control truth. | Verify snapshot/status freshness and matching provider/run identity. |
| Guarded stop request | What can the operator safely do? | CP for intervention request; ES/provider for stop-request receipt where applicable | Guarded request body/receipt, expected-state guard, ES/provider stop-request evidence | Request acceptance is not proof of terminal stop. | Exercise stale rejection and valid guarded request in the chosen demo mode. |
| Later observed terminal state | What happened after intervention? | ES lifecycle projection plus CP finalization state | Later status projection and CP durable intervention outcome | Later observation proves the outcome; do not say cancel was guaranteed. | Capture later terminal observation and CP intervention history. |
| Retained opaque result | What output evidence exists? | ES for retained bundle; CP for semantic interpretation | Result-bundle ref or fetch evidence, not raw bundle contents | Retained material is opaque ES output and not CP checkpoint/finalization truth by itself. | Verify retained result exists when claimed and keep contents non-inline. |
| CP review/finalization | Who decides whether work is accepted? | CP | Review, policy/audit/finalization summary, checkpoint/progression state where applicable | ES and IM do not finalize CP objectives. | Verify CP final state and review/finalization evidence align with the run. |
| Redacted support evidence | What can be shared for support or review? | IM for bundle assembly; CP/ES for their own evidence sections | Redacted support bundle/report summary, digests, non-authority labels | Support evidence is supporting narrative only, not run truth or production readiness. | Validate bundle redaction/deny scan and lineage; do not expose raw logs, prompts, diffs, workspaces, credentials, or retained bundles. |

## 10. Discovery questions

1. Where are coding agents or internal automation agents used today?
2. What repository paths, infrastructure surfaces, or operational workflows are
   agents currently forbidden to touch?
3. Which agent actions require human approval today, and where does that
   approval happen?
4. What slows approval down: unclear risk, missing evidence, tool friction, or
   lack of ownership?
5. Have you had an incident or near miss where automation acted faster than
   review, logging, or approval could keep up?
6. Which logs, traces, reports, or session recordings do reviewers trust today,
   and which do they distrust?
7. What evidence would a security reviewer need before allowing an agent near a
   deployment-adjacent workflow?
8. What identity or IAM expectations would you bring to agent execution?
9. Do you expect agent identity to be solved in an IAM system, a workflow
   system, a runtime system, or a separate governed-execution layer?
10. Which workflow/orchestration system owns approval, state, or finalization in
    your current process?
11. What would you expect an interrupt or stop action to mean operationally?
12. Where do you need requested action, accepted request, and observed effect to
    be separated?
13. What raw material should never appear in an operator UI or support bundle?
14. What would make an external demo credible enough for a second technical
    conversation?
15. What would immediately disqualify this product from security or platform
    review?
16. Would a governed execution layer be acceptable if it integrated with
    existing IAM/workflow/observability systems rather than replacing them?
17. Who would operate this day to day, and who would own failures?
18. What proof would move this from interesting to budgeted: live demo, design
    review, audit evidence, integration proof, or customer reference?

## 11. Success and rejection criteria

Signs this buyer profile is right:

- Security, platform, or infrastructure leaders describe agent adoption as
  blocked by admission, approval, evidence, identity, or intervention concerns.
- Technical champions can map the CP/ES/IM authority split onto their existing
  governance model.
- Operators react strongly to requested-vs-observed intervention state,
  authority/source labels, and stale/projection evidence markers.
- Buyers accept that the product is not another agent, chat UI, IAM replacement,
  workflow-engine replacement, observability replacement, or deployment
  platform.

Signs this buyer profile is wrong:

- Buyers primarily want developer productivity features, code quality
  automation, or agent UX rather than governed execution boundaries.
- The painful failure mode is already solved by their CI, workflow, IAM,
  observability, or deployment systems.
- They require broad production, HA, multi-tenant, enterprise IAM, or general
  deployment claims before the bounded MVP value is meaningful.
- They reject the accepted ES-backed qualifier and need governance for every
  arbitrary agent action immediately.

Evidence that would move the ICP:

- Toward platform: repeated demand for compatibility gates, profile emission,
  runtime repeatability, and integration with existing platform workflows.
- Toward security: repeated demand for identity handoff boundaries, evidence
  redaction, non-authority labeling, and audit-review posture.
- Toward infrastructure: repeated demand around remote host readiness,
  configuration drift, runtime hardening evidence, and support bundles.
- Toward developer productivity: repeated demand for faster coding throughput,
  code review automation, agent selection, or local dev UX, with little concern
  for governance boundaries.

Positioning must change if:

- Buyer discovery shows the strongest pain is not fast agent action outrunning
  controls, logs, and approval.
- Buyers treat logs/session replay as sufficient and do not value admission,
  bounded runtime handoff, guarded intervention, retained results, or CP-owned
  finalization.
- The winning buyer requires claims the claim ledger forbids or marks as source
  gaps, such as production readiness, full IAM, guaranteed cancellation, full
  sandboxing, or general deployment.

## 12. Open validation backlog

External market research needed:

- Current citations on enterprise agent governance, agent identity, coding-agent
  audit/session logging, workflow/orchestration expectations, and observability
  or audit-log limits.
- Current competitor/category research before naming vendors or making
  comparative claims.
- External evidence for the failure-mode frequency and buyer urgency.

Customer discovery needed:

- 10 to 15 interviews across security, platform, infrastructure, and developer
  productivity teams using the questions above.
- Validation of the economic buyer, technical champion, operator, skeptical
  reviewer, and likely blocker roles.
- Evidence of budget owner, buying trigger, disqualifiers, and required proof.

Demo proof needed:

- Demo-specific contract and prepare evidence for the accepted ES-backed path.
- Runtime-profile and non-secret runtime identity handoff evidence for the
  selected path.
- CP `ExecutionFlowSnapshot v1` or equivalent read-model evidence for the demo
  run.
- Guarded intervention proof that separates stale rejection, accepted request,
  stop-request evidence where applicable, and later terminal observation.
- Retained-result and CP finalization evidence with retained output kept opaque.
- Redacted support evidence with support-bundle non-authority and deny-scan
  posture validated before external sharing.

GUI feedback needed from the project owner:

- Which operator-console requirements should be treated as MVP demo-critical
  versus future polish.
- Which top-of-page trust summary fields best match the buyer narrative.
- How much support evidence should appear in the demo without distracting from
  CP/ES authority boundaries.
- Which failure-mode scenario should anchor the first buyer demo.

Claim-ledger updates needed if wording changes:

- Update the ledger before any public claim that strengthens the buyer profile,
  failure-mode urgency, production readiness, IAM integration, observability
  integration, deployment capability, interruptibility, sandboxing,
  least-privilege, audit/compliance, or competitor comparison.
- Add external citations or customer discovery evidence before moving buyer or
  market claims out of source-gap status.
- Preserve compatibility labeling for `control-plane-normal-shell/v1` and
  Remote Alpha unless governing docs explicitly change first.
