# Workstream C7 Consolidation Checkpoint

## 0. Purpose And Status

This document records a Workstream C7 consolidation checkpoint for ES
Admission and Runtime Boundary Realignment after the Remote Alpha
operator-healthcheck TLS signer/custody closeout.

Status:

- `Docs-only checkpoint`: C7 records current Workstream A, B, and C source
  state. It does not implement behavior.
- `No behavior/API/runtime change`: C7 makes no behavior, API, or runtime
  change.
- `Current invariant`: Workstream A shared-kernel gate is satisfied and remains
  narrow.
- `Current invariant`: Workstream B artifact publication/storage gate is
  satisfied and remains evidence-owned.
- `Bounded slice rule`: Workstream C0-C6 are present as the current ES
  admission/runtime guardrail history.
- `Temporary compatibility edge`: the current Control Plane governed-execution
  consumer path remains compatible only as documented.
- `Reopened redesign seam`: the long-term ES request, prepare, submit,
  runtime-profile, lifecycle-projection, retained-result, runtime-identity,
  workload-zone runtime-config, package-layout, and ARS discovery/index seams
  remain open unless an authoritative source already settles them.

C7 is a consolidation checkpoint, not a new route or runtime feature. No
route/API behavior changed by C7. C7 adds no route, API shape, runtime profile,
admission policy, scheduler behavior, signer option, renewal eligibility, CP
diagnostic behavior, IM profile lineage behavior, or MA scheduling eligibility.

## 1. Checkpoint Summary

Workstream C7 is a docs/static-test-only consolidation checkpoint. It records
that the ES Workstream A and B input-boundary gates are already satisfied for
the current Milestone 2C.1 ES work, Workstream C0 through C6 are present, and
the Remote Alpha operator-healthcheck TLS branch is paused in a blocked
source-insufficient signer/custody state.

The next behavior-changing Workstream C slice must preserve Control Plane
compatibility and non-authority boundaries unless an explicit migration or
versioning plan is documented first.

## 2. A And B Gate State

Workstream A shared-kernel gate is satisfied and remains narrow.
`internal/contracts/evidence/v1` remains the only active shared artifact
evidence kernel for the current `AGS -> ARS -> ES` path. It is not a standalone
service boundary, not a shared semantic dumping ground, and not ownership for
ES public execution/lifecycle grammar, CP orchestration, IM readiness, support
bundles, retained bundles, reports, logs, summaries, proof artifacts, or
generated evidence.

Workstream B artifact publication/storage gate is satisfied and remains
evidence-owned. AGS owns publish-time fact assembly, aggregate evidence,
signing, upload, and ARS registration. ARS owns blob storage, content-addressed
integrity, runtime-facing discovery records, descriptor/manifest support
reads, and discovery/index behavior. Payload identity, artifact identity, and
package identity remain distinct. ES must consume artifacts through the
designed ARS discoverability surface, not by inheriting ARS support tuple
grammar as ES public grammar.

## 3. Workstream C0-C6 State

Workstream C0-C6 are present.

- C0: docs and docs-contract gate only; no runtime implementation changes.
- C1: prepare/admission guardrail tests over bounded `:prepare` preflight
  non-effects, ARS discovery/evidence/payload/package identity consumption,
  signed evidence, narrow execution/runtime claims, support grammar exclusion,
  and current compatibility surfaces.
- C2: submit and lifecycle-projection guardrails that keep
  `POST /v1/executions:submit` as the ES-owned async handoff through Nomad and
  keep `lifecycle_projection.source=nomad` with an opaque same-run revision.
- C3: retained-result and `authority_handoff` guardrails that keep retained
  result bundles ES-owned opaque output artifacts and keep `authority_handoff`
  bounded, non-secret, and non-authoritative.
- C4: runtime identity and Vault handoff guardrails that keep credential
  acquisition workload-side and prevent ES from minting, fetching, brokering,
  storing, rotating, parsing, or validating Vault or Codex credential material.
- C5: status/logs/result/cancel compatibility and non-authority guardrails.
  Status remains Nomad-backed projection/evidence, logs remain bounded current
  compatibility/evidence, result remains opaque ES-retained output delivery,
  and cancel remains a bounded ES/Nomad cancellation handoff.
- C6: ES Admission Policy Layer v0 and its configurable-input follow-up. ES
  remains the final ES-bound admission-policy gate; CP may later preflight or
  render ES policy decisions, but CP is not the final ES admission gate. IM
  remains readiness, provenance, and diagnostics only.

## 4. Compatibility Edges Preserved

The next Workstream C slice must explicitly preserve these current edges until
a documented migration or versioning plan changes them:

- `control-plane-normal-shell/v1`.
- `execution_substrate.runtime_profile`.
- `GET /v1/executions:contract` remains a narrow producer declaration, not
  health/readiness/run authority.
- `POST /v1/executions:prepare` remains bounded preflight, not hidden
  orchestration.
- `POST /v1/executions:submit` remains the ES handoff surface.
- Status remains a Nomad-backed projection, not an ES-owned lifecycle model.
- ES-retained opaque `application/gzip` result bundles by `run_id`.
- CP owns orchestration, review, checkpoint, and finalization.
- IM profile/readiness/provenance remain diagnostics only.
- `authority_handoff` and `outcome_evidence` remain bounded non-authority
  evidence/projection surfaces.

## 5. Reopened Seams

C7 records these reopened seams without settling them:

- long-term ES request/submit DTOs;
- long-term `:prepare` role;
- admission policy model beyond C6 v0;
- runtime-profile vocabulary;
- execution locator/allocation projection;
- `/execution/...` package layout;
- retained-result route evolution;
- runtime identity handoff owner;
- workload-zone runtime-config owner;
- ARS discovery/index long-term shape.

Any future slice that resolves one of these seams must update `PLANS.md` and
the authoritative `.docs/` contract or boundary page before behavior changes
land.

## 6. Remote Alpha TLS Closeout

Remote Alpha TLS blocked decision reference:
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`.

The TLS branch is paused because current signer/custody evidence is
source-insufficient. No signer/custody option is selected.
operator-healthcheck TLS replacement remains blocked. `operator-healthcheck-tls-renew`
remains blocked by `unsupported_signing_topology`. Service and governance TLS
signers are not selected by inference.

At this C7 checkpoint, P0v noninteractive status was design/static only. It did
not implement a noninteractive status route, authorize MA scheduled execution,
enable renewal, select a signer, create replacement authority, or make
`unsupported_signing_topology` safe.

Later status alignment: a subsequent P0v tranche implements only the read-only
`operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format
json` observation route. That later route uses a dedicated local runtime and a
streamed fixed collector, has no fallback emitter, writes no remote summary,
does not authorize MA/IM/CP/Bridge/Coordinator consumption or scheduled
execution, and creates no route from status evidence to renewal permission.
Renewal and replacement remain blocked; signer/custody remains unresolved.

No CP diagnose rerun, IM refresh, ES route execution, renewal, replacement, or
live proof occurred as part of the TLS closeout. The TLS branch should not
block Workstream C product work unless new source-grounded signer/custody
evidence appears.

## 7. Next Safe Slices

### Producer Contract / Prepare Boundary Tests

- Why safe: strengthens existing C0-C1 guardrails around
  `GET /v1/executions:contract` and `POST /v1/executions:prepare` without
  changing runtime behavior.
- Risks: accidentally widening `:contract` into readiness or `:prepare` into
  hidden orchestration.
- Stop conditions: a test requires new route behavior, run state, scheduler
  contact, CP workflow grammar, or changed public DTOs.
- Validation hints: docs-contract tests plus targeted `es/admission` and
  `es/api` producer-contract/prepare tests.

### Runtime Profile Compatibility Matrix Cleanup

- Why safe: clarifies the current `execution_substrate.runtime_profile` and
  `control-plane-normal-shell/v1` compatibility matrix before new behavior.
- Risks: treating the current annotation/profile vocabulary as settled
  architecture or changing enablement semantics by documentation drift.
- Stop conditions: cleanup implies a new runtime profile, package kind,
  default profile, or CP-owned runtime decision.
- Validation hints: targeted runtime-profile resolution tests and docs-contract
  assertions.

### Retained Result Bundle Contract Clarification

- Why safe: documents the current opaque `application/gzip` bundle-by-`run_id`
  contract and CP non-ownership before route evolution.
- Risks: promoting retained bundle contents, manifests, paths, or materialized
  workspaces into CP orchestration/review/checkpoint/finalization authority.
- Stop conditions: clarification requires inspecting bundle payloads, changing
  result headers, adding route fields, or changing retention behavior.
- Validation hints: retained-result tests, API lifecycle-header tests, and
  docs-contract assertions.

### Lifecycle Projection Authority Labels

- Why safe: sharpens existing status/cancel/logs/result non-authority labels
  while preserving the current Nomad-backed projection model.
- Risks: exposing scheduler identifiers, turning projection revision into a
  write precondition, or implying an ES-owned lifecycle store.
- Stop conditions: proposed labels require new Nomad fields, changed lifecycle
  JSON, changed cancel semantics, or live scheduler validation.
- Validation hints: lifecycle projection, lifecycle headers, and Workstream C
  guardrail tests.

### Artifact Identity / Discovery Seam

- Why safe: can clarify how ES consumes AGS/ARS evidence, payload, package
  identity, and ARS discovery without changing admission behavior.
- Risks: inheriting ARS descriptor/manifest/index/support grammar as ES public
  grammar or collapsing payload identity into artifact/package identity.
- Stop conditions: proposed clarification requires new AGS/ARS API behavior,
  support tuple promotion, or altered ES admission lookup semantics.
- Validation hints: Workstream A/B/C guardrails and docs-contract tests.

### CP Compatibility Fixture Alignment

- Why safe: can align fixture expectations to current ES-owned surfaces while
  preserving CP as consumer and non-owner.
- Risks: allowing CP examples, proof harnesses, or diagnostics to define ES
  core contracts.
- Stop conditions: fixture work requires CP orchestration semantics in ES DTOs,
  changed ES routes, CP diagnose execution, IM refresh, proof startup, or live
  route execution.
- Validation hints: docs-contract tests, targeted CP compatibility fixture
  tests if local/static, and no live/proof/startup commands.
