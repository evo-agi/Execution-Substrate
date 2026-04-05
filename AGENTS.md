# Execution Substrate Agent Rules

## 1. Scope

These rules apply to the entire repository:

- `/Users/ds/Repositories/Execution Substrate`

## 2. Purpose

This file defines how agents must operate during the current redesign phase.

The repository is in a controlled mixed state:

- some surfaces are stable enough to treat as `Current invariants`
- some active behavior is only a `Bounded slice rule`
- some active shapes exist only as a `Temporary compatibility edge`
- some architecture-defining surfaces are intentionally open as a `Reopened redesign seam`

Agents must not treat everything as frozen.
Agents must not treat everything as mutable.

## 3. Authority hierarchy

Use authority in this order:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

Additional rules:

- Do not use `README.md` as design authority.
- Do not treat code as design authority for cross-service behavior.
- If docs and code disagree on factual behavior, code and tests win for current behavior, and the docs must be realigned.
- If docs disagree on design intent and code does not settle it, surface a design-governance conflict instead of guessing.

## 4. Required terminology

Agents must use the redesign-phase classification model from the core docs.

- `Current invariant`: Active behavior that must not change silently.
- `Bounded slice rule`: Active behavior that is real today but may be revised explicitly.
- `Temporary compatibility edge`: Active behavior retained for continuity and required to be labeled as temporary.
- `Reopened redesign seam`: An active architecture-defining surface that `PLANS.md` explicitly keeps open for re-derivation.

Rules for use:

- Do not call a surface frozen unless an authoritative doc explicitly names it as fixed.
- Do not treat a `Reopened redesign seam` as settled architecture.
- Do not treat a `Bounded slice rule` as optional or undocumented.
- Do not preserve a `Temporary compatibility edge` by inertia.

## 5. Required workflow before changes

Before making changes:

- consult `PLANS.md`
- consult the relevant `.docs/` pages
- identify the affected contracts, invariants, boundaries, lifecycle rules, and seam classifications
- confirm whether the change is an extension, refinement, or re-derivation
- confirm whether the affected surface is a `Current invariant`, `Bounded slice rule`, `Temporary compatibility edge`, or `Reopened redesign seam`
- surface conflicts instead of working around them

Agents must consult `PLANS.md` before making structural changes.

## 6. Redesign-phase behavior rules

- Do not preserve a contract, boundary, DTO, path convention, or shared package role just because it already exists.
- Do not assume the current architecture is final unless the authoritative docs explicitly retain it.
- Prefer structural clarity over backward familiarity.
- Treat reopened seams as intentional change points, not as off-limits areas.
- Re-derive a surface only when `PLANS.md` marks it as reopened.
- Do not introduce a new shared kernel or shared grammar casually.
- Do not let one service's convenience leak into another service's public contract without documentation.
- Label compatibility-heavy behavior explicitly.
- Prefer explicit ownership and non-ownership over implied coupling.

## 7. Doc-first change discipline

Doc-first discipline is mandatory for:

- slice extension
- slice refinement
- re-derivation of reopened seams

Required order:

1. update `PLANS.md` when redesign scope, seam status, sequencing, or design intent changes
2. update the authoritative `.docs/` pages that define the affected contract, boundary, lifecycle rule, or ownership split
3. update or add tests that express the intended behavior
4. implement code to match

Enforcement rules:

- No architectural change without corresponding doc update.
- Docs must be updated before code changes are treated as complete.
- Code must not become the first or only statement of cross-service behavior.
- Do not silently change an invariant, boundary, or lifecycle rule.
- Do not silently widen a shared package into a new de facto kernel.

## 8. During implementation

During implementation:

- prefer documented contracts over implementation convenience
- do not bypass governance, storage, policy, or lifecycle authority boundaries
- do not introduce undocumented behavior
- do not introduce implicit coupling between services
- do not rely on implementation shortcuts as justification for architecture
- keep compatibility edges explicit and narrow when they are intentionally retained

If a change touches a `Current invariant`, the related authoritative docs must be revised explicitly.

If a change touches a `Bounded slice rule`, the docs must still be updated explicitly.

If a change touches a `Temporary compatibility edge`, the reason, scope, and removal condition must remain documented.

If a change touches a `Reopened redesign seam`, ensure the redesign is allowed by `PLANS.md` and documented before implementation.

## 9. After changes

After changes:

- update `PLANS.md` when redesign intent, seam status, or active workstream implications changed
- update `.docs/system_overview/` when architecture, contracts, boundaries, or governance changed
- update `.docs/execution_lifecycle/` when lifecycle design, contract, or implementation behavior changed
- ensure docs, tests, and code describe the same current reality

Do not leave the repository in a state where code, tests, and docs disagree about authoritative semantics.

## 10. Conflict handling

If you discover drift or a design conflict:

- stop broadening the affected surface
- identify whether the issue touches an invariant, bounded rule, compatibility edge, or reopened seam
- classify the issue as unintended drift, temporary compatibility behavior, deliberate redesign change, or design-governance conflict
- realign docs before treating the implementation as complete

Do not work around a conflict by adding more hidden behavior.

## 11. Specific enforcement rules

- ALWAYS consult `PLANS.md` and `.docs/` before making changes.
- NEVER implement structural redesign without first checking whether the surface is reopened in `PLANS.md`.
- NEVER let code become the design source of truth for cross-service behavior.
- NEVER preserve an existing structure solely because it is already implemented.
- NEVER introduce implicit cross-service coupling.
- PREFER documented ownership boundaries over convenience reuse.
- PREFER explicit compatibility labeling over silent shape retention.

## 12. Capability probing rules

- ALWAYS consult `/Users/ds/Repositories/Execution Substrate/.docs/system_overview/capability_probing.md` when adding or changing capability-sensitive validation.
- NEVER introduce OS-based branching for capability-sensitive behavior.
- ALWAYS validate capability by behavior or static resource checks, not by platform labels.
- ENFORCE capability only at validation boundaries.
- FAIL fast when a required capability cannot be proven; do not add fallback behavior.
