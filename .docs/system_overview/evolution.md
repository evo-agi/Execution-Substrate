# System Evolution Rules

## 1. Purpose and status

This document defines change governance for the repository during the current bounded platform phase.

Doc-first discipline still applies: code must not be the first place a system contract, boundary, lifecycle rule, or shared-kernel decision appears.

This file governs how the repo may evolve. It does not decide which seams are open. `PLANS.md` sets:

- which architecture-defining surfaces are explicitly reopened
- which redesign work is in scope now
- which order redesign work must follow

The detailed current-state meaning of contracts, boundaries, and lifecycle rules lives in:

- `.docs/system_overview/architecture.md`
- `.docs/system_overview/contracts.md`
- `.docs/system_overview/boundaries.md`
- `.docs/execution_lifecycle/*`

## 2. Redesign-phase clarification

The repository is currently in a mixed state:

- some behavior is active and should be treated as a `Current invariant`
- some behavior is active only as a `Bounded slice rule`
- some active shapes exist only as a `Temporary compatibility edge`
- some architecture-defining surfaces are active today but intentionally open as a `Reopened redesign seam`

How to tell the difference:

- use `PLANS.md` to determine whether a surface is explicitly reopened
- use the core docs to determine whether a rule is an invariant, bounded rule, compatibility edge, or reopened seam
- use code and tests as the factual source of current behavior when prose is stale

Agent behavior in this phase:

- prefer structural clarity over preservation-by-inertia
- prefer explicit ownership over shared convenience
- preserve current structure only when the docs intentionally retain it
- surface design-governance conflicts instead of guessing

## 3. Change classifications

This repository uses the same governance terms as the core docs.

- `Current invariant`: An active rule that other components depend on and that must not change silently.
- `Bounded slice rule`: A live, intentionally narrow rule for the current slice. It is real today, but it is not automatically long-term architecture.
- `Temporary compatibility edge`: An active field, path, DTO shape, or behavior retained for continuity. It must be labeled explicitly and must not become permanent by inertia.
- `Reopened redesign seam`: A live surface that `PLANS.md` explicitly reopens for redesign. Its current shape is descriptive, not final.

These labels are intentionally separate. A rule can be active today and still be bounded, compatibility-heavy, or explicitly reopened.

## 4. Governed surfaces

Doc-first governance applies to all architecture-defining surfaces, especially:

- the shared cross-service kernel, including `internal/contracts/evidence/v1` or any future replacement
- workload-zone Vault runtime-config ownership, including the reference and blob-schema surface in `internal/contracts/runtimeconfig/v1`
- ARS storage, registration, index, and discoverability model
- AGS publication, caller binding, and evidence/fact assembly model
- ES admission, package resolution, submission, lifecycle projection, and public execution shape
- EGS trust-model and policy-publication shape
- CGS authorize DTO, proof fields, and policy-input model
- runtime identity handoff, reserved paths, and runtime workspace conventions
- execution lifecycle contract shape, including prepare, submit, status, logs, cancel, and scheduler lookup rules
- canonicalization and verification rules that cross service boundaries
- ownership boundaries and explicit non-ownership where service interaction depends on them

`PLANS.md` holds the redesign-phase list of reopened high-risk surfaces.

## 5. Allowed evolution modes

The repository may evolve in three ways.

### Extend slices

Add new behavior or a new bounded surface without changing the governing architecture of an existing surface that is not marked as a reopened redesign seam.

Use this when:

- adding a clearly scoped new capability
- widening a bounded slice intentionally
- introducing a new documented surface without reopening existing ownership

### Refine slices

Tighten, clarify, or constrain existing behavior without changing the structural boundary or core contract family.

Use this when:

- tightening validation
- clarifying ownership or non-ownership
- reducing ambiguity in an existing bounded slice
- labeling an active compatibility edge explicitly

### Re-derive seams

Rework an architecture-defining surface that is explicitly reopened in `PLANS.md`.

Use this when:

- the current contract or boundary is no longer the desired architectural endpoint
- a shared kernel role needs to be narrowed, replaced, or deliberately retained
- the current cross-service choreography is being re-derived rather than merely extended

Re-derivation is allowed only when the surface is explicitly reopened in `PLANS.md`. Re-derivation still requires doc-first governance and must not begin in code.

## 6. Required order of operations

For any governed change, the required order is:

1. confirm the surface classification in `PLANS.md` and the core docs
2. document the intended change in `PLANS.md` when redesign scope, sequencing, or seam status changes
3. update the authoritative `.docs/` pages that define the affected contract, boundary, lifecycle rule, or ownership split
4. update or add tests that express the intended behavior
5. implement code to match

Code may confirm current behavior. It must not become the design source of truth for cross-service contracts or architectural boundaries.

## 7. Decision rules

- Do not preserve a contract, boundary, DTO, path convention, or shared package role just because it already exists.
- Any re-derived surface must be documented before implementation.
- Any retained compatibility behavior must be labeled as a `Temporary compatibility edge`.
- A `Reopened redesign seam` must not be treated as fixed unless `PLANS.md` and aligned docs explicitly retain it.
- `Current invariant` changes require explicit cross-doc revision; they must not drift silently.
- `Bounded slice rule` changes still require documentation; bounded does not mean undocumented.
- Shared kernels must not grow implicitly. Any new shared meaning requires explicit ownership and cross-service justification.
- Structural coupling must be documented before it is preserved.
- Avoid introducing a new shared kernel or shared grammar casually.
- Do not let code comments or implementation shortcuts substitute for contract documentation.

## 8. Temporary compatibility edges and exceptions

Temporary behavior is allowed only when it is explicit and bounded.

Every temporary compatibility edge or exception must document:

- the reason
- the scope
- the affected contract or boundary
- whether it is test-only, local-runtime-only, or system-visible
- the removal condition

Temporary behavior must not silently redefine a contract. If externally visible behavior is temporary, the docs must say so explicitly.

## 9. Mixed-state guardrails

During the reset phase:

- stable current behavior may remain in place while a nearby seam is reopened
- reopened seams may be re-derived without treating current compatibility as a default requirement
- convenience reuse across services is not sufficient reason to retain a boundary or shared contract

Future agents should use the core docs to distinguish:

- top-level architecture in `architecture.md`
- cross-service contract rules in `contracts.md`
- ownership and non-ownership in `boundaries.md`
- execution lifecycle design and public semantics in `.docs/execution_lifecycle/*`

## 10. Drift and violation handling

If drift or a contract violation is discovered:

- stop further feature work on the affected surface
- identify whether the issue touches a `Current invariant`, `Bounded slice rule`, `Temporary compatibility edge`, or `Reopened redesign seam`
- classify the issue as:
  - unintended drift
  - undocumented compatibility behavior
  - deliberate redesign change
  - unresolved design-governance conflict
- realign the docs, tests, and code before continuing

Unresolved drift must not accumulate. Silent structural change is forbidden.
