# System Architecture Map

## 1. Purpose and status

This document is the top-level architecture map for the Go repository.

It describes the current system during an active redesign phase. The architecture documented here is real and implemented, but several major seams are intentionally reopened in `PLANS.md` and must not be treated as settled merely because they are active today.

This file stays high-level. Detailed cross-service contract rules belong in `.docs/system_overview/contracts.md`. Detailed ownership and non-ownership rules belong in `.docs/system_overview/boundaries.md`.

## 2. How to read this document

- **Observed current topology**: The major components and interactions implemented in the current Go repo.
- **Current architectural invariant**: A system-level rule the current code and docs rely on and that must not change silently.
- **Deliberate absence**: An architectural capability, boundary, or owner that the current Go system intentionally does not have.
- **Temporary compatibility-heavy convention**: An active shape or convention that keeps the current slice working but should not be mistaken for a settled long-term architectural choice.
- **Reopened redesign seam**: A major active architectural seam that `PLANS.md` explicitly reopens for redesign.

These labels are different on purpose: a current topology can be real without being final, and a compatibility-heavy convention can be active without being architecture to preserve.

## 3. System snapshot

The current Go system is a governed publication + storage + policy + admission + bounded execution system.

| Component | Observed current role |
| --- | --- |
| ARS | Blob storage, integrity verification, evidence-centered artifact registration, and runtime-facing artifact discoverability service |
| AGS | Evidence-first artifact publication service |
| EGS | Signed runtime-trust publication service |
| CGS | Separate authorize-only policy service |
| ES | Admission, submission, and Nomad-backed lifecycle projection service |
| Nomad | Scheduler and authoritative submitted-execution lifecycle source |
| Docker | Task runtime under Nomad for the current bounded execution slice |

This is a coherent architecture, but it is not presented here as the final decomposition.

## 4. Topology overview

**Observed current topology**

```text
publish caller -> AGS -> ARS

execution caller -> ES -> ARS
                       -> EGS
                    -> Nomad -> Docker

credential caller -> CGS
```

Top-level interaction notes:

- AGS is the write-time publication boundary. It publishes artifacts through ARS rather than owning storage itself.
- ES is the main composition boundary. It consumes ARS, EGS, and startup-owned runtime-config inputs to admit and submit work.
- CGS is active as a separate authorization surface, but it is intentionally outside the current ES hot path.
- Nomad is the execution backend and lifecycle authority for submitted work.
- Docker is the container runtime used underneath Nomad in the current slice.
- The current slice-0 operator topology runs ARS, EGS, AGS, and ES as containers on one Linux host/VM, while Nomad server/client and Docker run on that same host.
- Those hot-path service containers currently use Docker host networking as temporary compatibility-heavy scaffolding so the existing `127.0.0.1` dependency URLs and ES staging-path locality remain valid during slice 0.
- That one-host Linux topology has now been functionally proved through the real ES -> Nomad -> Docker path on a real Linux VM, but the current proof VM/startup mode is not yet naturally self-schedulable and may require explicit bounded `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` override handling.
- That schedulability caveat is currently treated as a proof-host environment/startup qualification, not as evidence that Linux or Docker/Nomad are the wrong platform direction for this bounded phase.
- `contracts/evidence/v1` is now the active shared kernel for the primary AGS-published artifact path into ES.
- `contracts/runtimeconfig/v1` is the active shared runtime-config surface for the workload-zone Vault config reference and blob schema.
- `observability` is cross-cutting support, not a system boundary.

## 5. Primary system flows

### Publication flow

AGS accepts publish requests in the current evidence-native grammar, derives artifact identity from package-facing identity inputs anchored to the payload digest, assembles the current aggregate artifact-evidence record with separate package claims, narrow derivation request-binding authorization claims, a smaller shared execution/runtime contract, and seal, signs that evidence, and writes the canonical publication record through ARS.

ARS then becomes the storage and retrieval boundary for the published artifact material. The current publication flow is `AGS -> ARS`, and downstream consumers do not bypass ARS for published artifact data.

The aggregate evidence model in `contracts/evidence/v1` matters here because AGS emits the first-class publication record that ES later verifies. ARS then exposes a smaller runtime-facing discovery record for ES, while descriptor and manifest support data remain secondary publication discoverability rather than the primary hot-path object.

### Admission / preparation / submission flow

ES is the current admission and submission composition point.

At a high level, ES:

- accepts execution requests through bounded preflight `:prepare` and primary submission `:submit`
- reads aggregate artifact evidence and payloads from ARS through the primary runtime-facing discovery record
- reads the workload-zone Vault config blob from ARS using the startup-configured `contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`
- loads and enforces the EGS trust model
- stages payload and mount data locally
- hands execution off to Nomad

ES does not own artifact publication, artifact storage, trust publication, or scheduler state. It composes those inputs into a bounded execution decision and submission.

For the main AGS-published artifact path, ES now requires the aggregate `contracts/evidence/v1` record. Missing or corrupt aggregate evidence is an admission failure, not a reason to re-enter the legacy fact family.

### Lifecycle flow

Lifecycle is Nomad-backed after submission.

ES exposes lifecycle and log endpoints, but it does so by deriving state from Nomad job and allocation data. ES does not keep its own lifecycle store, does not run reconciliation loops, and does not create a separate execution-state authority above Nomad.

### Policy / authorization flow

EGS and CGS occupy different roles today.

- EGS publishes signed runtime trust policy that ES verifies and enforces during admission, plus separate EGS-owned publication metadata.
- CGS provides a separate authorize-only surface backed by authenticated caller interpretation and explicit `id.conf` subject records.

CGS is active, but it is intentionally not part of the current ES hot path.

### Runtime identity / execution handoff flow

ES stages execution inputs, injects the current workload identity endpoint environment variable as the bounded workload-visible handoff, protects the ES-owned runtime subtree that backs the discovered endpoint from caller overlap, and carries a bounded workload-vault handoff derived from workload-zone vault runtime fields plus its default auth mode.

The system stops short of making ES the owner of runtime token minting, runtime identity endpoint implementation inside the workload, or a broader runtime credential lifecycle. ES currently owns the handoff boundary, not the full runtime identity system.

The checked-in workload-authored runtime-identity reference remains scaffolding only. It exercises the current contract without settling final ownership. The next bounded milestone is to prove platform-owned workload identity delivery behind the existing discovery contract rather than leaving the runtime bridge owned by workload authors.

## 6. Architectural invariants

**Current architectural invariants**

- ARS is the storage and retrieval boundary for published artifacts in the current system.
- AGS is a write-time publication service, not an execution-time dependency.
- ES is a composition boundary for admission and submission, not a scheduler.
- Nomad is authoritative for submitted execution lifecycle.
- Docker is the task runtime under Nomad in the current bounded execution slice.
- EGS publishes policy; it does not publish runtime state or own artifact execution.
- CGS is a separate authorization boundary and is not in the current ES hot path.
- `contracts/evidence/v1` is the only active shared artifact kernel in the current repo, and its scope must stay intentional rather than expanding casually.
- ES must not bypass upstream ownership boundaries for artifact storage, trust publication, or lifecycle authority.

## 7. Deliberate absences

**Deliberate absences**

- There is no standalone Deployment service boundary in this Go repo.
- There is no standalone IGS boundary in this Go repo.
- ES does not own a lifecycle-state store.
- There is no general-purpose execution orchestrator above Nomad.
- ES does not own runtime token minting.
- There is no separate artifact-translation or read-indirection service beyond the current ARS role plus startup-configured runtime-config references.
- The current Go repo does not define a separate lifecycle authority beyond ES projecting Nomad state.

These are current architectural absences, not omissions to fill automatically.

## 8. Current architectural pressure points

**Reopened redesign seams under active pressure**

- `contracts/evidence/v1` is now the only active shared artifact kernel for the AGS -> ARS -> ES path.
- The current named workload-zone Vault config reference and workload-zone Vault blob schema now live in `contracts/runtimeconfig/v1` rather than in ES-local ad hoc shapes.
- ARS currently combines storage integrity, registration, index shape, and canonical artifact retrieval in a way that influences AGS and ES choreography.
- AGS currently owns publication plus evidence and fact assembly for the active artifact model, which makes its publish surface a high-pressure architectural seam.
- ES currently carries the main request and runtime handoff composition burden, though its submit-side package resolution and staging conventions now live behind one explicit internal execution-package layout instead of drifting across helpers.
- EGS currently publishes a specific runtime-trust form that directly shapes execution-time enforcement.
- CGS currently exposes an authorize and policy-input shape closely tied to explicit `id.conf` subject records and caller/workload identity interpretation.
- Runtime identity handoff currently depends on reserved runtime workspace and path conventions that are active but not settled.

## 9. Temporary compatibility-heavy conventions

**Temporary compatibility-heavy conventions**

- `POST /v1/executions:prepare` is active today but explicitly bounded as a small preflight-success surface rather than declared as the permanent execution API shape.
- ES currently relies on `/execution/...` runtime path conventions for staged data and run data, while the runtime-identity endpoint itself is now run-scoped under an ES-owned runtime subtree.
- ES currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-visible runtime identity contract.
- The containerized hot path currently relies on Docker host networking for control-plane reachability during slice 0; that is a temporary compatibility-heavy deployment convention, not the final control-plane network model.
- Slice 0 proves the Linux substrate and governed execution handoff only. It does not yet prove strong workload identity or SPIFFE/SPIRE-backed runtime workload identity.
- AGS retains caller-supplied `policy_decisions` on the publish request even though AGS only normalizes them structurally rather than evaluating them semantically.
- CGS remains tied to `id.conf` as the current explicit subject-policy grammar.
- AGS no longer treats artifact identity as raw payload identity. The current bounded rule is instead: `artifact_digest` is a deterministic package identity derived by AGS, while payload bytes remain explicitly discoverable through the runtime-facing payload reference and cross-checked against evidence claims.
- The current aggregate evidence grammar is intentionally split into package-facing identity/publication claims, narrow derivation request-binding authorization claims, and execution/runtime claims rather than one mixed claim bag.

## 10. Relationship to detailed docs

Use the companion documents for detail:

- `.docs/system_overview/contracts.md` for cross-service surfaces, active invariants, compatibility edges, and reopened contract seams
- `.docs/system_overview/boundaries.md` for service ownership, explicit non-ownership, and boundary pressure points
- `.docs/execution_lifecycle/*` for lifecycle-specific behavior and constraints
- `PLANS.md` for redesign sequencing, superseded assumptions, and phase decision rules

This file should stay architectural and top-level. It should not absorb detailed contract inventories or service-by-service ownership rules.

## 11. Reopened redesign seams

- The shared-kernel role and long-term scope of `contracts/evidence/v1`
- The ownership shape of the workload-zone Vault runtime-config reference and blob schema
- The storage and discoverability shape of ARS
- The publication and fact-assembly shape of AGS
- The admission, package-resolution, and runtime-handoff shape of ES
- The policy-publication shape of EGS
- The authorize and policy-input shape of CGS
- The current runtime identity handoff conventions

These seams are active today and intentionally not fixed.

## 12. Decision rules for future edits

- Keep this file high-level and architecture-oriented.
- Move detailed cross-service rules into `.docs/system_overview/contracts.md`.
- Move ownership and non-ownership detail into `.docs/system_overview/boundaries.md`.
- Do not describe a seam as settled unless `PLANS.md` says it is settled.
- Document deliberate absences explicitly instead of implying them.
- If code and tests disagree with this file, update this file to match reality.
