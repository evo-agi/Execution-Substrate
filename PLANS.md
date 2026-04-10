# Execution Substrate Current Plan

## Status

This document is the authoritative planning document for the current Execution Substrate workstreams, bounded platform hardening, and explicitly reopened seams.

It supersedes the earlier slice-lock plan that treated ACS, ARS, AGS, EGS, CGS, ES, and the now-removed legacy signing kernel as near-final architectural endpoints.

The repository currently contains a coherent but constrained architecture that is visible directly in:

- `ars/`
- `ags/`
- `egs/`
- `cgs/`
- `es/`
- `.docs/system_overview/`
- `.docs/execution_lifecycle/`

That implementation remains useful evidence of current behavior. It is no longer the default answer to what the long-term architecture must be.

The redesign focus in this phase is the architecture-defining core:

- cross-service contracts
- invariants
- package and kernel boundaries
- publish, store, verify, and execute flow
- policy and authorization surfaces
- runtime identity and execution handoff

Docker scripts, runbooks, environment polish, and deployment helper glue are not the primary redesign target of this phase.

The repo has now reached a practical architecture-freeze line for the current bounded slice. Further architectural changes require explicit stop-condition justification. Primary implementation effort should now prefer:

- bootstrap automation
- startup graph hardening
- Docker/Nomad substrate normalization
- execution-path reliability
- operator and integration ergonomics
- operator failure-guidance hardening in scripts and runbooks, with `scripts/01_bringup.sh check` remaining the readiness source of truth

Current bounded implementation status:

- Slice 0 is functionally proved on Linux in the bounded sense the repo now claims: the real operator path has run on a real Linux VM through containerized ARS/EGS/AGS/ES, config-driven non-dev Nomad, ES `:submit`, Nomad allocation, Docker execution, and the same-path staging invariant.
- Supported-environment qualification for slice 0 is now proved on the current Apple Silicon Mac through a Lima `qemu` guest running Ubuntu 24.04 arm64 with Docker healthy, a packaged pre-managed non-`-dev` `nomad.service`, positive natural `cpu.totalcompute`, and no `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` override.
- The previously investigated Ubuntu 24.04 VMware/aarch64 local guest remains unsupported on this Mac for the slice-0 `supported` claim: under the real root-managed non-`-dev` service path it still leaves the ready node at `cpu.totalcompute=0` even though Docker is healthy and Nomad leadership is present.
- The previously investigated Lima `vz` Ubuntu 24.04 arm64 local guest also remains unsupported on this Mac for the same natural supported-host claim: the real root-managed non-`-dev` service path still leaves the ready node at `cpu.totalcompute=0`.
- Those unsupported local results are host/profile-specific qualification facts, not evidence that Ubuntu is unsupported in general, that Apple Silicon local Linux guests are unsupported in general, or that Docker/Nomad are the wrong bounded substrate direction for this phase.
- Supported-environment qualification for slice 0 is now narrower than the original local bring-up convenience path: the intended supported story is a Linux host/VM where Docker is healthy and a pre-managed non-dev Nomad client/server is already running in a naturally schedulable mode with positive `cpu.totalcompute`.
- The script-managed local Nomad path remains useful evidence and troubleshooting scaffolding, but it is now treated as a bounded fallback/operator convenience path rather than the clean supported-environment story for Linux.
- The operator readiness path must not silently treat `nomad agent -dev` as that supported profile; a pre-managed dev-mode agent is unsupported for the slice-0 support claim even if it reports healthy Docker and positive compute.
- Docker host networking remains temporary slice-0 compatibility scaffolding, not the final control-plane network architecture.
- Slice `1A` and slice `1B` are now landed in the bounded sense the repo claims: the real ES -> Nomad -> Docker path now proves a same-container platform-owned supervisor/helper, helper-private SPIRE channel, bounded workload-visible `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, fixed non-root workload launch boundary, bounded real SPIRE-backed JWT-SVID delivery for the `workload_vault` target, and helper-death/task-fatal behavior.
- That first workload-identity slice is intentionally compatibility-narrow: no root workloads, no arbitrary image-user execution, no shared helper/workload UID, and no supplemental groups that collapse the helper/workload boundary.
- Useful credential flow completion is now also landed in the bounded sense the repo claims: one workload can use the platform-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT` plus the bounded workload-vault metadata to authenticate to a real Vault dev/test target and read one secret through the real ES -> Nomad -> Docker path, without reintroducing workload-authored bridging or platform-owned Vault token brokerage.
- The current supported local proof path is now repo-owned and converged with the bounded useful credential-flow proof: `scripts/72_supported_local_setup.sh` prepares the guest-side supported-local proof environment, including a proof-scoped real SPIRE server/agent path plus a proof-scoped real Vault dev/test target, while `scripts/73_supported_local_proof.sh run` is the canonical host-side supported-local proof wrapper on this Mac. That path records canonical proof workspaces under `.out/es-proof-<id>/`, keeps generated proof bootstrap material in `managed-secrets.conf`, and uses guest `/tmp` scratch only as an internal Lima implementation detail because the mounted repo tree is read-only inside the guest.

## Current Planning Objective

The repository is no longer in rewrite-by-default mode.

The current goal is to keep bounded platform work honest while making reopened seams explicit. Core contracts or boundaries should be re-derived only when `PLANS.md` names them as reopened; otherwise, current implementation, docs, and proof tooling should be treated as bounded platform work to harden rather than rewrite by default.

The current plan must prioritize:

- structural clarity
- Go-native boundaries
- explicit package-local ownership
- reduced dependence on the existing cross-service grammar
- reduced leakage of one service's DTO or fact model into another service's public shape

Current code remains the starting point for any reopened-seam work, not a compatibility promise. Historical references outside this repo, including the Monolith/Python repository, may inform migration context or bounded proof/bootstrap conventions only; they are not current architecture authority.

## Current-State Facts To Preserve During Redesign

The following are useful current implementation facts and should remain visible to future agents while the redesign is underway:

- The repository currently implements five primary service boundaries: ARS, AGS, EGS, CGS, and ES.
- The current publication flow is `AGS -> ARS`.
- The current admission and execution flow is `request -> ES -> EGS / ARS -> Nomad -> Docker`.
- ES currently composes startup-owned runtime-config references, ARS, and EGS in its hot path. CGS exists but is not in the current ES hot path.
- The current primary artifact model crossing AGS, ARS, and ES is aggregate evidence plus payload, with manifest retained as supporting publication data.
- The repository now also carries a first parallel shared evidence kernel in `internal/contracts/evidence/v1` for the primary `AGS -> ARS -> ES` artifact path, and ES now requires that aggregate evidence on its first-class admission path.
- ARS currently exposes immutable blob reads plus a smaller runtime-facing discovery record for evidence and payload, while retaining descriptor/manifest support data as secondary publication discoverability.
- The repository now carries a small shared runtime-config surface in `internal/contracts/runtimeconfig/v1` for the named workload-zone Vault config reference and the current workload-zone Vault config blob schema.
- ES startup config currently carries the required workload-zone Vault config reference, while ARS remains the blob/discoverability owner for the corresponding runtime-config blob.
- CGS currently loads explicit subject policy records from startup `id.conf` input and returns bounded authorization decisions through `POST /v1/credential/authorize`.
- EGS currently publishes a signed runtime-trust payload with signer policy and artifact revocation policy, alongside separate EGS-owned publication metadata.
- ES currently exposes a bounded preflight `POST /v1/executions:prepare`, a primary public execution handoff at `POST /v1/executions:submit`, and minimal Nomad-backed lifecycle endpoints whose current `run_id` lookup and projected-allocation rules are explicit ES-internal slice policy rather than public contract.
- ES now localizes submit-time payload staging, mount staging, and runtime-ready package assembly behind one explicit internal execution-package layout; `/execution/staged` and `/execution/run` remain current bounded runtime conventions rather than diffuse helper assumptions.
- ES currently retains run-scoped host staging while the submitted workload may still depend on it, then best-effort removes `execution.staging_root_dir/<run_id>` after ES observes terminal success; failed, canceled, lost, or otherwise ambiguous outcomes retain staging for operator debugging.
- The primary operator bring-up/check path now distinguishes service health, prepare-ready state, and full submit-ready state instead of treating ES `/health` alone as execution readiness.
- The current bounded operator hot path now uses the operator SPIFFE identity as the sole caller for AGS publish and ES execution/lifecycle entry surfaces; `service/deployment` no longer defines that current slice.
- The current shared execution/runtime contract in `internal/contracts/evidence/v1` is now limited to environment allowlist input, required runtime capabilities, `target_platform`, and `network_access`; non-runtime workload metadata no longer defines the live AGS -> ARS -> ES hot path.
- ES currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as its bounded workload-visible runtime identity handoff and internally backs the discovered endpoint with a run-scoped ES-owned runtime subtree.
- ES currently derives its workload-vault handoff from workload-zone vault runtime fields plus a bounded local default auth mode rather than from workload-attribute selector policy.
- The current slice-0 operator path now targets one Linux host/VM, runs ARS/EGS/AGS/ES as containers, keeps Nomad server/client and Docker on that same host, and treats Docker host networking as temporary compatibility scaffolding rather than final control-plane network architecture.
- The current slice-0 operator path now requires strict client-cert authentication at the hot-path TLS boundary, including `/health`, and ARS now rejects the configured bootstrap issuer on both read and write paths like the rest of the hot path.
- The current slice-0 operator path records the ES same-path staging proof at bring-up time, while slice `1A` and slice `1B` now separately prove the first bounded strong workload-identity handoff for runtime workloads.
- The current slice-0 operator path has been functionally proved on a real Linux VM through the real ES -> Nomad -> Docker execution path, and the current supported local reference profile on this Mac is Lima `qemu` + Ubuntu 24.04 arm64 with pre-managed non-`-dev` Nomad and positive natural `cpu.totalcompute`; the previously investigated VMware/aarch64 and Lima `vz` local profiles remain unsupported on this Mac because natural `cpu.totalcompute` stays `0`.
- The current AGS publish path now distinguishes artifact identity from payload identity: payload bytes remain content-addressed by `payload_digest`, while AGS derives `artifact_digest` from package-facing identity inputs only before registering the runtime-facing discovery record through ARS.
- The current shared authorization surface inside `internal/contracts/evidence/v1` is now limited to derivation request binding (`derivation_spec_digest`, `output_id`); workload-binding, policy-linkage, producer-trace, and derivation-constraint residue no longer define the active shared kernel.

These facts describe the current repository. They are not, by themselves, decisions that the reset must preserve.

## Explicit Supersession Of Prior Assumptions

The earlier planning assumptions below are now reopened and no longer count as fixed architectural endpoints:

- ARS is no longer treated as a frozen end-state storage and artifact-index boundary.
- AGS is no longer treated as a frozen end-state publication and fact-assembly boundary.
- EGS is no longer treated as a frozen end-state runtime-trust boundary.
- CGS is no longer treated as a frozen end-state authorization boundary.
- ES is no longer treated as a bounded-but-settled execution boundary.
- The old `contracts/signing/v2` kernel has now been excised from the active repo, and its former shared-kernel role is superseded by the evidence-native artifact path.
- The first controlled kernel-migration cut is allowed to add a parallel shared kernel and migrate one bounded path before broader service redesign lands.

More specifically, the redesign phase explicitly reopens or qualifies these previously locked assumptions:

- The current ARS registration, index, and read contract are reopened. The current runtime-facing discovery record, secondary descriptor support path, and discoverability shape remain implementation facts, not fixed architecture.
- The current AGS publish contract and fact assembly model are reopened. The existing manifest and signed-fact bundle are not presumed to be the enduring publication grammar.
- The current cross-service contract forms are reopened. Existing wire and package contracts survive only until they are explicitly retained, replaced, or wrapped as temporary compatibility edges.
- The historical `contracts/signing/v2` package no longer participates in any current code path. The repository now relies on `internal/contracts/evidence/v1` as the only active shared artifact kernel, while the long-term scope of that kernel remains under review.
- The current ES, ARS, CGS, and EGS interaction model is reopened. Existing call paths and non-call paths are current facts, not architectural endpoints.
- The current ES public execution and admission shape is reopened. This includes the `:prepare` and `:submit` split, current request and result DTOs, current scheduler receipt model, and current lifecycle projection model.
- The current runtime identity handoff conventions are reopened. The current path layout, `vault_identity_jwt` handoff shape, and reserved container paths are implementation choices that must now be justified or replaced.

Compatibility with any current contract is allowed only as a temporary and explicit transition tactic. If compatibility is retained, document:

- the reason
- the scope
- the removal condition

Do not describe compatibility edges as frozen architecture.

## Architecture-Defining Redesign Scope

### In Scope Now

The first redesign pass is explicitly about the architecture-defining core:

- shared contracts and any shared kernel
- service API shapes and DTO ownership
- data model boundaries between services
- artifact publication, storage, retrieval, verification, and execution flow
- policy model and trust model ownership
- authorization model ownership
- runtime identity and execution handoff
- package structure where it defines architectural meaning
- explicit clarification of what remains shared versus service-local

### Out Of Scope For The First Redesign Pass

The following are not primary redesign targets until the core surfaces stabilize:

- Docker scripts
- runbooks
- environment polish
- deployment helper glue
- superficial renames
- broad cleanup unrelated to core contract and boundary redesign
- generic refactors that do not reduce architectural ambiguity

## Redesign Workstreams

### Workstream A - Shared Contract And Kernel Reset

Purpose:

- Re-derive the minimum shared contract surface needed across services.
- Keep the shared artifact kernel narrow and evidence-owned after excising the historical signing kernel.
- Stop treating a shared package as the default home for cross-service meaning unless that meaning is truly stable and jointly owned.

Target files and packages:

- `internal/contracts/evidence/v1/`
- `ags/publish/`
- `es/admission/`
- `egs/model/`
- `ars/index/`

Success condition:

- A documented shared-kernel decision exists.
- The future shared surface is smaller and intentionally owned.
- Cross-service semantics that do not need to be shared are moved back toward service-local ownership.
- Future agents can tell which contracts are kernel-level versus service-level without inferring from package reuse.

Dependencies:

- No upstream workstream dependency beyond this `PLANS.md` reset.

### Workstream B - Artifact Storage And Publication Contract Reset

Purpose:

- Redesign the AGS and ARS contract around publication, runtime-facing discovery records, payload and evidence relationships, and visibility rules.
- Decide whether the current runtime-facing discovery shape, the secondary descriptor support path, and the current AGS artifact-identity derivation rule survive.
- Separate storage integrity concerns from publication grammar and from ES consumption needs.
- Keep the shared evidence grammar narrow: package identity remains separate, shared admission authorization is limited to derivation request binding, and execution/runtime claims remain distinct from non-shared publication or policy residue.

Target files and packages:

- `ags/api/`
- `ags/publish/`
- `ars/api/`
- `ars/index/`
- `ars/store/`

Success condition:

- The write and read contract between AGS and ARS is intentional and documented.
- The artifact discovery model is explicit about what is canonical, what is runtime-discoverable, and what is merely current secondary publication/support implementation detail.
- Payload versus artifact identity is no longer hidden in convenience assumptions.
- ES can later consume artifact data through a designed discoverability surface rather than through an inherited tuple shape.

Dependencies:

- Workstream A

### Workstream C - Execution And Admission Reset

Purpose:

- Redesign ES public admission and execution surfaces.
- Re-derive the preparation and submission boundary, scheduler handoff, and runtime package resolution from the Go codebase rather than from current inherited grammar.
- Decide what ES should own, what ES should compose, and what ES should stop carrying.

Target files and packages:

- `es/api/`
- `es/admission/`
- `es/config/`
- `es/app/`
- `cmd/es/`

Success condition:

- ES has a clear public model for admission, submission, and lifecycle projection.
- ES no longer depends on the current inherited artifact and policy grammar by convenience.
- The remaining shared execution/runtime inputs are intentionally defined rather than passively inherited from upstream publication metadata.
- Scheduler handoff, payload resolution, and lifecycle projection are described as deliberate ES boundaries.

Dependencies:

- Workstream A
- Workstream B

### Workstream D - Policy And Authorization Reset

Purpose:

- Re-derive policy ownership across EGS and CGS.
- Decide what belongs to trust publication, what belongs to authorization, and what belongs nowhere in the long-term architecture.
- Reassess the current `id.conf` policy model, authorize DTO, and remaining policy/trust ownership seams.

Target files and packages:

- `egs/api/`
- `egs/model/`
- `egs/sign/`
- `cgs/api/`
- `cgs/policy/`
- `cgs/config/`
- `cgs/app/`

Success condition:

- Policy publication and authorization ownership are explicit.
- EGS and CGS no longer carry accidental compatibility behavior without documented ownership.
- The current `id.conf` and authorize shape are either intentionally retained, replaced, or explicitly downgraded to temporary compatibility edges.
- ES can consume policy and authorization outputs through designed contracts rather than through legacy compatibility DTOs.

Dependencies:

- Workstream A
- Workstream C

### Workstream E - Lookup And Config Indirection Reset

Purpose:

- Define and adopt an explicit replacement surface for the workload-zone Vault runtime-config reference and blob schema.
- Move the required workload-zone Vault config-reference guarantee into the replacement owner.
- Remove ACS from the live runtime path once the replacement surface is real.

Target files and packages:

- `internal/contracts/runtimeconfig/v1`
- `es/config/`
- `es/admission/`
- `es/app/`

Success condition:

- The named workload-zone Vault config reference and blob schema are explicit, shared, and no longer hidden in ES-local parsing.
- ES consumes the replacement surface directly without a transitional ACS lookup hop.
- Startup validation guarantees the required workload-zone Vault config reference exists before ES serves traffic.
- Future agents can tell that workload-zone Vault config semantics live in the runtime-config surface, ARS owns the blob, and ES remains only the consumer.

Dependencies:

- Workstream A
- Workstream B
- Workstream C
- Workstream D

### Workstream F - Runtime Identity Handoff Reset

Purpose:

- Redesign the ES-to-runtime identity boundary.
- Clarify ownership of runtime identity paths, Vault auth handoff, reserved interface conventions, and capability validation.
- Remove hidden coupling between ES submit behavior, policy surfaces, workload identity selection, and container path conventions.
- Prove platform-owned runtime identity delivery rather than workload-authored bridging.

Target files and packages:

- `es/admission/runtimeidentity.go`
- `es/admission/submit.go`
- `es/config/`
- `cgs/api/types.go`
- `cgs/config/`
- `.docs/system_overview/capability_probing.md`
- `.docs/execution_lifecycle/`

Success condition:

- Runtime identity handoff has explicit ownership and a documented contract.
- The current reserved paths survive only if intentionally retained.
- The handoff contract no longer depends on accidental coupling to current ES DTOs, current CGS authorize output, or current path names.
- Capability-sensitive validation remains behavior-based and local to validation boundaries.
- The workload-visible discovery contract remains explicit, but the implementation behind it is platform-owned.
- The final bounded slice does not depend on workload authors implementing their own identity-serving shim.

Current bounded planning direction:

- Preserve `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-visible discovery contract unless a later stop-condition justifies reopening it explicitly.
- Prefer a platform-owned runtime identity companion/bridge injected with the workload allocation over direct workload access to SPIRE internals or ES-owned runtime token minting.
- Treat the checked-in workload-authored runtime identity reference as example scaffolding only, not as an acceptable final ownership model.
- Treat the current slice-0 Linux schedulability caveat as an environment qualification issue that should remain explicit, not as a blocker to planning Workstream F.
- The bounded slice `1A` and slice `1B` implementation is now the same-container runtime helper launched by a platform-owned supervisor inside the workload task.
- Slice `1A` landed the runtime boundary before useful credential flow:
  - helper runs as `0:0`
  - workload runs as fixed `10000:10000`
  - workload gets no supplemental groups and no privilege-escalation path
  - the raw SPIRE Workload API socket remains helper-private under `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`
  - the workload-visible endpoint remains `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix:///run/es-runtime-identity/<run_id>/endpoint`
  - helper readiness is required before workload start and helper death is task-fatal in the first slice
- Slice `1B` keeps the public endpoint bounded:
  - support only a platform-defined JWT-SVID retrieval operation for the workload-vault target
  - reject arbitrary audience passthrough, raw SPIRE parameter passthrough, and X.509 delivery in this slice
- First-slice workload compatibility is intentionally narrowed:
  - no root workloads
  - no arbitrary image-user execution
  - no shared helper/workload UID
  - no supplemental groups that collapse the helper/workload boundary
- Useful credential flow is now proved on top of slice `1A` and slice `1B`:
  - the helper endpoint remains bounded to the workload-vault target
  - the workload performs the bounded Vault login flow itself as a client against a proof-scoped real Vault dev/test target
  - one secret read is proved through the real ES -> Nomad -> Docker path
  - the slice still avoids platform-owned Vault token brokerage
- The supported-host follow-through after that credential-flow proof is now landed in bounded form:
  - keep the current script-managed local Nomad path explicit as bounded fallback/troubleshooting
  - distinguish supported, bounded-fallback, and unsupported substrate states in operator output and runbooks
  - use Lima `qemu` + Ubuntu 24.04 arm64 as the current supported local reference host on this Mac
  - keep the previously investigated VMware/aarch64 and Lima `vz` local profiles explicit as unsupported on this Mac because natural `cpu.totalcompute` stays `0`
  - use the repo-owned `scripts/72_supported_local_setup.sh` helper plus `scripts/73_supported_local_proof.sh run` for the current supported local proof path instead of the earlier out-of-repo `/tmp` harnesses
  - keep the canonical supported-local proof workspace under `.out/es-proof-<id>/`, with guest `/tmp` only as internal Lima scratch when the repo mount is read-only
- That runtime narrowing is part of the claim-preserving slice boundary, not an accidental compatibility gap. If bounded implementation cannot preserve the helper-only SPIRE channel or the no-privilege-escalation workload launch model, stop and reopen only the runtime shape needed to keep ownership honest.

Dependencies:

- Workstream C
- Workstream D
- Workstream E

## Ordered Execution Plan

Future agents should follow this order unless a later revision to `PLANS.md` changes it explicitly.

1. Reset planning authority in `PLANS.md`.
   This step is complete when the repo no longer treats the old frozen-slice plan as the operative design target.

2. Execute Workstream A first.
   The shared contract and kernel decision had to happen before broad service redesign because the codebase previously leaked architecture through the historical signing kernel. The current repo now carries only the evidence-native kernel on the primary artifact path.

3. Execute Workstream B second.
   AGS and ARS define the artifact publication and retrieval substrate that ES currently consumes. Their redesign must happen before ES is reshaped in earnest.

4. Execute Workstream C third.
   ES should be redesigned only after the kernel decision and artifact contract direction are clear enough to avoid re-embedding the old choreography.

5. Execute Workstream D fourth.
   Policy and authorization surfaces should be re-derived once the ES execution shape is clear enough to say what policy inputs and outputs actually belong at runtime.

6. Execute Workstream E fifth.
   Lookup/config indirection should be reset only after artifact, execution, and policy contracts have been clarified, because the replacement owner depends on those decisions.

7. Execute Workstream F sixth.
   Runtime identity handoff should be redesigned after ES, policy, and runtime-config responsibilities are clear. Otherwise path conventions and auth-plan details will re-freeze around current incidental coupling.

8. Do scripts, runbooks, deployment glue, and peripheral cleanup only after the core contracts stabilize.
   Cleanup is valuable, but it should not happen while the architecture-defining surfaces are still moving.

This ordering is deliberate:

- redesign the kernel before the services that depend on it
- redesign publication and storage before redesigning execution consumption
- redesign execution before finalizing policy and lookup consumers
- redesign runtime identity only after the ES and policy boundaries are explicit

## Current Decision Rules

Future agents working in this phase must follow these rules:

- Redesign structure before renaming.
- Break core coupling before cleanup.
- Prefer package-local ownership over cross-service leakage.
- Do not preserve an old contract unless it is intentionally retained as a temporary compatibility edge.
- Document any new invariant in `PLANS.md` and the relevant `.docs/` pages before implementing against it.
- Do not introduce a new shared kernel casually. Shared code requires explicit ownership and a concrete cross-service reason.
- Use this repository as the planning authority. Treat the Monolith/Python repository as historical or bounded bootstrap reference only.
- Surface conflicts instead of working around them.
- Do not bypass governance, storage, trust, or scheduler boundaries as a shortcut during redesign.
- Keep capability-sensitive behavior validated by behavior or static resource checks, not by OS labels or fallback branching.
- Preserve current implementation behavior until a replacement contract is explicitly documented, tested, and implemented.
- Treat compatibility shims as temporary and track their removal conditions.

## Reopened-Seam Exit Criteria

The current reopened-seam plan is complete only when all of the following are true:

- The new shared kernel or contract layer is settled and explicitly documented.
- AGS and ARS no longer force the old artifact publication and retrieval choreography by default.
- ES no longer depends on the current inherited core grammar for its public admission and execution model.
- EGS and CGS have clearly defined policy and authorization ownership.
- The workload-zone Vault runtime-config reference and blob surface has a clearly justified long-term owner.
- Runtime identity and execution handoff have explicit ownership and no unresolved dependency on current incidental path conventions.
- Any retained compatibility edges are documented as temporary, with removal conditions.
- `PLANS.md`, `.docs/`, tests, and implemented code agree on the active architecture.
- Peripheral cleanup can proceed without architectural uncertainty.

Until those conditions are met, reopened seams must stay explicit in `PLANS.md`; outside those seams, treat the repository as bounded platform work rather than rewrite-by-default feature work.
