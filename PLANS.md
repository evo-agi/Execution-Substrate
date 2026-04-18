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
- The first bounded Control Plane normal-shell runtime contract is now an explicit opt-in ES runtime profile named `control-plane-normal-shell/v1`. It remains a bounded slice rule on the reopened ES runtime/package seam: CP still owns orchestration, review, checkpoint, and finalization semantics, while ES owns the governed Docker/Nomad runtime realization, platform-owned runtime identity delivery, the profile image selection, and non-secret credential-location metadata needed for workload-side Codex credential retrieval.
- The supported-local runtime surface for enabled local runtime-profile images now also owns the narrow Nomad/Docker image-lifecycle guardrail needed for repeated client runs from the same prepared environment: the supported single-node Nomad baseline disables Nomad Docker image cleanup through `client.options["docker.cleanup.image"]="false"`, and submit-readiness for enabled runtime-profile images refuses to claim ready when that guardrail is absent. This is a bounded slice rule for local image durability, not a general registry or image-cache architecture.
- The supported-local proof realization for that profile now uses a repo-owned deterministic proof Codex shim at the configured `EXEC_CODEX_CLI_PATH`, invokes it through the bounded normal-shell profile path, proves workload-side Vault credential acquisition, creates a deterministic workspace mutation and runner-style artifacts, fetches the retained ES result bundle, and validates the expected proof artifacts without depending on a live upstream Codex service.

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

## Primary Program Orientation

Execution Substrate is the primary program in this repository.

The current ES work is foundational boundary and contract work, and that is real program delivery: it decides what governed execution can safely admit, run, project, retain, and expose to callers.

Control Plane is an important first non-operator consumer. It improves ergonomics and governance around ES, but it does not define ES core contracts. Control Plane documents may describe how CP consumes accepted ES surfaces; they must not widen ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness ownership.

The next milestone package is **ES Admission And Runtime Boundary Realignment**.

That package is ES-owned. It should deliver a coherent ES milestone by:

- classifying stable ES semantic contracts, temporary compatibility edges, and implementation details/current slice constraints before implementation spreads outward
- completing only the Workstream A shared-kernel decisions needed to keep ES from inheriting accidental cross-service grammar
- completing only the Workstream B publication/storage/discoverability decisions needed to make ES input ownership explicit
- delivering Workstream C as the primary ES admission, submission, lifecycle-projection, retained-result, and runtime-boundary package
- preserving current CP compatibility for the governed execution path unless an explicit compatibility, drain, migration, or versioning plan is documented
- keeping the current `execution_substrate.runtime_profile` annotation and `control-plane-normal-shell/v1` profile as accepted bounded compatibility for the next milestone package

Stable semantic contracts for this next package:

- ES owns admission composition, submission handoff, Nomad-backed lifecycle projection, retained opaque result bundles, and runtime handoff boundaries.
- Nomad remains authoritative for submitted execution lifecycle; ES must not invent a parallel lifecycle store or scheduler authority.
- ES may expose a bounded lifecycle projection revision on status responses as an opaque read-coordination fact derived from Nomad observation. That revision is not a scheduler identifier, not an ordering promise across scheduler backends, not a write precondition for cancel/result/logs, and not evidence of an ES-owned lifecycle store.
- ES may expose a bounded `authority_handoff` read surface on submission/status responses for non-secret runtime authority facts ES actually selected and handed off for a run: effective runtime profile, workload-visible identity endpoint handoff, workload-vault auth metadata, selected workload-zone Vault config reference, and bounded profile credential-location metadata. This surface is read-only evidence of the submitted runtime handoff, not live credential state, lease state, scheduler identity, policy approval state, or a Control Plane lifecycle record.
- ES must not bypass ARS artifact storage/discoverability, EGS runtime-trust publication, or configured runtime-config ownership to make admission easier.
- ES-owned retained results remain opaque output bundles and must not become Control Plane checkpoint, review, finalization, or orchestration state.
- ES-owned runtime identity and workload-credential handoff must remain platform-owned, non-secret, and non-brokering: workloads use the discovered endpoint and workload-Vault metadata; ES does not fetch, mint, store, rotate, parse, or validate Vault or Codex credential material.
- Caller authentication and narrow SPIFFE allowlist authorization remain required on the governed execution path.

Temporary compatibility edges to preserve explicitly during this package:

- current CP compatibility for AGS publish plus ES prepare, submit, status, logs, result, and cancel over HTTPS+mTLS
- `POST /v1/executions:prepare` as an active bounded preflight surface
- `invocation.annotations["execution_substrate.runtime_profile"]` and the bounded `control-plane-normal-shell/v1` profile
- the current `static-script` overlay behavior for that profile
- `/execution/staged`, `/execution/run`, `/execution/run/result`, and current runtime-identity path conventions
- the current `authority_handoff` field names and evidence-source labels while the ES request/runtime-profile and runtime-identity seams remain reopened
- retained `application/gzip` result bundles keyed by public `run_id`
- supported-local profile-image durability checks, including the Nomad Docker `docker.cleanup.image=false` guardrail for enabled local runtime-profile images

Implementation details and current slice constraints not to promote into stable architecture:

- host staging roots, bind-mount source paths, `.out/` proof workspaces, generated helper artifacts, and guest `/tmp` scratch
- the internal Nomad job naming rule `exec-<run_id>`
- the latest-allocation projection rule, stdout-only log retrieval, single task named `task`, async-only submit, and no-retry/no-reschedule slice, except that the status response may expose an opaque lifecycle projection revision without exposing the underlying selection rule or scheduler IDs
- proof-only Codex shim behavior and supported-local proof bootstrap details
- helper scripts and examples as client contracts; the HTTPS API and documented runtime handoff are the client-facing surfaces

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
- ES status now includes a bounded lifecycle projection fact, `lifecycle_projection`, whose `source` is the current lifecycle authority and whose `revision` is an opaque equality token derived from Nomad modify indexes. This is a read coordination surface for consumers, not a write coordination API or a durable ES run record.
- ES submit/status now include a bounded `authority_handoff` fact for new submissions. It is derived from ES-selected submit-time handoff facts and the submitted runtime spec, and it exposes only non-secret runtime authority facts: selected runtime profile, workload identity endpoint URI/env, workload-vault auth metadata, workload-zone Vault config digest, and the bounded Control Plane normal-shell Codex credential-location metadata when that profile is selected.
- ES now localizes submit-time payload staging, mount staging, result-directory staging, and runtime-ready package assembly behind one explicit internal execution-package layout; `/execution/staged` and `/execution/run` remain current bounded runtime conventions rather than diffuse helper assumptions.
- ES currently reserves `/execution/run/result` as the bounded workload-authored terminal output directory for the current `static-script` slice. That convention is active for the retained-result slice, but it remains part of the reopened execution-package/runtime-path surface rather than settled architecture.
- ES currently retains run-scoped host staging while the submitted workload may still depend on it, captures any terminal result files from the reserved result directory into a retained ES-owned bundle outside staging, then best-effort removes `execution.staging_root_dir/<run_id>` after ES observes terminal success; failed, canceled, lost, or otherwise ambiguous outcomes retain staging for operator debugging.
- ES now exposes `GET /v1/executions/{run_id}/result` as a bounded retained-result bundle retrieval surface. The bundle is opaque tar.gz data keyed by `run_id`, not a Control Plane checkpoint, orchestration decision, or ES-owned lifecycle-state record.
- The primary operator bring-up/check path now distinguishes service health, prepare-ready state, and full submit-ready state instead of treating ES `/health` alone as execution readiness.
- The current bounded operator hot path now uses the operator SPIFFE identity as the sole caller for AGS publish and ES execution/lifecycle entry surfaces; `service/deployment` no longer defines that current slice.
- The current shared execution/runtime contract in `internal/contracts/evidence/v1` is now limited to environment allowlist input, required runtime capabilities, `target_platform`, and `network_access`; non-runtime workload metadata no longer defines the live AGS -> ARS -> ES hot path.
- ES currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as its bounded workload-visible runtime identity handoff and internally backs the discovered endpoint with a run-scoped ES-owned runtime subtree.
- ES currently derives its workload-vault handoff from workload-zone vault runtime fields plus a bounded local default auth mode rather than from workload-attribute selector policy.
- When the workload-zone Vault runtime config carries a non-secret CA bundle, ES stages that trust material into the runtime platform directory, injects `VAULT_CACERT`, and also exposes a staged combined TLS bundle through `SSL_CERT_FILE` for the bounded Control Plane normal-shell Python runner path. This is a workload-facing TLS trust-material handoff, not Vault token brokerage or relaxed verification.
- ES now also supports one explicit runtime profile selection annotation for the bounded Control Plane normal-shell slice:
  - `invocation.annotations["execution_substrate.runtime_profile"] = "control-plane-normal-shell/v1"`
  - the selected profile is enabled only by explicit ES submit config under `execution.runtime_profiles.control_plane_normal_shell`
  - the profile remains a `static-script` execution-package overlay rather than a package-kind or lifecycle redesign
  - the profile requires network access, a dedicated configured runtime image, an absolute configured Codex CLI path inside that image, and a configured workload-vault secret path/field for Codex credential material
  - ES injects only non-secret metadata for that Codex material; the workload uses the existing platform-owned runtime identity endpoint and workload-vault auth env to fetch the material itself
  - ES does not fetch, mint, broker, store, rotate, parse, or validate Codex tokens
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
- For the next milestone package, answer only the shared-kernel questions that ES needs to admit and execute governed artifacts without inheriting accidental AGS, ARS, or CP grammar.

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
- Future agents can tell which shared-kernel rules are stable ES admission semantics, which are temporary compatibility edges, and which are merely current slice implementation detail.

Dependencies:

- No upstream workstream dependency beyond this `PLANS.md` reset.

### Workstream B - Artifact Storage And Publication Contract Reset

Purpose:

- Redesign the AGS and ARS contract around publication, runtime-facing discovery records, payload and evidence relationships, and visibility rules.
- Decide whether the current runtime-facing discovery shape, the secondary descriptor support path, and the current AGS artifact-identity derivation rule survive.
- Separate storage integrity concerns from publication grammar and from ES consumption needs.
- Keep the shared evidence grammar narrow: package identity remains separate, shared admission authorization is limited to derivation request binding, and execution/runtime claims remain distinct from non-shared publication or policy residue.
- For the next milestone package, treat AGS and ARS work as an ES-enabling input-boundary reset: AGS/ARS own publication and discoverability; ES consumes their designed outputs; CP examples or probes do not define that contract.

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
- CP consumer compatibility can rely on the accepted API path, but CP-specific convenience expectations are not mistaken for AGS/ARS/ES core semantics.

Dependencies:

- Workstream A

### Workstream C - Execution And Admission Reset

Purpose:

- Redesign ES public admission and execution surfaces.
- Re-derive the preparation and submission boundary, scheduler handoff, and runtime package resolution from the Go codebase rather than from current inherited grammar.
- Decide what ES should own, what ES should compose, and what ES should stop carrying.
- Deliver the primary ES milestone package after the Workstream A and B input-boundary gates are explicit enough for ES not to inherit their ambiguities.
- Preserve the accepted CP governed-execution compatibility edge without letting CP orchestration, review, checkpoint, or finalization assumptions become ES-owned semantics.

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
- The current CP path, `execution_substrate.runtime_profile`, and `control-plane-normal-shell/v1` remain compatible unless an explicit migration/versioning note says otherwise.
- Stable semantic contracts, temporary compatibility edges, and implementation details/current slice constraints are classified in `PLANS.md` and the adjacent system/lifecycle docs.

Dependencies:

- Workstream A, as the shared-kernel gate needed for ES admission ownership
- Workstream B, as the AGS/ARS input-boundary gate needed for ES payload and evidence ownership

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
  - ES provides any workload-zone Vault CA trust material from the resolved runtime config as workload-visible CA files and standard TLS environment, without disabling verification
  - one secret read is proved through the real ES -> Nomad -> Docker path
  - the slice still avoids platform-owned Vault token brokerage
- The bounded `control-plane-normal-shell/v1` runtime profile builds on that same identity boundary:
  - ES selects the configured profile image for opt-in requests
  - the repo-owned reference image recipe provides Python, git, narrow shell utilities, and a configured Codex CLI realization at the configured path
  - the supported-local Nomad baseline disables Nomad Docker image cleanup for enabled local runtime-profile images so a local proof image is not removed merely because a prior successful allocation terminated
  - the supported-local proof realization uses the proof-only Codex shim at that path, seeds proof-scoped Codex credential material in Vault, proves workload-side credential acquisition through the existing identity endpoint, invokes the shim with stdin prompt input, creates a deterministic workspace mutation, renders a result diff that includes tracked changes and proof-created untracked files, and writes runner-style final-message, diff, stdout/stderr, and workspace-archive artifacts under `/execution/run/result`
  - the proof fetches and validates the retained ES result bundle for those artifacts
  - the proof intentionally does not prove real upstream Codex service behavior because this repo cannot own a non-sensitive production Codex credential or external Codex service availability
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

2. Execute the next milestone as **ES Admission And Runtime Boundary Realignment**.
   This is a package made of Workstream A, Workstream B, and Workstream C, with ES as the primary delivery owner. Workstream A and Workstream B are gates that keep ES input contracts honest; Workstream C is the delivered ES milestone.

3. Complete the Workstream A gate first.
   The shared contract and kernel decision must be explicit enough that ES admission does not inherit accidental shared grammar. This gate is not permission to create a broad new shared kernel, and it is not CP-owned.

4. Complete the Workstream B gate second.
   AGS and ARS define the artifact publication and retrieval substrate that ES consumes. This gate must make the ES-consumed discovery and payload/evidence ownership explicit without letting CP examples or helper scripts become contract authority.

5. Deliver Workstream C third.
   ES admission, submission, lifecycle projection, retained-result behavior, runtime-profile handling, and runtime-boundary ownership are the primary next milestone delivery. Preserve the accepted CP governed-execution path as bounded compatibility while keeping ES-owned semantics in ES docs.

6. Execute Workstream D fourth.
   Policy and authorization surfaces should be re-derived once the ES execution shape is clear enough to say what policy inputs and outputs actually belong at runtime.

7. Execute Workstream E fifth.
   Lookup/config indirection should be reset only after artifact, execution, and policy contracts have been clarified, because the replacement owner depends on those decisions.

8. Execute Workstream F sixth.
   Runtime identity handoff should be redesigned after ES, policy, and runtime-config responsibilities are clear. Otherwise path conventions and auth-plan details will re-freeze around current incidental coupling.

9. Do scripts, runbooks, deployment glue, and peripheral cleanup only after the core contracts stabilize.
   Cleanup is valuable, but it should not happen while the architecture-defining surfaces are still moving.

This ordering is deliberate:

- use Workstream A and Workstream B as gates so ES does not inherit accidental shared or publication/storage grammar
- deliver Workstream C as the next ES-owned program milestone, not as a CP-shaped feature expansion
- preserve current CP compatibility as a bounded consumer edge while ES-owned contracts remain defined in this repo
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
- Do not describe foundational ES boundary and contract work as secondary to the program; it is the current primary ES milestone.
- Do not let Control Plane documents, probes, or examples define ES core contracts. They may document consumption of accepted ES surfaces only.
- Preserve current CP compatibility for the governed execution path, including `execution_substrate.runtime_profile` and `control-plane-normal-shell/v1`, unless a coordinated compatibility, drain, migration, or versioning plan is documented first.

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
