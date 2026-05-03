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
- Remote Supported-Host Alpha may now extend the narrower helper-install proof with a separate host-local Vault/workload-auth proof slice: install a single-node Alpha/internal Vault system service on the remote Linux host, constrain it to the helper SPIFFE identity JWT path needed by future ES runtime identity, and record only non-secret host evidence without claiming `runtime_profile_ready`, `submit_ready`, `es_services_healthy`, `producer_contract_compatible`, or retained-result readiness.
- Remote Supported-Host Alpha may now also use one separate operator-owned Vault service-user migration helper slice: default `check_only`, require explicit `--apply`, stay bounded to the dedicated Vault service account, the Vault systemd drop-in, and the minimum config/storage/log/audit/TLS ownership or readability changes needed for Vault, record backup plus rollback evidence before mutation, and run honest post-apply Vault plus ES health or contract checks. That helper must preserve workload-side Vault JWT login, the ES-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT` handoff, and the no-ES-Vault-token-brokerage rule; it does not claim `runtime_profile_ready`, `submit_ready`, Vault production readiness, governed execution proof, full ES/runtime de-root, full Nomad client de-root, or SPIRE redesign.

## Current Remote Alpha Hardening Tranche

`Bounded slice rule`: the current Remote Supported-Host Alpha bounded hardening
posture is `AGS sealed + ARS de-root + EGS de-root + ES config/TLS prep
applied + ES stable writable-state prep applied + long-lived es.service de-root
applied`.

- AGS is already de-rooted and sealed in this tranche; preserve the landed
  `ags:ags` service posture and its existing host-local summary/evidence shape.
- ARS is already de-rooted in this tranche; preserve the landed `ars:ars`
  service posture, its dedicated TLS/state ownership model, and its existing
  host-local summary/evidence shape.
- EGS is already de-rooted in this tranche; preserve the landed `egs:egs`
  service posture and its existing host-local summary/evidence shape.
- ES config/TLS prep is applied and productized for the live host.
- ES writable-state roots are prepared under the documented stable `es:es`
  ownership model, and future writable-state readiness has passed.
- The current live long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`.
- Post-apply `/health`, `GET /v1/executions:contract`, and the current
  lowest-cost existing post-apply happy path all passed after the bounded live
  service-user change, and Infrastructure Manager readiness is accepted.
- The repo-local rollback rehearsal/check-only evidence set for that landed
  service-user slice now passes and remains non-mutating evidence only.
- This tranche does not claim full ES/runtime de-root.
- The root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad root selector posture, and Vault/workload-zone
  handoff remain bounded compatibility edges.
- The long-lived ES startup path keeps
  `execution.spire_workload_api_socket_path` as a config-shape and submit
  input only; operator/readiness tooling remains responsible for proving the
  host path is a real Unix socket, and runtime-helper failure to use that
  helper-private raw SPIRE path must remain explicit and fail closed.
- Future writable-state readiness and service-user migration check-only now
  require `execution.staging_root_dir` and `execution.results_root_dir` to
  resolve to one shared target owner UID:GID; mismatched stable-root owner
  models are honest blockers rather than compatibility noise.
- Old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by inertia.
- Future cleanup/archive planning for those preserved roots is a repo-local,
  non-mutating evidence step only: consume local apply-summary artifacts,
  keep rollback-window status explicit, and do not SSH, use `sudo`,
  recursively re-owner preserved contents, archive live-host content, or
  delete anything by default.
- This tranche must not change ES public contracts or Control
  Plane/Infrastructure Manager ownership boundaries.
- This tranche preserves the direct Mac -> AGS/ES HTTPS+mTLS posture, the
  current EGS loopback-only dependency path, the landed AGS/ARS service
  postures, and the no-bridge/no-shared-filesystem remote posture.
- This tranche may now use one separate operator-owned Vault service-user
  migration helper. That helper must stay check-only by default, explicit
  apply only, bounded to Vault host/service hardening, and must not widen into
  ES public API changes, Nomad task-user changes, SPIRE boundary changes, or
  Vault token brokerage.
- This tranche is bounded host/service hardening only. Do not widen it into a
  runtime-boundary redesign or broader proof expansion.

## Milestone 1: Least-Privilege Runtime/Security Boundary Closeout

`Bounded slice rule`: Milestone 1 is named `least-privilege runtime/security
boundary closeout`.

`Current invariant`: the landed long-lived `es.service` service-user change is
already on the least-privilege side of this milestone baseline:
`User=es`, `Group=es`, `UMask=0027`, with post-apply `/health`,
`GET /v1/executions:contract`, the current lowest-cost existing happy path,
and future writable-state readiness all passing.

Do not call this milestone `rootless everything` or full ES/runtime de-root.

Milestone 1 preserves these current boundaries:

- Nomad remains lifecycle authority after ES submission.
- ES remains a lifecycle projector, not a parallel scheduler.
- The raw SPIRE Workload API socket remains helper-private.
- Workloads see `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, not the raw SPIRE Workload
  API socket.
- Workload-side Vault credential acquisition remains preserved.
- ES does not fetch, mint, broker, store, rotate, parse, or validate Vault
  tokens.
- Infrastructure Manager support bundles and readiness/support artifacts remain
  evidence/projection/diagnostics only. They are not authority and are not
  governed execution proof by themselves.

Milestone 1 boundary posture matrix:

| Surface | Posture | Rationale | Current evidence | Removal condition | Explicit non-claim |
| --- | --- | --- | --- | --- | --- |
| Nomad host client/server substrate | `blocker` | The current supported substrate still depends on a pre-managed non-dev Linux Nomad client/server. Upstream least-privilege guidance is to keep Nomad servers as narrow as feasible, but the Linux Nomad client remains a root-managed isolation boundary today and a rootless client is not the current supported/well-tested repo posture. | Supported-host qualification still requires a pre-managed non-dev Nomad baseline, `scripts/01_bringup.sh check` still treats Nomad readiness as an environment gate, and the landed ES happy paths still hand lifecycle authority to Nomad rather than replacing it. | Revisit only if a later separately documented substrate decision proves a supported client posture that does not depend on an unsupported rootless-client assumption while preserving Nomad as lifecycle authority. | Milestone 1 does not claim a rootless Nomad client or full Nomad least-privilege closeout. |
| SPIRE raw-socket traversal and selector posture | `accepted MVP compatibility edge` | The workload-visible contract is already narrowed to `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, but the helper-private raw SPIRE path and the broad root selector scope remain explicit compatibility edges rather than a finished least-privilege identity model. | Slice `1A`/`1B` proof, runtime-helper tests that keep the raw SPIRE path out of workload env, the remote runtime-identity helper summary, and the service-user migration check-only gate that validates helper-private runtime input without making `es:es` a raw-socket reader. | Revisit only through the later runtime-boundary redesign seam after a narrower helper principal or equivalent traversal model is documented and re-proved. | Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege. |
| Vault workload-side auth / workload-zone handoff | `accepted MVP compatibility edge` | The least-privilege direction is workload-side credential acquisition without ES token brokerage. The repo preserves that handoff boundary; where Vault host posture is operator-owned, the intended direction is a dedicated unprivileged Vault service account rather than root, but Milestone 1 does not widen ES contracts into full remote Vault lifecycle authority. | Useful credential flow completion is already landed, `scripts/remote_alpha_vault_workload_auth_check.sh` records bounded host-local evidence, and the current `authority_handoff` plus `readiness_not_claimed.*` vocabulary already preserve non-brokering, workload-side auth. | Revisit only if a later documented boundary change keeps workload-side auth intact and preserves the no-token-brokerage rule. | ES does not broker Vault tokens, and Vault/readiness summaries do not by themselves prove runtime-profile readiness or governed execution proof. |
| ES runtime helper | `accepted MVP compatibility edge` | The current helper isolates privileged runtime bootstrap from the long-lived ES service path, but it still starts from root and therefore remains a bounded compatibility edge rather than a full runtime de-root result. | Runtime-helper tests, supported-local proof, helper-death/task-fatal behavior, and the remote runtime-identity helper summary all prove the current fail-closed helper boundary. | Revisit only if a later redesign re-proves equivalent runtime identity delivery, workload launch, and result-path guarantees with a narrower startup privilege model. | Milestone 1 does not claim rootless helper startup or full ES/runtime de-root. |
| Nomad task user | `accepted MVP compatibility edge` | The current runtime companion still needs task-start `0:0` so it can create the helper-private SPIRE boundary and exec the workload as fixed non-root `10000:10000`. | The landed happy path still uses the current job-spec model, job-spec tests preserve `User: "0:0"`, and the runtime-helper/workload-boundary tests still depend on that task-start contract. | Revisit only as part of a broader runtime-boundary redesign that re-derives helper launch, workload launch, and SPIRE/Vault handoff together. | The current posture is not non-root task launch and not rootless workload orchestration. |
| Evidence/support artifacts | `accepted MVP compatibility edge` | Privilege-sensitive host evidence collection may still be necessary, but it must stay outside ES/CP authority boundaries and must not backdoor a broader runtime claim. | Remote doctor output, support-bundle summaries, staged-helper records, and apply summaries are all already documented as evidence/projection/provenance only. | Revisit only if later operator tooling reduces privileged collection without weakening the non-authority and non-proof boundary. | Support bundles, readiness reports, and apply summaries are not ES/CP/IM authority and are not governed execution proof by themselves. |

Milestone 1 now also carries one repo-owned Remote Alpha runtime/security
boundary posture checker as a bounded host-local evidence surface:

- `scripts/remote_alpha_runtime_security_boundary_check.sh`
- `scripts/internal/remote_alpha_runtime_security_boundary_check.sh`

That checker must default to `check_only`, stay non-mutating, classify the
current Nomad/runtime-helper/SPIRE/Vault/evidence posture honestly, and fail
closed if its output contains secret-like material or overclaim text. By
default it must not SSH, mutate services, change ownership, restart services,
archive files, or delete anything. It records evidence/projection only; it
does not change ES submit behavior, runtime-helper behavior, the current Nomad
task user, the helper-private raw SPIRE boundary, Vault token brokerage, or
governed execution proof claims.

## Current Remote Alpha ES Config/TLS Ownership Prep Slice

`Bounded slice rule`: Remote Supported-Host Alpha may now extend the current
host-local hardening work with one separate ES config/TLS ownership prep slice.

`Current invariant`: this earlier bounded slice is already applied on the live
host and remains the source of truth for the dedicated `root:es` readable
config/TLS model consumed by the current `User=es` long-lived ES service.

- This slice introduces a dedicated ES-readable config ownership model and a
  dedicated ES-readable TLS directory for the current ES runtime config.
- This slice may create a narrow dedicated `es:es` prep account only to own
  readable ES config/TLS material for a later ES de-root step; it must not
  introduce a shared `execution-substrate` Unix-account model.
- At apply time, this slice kept the live `es.service` user/group posture
  unchanged.
- This slice must not change ES public contracts, the current SPIRE selector
  posture, current SPIRE socket traversal, Vault/runtime-helper semantics, or
  Nomad task user model.
- This slice must not move ES writable state, including staging and retained
  results ownership.
- This slice preserves the current AGS, ARS, and EGS service postures plus the
  direct Mac -> ES HTTPS+mTLS posture.
- This slice is bounded host-local config/TLS ownership preparation only. Do
  not widen it into ES de-root, Control Plane or Infrastructure Manager
  changes, or broader proof reruns; rerun only the small verification needed to
  validate the ES host-side apply and refresh the non-secret summary.

## Future ES Privilege-Boundary Design Track

`Reopened redesign seam`: full ES/runtime de-root beyond the now-landed
long-lived `es.service` user flip remains a future structural design track.

- This future track covers the long-lived ES service privilege model, Nomad
  task user model, runtime-helper/supervisor ownership, SPIRE selector posture,
  SPIRE socket traversal, staging/results ownership, retained-result
  materialization, and operator maintenance/rollback model as one boundary
  package rather than as implicit follow-on hardening.
- One bounded implementation slice on this seam is now landed: the repo-side
  binary-deployment helper, stable writable-state ownership helper, and
  long-lived `es.service` migration helper were all exercised in bounded
  sequence to reach the current live service-user posture.
- The current accepted Alpha posture now includes bounded long-lived ES
  service-user de-root: ES config/TLS prep is applied, stable writable-state
  roots are prepared, live `es.service` runs as `User=es`, `Group=es`,
  `UMask=0027`, post-apply lowest-cost happy path passed, and future
  writable-state readiness passed. Do not treat that bounded slice as proof
  that the full ES/runtime privilege boundary is solved.
- The current branch now carries design-only and branch-local readiness inputs
  for parts of Option B: the privileged-operation matrix, writable-state
  ownership model, runtime ownership-normalization contract, non-mutating
  writable-state readiness checker with `alpha-compat` and
  `future-non-root-required` modes, and repo-local normalized-run lifecycle
  tests covering success, failed, lost, canceled, invalid-marker,
  missing-marker Alpha compatibility, and future non-root-required preflight
  behavior.
- That repo-local readiness was necessary but not sufficient: the bounded live
  rollout also required host-side ES/runtime-helper binary parity, stable
  writable-state preparation, an explicit `future-non-root-required`
  readiness pass, and then the bounded long-lived service-user apply. Those
  helper flows are live-host evidence for their own bounded slices, not by
  themselves proof that the runtime/task/SPIRE boundary is fully de-rooted.
- The bounded rollout sequence that led to the current live posture was:
  resolve live ES/runtime-helper binary parity first, then prepare only the
  stable staging/results roots plus any bounded parent-traversal or
  legacy-artifact reconciliation needed to make those live roots future
  non-root-manageable, then rerun the explicit
  `future-non-root-required` writable-state gate, then use the long-lived
  `es.service` migration helper check-only path immediately before the
  bounded live service-user apply.
- Post-migration ES/runtime-helper binary refreshes now remain bounded to the
  current accepted live `User=es`, `Group=es`, `UMask=0027` host slice. The
  binary-deployment helper is no longer a root-like service-posture surface;
  any return to a root-era long-lived service identity must happen through a
  separate rollback/service-user action rather than through binary deployment.
- The helper-private raw SPIRE socket path remains a privileged runtime
  dependency and must stay operator-validated rather than being treated as a
  direct long-lived ES service-user read requirement.
- Design assessment for Remote Alpha -> Beta may compare alternative
  architectures, but implementation work must not proceed until the chosen
  boundary model and required evidence are documented explicitly.

## Explicit Deferred Post-Migration Actions

The current branch-level milestone for the completed long-lived `es.service`
service-user migration is now:

- ES config/TLS prep applied
- stable writable-state prep applied
- live `es.service` running as `User=es`, `Group=es`, `UMask=0027`
- post-apply `/health` and `GET /v1/executions:contract` passed
- post-apply lowest-cost existing happy path passed
- future writable-state readiness passed
- rollback rehearsal/check-only evidence passed
- old-root cleanup/archive planner present as a repo-local non-mutating
  planning surface only

`Current invariant`: that branch-level milestone does not claim full
ES/runtime de-root.

`Bounded slice rule`: old root-era cleanup/archive execution is explicitly
deferred.

- Any later implementation must be a separate live-mutating operator action,
  not a side effect of the writable-state or service-user helpers.
- Preconditions are explicit:
  - the rollback window is explicitly closed
  - preserved old-root evidence is archived elsewhere or explicitly deemed
    unnecessary
  - operator signoff is recorded
- If productized later, the surface should expose explicit `check-only` and
  `apply` modes.
- That later action must not recursively `chown` old roots and must not
  delete by default.

`Bounded slice rule`: an optional rollback execution helper is explicitly
deferred.

- It is not needed while the current `es:es` service posture is healthy.
- It must remain recovery-only rather than routine maintenance.
- Any future implementation must be bounded, must expose explicit
  `check-only` and `apply` modes, and must not run live rollback unless
  operationally necessary.

`Reopened redesign seam`: Option C runtime-boundary redesign remains a
separate architecture track, not a cleanup follow-on.

- Any future work on the root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, broad root selector posture, or
  Vault/workload-zone handoff must proceed only as that separately documented
  redesign track.

`Current invariant`: the completed branch-level milestone does not imply a
`master` merge.

- Merge remains a human milestone decision after review of the bounded
  evidence set and governance posture.

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

Milestone 0 MVP claim freeze is recorded in `.docs/mvp.md`. That document is a
planning and documentation freeze only: it captures the current MVP claim,
surface classifications, and explicit non-claims without widening ES contracts
or promoting proof-harness behavior into architecture.

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
- ES may expose a bounded lifecycle projection revision on status responses as an opaque same-run read-coordination fact derived from Nomad observation. Callers may compare equality/change for the same run only. They must not parse or order it, infer scheduler or backend state from it, use it as a write precondition for cancel/result/logs, or treat it as a Nomad identifier or index. It is not evidence of an ES-owned lifecycle store.
- ES may expose a bounded `authority_handoff` read surface on submission/status responses for non-secret runtime authority facts ES actually selected and handed off for a run: effective runtime profile, workload-visible identity endpoint handoff, workload-vault auth metadata, selected workload-zone Vault config reference, and bounded profile credential-location metadata. This surface is read-only evidence of the submitted runtime handoff, not live credential state, lease state, scheduler identity, policy approval state, or a Control Plane lifecycle record.
- ES must not bypass ARS artifact storage/discoverability, EGS runtime-trust publication, or configured runtime-config ownership to make admission easier.
- ES-owned retained results remain opaque output bundles and must not become Control Plane checkpoint, review, finalization, or orchestration state.
- ES-owned runtime identity and workload-credential handoff must remain platform-owned, non-secret, and non-brokering: workloads use the discovered endpoint and workload-Vault metadata; ES does not fetch, mint, store, rotate, parse, or validate Vault or Codex credential material.
- Caller authentication and narrow SPIFFE allowlist authorization remain required on the governed execution path.

Temporary compatibility edges to preserve explicitly during this package:

- current CP compatibility for AGS publish plus ES prepare, submit, status, logs, result, and cancel over HTTPS+mTLS
- `GET /v1/executions:contract` as a narrow read-only producer compatibility declaration for the current governed-execution contract, including the mandatory outcome-evidence response surfaces
- `POST /v1/executions:prepare` as an active bounded preflight surface
- `invocation.annotations["execution_substrate.runtime_profile"]` and the bounded `control-plane-normal-shell/v1` profile
- the current `static-script` overlay behavior for that profile
- `/execution/staged`, `/execution/run`, `/execution/run/result`, and current runtime-identity path conventions
- the current `authority_handoff` field names and evidence-source labels while the ES request/runtime-profile and runtime-identity seams remain reopened
- the current additive `outcome_evidence` JSON field and successful logs/result outcome-evidence headers while lifecycle/status/result/log/cancel evidence vocabulary remains bounded to the current Nomad/retained-result slice
- retained `application/gzip` result bundles keyed by public `run_id`
- supported-local profile-image durability checks, including the Nomad Docker `docker.cleanup.image=false` guardrail for enabled local runtime-profile images
- the ES config/TLS ownership prep bridge where live `es.service` stays
  `root(default)` while dedicated `root:es` readable config/TLS material is
  staged for a later ES de-root slice

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
- ES currently exposes a narrow read-only producer compatibility declaration at `GET /v1/executions:contract`, a bounded preflight `POST /v1/executions:prepare`, a primary public execution handoff at `POST /v1/executions:submit`, and minimal Nomad-backed lifecycle endpoints whose current `run_id` lookup and projected-allocation rules are explicit ES-internal slice policy rather than public contract.
- ES status now includes a bounded lifecycle projection fact, `lifecycle_projection`, whose `source` is the current lifecycle authority and whose `revision` is an opaque same-run read-coordination token produced from implementation-private Nomad observation during the status read. Consumers may compare equality/change for the same run only. They must not parse or order it, infer scheduler or backend state from it, use it as a write guard, or treat it as a Nomad identifier or index. This is a read coordination surface for consumers, not a write coordination API or a durable ES run record.
- ES lifecycle/status/result/log/cancel surfaces now expose a smallest additive `outcome_evidence` descriptor family for facts ES can directly source today: status labels the Nomad observation family behind the projection and references the opaque lifecycle projection token, cancel labels the accepted Nomad stop request without claiming observed termination, logs label successful bodies as current Nomad task stdout, and result labels successful bodies as opaque ES-retained bundles. These descriptors are read-only current-slice evidence labels, not scheduler identifiers, write preconditions, policy truth, credential truth, or a global ES run revision.
- The producer compatibility declaration names the current governed-execution producer contract and the required status/cancel/logs/result outcome-evidence carriers without proving service health, submit readiness, run existence, credential possession, lifecycle write coordination, policy decisions, or scheduler internals.
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

Current bounded decision status for Milestone 2A.1:

- The Workstream A shared-kernel decision is recorded in `.docs/system_overview/shared_kernel.md`.
- `internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel for the current `AGS -> ARS -> ES` path, but it is not a standalone service boundary.
- Kernel-level shared meaning stays limited to package identity, narrow derivation request-binding authorization, narrow execution/runtime claims ES actually enforces, and evidence canonicalization plus `seal` verification.
- AGS publication claims, ARS discoverability/index shapes, ES public execution/lifecycle grammar, and the long-term workload-zone Vault runtime-config owner remain service-owned or reopened elsewhere; Workstream A does not widen them into the kernel.

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

Current bounded decision status for Milestone 2B.1:

- The Workstream B publication/storage/discoverability decision is recorded in
  `.docs/system_overview/artifact_publication_storage.md`.
- AGS owns publish-time fact assembly, caller-bound publication semantics,
  aggregate evidence assembly, signing, payload/support upload, and
  registration into ARS.
- ARS owns blob storage, content-addressed integrity, artifact registration,
  runtime-facing discovery records, and the read surfaces ES may later
  consume.
- The current ARS discovery record remains the canonical runtime-discoverable
  surface for the current slice. Descriptor/manifest support remains secondary
  publication detail, and the current index entry shape remains
  implementation-only/current-slice detail.
- Payload identity and artifact identity remain separate:
  `payload_digest` content-addresses bytes, while `artifact_digest` is
  package-facing identity derived from `payload_digest`, `artifact_type`, and
  `intent_digest`.
- The current discovery/register JSON shapes are retained only as bounded
  slice rules, the secondary descriptor support path remains a temporary
  compatibility edge, and the long-term discovery/index/publication-support
  model remains reopened.

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

Current bounded decision status for Milestone 2C.1:

- The Workstream C ES public admission/execution model decision is recorded in
  `.docs/execution_lifecycle/es_execution_admission_model.md`.
- `GET /v1/executions:contract` and `POST /v1/executions:prepare` remain
  temporary compatibility edges for the current CP/IM consumer path, while
  `POST /v1/executions:submit` remains the real ES execution handoff surface.
- Nomad remains authoritative for submitted execution lifecycle. ES status,
  logs, and cancel remain bounded read-through projections, and result
  retrieval remains ES-owned opaque bundle access.
- ES admission composition remains limited to caller auth/allowlist plus ARS
  discovery/evidence/payload refs, narrow `internal/contracts/evidence/v1`
  execution claims, EGS runtime-trust output, and the configured workload-zone
  Vault runtime-config reference/blob.
- `invocation.annotations["execution_substrate.runtime_profile"]`,
  `control-plane-normal-shell/v1`, the current `/execution/...` conventions,
  the current `authority_handoff` vocabulary, the current `outcome_evidence`
  vocabulary, and retained `application/gzip` result bundles keyed by `run_id`
  remain explicit compatibility edges rather than settled architecture.

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

Current bounded planning direction:

- Treat the current `POST /v1/credential/authorize` request/response shape as a CGS v1 compatibility surface and the current `GET /v1/trust-model` route plus wrapper/payload shape as an EGS v1 compatibility surface.
- Do not semantically widen either current v1 surface in place. Semantic expansion requires explicit versioning before implementation.
- Treat `audit.policy_version` and EGS `publication.version` as service-owned audit/publication metadata, not transport/schema/API versioning.
- Treat `id.conf` as current-CGS-v1 compatibility/config residue rather than as final repo-wide policy language.
- Preserve ES CGS-independence in D1. If ES later consumes CGS output, it must do so through a separately versioned bounded authorization fact such as allow/deny plus opaque decision reference and expiry rather than by reusing the current CGS v1 shape or `id.conf`-derived subject grammar.
- D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.

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
