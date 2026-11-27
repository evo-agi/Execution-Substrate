# Execution Substrate Current Plan

This file holds the current plan, its intent and order: the objective, the
ordered plan, the decision rules, the scope and active workstreams, the current
slices, and the reopened seams.

How this file is kept:

- Edit the section that states a fact when scope, seam status, sequencing, or
  design intent changes, so the plan stays current. Do not add dated status
  entries: say what a change did and why in its pull request description, and
  let the owning `.docs/` contract hold the precise wording.
- Put a standing rule in the file that owns it, not here. The standing rules
  that used to sit in this file moved, unreworded, to `.docs/standing_rules/`:
  [`execution_admission_and_custody.md`](.docs/standing_rules/execution_admission_and_custody.md)
  holds the Workstream C admission and custody rules,
  [`remote_alpha_operator_routes.md`](.docs/standing_rules/remote_alpha_operator_routes.md)
  holds the Remote Alpha operator route rules P0i to P0v and the Remote Alpha
  access contract v1,
  [`workstream_decisions.md`](.docs/standing_rules/workstream_decisions.md)
  holds the decision records of Workstreams A to F, and
  [`host_and_runtime_boundary.md`](.docs/standing_rules/host_and_runtime_boundary.md)
  holds the host and runtime boundary slice rules. Edit a rule there, in place.
- Cite this file by section heading, never by line number, because its lines
  move.
- The dated record that used to open this file moved to
  [`.docs/history/plans-record.md`](.docs/history/plans-record.md) on 2026-11-24,
  unreworded: the `Status` entries up to that day, the source publication and
  selection history of 2026-11-17 and 2026-11-18, and the records of the
  superseded Remote Alpha operator facade routes P0n and P0r. The record is
  closed and is historical evidence only. Read it when a change touches a
  surface one of its entries names.

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

## Document Scope And Current Implementation

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
- The current supported local proof path is repo-owned and converged with the bounded useful credential-flow proof: `scripts/72_supported_local_setup.sh` prepares the guest-side supported-local proof environment, including proof-scoped SPIRE and Vault dev/test targets, while `scripts/73_supported_local_proof.sh run` is the canonical host wrapper on this Mac. The host `.out/es-proof-<id>/` path is evidence-only; task-owned host bootstrap/transport scratch is separate and private. Guest `/tmp` scratch remains an internal Lima implementation detail because the mounted repo tree is read-only inside the guest.
- The named bounded slice rules `SUPPORTED-LOCAL-ROOT-OWNER-01`, `R14-ROOT-CUSTODY-01`, `GENERIC-ES-LAUNCHER-USER-01` and `GENERIC-SERVICE-LAUNCHER-USER-01`, for the supported-local execution roots and the users the bring-up launchers run as, are in [`.docs/standing_rules/host_and_runtime_boundary.md`](.docs/standing_rules/host_and_runtime_boundary.md#supported-local-execution-roots-and-launcher-users).
- The first bounded Control Plane normal-shell runtime contract is now an explicit opt-in ES runtime profile named `control-plane-normal-shell/v1`. It remains a bounded slice rule on the reopened ES runtime/package seam: CP still owns orchestration, review, checkpoint, and finalization semantics, while ES owns the governed Docker/Nomad runtime realization, platform-owned runtime identity delivery, the profile image selection, and non-secret credential-location metadata needed for workload-side Codex credential retrieval.
- The supported-local runtime surface for enabled local runtime-profile images now also owns the narrow Nomad/Docker image-lifecycle guardrail needed for repeated client runs from the same prepared environment: the supported single-node Nomad baseline disables Nomad Docker image garbage collection through the explicit Docker plugin block's `gc { image = false }` (formerly `client.options["docker.cleanup.image"]="false"`; the same plugin block now also refuses privileged containers and limits capabilities, and the client enables only the Docker driver), and submit-readiness for enabled runtime-profile images refuses to claim ready when that guardrail is absent. This is a bounded slice rule for local image durability, not a general registry or image-cache architecture.
- The supported-local proof realization for that profile now uses a repo-owned deterministic proof Codex shim at the configured `EXEC_CODEX_CLI_PATH`, invokes it through the bounded normal-shell profile path, proves workload-side Vault credential acquisition, creates a deterministic workspace mutation and runner-style artifacts, fetches the retained ES result bundle, and validates the expected proof artifacts without depending on a live upstream Codex service.
- Remote Supported-Host Alpha may now extend the narrower helper-install proof with a separate host-local Vault/workload-auth proof slice: install a single-node Alpha/internal Vault system service on the remote Linux host, constrain it to the helper SPIFFE identity JWT path needed by future ES runtime identity, and record only non-secret host evidence without claiming `runtime_profile_ready`, `submit_ready`, `es_services_healthy`, `producer_contract_compatible`, or retained-result readiness.
- Remote Supported-Host Alpha may now also use one separate operator-owned Vault service-user migration helper slice: default `check_only`, require explicit `--apply`, stay bounded to the dedicated Vault service account, the Vault systemd drop-in, and the minimum config/storage/log/audit/TLS ownership or readability changes needed for Vault, record backup plus rollback evidence before mutation, and run honest post-apply Vault plus ES health or contract checks. That helper must preserve workload-side Vault JWT login, the ES-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT` handoff, and the no-ES-Vault-token-brokerage rule; it does not claim `runtime_profile_ready`, `submit_ready`, Vault production readiness, governed execution proof, full ES/runtime de-root, full Nomad client de-root, or SPIRE redesign.
- Remote Supported-Host Alpha may now also use one operator-owned SPIRE agent bootstrap-trust and recovery helper, `scripts/remote_alpha_spire_agent.sh` (`status`, `pin`, `recover`; `pin` and `recover` change nothing without `--apply`). `pin` replaces the agent's `insecure_bootstrap` with a `trust_bundle_path` file exported over the SPIRE server admin socket and adds a boot-time rule for the SPIRE runtime directories; `recover` re-attests an agent whose join-token SVID expired with a fresh single-use token kept off command lines and output. It changes no ES, AGS, ARS or EGS contract, no SPIRE registration model and no Vault configuration, and it does not make join-token attestation self-healing; that, expiry alerting and a reproducible host SPIRE setup remain later work. The contract is in `.docs/system_overview/remote_supported_host_alpha.md`, section "Remote SPIRE Agent Bootstrap Trust And Recovery Helper".
- Remote Supported-Host Alpha may now also use one existing-host migration contract, `scripts/remote_alpha_upgrade_es.sh` (`build`, `check`, `apply`, `rollback`). It moves the box from where ES PR #54's upgrade left it (ES built from `16cbf739`, Nomad enforcing ACLs on plain HTTP) to one named `trunk_dev` commit with Nomad's API and RPC only on TLS 1.3: it issues Nomad's TLS material with the `nomad_tls` functions of `scripts/70_linux_setup.sh`, adds that script's `tls` block to `nomad.hcl`, reruns `scripts/nomad_acl_setup.sh` (`provision`, then `placement`) over HTTPS, adds the Nomad TLS keys and the server key's pin to `es.json` after the new ES's own `config.Load` accepts the result, installs the binaries, verifies with `scripts/internal/nomad_tls_identity.py`, and puts its backup back on any failure. It reads the host's shape part by part first: a box it already moved is only verified and left unchanged, and any other shape is refused with each part's state named. It does not redeploy AGS, ARS or EGS. It does not reopen the retired writable-state and service-user family, and other old or nonempty hosts stay blocked. The contract is in `.docs/system_overview/remote_supported_host_alpha.md`, section "Remote ES Upgrade And Nomad HTTPS".
- The accepted Remote Alpha retirement/retain-staging tranche retires the six existing-host ES writable-state, ES service-user, ownership, staging, rollback-generation, and old-root-planning helper implementations. Their fixed fail-closed tombstones produce no evidence and the unchanged public wrappers only delegate to those tombstones. Archived v1 artifacts are historical evidence only, no live operator route parses or projects them, and no v2 replacement exists for that retired family. This retirement does not apply to unrelated Remote Alpha Vault, TLS, runtime-identity, governance, operator-healthcheck, recovery, or Vault service-user routes; the unrelated current EGS hardening v2 schema also remains current.
- ES now retains every exclusively created per-run staging root on every post-claim return. Failed or ambiguous submit, accepted registration, every terminal observation, and every retained-result publication outcome have no automatic whole-root cleanup consequence. Descriptor closure is idempotent, exact operation-local temporary cleanup remains bounded to the object created by that operation, and governed staging reclamation is an ES-owned `Reopened redesign seam`.
- Fresh-host provisioning is the required direction for future Remote Alpha infrastructure recovery, but no complete supported fresh-host ES provisioner currently exists. Reuse of an old or nonempty host remains blocked unless a separately governed existing-host migration contract is selected. No scheduler-drain or submitter-fence contract exists in this tranche.

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
- ES owns the public admission model, prepare model, submit model,
  Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- Nomad remains authoritative for submitted execution lifecycle; ES must not invent a parallel lifecycle store or scheduler authority.
- ES may expose a bounded lifecycle projection revision on status responses as an opaque same-run read-coordination fact derived from Nomad observation. Callers may compare equality/change for the same run only. They must not parse or order it, infer scheduler or backend state from it, use it as a write precondition for cancel/result/logs, or treat it as a Nomad identifier or index. It is not evidence of an ES-owned lifecycle store, not a Control Plane workflow version or revision, and not proof of freshness outside the documented same-run status read model.
- ES may expose a bounded `authority_handoff` read surface on submission/status responses for non-secret runtime authority facts ES actually selected and handed off for a run: effective runtime profile, workload-visible identity endpoint handoff, workload-vault auth metadata, selected workload-zone Vault config reference, and bounded profile credential-location metadata. This surface is read-only evidence of the submitted runtime handoff, not live credential state, lease state, scheduler identity, policy approval state, or a Control Plane lifecycle record.
- ES must not bypass ARS artifact storage/discoverability, EGS runtime-trust publication, or configured runtime-config ownership to make admission easier.
- ES-owned retained results remain opaque output bundles and must not become Control Plane checkpoint, review, finalization, or orchestration state.
- ES-owned runtime identity and workload-credential handoff must remain platform-owned, non-secret, and non-brokering: workloads use the discovered endpoint and workload-Vault metadata; ES does not fetch, mint, store, rotate, parse, or validate Vault or Codex credential material.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
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
- supported-local profile-image durability checks, including the Nomad Docker plugin `gc.image = false` guardrail for enabled local runtime-profile images
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
- ES submits to Nomad only with its own least-privilege ACL token in namespace `es-submit-v1`, and only while Nomad enforces ACLs with no anonymous policy; Nomad's management token never reaches ES.
- ES reaches Nomad only over TLS 1.3 at a loopback `nomad.base_url`, trusting only `nomad.root_ca_file` for `nomad.server_name` and only the server key `nomad.server_spki_sha256` pins.
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
- ES currently retains every exclusively created run-scoped host staging root on every post-claim return. Terminal result capture into the ES-owned result store is independent and never authorizes staging mutation; success, failure, cancellation, loss, ambiguity, absence, publication conflict, and publication failure all retain the same visible staging root.
- The isolated resolved-plan/custody candidate retains every successfully claimed run-scoped host staging root, including terminal success, while the submitted workload may depend on its bind mounts. Terminal result files remain opaque ES-owned bundles outside staging. This interim retention increases disk use and sensitive-material residence; no automatic whole-root reclamation authority is selected, and acceptance gates remain pending.
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
- ARS, AGS, EGS, CGS, and ES authenticate callers through the one shared package `internal/callerauth` (contract: `.docs/system_overview/contracts.md` section 3A). Only a verified client certificate whose chain is still within its validity period at each request, and whose leaf is an end-entity certificate with exactly one URI SAN that is a conforming SPIFFE ID in the trust domain `execution.internal` and not a workload identity, identifies a caller; authorization stays in each service.
- ARS, AGS, and ES check their configured path-prefix allowlists at startup and match callers against them through the one shared package `internal/callerallowlist` (same section 3A): a prefix must be a canonical SPIFFE ID path of at least two segments whose first segment is not `workload` in any letter case, and a prefix that fails the rule matches nothing.
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
- `egs/contract/`
- `ars/index/`

Success condition:

- A documented shared-kernel decision exists.
- The future shared surface is smaller and intentionally owned.
- Cross-service semantics that do not need to be shared are moved back toward service-local ownership.
- Future agents can tell which contracts are kernel-level versus service-level without inferring from package reuse.
- Future agents can tell which shared-kernel rules are stable ES admission semantics, which are temporary compatibility edges, and which are merely current slice implementation detail.

The current bounded decision status for Milestone 2A.1, including which
meanings stay service-owned or reopened elsewhere, is in
[`.docs/standing_rules/workstream_decisions.md` § Workstream A decision record](.docs/standing_rules/workstream_decisions.md#workstream-a-decision-record).

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
- `ars/contract/`
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

The current bounded decision status for Milestone 2B.1, including which parts
of the discovery, index and publication-support model remain reopened, is in
[`.docs/standing_rules/workstream_decisions.md` § Workstream B decision record](.docs/standing_rules/workstream_decisions.md#workstream-b-decision-record).

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

The current bounded decision status for Milestone 2C.1, with the C0 to C7
slices and the compatibility edges they keep, is in
[`.docs/standing_rules/workstream_decisions.md` § Workstream C decision record](.docs/standing_rules/workstream_decisions.md#workstream-c-decision-record).

### Workstream D - Policy And Authorization Reset

Purpose:

- Re-derive policy ownership across EGS and CGS.
- Decide what belongs to trust publication, what belongs to authorization, and what belongs nowhere in the long-term architecture.
- Reassess the current `id.conf` policy model, authorize DTO, and remaining policy/trust ownership seams.

Target files and packages:

- `egs/api/`
- `egs/contract/`
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

The current bounded planning direction, with the accepted D1b to D1d slices and
the Workstream D seams that remain reopened, is in
[`.docs/standing_rules/workstream_decisions.md` § Workstream D decision record](.docs/standing_rules/workstream_decisions.md#workstream-d-decision-record).

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

The E0 decision status and the Workstream E guardrail status, including what
remains open in Workstream E, are in
[`.docs/standing_rules/workstream_decisions.md` § Workstream E decision record](.docs/standing_rules/workstream_decisions.md#workstream-e-decision-record).

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

The current bounded planning direction, with slices 1A and 1B, the F0 runtime
identity handoff ownership decision and the F1 named workload identities and
workload grants slice, including what remains open in Workstream F, is in
[`.docs/standing_rules/workstream_decisions.md` § Workstream F decision record](.docs/standing_rules/workstream_decisions.md#workstream-f-decision-record).

Dependencies:

- Workstream C
- Workstream D
- Workstream E

## Host And Runtime Boundary Rules

The standing rules of the current host and runtime boundary slices are in
[`.docs/standing_rules/host_and_runtime_boundary.md`](.docs/standing_rules/host_and_runtime_boundary.md):
the Remote Alpha hardening history and current retirement, Milestone 1 (the
least-privilege runtime/security boundary closeout) with its boundary posture
matrix and posture checker, the Remote Alpha ES config/TLS ownership prep
slice, and the Remote Alpha host network boundary slice with its host firewall
and its P0q workload-auth bootstrap refinements. Each has a section of the same
name there.

## Future ES Privilege-Boundary Design Track

`Reopened redesign seam`: full ES/runtime de-root beyond the now-landed
long-lived `es.service` user flip remains a future structural design track.

- This future track covers the long-lived ES service privilege model, Nomad
  task user model, runtime-helper/supervisor ownership, SPIRE selector posture,
  SPIRE socket traversal, staging/results ownership, retained-result
  materialization, and operator maintenance/rollback model as one boundary
  package rather than as implicit follow-on hardening.
- Archived v1 evidence records an earlier bounded rollout involving binary
  parity, stable writable-state preparation, and a long-lived ES service-user
  change. The ES writable-state, service-user, ownership, staging, rollback,
  and cleanup-planning helpers from that rollout are now retired and cannot
  inspect a host, refresh evidence, or authorize another rollout.
- The privileged-operation matrix, writable-state ownership model, and runtime
  ownership-normalization document remain design history. They do not define a
  current existing-host migration contract. Reuse of an old or nonempty host
  remains blocked without a separately accepted contract.
- The retained rationale is explicit in the superseded, non-authoritative
  historical-design sections of
  `.docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md`,
  `.docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md`,
  and
  `.docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md`.
  Those sections preserve privilege separation, service-user, SPIRE, Vault,
  ownership-normalization, helper-limit, and compatibility reasoning only;
  they are not available operator routes and confer no migration, cleanup, or
  reclamation authority.
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

## Retired Existing-Host Actions and Later Infrastructure Seams

The former writable-state preparation, ES service-user migration, generated
rollback rehearsal, migration staging, and old-root planning actions are
retired. Their v1 artifacts are historical evidence only. No v1 artifact may
authorize deployment, migration, drain, reclamation, or mutation, and no v2
artifact or replacement protocol exists for that retired ES writable-state/
service-user migration family. This does not describe or retire the unrelated
current EGS hardening v2 schema.

Fresh-host provisioning is the required recovery direction, but ownership and
acceptance of a complete supported fresh-host ES provisioner remain unresolved.
The current repository does not implement one. Old-host migration may return
only if a real requirement selects a separately governed contract. Scheduler
drain and submitter fencing likewise remain undefined later seams.

`Reopened redesign seam`: Option C runtime-boundary redesign remains a
separate architecture track, not a cleanup follow-on.

- Any future work on the root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, broad root selector posture, or
  Vault/workload-zone handoff must proceed only as that separately documented
  redesign track.
- Workstream F slice F1 is the separately documented redesign for the broad
  root selector posture and the per-workload Vault handoff. It leaves the
  root-start runtime helper, Nomad task `User: "0:0"` and helper-private SPIRE
  traversal unchanged.

`Current invariant`: the completed branch-level milestone does not imply a
`master` merge.

- Merge remains a human milestone decision after review of the bounded
  evidence set and governance posture.

## Cross-Repo Hybrid Integration ADR Pointer

The accepted Hybrid Integration Architecture ADR is recorded at
`.docs/system_overview/hybrid_integration_architecture_adr.md`. It is the
canonical cross-repository current-status and migration-boundary decision for
this alignment tranche. It does not implement or change ES product behavior,
and it enables no integration behavior.

Phase D is complete for planning status: Coordinator is parallel to CP as a
bounded coding-work domain authority, not a CP subordinate internally and not a
product workflow by itself. The connector -> Bridge -> Coordinator -> ES route
without CP is not an established compatibility path, product workflow, or
authorized integration implementation. That current non-claim does not freeze
no-CP routing as proof-only target architecture. The CP-authoritative path is
the current maintained MVP/demo compatibility path only; CP is absent from the
target autonomous-development architecture except as current behavior,
compatibility, filming, migration, or retirement context.

Strategic target direction is recorded here only as target direction: model
reasoning may become the cognitive engineering lead, the user is not expected
to remain a routine per-task approval service, and Coordinator is intended to
become a durable autonomy core while ES remains admission/runtime authority.
That target direction does not describe current implementation behavior and does
not make connector availability, a first-class Development Program, full
append-only event sourcing, finite backlog, external-only authority issuance,
or current IM/Maintenance Agent repository survival a global prerequisite.

Phase E is complete with Symphony deferred. Symphony is source/reference
material only, useful for worker-supervision mechanics, not included in the MVP
or product architecture, and no Symphony experiment, installation, or
integration is authorized.

Earlier planning identified four unresolved contract-seam themes:

- Authority Issuance;
- Coordinator Ingress;
- Worker / Runtime Handoff;
- Correlation And Recovery.

Those names remain a current capability-gap inventory only. Their exact
contents, ownership, repository placement, and sequencing are reopened target
seams, not a fixed package decomposition, global blocker, or mandatory next
implementation sequence.

The Coordinator current status is bounded durable SQLite mutation authority for
coding-work state: internal durable writer issuance, private atomic transition
and global-stop persistence, guarded public delegation, verification of
already-persisted decision receipts, fencing, idempotency, replay, CAS, rollback,
one COMMIT attempt, commit uncertainty, and retry. Coordinator still does not
own work-item production provisioning, lease issuance, executable authorization
issuance, decision-receipt provisioning, a worker, scheduler, queue consumer,
Codex invocation, ES runtime, CP workflow, publication, or general
orchestration.

Architecture/status alignment is the immediate documentation program. After
alignment, the next implementation selection is reopened contract-seam design,
not end-to-end execution or a fixed global sequence. ES Admission And Runtime
Boundary Realignment remains the ES planning authority and is not displaced by
Coordinator integration work; it remains required for any ES-owned
admission/runtime change.

Classification for this ADR tranche:

- Current invariant: ES remains admission/runtime authority; CP remains
  workflow, progression, review, checkpoint, cancellation decision,
  intervention, and finalization authority inside the current maintained
  MVP/demo compatibility path; IM remains profile/provenance/readiness/
  diagnostics authority; Workstream C guardrails remain integration-enabling
  product boundaries.
- Bounded slice rule: Bridge and Maintenance Agent may record or consume
  non-authoritative proposals, summaries, and evidence only under their own
  documented boundaries; Coordinator bounded SQLite mutation authority remains
  coding-work state authority only.
- Compatibility edge: `control-plane-normal-shell/v1` remains a bounded
  compatibility edge and is not changed by Coordinator integration planning.
- Temporary compatibility edge: Remote Alpha helper/status/renewal routes
  remain proof/support containment until promoted by explicit ES route
  contracts and tests.
- Reopened redesign seam: operator-healthcheck TLS signer/custody remains
  blocked and source-insufficient; the next TLS step requires source-grounded
  signer/custody evidence or an explicit ES product decision.
- Reopened target seam: work-source shape, backlog model, authority
  issuance/delegation, Coordinator ingress, worker/runtime handoff,
  correlation/recovery, package boundaries, and current component survival are
  reopened and not settled by this ADR pointer.

Bridge connector-safe source intake and no-mutation Codex handoff are
implemented/live-tested as Bridge-local evidence/projection only. The already
implemented Bridge source/handoff evidence slice must remain no-write,
no-shell, no-Codex-invocation, non-authoritative for ES, and separate from local
runner, acceptance, commit, push, PR, merge, and Coordinator durable coding-work
state. They do not invoke Codex, run shell, mutate repositories, or alter ES
admission, runtime, lifecycle, status, route, TLS, or noninteractive-route
authority. This planning pointer does not change ES priorities or ES route
eligibility. Contract design may proceed only within reopened seam boundaries
above and must not authorize autonomous execution.

### Workstream C admission and custody rules

The standing Workstream C admission, material, custody, proof and
startup-probe rules, with the outside-observer Stage A slice, the
reliable-submit tranche status and the current paired-root custody and
acceptance scope, are in
[`.docs/standing_rules/execution_admission_and_custody.md`](.docs/standing_rules/execution_admission_and_custody.md).

## Highest-Priority Backlog Entry

P0: ES Remote Alpha operator-helper consolidation and manual recovery
minimization.

This P0 is bounded to operator ergonomics over the existing Remote Alpha proof
and support helpers. Implementation must be split into small audited slices,
starting with docs/static-test prep, then help/inventory/print-command
ergonomics, then narrowly reviewed delegation to existing staged helpers, and
only later any secret-sensitive reset/unseal routing after reset-helper tests
and audit. It must not widen ES public contracts, CP orchestration semantics,
IM authority, Nomad task-user semantics, SPIRE exposure boundaries, or Vault
token brokerage. ES product architecture leads: an implemented Remote Alpha
operator compatibility surface is not thereby an ES product invariant. The
facade must preserve Remote Alpha as bounded proof/support posture only and
must preserve unrelated IM-consumed artifact filenames, but obsolete facade
parsing, aggregation, discovery, staging, and projection compatibility may be
retired explicitly rather than preserved by inertia.
The objective is one repo-supported ES operator facade/workflow/script that
minimizes manual stitching, copying, and recovery sequencing across bounded
operator work. Operator involvement is expected and allowed: success does not
mean eliminating every prompt. Explicit interactive modes are valid when they
are named, bounded to a mode or subcommand, visible to the operator, and
secret-safe. Default noninteractive sudo remains an ergonomic optimization for
helpers that support it, not a universal success criterion for the operator
facade. The facade must remain a helper workflow and evidence surface, not an
authority source, Vault token broker, IM reconciler, CP recovery authority, or
Remote Alpha deployment/reconciliation system.
The P0b implementation slice is limited to an inert
`scripts/remote_alpha_operator.sh` help/inventory/print-command skeleton:
it may document available and future surfaces, print exact Mac-side
Infrastructure Manager refresh/support-bundle commands, and refuse blocked or
not-yet-implemented subcommands. It must not route to Remote Alpha helpers,
run IM collection commands, stage generic remote helpers, invoke sudo or SSH,
perform Vault reset/unseal behavior, add Vault workload-auth bootstrap, or
write generated artifacts.

P0c, P0d, and P0f are now retired compatibility history. The
`es-writable-state-readiness-check` and `readiness-session` operator routes no
longer inspect or contact a host and no longer produce or refresh evidence.
Their underlying six public wrappers remain only as compatibility delegators
to fixed exit-2 tombstones. Selecting a future diagnostic or existing-host
migration contract is a separately governed decision; this plan does not
define one. The global privacy prefilter is the first argument-sensitive
operation for the retired operator routes. Argument classification occurs
before script-directory canonicalization or helper-path initialization, so a
privacy or stale-route refusal performs no file access, host inspection, or
helper execution first.

### Current Remote Alpha operator evidence-compatibility cutoff

The former P0g evidence-ingestion surface and the P0n/P0r facade staging and
aggregation routes are superseded compatibility history. The live operator no
longer parses, validates, interprets, aggregates, discovers, stages, or projects
the runtime-identity helper summary, Vault workload-auth summary, or Vault
service-user summary families. Their retired routes, aliases, and flags fail
through one fixed, path-free, non-echoing, effect-free refusal before file
access or helper-path initialization; the global secret-option privacy
prefilter remains first.

The three underlying producer families remain optional owner-local proof
emitters under their separately documented contracts for this tranche. That
tranche-local protection neither promotes them to permanent ES architecture nor
creates an operator compatibility requirement. Their facade compatibility is
not a Tranche B prerequisite and must not block core ES work. The cutoff does
not retire or change runtime identity, SPIRE handoff, admission handoff, or
workload-side Vault product behavior, and it introduces no replacement schema,
adapter, projection, registry, v2 protocol, or Infrastructure Manager reader.

The resolved-plan documentation-truth and finite-source-inventory obligation
is now complete. Its accepted scope remains exactly: correcting the
resolved-plan documentation truth and strengthening finite source inventories
for expected-tree `ReadDir`, custody claim/materialization entry points,
synchronized state, rejected A3 topology, and retired operator aliases. The
authoritative closure inventory is recorded in
`.docs/execution_lifecycle/es_execution_admission_model.md` and the exact
operator compatibility inventory is recorded in
`.docs/system_overview/remote_supported_host_alpha.md`. This completion changes
no production custody or staging source and begins no additional Tranche B
behavior.

### Historical P0g evidence ingestion — superseded and non-authoritative

P0g formerly supplied a safe/local recovery sequencing skeleton plus a bounded
local evidence checker. Its no-follow file-reading, strict JSON, privacy,
bounded-output, and non-authority rationale remains useful design history, but
it grants no current facade ingestion or projection behavior and is not a
compatibility promise.

P0h's historical-v1 display is retired. The live operator no longer accepts
`--readiness-summary` or `--staging-record`, discovers their historical
filenames, recognizes the three retired ES schema identifiers, or publishes
their schema, byte count, digest, or archived fields. Stale historical flags
receive one fixed non-echoing refusal before file access. Archived v1 fixture
and artifact bytes remain evidence only outside live operator behavior and
grant no current authority.

The former current-schema checker, its automatic evidence-directory discovery,
and its safe-field projections are retired with P0g. No empty generic evidence
parser or dormant compatibility registry remains in the facade.

### Remote Alpha operator facade route rules (P0i to P0v)

The current route rules for the Remote Alpha operator facade, P0i to P0m
(Vault unseal and disposable reset), P0o to P0q (Vault workload-auth bootstrap)
and P0s to P0v (TLS status, renewal and diagnostics), are in
[`.docs/standing_rules/remote_alpha_operator_routes.md`](.docs/standing_rules/remote_alpha_operator_routes.md).
The Remote Alpha access contract v1 (Tranche A) and its reopened access-profile
and access-status seams, the operator-healthcheck TLS replacement design, the
external TLS single-use incident and the maintenance-monitor route eligibility
are there too, in the section "Remote Alpha access contract v1 — Tranche A".
