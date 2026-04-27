# Remote Alpha To Beta ES Writable-State Ownership Model

## 1. Purpose and status

This document defines the design-only writable-state ownership model for the
recommended **Option B** direction:

- de-root the long-lived ES service
- keep the current root-start runtime helper and Nomad task model explicit as
  bounded compatibility edges for Beta
- defer full runtime-boundary re-derivation to later Option C work

This document does not authorize implementation by itself. It does not claim
that the full ES/runtime privilege boundary is solved. It describes the
accepted Alpha posture where the long-lived `es.service` now runs as
`User=es`, `Group=es`, `UMask=0027`, while the remaining runtime/task/SPIRE
compatibility edges stay explicit.

Authoritative inputs for this document are:

- `.docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md`
- `.docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md`
- `.docs/system_overview/configuration.md`
- `.docs/system_overview/remote_supported_host_alpha.md`
- `.docs/execution_lifecycle/design.md`
- `.docs/execution_lifecycle/implementation.md`
- current ES submit, lifecycle, result-retention, and runtime-helper code and
  tests

## 2. Design goals and constraints

This ownership model is intentionally narrow.

- `Current invariant`: ES public APIs, lifecycle semantics, retained-result
  semantics, and `authority_handoff` semantics stay unchanged.
- `Current invariant`: the workload remains fixed non-root `10000:10000` with
  no supplemental groups and no privilege-escalation path.
- `Temporary compatibility edge`: the root-start runtime helper and Nomad task
  `User: "0:0"` may remain for Beta, but they must not define long-lived ES
  writable-state ownership by inertia.
- `Bounded slice rule`: the runtime companion now emits the
  ownership-normalization marker after successful current post-workload
  normalization under the stable `run/platform` subtree.
- `Temporary compatibility edge`: current Alpha-compatible ES preflights must
  not treat a missing marker as a blocker by itself yet.
- `Bounded slice rule`: a structurally valid present marker is accepted as
  marker evidence in current Alpha compatibility mode, but it is not future
  non-root-ready proof unless `target_uid` and `target_gid` are checked
  against the expected long-lived ES service owner and match.
- `Bounded slice rule`: retained-result bundles stay opaque ES-owned artifacts
  under `execution.results_root_dir`, outside staging.
- `Bounded slice rule`: failed, canceled, lost, and otherwise ambiguous runs
  retain staging for debugging unless and until an explicit cleanup policy says
  otherwise.

The primary design blocker this document resolves is:

- the current root-run ES service can ignore ownership drift inside host-backed
  run staging because it is root
- a non-root ES service cannot rely on that shortcut
- therefore any host-backed path ES must read or delete after workload exit
  cannot remain permanently runtime-owned or root-only

## 3. Proposed account and ownership rules

### 3.1 Target ES service account and group

The recommended target service posture is:

- service account `es`
- primary group `es`
- no supplemental groups for the long-lived ES service
- service unit posture equivalent to:
  - `User=es`
  - `Group=es`
  - `UMask=0027`

This keeps the existing narrow prep account aligned with the long-lived ES
service instead of inventing a second shared runtime identity.

### 3.2 Is `es:es` sufficient?

Yes. The existing narrow `es:es` prep account is sufficient for the
long-lived ES service and for ES-owned writable state.

A separate runtime group is **not** recommended for Option B.

Why:

- it would create a new shared Unix-group boundary between the long-lived ES
  service and per-run runtime state
- it would pressure future supplemental-group exceptions for the workload or
  helper, which conflicts with the current no-supplemental-groups invariant
- it would preserve a cross-phase ownership shortcut instead of keeping
  long-lived ES ownership explicit
- the root-start runtime companion can remain a bounded compatibility edge for
  Beta without forcing the long-lived ES service into a shared runtime group

### 3.3 Core ownership rule

Under Option B, host-backed writable state falls into two classes:

1. **Stable ES-owned state**
   These paths are owned by `es:es` and remain ES-owned across the full run
   lifecycle unless this document explicitly says otherwise.

2. **Transient runtime-owned state**
   These are host-backed paths inside a run-scoped staging tree that the
   runtime companion or workload may transiently own while the task is active.
   If ES must read or delete them after workload exit, the root-start runtime
   companion must normalize them back to ES-owned readable and deletable state
   before ES performs retained-result packaging or successful-stage cleanup.

This document intentionally avoids ACL-dependent or supplemental-group-based
ownership tricks. The model is explicit Unix ownership, not hidden access
control.

The detailed runtime-companion bridge contract for those transient-to-ES-owned
transitions now lives in
`.docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md`.

Future non-root-required readiness and service-user migration check-only now
also require the two stable roots themselves,
`execution.staging_root_dir` and `execution.results_root_dir`, to resolve to
one shared target owner UID:GID. A mismatched stable-root owner model is not
future-ready proof even if one or both roots remain otherwise readable.

The repo-owned non-mutating readiness checker for this ownership model is
`scripts/remote_alpha_check_es_writable_state_readiness.sh`. It is host-local
readiness and provenance only. It is not approval to flip the live ES service
user. When an `es` UID:GID can be determined, that checker evaluates future
non-root-required readiness and must block on missing markers, invalid present
markers, marker `target_uid` or `target_gid` mismatch, or staging/results
stable-root owner-model mismatch. When the expected `es` owner cannot be
determined, the checker may report only unverified marker evidence rather than
future non-root-ready proof. The checker defaults to `--mode alpha-compat`,
which preserves the current Alpha-compatible marker semantics and reports
future-only gaps as warnings or not-observed evidence.
Operators must use explicit `--mode future-non-root-required` to ask the
checker for a future non-root readiness gate. That explicit gate is still
check-only and non-mutating; it does not change the live ES service user and
it is not approval to implement ES de-rooting.

The preferred repo-side operator wrapper for staging that checker onto a
Remote Alpha host is
`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`. That
wrapper stages only
`scripts/remote_alpha_check_es_writable_state_readiness.sh` plus
`scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`,
executes the staged checker only from a root-owned staged path under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`, writes
the Infrastructure Manager-compatible local artifacts
`es-writable-state-readiness.json` and
`es-writable-state-readiness-helper-staging-record.json`, and records the
staged helper provenance needed to prove the checker ran from a root-owned
path rather than a user upload directory. That wrapper is non-mutating except
for temporary checker staging. It is readiness evidence only, not governed
proof, and not approval to de-root ES. Explicit
Those `--mode future-non-root-required` blocker findings were expected before
the now-applied long-lived service-user migration. That future-mode gate
remains the authoritative check for preserving non-root writable-state
readiness and for evaluating any later rollback-window changes.

Current branch status for this ownership model:

- `Design-only`: this document now supplies the authoritative staging/results
  ownership model for Option B.
- `Repo-local test-backed`: repo-local writable-state and normalized-run
  lifecycle tests now cover retained-result packaging, repeat fetch after
  cleanup, successful cleanup, and failed, lost, or canceled staging
  retention under owner-only temp-dir stand-ins for the future service user.
- `Checker-backed`: the non-mutating readiness checker now distinguishes
  current Alpha-compatible evidence from explicit
  `future-non-root-required` gating.
- `Live-host evidenced`: the bounded live rollout now proves the stable
  staging/results roots are presented as `es:es`-owned, readable, and
  deletable to the non-root long-lived ES process, with future writable-state
  readiness passing afterward.
- `Live-host service-user slice evidenced`: the staged operator migration
  helper is no longer only design input; the bounded long-lived `es.service`
  user flip is now live-host evidenced. The consolidated ledger lives in
  `.docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md`.

## 4. Path ownership matrix

The left-hand column below records the earlier pre-service-user root-era owner
or mode assumptions that the landed bounded migration moved away from. It is
not the current live posture.

| Path/category | Historical pre-service-user owner/mode assumption | Proposed Option B owner/mode | Access and visibility | Post-exit readability, deletion, and rollback |
| --- | --- | --- | --- | --- |
| `execution.staging_root_dir` | Created by root-run ES startup with `MkdirAll(..., 0755)` when submit is configured. In practice the current service can tolerate root-owned or otherwise root-writable state because the long-lived service still runs as root. | Owner `es:es`, mode `0750`. The top-level staging root is stable ES-owned state and must not become workload-owned. | Runtime helper writes: no direct writes to the root itself.<br>Workload writes: no direct writes.<br>ES writes: yes, creates run-scoped staging under it.<br>ES reads: yes for staging inspection and cleanup.<br>Nomad/Docker visibility: indirect only through run-scoped bind-mounted children. | Must remain traversable and writable by ES for the full service lifetime.<br>The top-level root is not deleted by lifecycle success cleanup; only child run directories are removed.<br>Rollback: root-run ES can continue operating on an `es:es` root immediately; a full Alpha rollback may restore the pre-change owner or mode snapshot later if required. |
| Per-run staging directory `<staging_root>/<run_id>` | Created by the root-run ES submit path through `stageExecutionInputs`, with the practical assumption that root can always clean it later. | Owner `es:es`, mode `0750`. ES must reconcile the run-scoped root itself to the owner model derived from `execution.staging_root_dir` when the directory is first created; it is not enough to normalize only the child `payload`, `run`, or `mounts` descendants. The per-run root stays ES-owned even if selected descendants become transiently runtime-owned while the task is active. The current fixed workload boundary still requires one bounded compatibility exception on the bind-mounted `/execution/run` parent path: while the task is active, the root-start companion may widen only the execute traversal needed for the workload to reach `/execution/run/work`, `/execution/run/result`, and the workload-readable trust files under `/execution/run/platform`, then restore the stable ES-owned restrictive mode after workload exit. | Runtime helper writes: indirect, through descendants under `run/`.<br>Workload writes: indirect, through descendants under `run/`.<br>ES writes: yes, creates payload, run, and mount staging.<br>ES reads: yes for retention, diagnostics, and cleanup decisions.<br>Nomad/Docker visibility: indirect through bind-mounted descendants. | On terminal success, ES may delete the entire run root only after retained-result capture has been attempted and transient runtime-owned descendants have been normalized back to ES-deletable state.<br>On failed or canceled runs, the run root stays in place for debugging.<br>If older root-run submissions left incompatible run-scoped roots under the fresh live staging root, the bounded writable-state helper may quarantine those inactive roots outside the live staging tree instead of recursively re-owning them in place.<br>Rollback: reverting the service to root preserves the retained tree; no forced deletion is required. |
| Payload staging `<staging_root>/<run_id>/payload` and `artifact.tar.gz` | Directory is created with requested mode `0755`; payload archive is written with mode `0600`; both are effectively root-owned because ES is root-run today. | Directory owner `es:es`, mode `0750`.<br>Payload archive owner `es:es`, mode `0600`. | Runtime helper writes: no.<br>Workload writes: no.<br>ES writes: yes, stages the payload archive.<br>ES reads: yes if needed for diagnostics; not needed after successful submit.<br>Nomad/Docker visibility: yes, bind-mounted read-only to `/execution/staged`. | The payload staging area only needs to remain ES-readable while the run-scoped stage root is retained for debugging.<br>It may be deleted with the full run-scoped stage root after terminal success and retained-result handling.<br>Rollback: root-run ES can consume the existing `es:es` payload tree without reowning it first. |
| Mount staging `<staging_root>/<run_id>/mounts/*` | Mount staging root and extraction directories are created with requested mode `0755`; temporary archives are written `0600`; extracted file modes come from the archive and are effectively root-owned today. | Mount staging root owner `es:es`, mode `0750`.<br>Per-mount extraction roots owner `es:es`, mode `0750`.<br>Extracted files remain `es:es` with archive execute bits preserved, masked by `UMask=0027` so they are not world-readable or world-writable. | Runtime helper writes: no.<br>Workload writes: no.<br>ES writes: yes, stages and extracts governed mount artifacts.<br>ES reads: yes for diagnostics if the stage is retained.<br>Nomad/Docker visibility: yes, bind-mounted read-only under `/execution/mounts/...`. | Mount staging must remain ES-readable while a failed or canceled stage root is retained for debugging.<br>It may be deleted with the run-scoped stage root after terminal success and retained-result handling.<br>Rollback: root-run ES can continue to consume or delete the existing mount staging tree. |
| Run platform staging `<staging_root>/<run_id>/run/platform` | Created by ES with requested mode `0755`; runtime support binary is copied with requested mode `0755`; staged Vault trust files are written with requested mode `0644`. The current root-start supervisor then `chown`s the platform directory to `root:root` and `chmod`s it `0755`, which the current root-run ES tolerates but a non-root ES service cannot rely on. | Stable host-backed owner `es:es`, directory mode `0750` before and after the active task window.<br>Runtime support binary owner `es:es`, mode `0750`.<br>Non-secret staged trust files owner `es:es`, stable mode `0640` before and after the active task window.<br>While the workload runs, the root-start companion may widen only the directory traversal and non-secret trust-file readability needed by the current fixed `10000:10000` workload boundary, then restore the stable ES-owned restrictive modes after workload exit. | Runtime helper writes: yes, bounded runtime-companion writes may still happen here while the Beta helper model remains a compatibility edge.<br>Workload writes: no.<br>ES writes: yes, stages the runtime support binary and non-secret trust material.<br>ES reads: yes for diagnostics and rollback inspection.<br>Nomad/Docker visibility: yes, via `/execution/run/platform`. | The platform subtree must remain ES-readable and ES-deletable after workload exit because it is part of the retained stage root on failed or canceled runs and part of the success cleanup path.<br>On success it may be deleted with the full run root.<br>Rollback: root-run ES can still operate on an `es:es` platform subtree; a full Alpha rollback may reapply the previous owner or mode snapshot if desired. |
| Run work staging `<staging_root>/<run_id>/run/work` | Not created by submit staging directly. The root-start supervisor creates it at task start, untars the payload there, strips setuid or setgid bits, recursively `lchown`s the active tree to `10000:10000`, and now performs a post-workload normalization pass back to its current target owner. Before the landed long-lived service-user slice, that target owner still matched the root-run service owner; the current live posture now expects `es:es`, and the bounded future writable-state readiness plus service-user evidence cover that cut line. | **Phase-specific**.<br>Active runtime phase: workload-owned transient subtree, owner `10000:10000`, sanitized workload modes as required for execution compatibility.<br>Post-exit retained or cleanup-ready phase: the root-start supervisor must recursively normalize the work subtree back to owner `es:es`; directories `0750`, files `0640` or `0750` only where execute is still required for bounded debugging. | Runtime helper writes: yes, prepares and sanitizes the subtree before workload exec.<br>Workload writes: yes, workloads may mutate the work tree today even though it is not a retained-result contract surface.<br>ES writes: no after handoff.<br>ES reads: not part of the ES result contract, but ES may need to delete it and operators may inspect it on retained failed or canceled runs.<br>Nomad/Docker visibility: yes, via `/execution/run/work`. | This subtree does not need to remain a public ES contract surface after exit, but it must become ES-deletable for successful cleanup and ES-readable enough for retained failed or canceled debugging.<br>On success it may be deleted with the run root.<br>On failed or canceled runs it remains retained for debugging.<br>Rollback: if normalization is missing, reverting the service to root restores cleanup capability immediately; this is one of the concrete reasons the earlier root-run service could mask the blocker. |
| Run result staging `<staging_root>/<run_id>/run/result` | ES creates the reserved path during submit staging, then the root-start supervisor removes and recreates it as workload-owned `10000:10000` with mode `0755`. After workload exit the current implementation now normalizes the result tree back to its current target owner and emits the ownership-normalization marker when that phase succeeds. Before the landed long-lived service-user slice, that target owner still matched the root-run service owner; the current live posture now expects `es:es`, and the bounded future writable-state readiness plus service-user evidence cover that cut line. | **Phase-specific**.<br>Active runtime phase: workload-owned transient subtree. The top-level result directory should be created as owner `10000:10000` and not be world-writable.<br>Post-exit retained or cleanup-ready phase: before ES retained-result packaging or successful cleanup, the root-start supervisor must recursively normalize the result subtree to owner `es:es`, directory mode `0750`, file mode `0640`, while preserving the existing result-retention restrictions on unsupported file types. | Runtime helper writes: yes, creates and later normalizes the result subtree.<br>Workload writes: yes, this is the bounded workload-authored output directory.<br>ES writes: no.<br>ES reads: yes, this is the source for retained-result packaging and failed or canceled debugging.<br>Nomad/Docker visibility: yes, via `/execution/run/result`. | This subtree must remain ES-readable after workload exit for retained-result packaging and for failed or canceled debugging when staging is retained.<br>On success it may be deleted with the run root only after retained-result capture has been attempted.<br>On failed or canceled runs it remains retained in place for debugging.<br>Rollback: root-run ES can still read or delete it even if the normalized `es:es` owner or mode model is only partially landed. |
| `execution.results_root_dir` | Created by root-run ES startup with `MkdirAll(..., 0755)` when submit is configured. The current service tolerates root-owned state by virtue of running as root. | Owner `es:es`, mode `0750`. This is stable ES-owned state and is never workload-owned. | Runtime helper writes: no.<br>Workload writes: no.<br>ES writes: yes, creates run-scoped retained-result directories, bundles, and preserved normalization evidence sidecars.<br>ES reads: yes, serves repeat result fetches and future-readiness evidence from here.<br>Nomad/Docker visibility: no. | Must remain ES-readable across repeated `GET /result` requests even after the run-scoped staging tree has been removed.<br>The top-level results root is not deleted by lifecycle cleanup.<br>Rollback: root-run ES can continue serving bundles from an `es:es` results root immediately; full Alpha rollback may restore prior owner or mode later if needed. |
| Retained result bundle `<results_root>/<run_id>/result.tar.gz` plus preserved normalization evidence `<results_root>/<run_id>/ownership-normalization.json` | Parent directory is created with requested mode `0755`; the temp bundle file is created by `CreateTemp` and the final linked bundle is effectively root-owned today, typically readable only to the root-run ES service. The original normalization marker currently lives only under staging and disappears when successful cleanup removes that stage root. | Parent directory owner `es:es`, mode `0750`.<br>Final bundle owner `es:es`, mode `0600`.<br>Preserved normalization evidence owner `es:es`, mode `0640`. | Runtime helper writes: no.<br>Workload writes: no.<br>ES writes: yes, packages the opaque tar.gz bundle here and preserves validated normalization evidence here before successful cleanup can remove the staging copy.<br>ES reads: yes, repeat fetches come from here without further runtime lookup when already retained, and future readiness may use the preserved normalization evidence after cleanup.<br>Nomad/Docker visibility: no. | Must remain ES-readable after stage cleanup because the public retained-result endpoint is served from here.<br>Successful cleanup may remove the original staging marker location, so future-readiness evidence that must survive cleanup has to be preserved here first.<br>Repeat retained-result reads may perform only narrow target-owner reconciliation on the retained run directory, bundle, and preserved normalization evidence sidecar; they must not recurse through bundle contents, arbitrary result trees, or quarantined roots.<br>If a legacy retained run directory lacks the preserved normalization sidecar needed for future non-root proof, the bounded writable-state helper must quarantine that entire retained run directory outside the live results root rather than fabricate evidence or recursively rewrite arbitrary retained contents in place.<br>These retained artifacts are never deleted by successful stage cleanup.<br>Deletion is an explicit operator retention or garbage-collection action, not part of current lifecycle success handling.<br>Rollback: root-run ES can still read or narrowly re-normalize existing retained artifacts under the `es:es` target-owner model without touching quarantined roots or arbitrary result trees. |
| Successful staging cleanup | Current root-run ES calls `os.RemoveAll(<staging_root>/<run_id>)` only after terminal success and after one retained-result attempt. Root ownership masks any intermediate subtree ownership drift. | Non-root ES keeps the same external behavior, but it may delete the run-scoped stage root only after all transient runtime-owned descendants that ES must traverse or delete have been normalized back to ES-deletable state. The deletion target remains the full run-scoped stage root under `es:es` ownership. | Runtime helper writes: no further writes after terminal normalization is complete.<br>Workload writes: no after terminal exit.<br>ES writes: yes, performs the success cleanup deletion.<br>ES reads: yes, performs the final retained-result attempt first.<br>Nomad/Docker visibility: not relevant after terminal success is observed. | What can be deleted and when is unchanged semantically: the entire run-scoped stage root may be removed only after terminal success and after retained-result handling has been attempted.<br>Rollback: reverting the service to root restores the current cleanup capability immediately if any ownership normalization bug is discovered. |
| Failed, lost, or canceled staging retention for debugging | The current slice retains the full stage root for failed, canceled, lost, and otherwise ambiguous outcomes, and the current root-run ES can still inspect or later clean it because it is root. | Failed, lost, and canceled terminal runs should retain the full run-scoped stage root in ES-readable form under the model above: stable ES-owned parents, ES-owned payload and mount staging, ES-owned platform staging, and post-exit normalized work and result subtrees when normalization succeeds. Lost or otherwise ambiguous runs may remain a bounded compatibility subcase where normalization cannot be proven and root operator inspection is still required. | Runtime helper writes: only the bounded runtime companion writes under the retained run root while the task is active.<br>Workload writes: only inside the transient work and result subtrees while running.<br>ES writes: no further writes except any future operator retention metadata; current ES keeps the retained tree in place.<br>ES reads: yes for diagnostics and operator-guided inspection.<br>Nomad/Docker visibility: not relevant after terminal retention. | Failed, lost, and canceled runs must remain readable enough for ES-side diagnostics and operator inspection without requiring that the long-lived ES service be root again.<br>They are not auto-deleted by the current lifecycle slice.<br>Rollback: reverting the service to root preserves retained debugging trees and restores current inspection or cleanup capability for any ambiguous retained roots. |

## 5. Migration plan

This is a design-only migration sequence. It is not approval to execute it on a
host today.

Recommended migration package:

1. Preserve the accepted Alpha inputs that already exist:
   - the dedicated `root:es` readable config and TLS model
   - the current runtime helper compatibility edges
   - the current Nomad task `User: "0:0"` posture
   - the current helper-private SPIRE traversal, broad root selector scope,
     and workload-zone Vault handoff semantics as explicit bounded
     compatibility edges
2. Require a drain window before any writable-state migration:
   - no active submissions in progress
   - no live Nomad allocations that still depend on existing run-scoped bind
     mounts
   - retain failed or canceled run stage roots in place for debugging
3. Snapshot the current writable-state roots before any ownership flip:
   - `execution.staging_root_dir`
   - `execution.results_root_dir`
   - retained per-run stage roots still present for debugging
   - retained result bundle directories and bundle files
4. Validate or create the narrow `es:es` account if not already present.
5. If the stable writable-state roots are empty, re-owner only those two live
   stable roots to the target long-lived service model:
   - `execution.staging_root_dir` -> `es:es` `0750`
   - `execution.results_root_dir` -> `es:es` `0750`
6. If the stable writable-state roots are non-empty, use an explicit
   maintenance-window root rotation instead of recursively re-owning retained
   contents:
   - require a bounded drain-safe decision first; active or unknown runs still
     block the operation
   - classify legacy staging-root run directories read-only before any
     mutation when retained-result or normalization-marker evidence is missing
   - use only the existing configured Nomad connection from `es.json` for that
     read-only classifier, with the current internal locator mapping
     `run_id -> exec-<run_id>`
   - treat Nomad-active, scheduler-unavailable, or otherwise unknown legacy
     directories as hard blockers
   - allow rotation only when each legacy directory can be classified as a
     terminal scheduler run or a stale-orphan candidate with no active
     scheduler task
   - require an additional explicit operator acceptance such as
     `--accept-stale-orphaned-runs` before rotating roots that still contain
     legacy directories without retained-result or normalization-marker
     evidence
   - stop `es.service` while it remains `root(default)`
   - move the old configured staging/results roots aside to timestamped
     root-owned quarantine paths
   - create fresh live roots at the original configured paths as `es:es`
     `0750`
   - preserve the old staging/results contents in place for rollback or
     debugging
   - do not recursively `chown` the old root contents
   - do not delete the old root contents
   - record explicitly that retained bundles preserved under the old results
     root may no longer be available through the normal ES API after rotation
     until rollback or a later explicit migration step
7. If the live staging/results roots already match the documented `es:es`
   model but a shared traversal parent still blocks future non-root ES, use a
   separate bounded parent-traversal fix instead of revisiting root rotation:
   - inspect only the minimal common parent directory or directories required
     to traverse to `execution.staging_root_dir` and
     `execution.results_root_dir`
   - preserve the existing parent owner rather than making ES the owner of
     unrelated host state
   - grant the long-lived ES service group traversal and bounded read access
     with group `es` and mode `0750`
   - under the current Remote Alpha host layout, that means the blocked parent
     `/var/lib/execution-substrate/es` should become `root:es` `0750`
     because the existing owner is already `root`
8. If the live staging/results roots already match the documented owner model
   but specific legacy artifacts created during the migration attempt still
   block future readiness, use one separate bounded artifact-reconciliation
   path instead of revisiting root rotation:
   - require explicit `--apply --reconcile-artifacts`
   - keep default check-only behavior non-mutating
   - inspect only retained run directories under `execution.results_root_dir`
     and direct run-scoped stage roots under `execution.staging_root_dir`
   - repair only the retained run directory, retained bundle, and preserved
     normalization sidecar when that direct bounded set is sufficient
   - quarantine legacy retained run directories that still lack preserved
     normalization evidence outside the live results root instead of
     fabricating a sidecar
   - quarantine inactive incompatible run-scoped stage roots outside the live
     staging root instead of recursively re-owning arbitrary descendants
   - block on active, scheduler-unavailable, or otherwise unknown run state
   - avoid service restart unless a measured host proves it is required
   - preserve rollback notes and exact changed/quarantined paths
   - do not modify quarantined old roots created by the maintenance-window
     rotation; they remain rollback/debug evidence only
   - do not stop or restart `es.service` for that parent-only traversal fix
     unless a future measured host proves a service interruption is required
8. Do not recursively re-owner retained failed or canceled run trees as part
   of that maintenance-window rotation. Those trees remain preserved under the
   quarantined old roots for rollback/debug purposes unless a later explicitly
   approved slice moves them separately.
9. Change the service unit to the target long-lived service posture:
   - `User=es`
   - `Group=es`
   - `UMask=0027`
10. Only after the code path can preserve the host-backed ownership model for
   `run/platform`, `run/work`, and `run/result` should the repo consider the
   non-root long-lived ES service change ready for host-side application.

That bounded sequence is now live-host evidenced for the current long-lived ES
service cut line: ES config/TLS prep is applied, binary parity was resolved,
stable writable-state roots were prepared, future writable-state readiness
passed, the long-lived `User=es` / `Group=es` service-user apply passed, the
current lowest-cost existing post-apply happy path passed, and the old
root-era staging/results roots remain preserved as rollback/debug/evidence
state until a later explicit cleanup/archive action after the rollback window
expires.

The preferred repo-side operator surface for that bounded migration package is:

- `scripts/remote_alpha_migrate_es_service_user.sh`

Its sourced internal helper is:

- `scripts/internal/remote_alpha_migrate_es_service_user.sh`

That helper is a repo-side migration surface only. It must default to
non-mutating `--check-only`, require explicit `--apply` for any future host
mutation, stage only the minimal helper tree needed for the migration helper
plus the existing writable-state readiness checker, and must not claim that
the full ES/runtime privilege boundary is solved.

Important migration rule:

- do not flip the long-lived ES service user before the runtime companion can
  preserve or restore ES-deletable ownership on host-backed descendants that ES
  must read or delete after workload exit

## 6. Rollback plan

Recommended rollback package back to the earlier pre-service-user root-era
posture:

1. Stop ES.
2. Revert the service unit back to the earlier pre-service-user root-era
   posture:
   - remove `User=es`
   - remove `Group=es`
   - return to `root(default)`
3. Start ES as root.

That immediate rollback is operationally sufficient because a root-run ES
service can still consume and clean `es:es` writable state.

For a full posture rollback that restores the pre-change owner or mode model as
well:

4. Reapply the saved writable-state snapshot to:
   - `execution.staging_root_dir`
   - `execution.results_root_dir`
   - retained run-scoped stage roots
   - retained result bundle directories and files
5. Preserve retained failed or canceled stage roots during rollback; do not
   delete debugging evidence as part of the service-user rollback itself.

## 7. Required test plan before implementation

Before approving implementation, the repo should require tests that prove the
ownership model rather than assuming it.

The current branch now satisfies several repo-local portions of this plan via
`es/admission/writablestate_readiness_test.go`, but that coverage remains
readiness evidence only. It does not prove live-host `es:es` ownership and it
does not approve flipping the long-lived service user.

Repo-local readiness tests may model the future long-lived `es:es` service
account with the current non-root test-process user. Those tests should use
temp directories plus owner-only permission modes to prove what ES must be
able to read, write, and delete without requiring a real `es` account, host
`chown`, live service changes, SSH, `sudo`, or governed proof.

Required coverage:

- **Submit staging**
  - ES running as the target non-root service account can create the
    run-scoped stage root
  - payload, mount, and platform staging are created under the expected
    `es:es` owner or mode model
  - failed submit still removes the run-scoped stage root
- **Retained-result packaging**
  - after workload exit, ES running non-root can read `run/result` and package
    a retained bundle under `execution.results_root_dir`
  - success cleanup still waits until retained-result handling has been
    attempted
- **Retained-result fetch**
  - repeat `GET /result` reads continue to work after stage cleanup
  - retained result bundle owner or mode is sufficient for non-root ES reads
- **Successful staging cleanup**
  - a successful run removes the full run-scoped stage root
  - cleanup still fails closed if retained-result packaging cannot read the
    result subtree
  - host-backed `run/platform`, `run/work`, and `run/result` descendants are
    ES-deletable before `RemoveAll` runs
- **Failed, lost, or canceled staging retention**
  - failed, lost, or canceled runs keep the run-scoped stage root
  - retained debug trees remain ES-readable under the proposed owner or mode
    model
  - lost or ambiguous outcomes still remain retained and do not claim cleanup
    success
- **Unreadable result negative case**
  - if the post-exit result subtree is not readable to non-root ES,
    retained-result packaging must fail closed and successful cleanup must be
    skipped
  - `GET /result` must continue to return the bounded unavailable or not-found
    behavior rather than claiming a retained bundle exists
- **No supplemental-group or privilege leakage**
  - the long-lived ES service runs as `es:es` with no supplemental groups
  - the workload still runs as fixed `10000:10000` with no supplemental groups
  - the root-start helper compatibility edge does not turn into a shared
    runtime group
  - existing helper-capability drop and workload-boundary assertions remain
    green

Helpful additional coverage:

- a unit or integration check that the runtime companion does not leave
  `run/platform` root-owned after workload exit
- a unit or integration check that `run/work` and `run/result` are normalized
  back to ES-readable and ES-deletable state before non-root cleanup or
  retained-result packaging
- a unit or integration check that the normalization marker contract is
  validated in both required modes:
  - current Alpha compatibility mode keeps missing marker as an explicit
    compatibility edge, accepts structurally valid present-marker evidence, and
    fails closed on invalid present markers
  - future non-root-required mode blocks missing markers, blocks
    `target_uid` or `target_gid` mismatch, and still requires stat-based proof
    that the host-backed trees ES reads or deletes are owned by and accessible
    to the expected `es:es` service owner

## 8. Compatibility edges that remain out of scope

This document does not re-derive these existing compatibility edges:

- the root-start runtime helper and supervisor model
- the current Nomad task `User: "0:0"` model
- helper-private SPIRE socket traversal
- the broad root selector scope used by the current Remote Alpha helper proof

Those edges may remain for Option B, but they must not silently redefine
long-lived ES writable-state ownership.

## 9. Approval boundary

This document is not approval to implement ES de-rooting.

It is a design input only. Implementation still requires updated authoritative
docs for the chosen architecture, tests proving the owner or mode model, a
migration sequence, a rollback sequence, and bounded evidence requirements
before any code or host change is treated as accepted.
