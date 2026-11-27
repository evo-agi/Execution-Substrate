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
  holds the Workstream C admission and custody rules, and
  [`remote_alpha_operator_routes.md`](.docs/standing_rules/remote_alpha_operator_routes.md)
  holds the Remote Alpha operator route rules P0i to P0v. Edit a rule there, in
  place. Two standing-rule sections are still here and are to move the same
  way: "Current paired-root custody and acceptance scope" and "Remote Alpha
  access contract v1 — Tranche A".
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
- `SUPPORTED-LOCAL-ROOT-OWNER-01` is a bounded supported-local configured-consumer integration refinement. The selected rootful, identity-mapped generic ES service profile is UID:GID `0:0`: canonical setup must require a fresh proof root and create only its two fresh configured execution roots as `0:0` with exact `0755` directory mode through a narrow noninteractive privileged helper. The generated profile requires one read-only validator of that static owner/mode contract, proof binding, service image, config, and exact same-path read-write mounts in prepare-only bring-up, the ES launcher, and full-profile submit-readiness (including direct health check and diagnostics use). The ordinary operator needs static inspection access, not write authority to service-owned roots. Generic callers without this explicit profile retain caller-writable readiness; unknown profiles refuse. A fixed safe setup projection records that static owner/mode check in retained proof evidence without paths, key material, or a claim that container capability passed. Existing failed proof roots remain for separately bounded cleanup rather than in-place owner migration. Prepare-only orchestration retains configured Submit, key loading and root capability qualification before listening. ES's `0750` per-run natural-directory capability rule, external result-auth key, and workload `10000:10000` boundary remain unchanged. Review-15's failed full check did not capture its first failed subcheck; this source-demonstrated readiness mismatch does not retrospectively identify that subcheck. Offline fixtures do not qualify a future container view or live supported-local proof; independent review and live proof remain open.
- `R14-ROOT-CUSTODY-01` refines only that helper's fresh-child custody: it must bind each visible fixed child to the same held descriptor before owner/mode normalization, retain both descriptor identities through a final pair check, and refuse drift without repair or cleanup. The operator-owned proof parent permits an independent writer to replace an entry between `mkdir` and descriptor acquisition; those calls are not atomic creation-and-open proof. No protected creation namespace or proof-parent ownership change is selected here. This bounded source repair closes the initialized-descriptor/reopened-name substitution, while arbitrary concurrent pre-acquisition interference remains an explicit design and live-proof limit.
- `GENERIC-ES-LAUNCHER-USER-01` is a **Bounded slice rule** refinement of the generic (no-profile) ES launcher. That path creates missing execution roots as the calling operator and requires them to be caller-writable, while configured-Submit startup requires ES's naturally created `0750` result directory to carry the roots' UID and GID. The launcher therefore runs the ES container as the caller's effective UID and primary GID instead of the image's default root user, so ES holds no more host authority than the operator who started it. It reads both IDs with `id` before any image, root or container effect and refuses unless both are numeric, because `docker run --user` with an empty UID runs as root. Docker gives that identity no supplementary groups, so the roots must carry the caller's UID and primary GID, and every file the ES config names must be readable by that UID or GID. ES's behavioral startup checks stay the only capability gate; the launcher does not branch on daemon labels. On a user-namespace-remapped Docker daemon, Docker itself refuses the host networking that bring-up requires, so bring-up stops at its host-loopback check and ES never starts; rootless Docker is untested and unsupported for bring-up. The `service-root-v1` profile keeps the image's default user for its `0:0` roots. `GENERIC-SERVICE-LAUNCHER-USER-01` applies the same identity to the other bring-up services.
- `GENERIC-SERVICE-LAUNCHER-USER-01` is a **Bounded slice rule** refinement of the bring-up launchers for ARS, EGS and AGS. They run their containers as the caller's numeric effective UID and primary GID instead of the image's default root user, through the same `control_plane_operator_user` helper as the generic ES launcher, which refuses before any image, storage or container effect unless both IDs are numeric. None of the three needs root in bring-up: the documented ports (8442 to 8445) are unprivileged, so a configured port below 1024 now fails to bind unless the host allows unprivileged binding there, and none of them changes file ownership. EGS and AGS only read their config and TLS files. ARS writes its blob store and index as `0600` files, so `scripts/02_start_ars.sh` (and `scripts/01_bringup.sh up`, before starting any service) first checks that ARS can use its storage. On the host, as the caller, the check only reads the config: `storage.root_dir` and `storage.index_file` must be absolute and written in normal form, as Python's `os.path.normpath` writes it (no `.` or `..` component, no repeated or trailing slash, no leading or trailing whitespace; POSIX keeps a leading `//`), because ARS opens both exactly as written while the mounts it gets use the normal form, so only a path in normal form means the same file to both; the refusal names the form to write. A missing storage root is created as the caller instead of letting Docker create the bind source as root, and the index file must already exist as a regular file, not a symbolic link (ARS refuses to start without it, and replaces it with a regular file at its first write). The check then does what ARS does with that storage in a short-lived container that runs exactly as ARS will: the control-plane image, the UID:GID that `control_plane_operator_user` printed, so with no supplementary groups, the mounts `control_plane_mount_specs ars` gives ARS, and ARS's container name, so Docker refuses the check while an ARS container still exists (`02_start_ars.sh` removes the container it replaces first). In that container it changes into every directory on the way to the storage root and the index directory, creates and removes a file in the index directory, creates a file in every directory under the storage root and finds it again by listing that directory, opens the index and every regular file under the root for reading, refuses any other entry under the root (a symbolic link or special file, which ARS never creates, and a link ARS would pass through at a blob or shard path), removes the files it created in batches and refuses the first directory where ARS could not remove its own file, and last, only when all of that passed, writes the index the way ARS does: a new `0600` file with the index's content, renamed over it. The kernel, and on macOS Docker Desktop's file sharing, therefore decides every step for that identity through the mounts ARS will see; owners, groups, modes, POSIX ACLs and the sticky rule are not emulated, and UID 0 gets what root gets in a container. A passing check leaves the index owned by that identity with mode `0600`, as ARS's first write would. Stopped by SIGHUP, SIGINT or SIGTERM, which covers Ctrl-C and the way `scripts/01_bringup.sh` stops ARS's launcher when `up` fails, the check passes the first such signal on to its probe and waits until the probe has removed its files and ended, however often it is signalled again; a probe killed outright, for example by `docker rm -f`, can leave at most one batch of its empty `.ars-storage-check.*` files, those of 256 directories, which the next check reads as ordinary files. The check needs `/bin/sh` with `mktemp`, `xargs`, `rm`, `cat`, `chmod` and `mv` in the image, which the generated image's Alpine BusyBox provides. Its walk uses only shell built-ins per directory and starts no process per directory, because ARS's blob layout `sha256/xx/yy/<digest>` grows to 65,794 directories with the root; at that size the check took 10 to 20 s in the cloud test container, varying from run to run. `TestARSStorageCheckScalesToARSFullFanOut` pins that cost by structure, not by time: it counts the processes the check starts at that size, about 540 with removal in batches of 256 directories, and requires fewer than one per 32 directories. `scripts/01_bringup.sh up` runs the check itself and ARS's launcher runs it again before it starts ARS; ARS's readiness wait (`READY_TIMEOUT_SECONDS`) starts only once the launcher reports that its check passed, through a file `02_start_ars.sh` writes after the check, so the check's time never counts against ARS's readiness and the report cannot skip the check. If the launcher stops before that, `up` fails with the end of its log. `scripts/01_bringup.sh up` derives that identity before any image, storage or container effect, like the launchers. Storage that an earlier bring-up wrote as root, or that is shared through another group, fails that check with the exact `sudo chown` that hands it back, and a directory above the storage that the identity cannot search is refused with its path; the check does not repair ownership itself. Every file named in an ARS, EGS or AGS config must be readable by the caller's UID or primary GID, because Docker gives the container no supplementary groups. The `service-root-v1` profile concerns only ES's roots, so these services run as the caller under it too.
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
- The current shared execution/runtime contract in `internal/contracts/evidence/v1` is now limited to environment allowlist input, declared mount targets, required runtime capabilities, `target_platform`, and `network_access`; non-runtime workload metadata no longer defines the live AGS -> ARS -> ES hot path.
- The artifact's signed environment allowlist and declared mount targets are the only source of what a caller may set or mount in a run: an empty list admits nothing, a caller key must be a portable name, and ES reserves loader, shell-startup, program-lookup, interpreter, proxy and TLS-trust keys whatever the artifact declares (`.docs/execution_lifecycle/contracts.md`, section 5).
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
- ARS, AGS, EGS, CGS, and ES authenticate callers through the one shared package `internal/callerauth` (contract: `.docs/system_overview/contracts.md` section 3A). Only a verified client certificate whose chain is still within its validity period at each request, and whose leaf is an end-entity certificate with exactly one URI SAN that is a conforming SPIFFE ID in the trust domain `execution.internal`, identifies a caller; authorization stays in each service.
- ARS, AGS, and ES check their configured path-prefix allowlists at startup and match callers against them through the one shared package `internal/callerallowlist` (same section 3A): a prefix must be a canonical SPIFFE ID path of at least two segments, and a prefix that fails the rule matches nothing.
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
- `internal/contracts/evidence/v1` is not a cross-service semantic dumping ground. Fields, helper DTOs, proof outputs, generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts do not become shared-kernel authority by proximity to the shared evidence package.
- Workstream A0 preserves the current `execution_substrate.runtime_profile` annotation and bounded `control-plane-normal-shell/v1` compatibility edge. It does not change the runtime path, runtime-profile selection mechanism, or `static-script` overlay behavior.

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
- B0 is the docs and docs-contract-test gate for artifact publication,
  storage, discoverability, payload identity, artifact identity, and
  compatibility/support shapes. It makes no runtime implementation changes.
- B1 is the focused code-facing guardrail slice over the same B0 boundary. It
  adds tests for AGS publication output, ARS runtime-facing discovery, ES
  admission hot-path consumption, payload/artifact/package identity separation,
  CP proof/example non-authority, and `control-plane-normal-shell/v1`
  compatibility. It does not redesign AGS, ARS, or ES runtime behavior.
- AGS owns publish-time fact assembly, caller-bound publication semantics,
  aggregate evidence assembly, signing, payload/support upload, and
  registration into ARS.
- ARS owns blob storage, content-addressed integrity, artifact registration,
  runtime-facing discovery records, index behavior, descriptor/manifest support
  reads, and the ARS-owned read surfaces ES may later consume.
- The current ARS discovery record remains the canonical runtime-discoverable
  surface for the current slice. Descriptor/manifest support remains secondary
  publication detail, and the current index entry shape remains
  implementation-only/current-slice detail.
- `claims.package.identity` is the shared-kernel identity surface ES consumes;
  AGS-owned publication claims and ARS descriptor/manifest/index/support tuples
  do not become that identity surface.
- Payload identity and artifact identity remain separate:
  `payload_digest` identifies payload bytes or payload content identity, while
  `artifact_digest` identifies artifact/package identity as currently derived
  from `payload_digest`, `artifact_type`, and `intent_digest`.
- The current discovery/register JSON shapes are retained only as bounded
  slice rules, descriptor/manifest/index/support tuples are
  compatibility/support or implementation-only surfaces unless explicitly
  migrated, the secondary descriptor support path remains a temporary
  compatibility edge, and the long-term discovery/index/publication-support
  model remains reopened.
- ES must consume artifacts through a designed discoverability surface, not by
  inheriting ARS support tuple grammar as ES public grammar.
- CP examples and proof harness artifacts do not define AGS/ARS/ES core
  semantics; generated evidence, `.out`, support bundles, retained bundles,
  reports, traces, logs, summaries, and proof artifacts remain
  evidence/projection only.

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

- C0 is the docs and docs-contract-test gate for ES admission, prepare,
  submit, lifecycle projection, retained-result ownership, runtime-profile
  compatibility, runtime handoff, outcome evidence, runtime identity/workload
  credential handoff boundaries, and Control Plane compatibility.
- C0 makes no runtime implementation changes.
- Workstream C implementation must not start until C0 docs and docs-contract
  tests pass.
- C1 is the focused code-facing guardrail slice over the accepted C0 model.
  It adds or strengthens tests for bounded `:prepare` preflight non-effects,
  ARS discovery/evidence/payload/package-identity consumption, signed evidence
  and narrow execution/runtime claim enforcement, AGS/ARS support/CP grammar
  exclusion, payload-digest versus package-identity mismatch separation,
  current compatibility surfaces, and `authority_handoff`/`outcome_evidence`
  non-authority. It does not redesign runtime behavior.
- C2 is the focused tests/docs guardrail slice over the accepted submit and
  lifecycle-projection boundary. It pins `POST /v1/executions:submit` as the
  ES-owned async execution handoff through Nomad, keeps the submit receipt
  bounded and free of Control Plane attempt/review/checkpoint/finalization,
  intervention, approval, hold/resume/reject, Temporal, or workflow grammar,
  preserves `authority_handoff` as non-secret handoff evidence only, keeps
  `lifecycle_projection.source=nomad` with an opaque same-run
  read-coordination `revision`, preserves status/logs/result/cancel and
  `control-plane-normal-shell/v1` compatibility, and prevents generated
  evidence, reports, logs, support bundles, retained bundles, proof artifacts,
  and maintenance summaries from becoming authority. It does not redesign
  runtime behavior, retained results, runtime identity, Vault handoff, Nomad
  integration, or Control Plane behavior.
- C3 is the focused tests/docs guardrail slice for retained-result and
  `authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
  C3 pins that retained result bundles remain ES-owned opaque output artifacts
  and that CP may materialize, review, checkpoint, and finalize retained result
  contents semantically, but CP does not own the retained bundle as run-control
  state. Retained result references, paths, manifests, archives, `.out`
  copies, and materialized workspaces are evidence/projection or
  implementation detail, not orchestration authority.
  `GET /v1/executions/{run_id}/result` compatibility shape remains unchanged
  unless an explicit migration/versioning plan exists. `authority_handoff`
  remains bounded non-secret runtime handoff evidence only.
  `authority_handoff` never carries or implies live credentials, Vault tokens,
  Codex credentials, leases, approvals, operator authorization, CP workflow
  state, scheduler truth, or retained-result authority. Runtime identity/Vault
  handoff remains workload-side and non-secret; ES does not become a Vault
  token broker or Codex credential broker. `outcome_evidence` remains bounded
  evidence/projection; current labels remain compatibility surfaces.
  `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- C4 is the focused tests/docs guardrail slice for runtime identity and Vault
  handoff boundaries. C4 is guardrail work, not runtime redesign and not live
  helper execution. Runtime identity acquisition is workload-side or
  helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
  non-secret runtime identity and Vault configuration metadata, but ES must
  not mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES
  must not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies,
  private keys, API keys, proof secrets, root tokens, unseal keys, Vault client
  tokens, or secret payloads through public DTOs, lifecycle responses,
  retained-result metadata, summaries, logs, reports, `.out`, support bundles,
  or proof artifacts. `authority_handoff` may include non-secret
  credential-location and configuration metadata only. `authority_handoff`
  must not carry live credentials, leases, approvals, Vault tokens, Codex
  credentials, JWT-SVIDs, API keys, or scheduler truth. Workload-side Vault
  auth remains workload-side; Vault owns token, secret, and lease authority.
  SPIRE owns identity issuance and SVID material. ES must not expose raw SPIRE
  socket access to workloads as public ES grammar.
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the workload-facing identity
  endpoint contract rather than raw SPIRE socket access. Runtime identity and
  Vault handoff evidence remains non-authoritative and redacted. CP may
  consume runtime identity/Vault handoff evidence, but CP does not own
  credential acquisition, Vault tokens, SPIRE identity issuance, or ES runtime
  handoff boundaries. IM and Maintenance Agent may report
  diagnostics/readiness/status, but do not own runtime identity or Vault
  authority. `control-plane-normal-shell/v1` and
  `execution_substrate.runtime_profile` compatibility remain preserved unless
  an explicit migration/versioning plan exists. Existing workload-auth Remote
  Alpha helpers remain bounded operator/support surfaces, not ES token
  brokerage or production Vault readiness.
- C5 is the focused tests/docs guardrail slice for current
  status/logs/result/cancel compatibility and non-authority posture. C5 is
  guardrail work, not runtime redesign, live proof, or remote validation.
  Status remains Nomad-backed lifecycle projection and evidence, not CP
  workflow truth or ES lifecycle-store truth. Logs remain a bounded current
  compatibility/evidence surface, not final log architecture, CP run-control
  truth, or scheduler authority. Result remains opaque ES-retained output
  delivery, not CP checkpoint, finalization, or review state. Cancel remains a
  bounded ES/Nomad cancellation handoff, not CP intervention authority,
  operator approval authority, or Temporal workflow truth. Status/cancel JSON
  envelopes and successful logs/result headers must exclude CP run-control
  grammar and live credential/security fields; logs/result bodies remain
  payload/output surfaces governed by the existing compatibility contract and
  must not be newly sanitized, interpreted, or promoted into authority.
- C6 is the focused ES Admission Policy Layer v0 slice. It is a Workstream C
  admission extension, not the Workstream D CGS/EGS policy-language redesign.
  It adds a small ES-owned, replaceable policy-evaluation seam in the shared
  `:prepare`/`:submit` admission path and one built-in selected-pattern
  static-script content policy to prove the seam. ES remains the final
  admission-policy gate for ES-bound executions. Control Plane may later
  preflight or render ES policy decisions, but CP is not the final ES
  admission gate. IM remains readiness, provenance, and diagnostics only. C6
  may read bounded payload bytes during `:prepare` only when an enabled ES
  admission policy requires the ES-visible static-script text input class, and
  only through the explicit ARS payload digest relationship already discovered
  and cross-checked by ES admission. C6 must not add OPA/Rego, a DSL, customer
  regex configuration, CGS `id.conf` reuse, signed policy bundles, an external
  policy-decision service, durable policy-decision storage, CP prompt/workspace
  parsing, workspace archive decoding, binary payload inspection, retained
  bundle scanning, support-bundle scanning, or raw payload/matched-content
  disclosure.
- The C6 configurable-input follow-up is a bounded slice refinement of ES
  Admission Policy Layer v0. It may add ES deployment/admin configuration for
  inputs to built-in ES admission policies only. The follow-up adds the
  built-in
  `execution-substrate.admission.configured-static-script-literal-deny/v1`
  policy with reason code `configured_static_script_content_denied`, safe
  message `static script content denied by admission policy`, mode `disabled`
  or `enforce`, safe entry IDs, a bounded list of literal deny entries, and
  the fixed input class
  `static_script_payload_text`. These inputs are ES deployment/admin config
  only; CP does not define or supply them, IM remains readiness/provenance/
  diagnostics only, and request payloads cannot carry policy entries. This
  follow-up must not add evaluator injection, OPA/Rego, a DSL, arbitrary
  regex/glob/shell-expression config, customer-authored policy bundles, an
  external evaluator service, CGS `id.conf` reuse, user-defined reason codes,
  user-defined API messages, CP prompt/workspace parsing, workspace archive
  decoding, binary payload inspection, or raw configured-literal/matched-
  content disclosure. Denials remain redacted.
- The C6 workload-grant follow-up is part of Workstream F slice F1 and is
  not yet implemented: two built-in policies read exact-match owner grants
  from ES deployment/admin configuration, keep every absence listed for the
  configurable-input follow-up, and cannot be turned off. Their contract is
  section 5B of `.docs/execution_lifecycle/contracts.md`.
- C7 is a docs/static-test-only consolidation checkpoint recorded in
  `.docs/execution_lifecycle/workstream_c7_checkpoint.md`. It records that
  Workstream A/B gates are satisfied, C0-C6 are present, Remote Alpha
  operator-healthcheck TLS is paused/blocked due to source-insufficient
  signer/custody evidence, and next behavior-changing C work must preserve CP
  compatibility and CP/IM non-authority boundaries. It makes no behavior, API,
  route, runtime, TLS, CP diagnose, IM refresh, live proof, or route
  eligibility change.
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
  execution claims, EGS runtime-trust output, the configured workload-zone
  Vault runtime-config reference/blob, and the ES-owned Admission Policy Layer
  v0 seam.
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
- D1b is an accepted docs/tests-only slice on that seam: keep the current `POST /v1/credential/authorize` route and wire shape as CGS v1 compatibility, define any future CGS v2 authorize contract only at design level, and require explicit versioning before any behavior change lands.
- In D1b, a future versioned CGS authorization fact may carry only allow/deny, an opaque decision reference, and expiry or another bounded freshness indicator if justified. Any audit/evaluation metadata on that fact remains non-authoritative outside CGS.
- That future D1b design must not carry runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler facts, ES lifecycle/admission facts, runtime-config refs, workload-zone Vault ownership facts, identity-handoff facts, or Control Plane review/approval/checkpoint/finalization semantics.
- D1b keeps `id.conf` as current-CGS-v1 compatibility/config residue, does not rewrite its grammar or evaluation, and does not expand EGS beyond signer/artifact runtime-trust publication.
- D1c is an accepted docs/tests-only slice on that seam: keep the current `GET /v1/trust-model` route plus wrapper/payload shape as EGS v1 compatibility, define any future EGS versioned runtime-trust wrapper only at design level, and require explicit wrapper/payload/versioning before any semantic expansion lands.
- D1c keeps EGS v1 publishing signed `runtime_trust` signer/artifact trust only. EGS publication metadata remains outside the signed runtime-trust payload, and `publication.version` remains service-owned publication metadata rather than trust-contract/schema/API versioning.
- In D1c, a future versioned EGS trust wrapper must distinguish signed runtime-trust payload facts, unsigned publication/discovery metadata, compatibility routing or API version, and non-authoritative service metadata.
- That future D1c wrapper design must not carry CGS authorization decisions, Control Plane review/approval/checkpoint/finalization semantics, runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler truth, ES lifecycle/admission truth, runtime-config refs, workload-zone Vault ownership facts, runtime identity handoff facts, or AGS/ARS artifact-publication authority.
- D1c keeps ES consuming EGS only for signer/artifact runtime trust, keeps ES consuming no CGS facts, does not reopen the accepted Workstream A/B/C decisions, does not change the Workstream B AGS/ARS artifact publication/storage/discoverability decision or the Workstream C ES admission/runtime public model, and does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.
- D1d is an accepted docs/tests-only slice on that seam: keep checked-in `cgs/policy/id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` as current-CGS-v1 compatibility/config residue only.
- In D1d, `id.conf` is not a shared policy language, not an ES admission policy input, not an EGS trust input, not a Control Plane review/approval/checkpoint/finalization policy input, and not an Infrastructure Manager readiness/profile/support-bundle authority input.
- D1d keeps the current CGS v1 subject grammar local to current CGS v1 evaluation, keeps the checked-in `cgs/policy/id.conf` baseline as implementation/config residue rather than future product policy architecture, and keeps `policy.id_conf_path` as a CGS-local current-v1 configuration pointer rather than a repo-wide policy registry.
- D1d must not move `id.conf` into runtime-config ownership before Workstream E or fold it into runtime-identity handoff before Workstream F.
- Future policy-input redesign requires explicit Workstream D follow-up and, if it changes CGS semantics, a versioned CGS contract. D1d does not change CGS v1 authorize behavior, does not implement CGS v2, and does not change EGS, ES admission, Workstream E runtime-config ownership, or Workstream F runtime-identity handoff.
- Workstream D checkpoint: D0-D1d completed the guardrail/design phase. Workstream D remains open; the long-term CGS authorize DTO, future CGS/EGS versioned contracts, and long-term `id.conf`/policy-input model remain reopened seams.
- Those remaining D seams are non-blocking follow-ups for Workstream E planning. No D2 behavior-changing slice is required before Workstream E planning.
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

Current docs/tests-only decision status for E0:

- The Workstream E runtime-config ownership decision is recorded in
  `.docs/system_overview/runtime_config_ownership.md`.
- E0 is docs/tests-only. It does not change runtime behavior, public DTOs,
  route handlers, wire shapes, ES admission behavior, runtime identity handoff,
  Control Plane compatibility, Infrastructure Manager inputs, or M6
  support-bundle input shapes.
- Runtime-config semantics are owned by the runtime-config contract surface.
  The current typed shared schema for workload-zone Vault runtime config is
  `internal/contracts/runtimeconfig/v1`.
- ARS owns blob storage and read by digest only. ARS does not own
  workload-zone Vault runtime-config semantics.
- ES is the current runtime-config consumer and lookup orchestrator during
  `:prepare` and `:submit`.
- ES startup config currently carries the required workload-zone Vault
  runtime-config reference. That placement is compatibility/config residue on
  a reopened ownership seam, not the declared final owner.
- The startup guarantee remains: the required typed runtime-config reference
  must be configured and validated before ES serves governed execution traffic.
  This is a reference-availability guarantee, not a new E0 guarantee that the
  ARS blob has been fetched before startup completes.
- The digest-only ref shape is active as a temporary compatibility edge and
  bounded current surface, not final runtime-config architecture.
- There is no ACS hop in the runtime-config path.
- Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff.
- Optional workload-zone Vault CA trust material remains standard non-secret
  TLS/env-based trust configuration only.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority or live credential truth.
- E0 preserves `GET /v1/executions:contract`,
  `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP
  compatibility, and M6 support-bundle inputs.
- E0 keeps CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, EGS `publication.version`, EGS unsigned publication
  metadata, AGS `policy_decisions`, ES retained bundles, ES
  `outcome_evidence`, ES `authority_handoff`, IM profiles, support bundles,
  logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state outside runtime-config
  authority.
- E0 does not settle Workstream F runtime-identity handoff, does not reopen
  Workstreams A/B/C, does not mark full Workstream D complete, and does not
  mark full Workstream E complete.

Workstream E guardrail status:

- E0 and E1 are sufficient guardrails before Workstream F planning.
- Full Workstream E remains open for long-term runtime-config owner,
  reference/versioning, and `workload_vault_auth.default_mode` follow-ups.
- Later Workstream E work must not drift into runtime identity handoff,
  helper behavior, SPIRE/Vault handoff implementation, or Workstream F
  reserved-path decisions.

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
  - keep canonical supported-local host evidence under `.out/es-proof-<id>/`, private host bootstrap scratch outside the repository and evidence directory, and guest `/tmp` as internal Lima scratch when the repo mount is read-only
- That runtime narrowing is part of the claim-preserving slice boundary, not an accidental compatibility gap. If bounded implementation cannot preserve the helper-only SPIRE channel or the no-privilege-escalation workload launch model, stop and reopen only the runtime shape needed to keep ownership honest.

F0 - Runtime Identity Handoff Ownership Decision:

- F0 is docs/tests-only. It records the current runtime-identity handoff
  ownership model before any behavior-changing Workstream F implementation.
- The F0 decision is recorded in
  `.docs/system_overview/runtime_identity_handoff.md`.
- Runtime identity handoff is currently ES-selected and platform-delivered.
  ES owns handoff selection, env injection, reserved path layout, mounts, and
  Nomad job construction for the current slice.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- The runtime supervisor/helper owns the in-task endpoint implementation,
  helper-private SPIRE traversal, readiness-before-workload, and
  root-to-workload privilege boundary for the current implementation.
- SPIRE owns JWT-SVID issuance. Vault owns token, secret, and lease issuance
  after workload-side login.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces
  are bounded or compatibility-heavy, not final generalized architecture.
- Capability validation remains behavior-based and local to validation
  boundaries, not based on accidental DTO/path coupling.
- F0 does not change runtime-config ownership from E0/E1, does not consume or
  promote D seams, does not change CP compatibility or
  `control-plane-normal-shell/v1`, and does not change M6 support-bundle
  inputs.
- F0 keeps CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, runtime-config refs, `authority_handoff.runtime_config_refs`,
  ARS blob mechanics, digest-only runtime-config refs,
  `workload_vault_auth.default_mode`, ES retained bundles,
  `outcome_evidence`, `authority_handoff`, IM profiles, support bundles,
  logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state outside runtime-identity and
  credential authority.
- F0 does not reopen Workstreams A/B/C, does not mark full Workstream D
  complete, does not mark full Workstream E complete, and does not mark full
  Workstream F complete.
- Full Workstream F remains open for long-term runtime-identity owner,
  helper/root/task-user, SPIRE selector/traversal, reserved-path, and
  workload-credential handoff follow-ups.
- F0 does not claim full ES/runtime de-root, rootless Nomad client,
  production readiness, production Vault readiness, or generalized remote
  deployment architecture.

F1 - Named Workload Identities And Workload Grants:

- F1 is the next behavior-changing Workstream F slice, approved by the project
  owner and not yet implemented. The decision is section 11 of
  `.docs/system_overview/runtime_identity_handoff.md`; the workload grants it
  adds to C6 are section 5B of `.docs/execution_lifecycle/contracts.md`.
- It closes two gaps that existed before F1: every workload run shared one
  SPIFFE ID and one Vault role, so any workload could read any other
  workload's secrets; and the publisher's signed `network_access` alone
  decided network access.
- Identity: one identity per named workload,
  `spiffe://execution.internal/workload/<name>`, with its own SPIRE entry
  (Docker label selector plus `unix:uid:0`) and its own Vault role and policy.
  The entry that gives `spiffe://execution.internal/workload` to every root
  process on the host is removed. ES picks the name from owner grant rules and
  holds no SPIRE or Vault administrative access; publishers request no name.
- Network: `network_access=true` also needs an owner grant naming an egress
  lane. Until lanes land, the only lane is `unrestricted`, a `Temporary
  compatibility edge` that readiness reports as
  `workload_egress_unrestricted=true`; its removal condition is WI-4.
- Workload identities are never callers, a run without an identity grant
  gets no identity handoff, admission decides in names only, and runtime
  realization alone maps names to Nomad and Docker values.
  `workload/<name>/run/<run_id>` is reserved so per-run identities can be
  added later without removing code.
- Delivery, one pull request each: WI-1 docs and contracts; WI-2 network
  grants; WI-3a caller refusal; WI-3 named identities; WI-4 egress lanes;
  WI-5 the durable format revision, before D3 makes those formats live state.
- F1 keeps `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, the root-start helper, the Nomad
  task user `0:0`, the fixed `10000:10000` workload user, helper-private SPIRE
  traversal and ES's no-brokering rule. It does not mark full Workstream F
  complete.

Dependencies:

- Workstream C
- Workstream D
- Workstream E

## Remote Alpha Hardening History and Current Retirement

`Temporary compatibility edge`: archived v1 evidence records an earlier Remote
Supported-Host Alpha hardening exercise. It is historical evidence only and is
not current host truth, readiness, migration authority, or permission to reuse
an old or nonempty host. Current ES-owned existing-host writable-state,
service-user, ownership, staging, rollback-generation, and old-root-planning
routes are retired through fixed fail-closed tombstones. No v2 replacement is
defined for that retired ES writable-state/service-user migration family. The
unrelated current EGS hardening v2 schema remains current.

- AGS is already de-rooted and sealed in this tranche; preserve the landed
  `ags:ags` service posture and its existing host-local summary/evidence shape.
- ARS is already de-rooted in this tranche; preserve the landed `ars:ars`
  service posture, its dedicated TLS/state ownership model, and its existing
  host-local summary/evidence shape.
- EGS is already de-rooted in this tranche; preserve the landed `egs:egs`
  service posture and its existing host-local summary/evidence shape.
- ES config/TLS prep is applied and productized for the live host.
- Archived v1 files may record that an earlier host had prepared ES writable
  roots, ran `es.service` as `User=es`, `Group=es`, `UMask=0027`, and passed
  bounded checks. Those records do not establish current state, readiness, or
  apply authority and cannot be refreshed by the retired routes.
- This tranche does not claim full ES/runtime de-root.
- The root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad root selector posture, and Vault/workload-zone
  handoff remain bounded compatibility edges. Workstream F slice F1 removes
  the broad root selector posture and the one shared Vault role with WI-3; it
  keeps the other three.
- The long-lived ES startup path keeps
  `execution.spire_workload_api_socket_path` as a config-shape and submit
  input only; runtime-helper failure to use that helper-private raw SPIRE path
  remains explicit and fail closed. The retired helpers no longer prove that
  host dependency.
- Old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by inertia.
- The former old-root cleanup/archive planner is retired. Archived summaries
  cannot authorize archive, deletion, ownership change, drain, fence, or any
  other host mutation.
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
- This tranche may carry one disposable Remote Alpha Vault reset/rebootstrap
  operator script for the sealed-and-unrecoverable Shamir-key case. That script
  must stay dry-run by default, require an interactive TTY plus the exact
  destructive confirmation phrase before reset, move the existing Vault raft
  path to a timestamped backup rather than deleting it, run Vault init/unseal
  only in the operator's interactive terminal, and never persist or relay
  unseal keys, root tokens, client tokens, TLS private keys, SPIFFE material,
  API keys, or raw prompts. It is a bounded Alpha recovery helper only; it is
  not IM automation, Vault production lifecycle, CP/ES proof, submit
  readiness, runtime-profile readiness, or a broader deployment architecture.
  The same helper may provide a non-destructive `--unseal-only` path for the
  case where the operator still has the Shamir unseal key; that mode must not
  move storage or run Vault init, and must still require an interactive TTY and
  interactive `vault operator unseal` with no key material on the command line.
- This tranche is bounded host/service hardening only. Do not widen it into a
  runtime-boundary redesign or broader proof expansion.

## Milestone 1: Least-Privilege Runtime/Security Boundary Closeout

`Bounded slice rule`: Milestone 1 is named `least-privilege runtime/security
boundary closeout`.

Archived v1 evidence records a prior long-lived `es.service` service-user
change to `User=es`, `Group=es`, `UMask=0027`. That historical record is not a
current invariant, current readiness proof, or migration authority.

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
| SPIRE raw-socket traversal and selector posture | `accepted MVP compatibility edge` | The workload-visible contract is already narrowed to `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, but the helper-private raw SPIRE path and the broad root selector scope remain explicit compatibility edges rather than a finished least-privilege identity model. | Slice `1A`/`1B` proof, runtime-helper source and tests that keep the raw SPIRE path out of workload env, and the remote runtime-identity helper summary preserve the helper-private boundary. Retired existing-host migration artifacts are historical evidence only and are not current boundary proof. | Revisit only through the later runtime-boundary redesign seam after a narrower helper principal or equivalent traversal model is documented and re-proved. Workstream F slice F1 removes the broad root selector scope with WI-3 and keeps the helper-private raw SPIRE path. | Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege. |
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
governed execution proof claims. The same evidence surface may record
non-secret host/runtime/CVE inventory fields, including kernel and package
versions, Docker/Nomad runtime chain observations, FUSE/fuse-overlayfs,
Podman/crun, idmapped or `mount_setattr` path observations, and
vendor-observed CVE readiness classifications for CVE-2026-31431 and
CVE-2026-31465. CVE readiness classifications are `fixed`, `vulnerable`,
`not_affected`, `mitigated_not_fixed`, or `unknown`. For CVE-2026-31431,
`mitigated_not_fixed` may only mean vendor/package evidence still reports a
vulnerable host while non-mutating local evidence shows `algif_aead` is not
loaded and modprobe policy blocks autoload. That state is not a kernel patch,
not proof of production safety, and remains a blocker unless the checker is
run with an explicit bounded internal Remote Alpha mitigation-risk acceptance
flag.
Those fields remain evidence/projection only: they are not service health,
submit readiness, runtime-profile readiness, governed execution proof, full
ES/runtime de-root, rootless Nomad client proof, support bundle authority, or
CVE patch authority. Direct vendor status observation is evidence for CVE
classification only.

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

## Current Remote Alpha Host Network Boundary Slice

`Bounded slice rule`: Remote Supported-Host Alpha may carry one operator-run
host firewall for the box on the home network, defined in the section
"Remote Alpha Host Firewall" of
`.docs/system_overview/remote_supported_host_alpha.md`. It closes findings
INF-01 (containers reach the home LAN), INF-13 (ES and AGS listeners open to
the whole LAN) and INF-23 (SSH password login from everywhere, SSH on public
IPv6) of the 2026-11-23 infrastructure audit, as a short-term bridge until
the named workload identities, network grants and egress lanes of
Workstream F slice F1 land.

- Scripts: `scripts/remote_alpha_host_firewall.sh`,
  `scripts/internal/remote_alpha_host_firewall.sh` and
  `scripts/internal/remote_alpha_host_firewall.py`. Modes `--plan`
  (default, read-only), `--apply`, `--confirm`, `--status`, `--probe`,
  `--rollback`, `--render`.
- It owns only the nftables tables `inet es_host_firewall` and
  `bridge es_host_firewall`, its files under
  `/etc/execution-substrate/host-firewall`, the unit
  `es-host-firewall.service`, the sshd drop-in
  `/etc/ssh/sshd_config.d/00-execution-substrate-host-access.conf` and a
  transient rollback timer. It never touches Docker's, ufw's or other rules,
  other sshd files, Vault, Nomad or ES, and reads no secrets.
- One chain in its own table keeps the box's own connections to Vault on the
  bridge address as their source (an identity snat ahead of Docker's
  masquerade rule), so the Vault role's bridge-subnet limit sees the box as
  the bridge address and not as its LAN address. It is the ruleset's only
  address rewrite.
- The operator's choices live in the root-owned settings file
  `/etc/execution-substrate/host-firewall/settings.env`; adding a device that
  may call ES and AGS is a one-line change there.
- `--apply` arms an automatic rollback that only `--confirm` from an SSH
  connection opened after `--apply` cancels.
- Validation: rendering against a golden ruleset, real-kernel tests in
  network namespaces, a real-sshd test of the drop-in, fakes for the
  apply/confirm/rollback order, and a container probe on the box.
- Workstream F slice F1 builds on this firewall rather than replacing it.
  Until WI-4, the only egress lane is `unrestricted`, which is the current
  `bridge` network under this firewall. WI-4 keeps the firewall as the second
  wall under egress lanes: lane networks get its rules, and each workload
  Vault role's bound CIDRs cover the lane subnets.

`Bounded slice rule`: the same tranche refines the P0q workload-auth
bootstrap helper (INF-04, INF-05, and the root-token half of INF-06):

- role `service_execution` gets `token_ttl` (default `15m`),
  `token_max_ttl` (default `30m`) and `token_bound_cidrs` (default
  `172.17.0.0/16`), validated before any prompt;
- every earlier version and the metadata of both proof paths are deleted
  before the new value is written;
- `REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key` replaces a standing root
  token: the helper makes a root token from the single unseal key share,
  uses it once for a 15-minute orphan token, revokes it with the next
  request, and revokes the 15-minute token before it exits; SIGINT,
  SIGTERM, SIGHUP and SIGQUIT wait until the root token is revoked and
  Vault's configuration is back, and Ctrl-Z (SIGTSTP, SIGTTIN, SIGTTOU)
  takes effect only then; core dumps are off before anything is read;
- `REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config` adds
  `enable_unauthenticated_access = ["generate-root"]` to Vault's
  configuration only for the generate-root step and puts the file back byte
  for byte through a reload (Vault 2.x refuses unauthenticated generate-root
  by default), after the root token is revoked; it refuses a Vault that
  allows generate-root without the file saying so;
- with the 15-minute token, the helper counts root tokens that never
  expire, and `REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke` revokes
  them, which is how a run killed by SIGKILL or a power loss is cleaned up;
- `REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate` writes a random value nobody
  sees, which discards the Codex key.

Its validation adds one test against a real local Vault server (raft, TLS,
one key share; CI installs Vault 2.2.2). It still runs no live box, SSH or
sudo. These refinements do not make ES a Vault token broker and do not
change ES public contracts.

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

### Workstream C admission and custody rules

The standing Workstream C admission, material, custody, proof and
startup-probe rules, with the outside-observer Stage A slice and the
reliable-submit tranche status, are in
[`.docs/standing_rules/execution_admission_and_custody.md`](.docs/standing_rules/execution_admission_and_custody.md).

### Current paired-root custody and acceptance scope

**Superseded CUST-1/CUST-2 gate history.** The earlier final-audit sequence
allowed repository implementation and local validation before a running-
deployment topology observation, then treated that observation, repaired-helper
mounted fixtures, sequential native Linux lanes, and a fresh audit as blanket
pre-commit gates. That pre-integration linkage is not a current local commit
rule. The accepted predecessor tree supplied source evidence for the
then-current-base candidate, which at that gate remained uncommitted and
pending independent audit. That historical source gate closed with PR #8;
its source publication did not close operating gates. Focused changed-interaction
assessment, validation, and separately authorized commit were required there.
C's selected native observations remain historical evidence
for exact C source and command identities, not executions of this tree. Any
new bounded witness must be selected for a concrete changed interaction rather
than inferred from merge ancestry. Operational topology, key exposure,
capacity, residence, reclamation, and publication gates remain open for their
operational scope; none is waived by local source work. The one-time WIP
checkpoint exception is consumed and supplies no authority here.

**Current invariant — staging non-mutation and retained-output independence.**
Result retention, publication, and read do not mutate a claimed staging root;
result-side proof supplies no independent deletion or existing-object repair
authority.

**Bounded slice rule pending integrated review — paired-root qualification.**
`execution.staging_root_dir` and `execution.results_root_dir` form one
operation-local qualified root set. Lexical absolute/non-overlap validation is
an early shape check, not physical proof. Before submit-enabled startup
provisioning, Submit run-root claim, or current retained-result directory
creation, new-object initialization, no-replace publication, and authenticated
read/check, ES qualifies both configured paths component-by-component without
symlink traversal and proves that they are neither the same backing object nor
ancestor and descendant in either direction. Every named result operation uses
the descriptor-held root that participated in a fresh visible-object and
topology proof; ES does not validate one pathname and reopen an unrelated
pathname for the operation. Pair proof is a prerequisite, not deletion or
repair authority. Existing result directories, finals, and normalization
evidence are validated without metadata repair or adoption.

Linux binds each held descriptor to `fstat`, a complete
`statx(AT_EMPTY_PATH)` identity including `STATX_MNT_ID`, a no-follow rewalk of
its `/proc/self/fd` canonical presentation, and the uniquely selected record
from a stable, at-most-8-MiB/65,536-record `/proc/self/mountinfo` acquisition.
Mountinfo record integrity is separate from root-coordinate eligibility. Every
bounded record retains its filesystem type, absolute component-clean
mountpoint, parent/stack relationships, and classified root value. Ordinary
canonical pathname roots are coordinate-eligible. An `nsfs` root with the
source-grounded namespace-object envelope `<kind>:[<canonical decimal inode>]`
is retained as opaque, where `<kind>` is exactly `mnt`, `net`, `uts`, `ipc`,
`pid`, `user`, `cgroup`, or `time`; the decimal label is structurally checked
but not numerically interpreted or given a separate ES width limit.
`pid_for_children` and `time_for_children` are not root kinds because the
kernel's namespace-object rendering uses their canonical `pid` and `time`
operations. Malformed `nsfs` labels and every other non-path root class reject.
Opaque records still count toward byte/record limits, ID and parent/cycle
integrity, stacking, and canonical descendant-mount checks. If descriptor
selection names an opaque record, proof refuses before device shortcuts,
coordinate arithmetic, or any governed effect; ES never prefixes `/`, joins,
cleans, substitutes the mountpoint for, or otherwise converts that label into
a directory coordinate. This recognition does not make `nsfs` a supported
configured execution-root filesystem.
Source coordinates derive from the selected record and canonical descriptor
presentation, never configured spelling. Equal or component-prefix
coordinates reject; component-disjoint coordinates, including provable sibling
bind sources, are accepted. The parser permits one unambiguous `/` top-of-tree
self-parent terminal and parents hidden outside the process view, while
rejecting duplicate IDs, nontrivial cycles, non-top self-parent records,
malformed escapes, incomplete identity masks, device disagreement, unstable
snapshots, ambiguity, and canonical descendant mounts. Darwin binds
`F_GETPATH`, no-follow descriptor identity, `fstatfs`, and bounded `getfsstat`;
same-FSID distinct presentations remain unprovable and reject. Neither platform
uses OS-label branching or a fallback proof.

Missing suffixes are validated intent, not canonical objects. A first absent
component must be observed as `ENOENT`. Two missing roots under the same
deepest existing object, or otherwise dependent on comparing unobserved names
in one lookup context, reject; canonically disjoint existing parents may
proceed. Startup plans without mutation, provisions one descriptor-relative
component at a time, and reacquires the pair after every component before any
later effect. Submit acquires after freeze and reobserves immediately before
the exclusive staging claim. Retained reads may serve an existing bundle when
staging or its run is absent, but never provision a missing results root and
never turn a topology failure into Nomad fallback. Result-side operations use
a fresh pair at each current named directory creation, new-object metadata
initialization, temporary creation, final/record publication, and authenticated
read/check boundary; bytes streamed through an already-held descriptor do not
rescan topology. New unpublished result temporaries/records and newly created
normalization evidence may receive their selected owner and mode through
`Fchown`/`Fchmod`. Existing objects are checked without metadata mutation or
adoption. Incomplete leaves, uncertain unpublished temporaries, and startup
probe fixtures remain retained where exact-object cleanup ownership is
unproved. No result pathname cleanup or whole-root reclamation is selected.

The mount-archive namespace validator uses one invocation-local iterative
compressed byte-radix ledger. Labels are substring views into retained
normalized entry names, branching is byte-keyed, ancestry is recognized only
at `/` boundaries, and commit follows all fallible per-entry work. It retains
existing namespace/error precedence and the 16/64-MiB complete decompressed-
stream budgets without adding an ES name or entry cap. Reachable PAX/GNU and
32,768-header EOF cases exercise production probe/commit counters. The pinned
`archive/tar` implementation's 1-MiB hidden special-file processing ceiling is
dependency behavior, not an ES resolved-name or entry-count policy.

**App-fixture migration and local revalidation scope.** The positive app
integration stack closes its test-fixture `Temporary compatibility edge` by
exclusively creating exactly two independent, empty execution-root directories
before `esapp.New`. Regression coverage must prove their configured paths,
directory type, distinct filesystem identity, current test-owner identity,
expected mode, and emptiness. This is a fixture refinement that aligns positive
integration paths with the dual-root `Current invariant` and active `Bounded
slice rule`; it does not relax dual-missing rejection, pre-create a run object,
or change production admission, provisioning, custody, or capability behavior.
The correction is confined to the shared constructor in
`es/app/submit_integration_test.go`; pre-edit inventory found no identical
direct-construction defect in another app test.

The corresponding external validation runner must use short, unique,
mode-`0700` lane scratch roots under `/private/tmp` and preserve the inherited
umask. This removes runner-created Unix-socket pathname inflation without
changing `TestProofCodexShimAcquiresCredentialAndMutatesWorkspace` or widening
its capability skip. Passing local app, admission, default, physical-temp, and race lanes does not
qualify an operational deployment or turn C's historical native observations
into integrated-source execution. Running-deployment topology, key exposure,
capacity, residence, reclamation, publication, and claimed-architecture native
witnesses remain operational gates. A new integrated-source bounded witness is
selected only for a concrete changed interaction; these gates do not
collectively become a blanket local pre-commit requirement.

**CUST-2 nsfs assurance continuation.** The current continuation is a bounded
test-assurance refinement only: it may align the explicit Linux post-freeze
semantic-call ledger with the already documented nsfs implementation and may
replace the proof-Codex test's caller-temp-derived Unix-socket path with a
unique, owner-only, test-owned short physical fixture beneath `/tmp`.
Production nsfs behavior, capability policy, lifecycle contracts, credential
flow assertions, and all external gates remain unchanged. Allocation and
listener failures in that required local test fail rather than masquerade as a
capability skip. After a single freeze, validation remains ordered local
default, local physical-temp, local race, native linux/amd64, then native
linux/arm64. One distinct successor generation is allowed only after closing
and preserving a causally demonstrated defect confined to the authorized test
expectation, socket fixture, or minimal validation plumbing; at most two final
generations may run, unchanged failures are never retried, and no earlier pass
is credited to changed bytes. This continuation does not pass or waive the
running-deployment observation, mounted-topology fixtures, supported-local
consumer/operator proof, fresh independent audit, or exact-byte publication
authority.

This foundation does not select or implement canonical effective-plan
encoding, `PlanBinding`, a complete effective-plan witness, durable material or
replay-envelope custody, host-context replay treatment, mutable image-content
identity, state-path configuration, TTL, public reliable-submit vocabulary,
HTTP or recovery routes, Nomad ambiguity reconciliation, reliable dispatch,
Coordinator integration, or cross-repository behavior. It must not synthesize
`PrepareRequest` or `Manifest` proof from the plan, create a parallel admission
engine, change environment or mount admission (which the shared admission
path owns, `.docs/execution_lifecycle/contracts.md`, section 5), or
infer authority-handoff inapplicability contrary to current `Submit` behavior.

The `reliable-submit-durable-same-operation-replay-repair` source tranche is
implemented inside the private durable source and remains required before
reliable-submit config/store lifecycle wiring, producer enablement, or public
runtime enablement. The committed private durable service now derives a
latest-operation descriptor, recognizes the current latest committed mutation
before stale-revision and inactive-state refusal, returns exact replay for same
mutation plus same operation kind/input binding, returns mutation conflict for
same-mutation/different-kind-or-binding reuse, reloads CAS losers through the
same classification, and keeps COMMIT-unknown recovery on stricter full-record
equality including the descriptor. SQLite schema v2 persists the descriptor for
codec-2 rows and preserves migrated v1 rows as legacy/unbound without inventing
operation semantics. Historical mutation retention remains out of scope, and
the private store remains runtime-unwired, so this repair does not affect
current public execution behavior.

Reliable dispatch remains blocked until later implementation and audit. Both
caller-to-ES response loss and ES-to-Nomad registration-response uncertainty
are in scope for the target contract. The target must prevent duplicate
semantic execution from transport redelivery while preserving the current
no-key submit compatibility path, `control-plane-normal-shell/v1`, Nomad
lifecycle authority, and the prohibition on a broad ES lifecycle store.

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

### Remote Alpha access contract v1 — Tranche A

`Reopened redesign seam`: ES has no implemented Remote Alpha access-profile
validator, access-status schema, or fixed identity-only access route at this
baseline. This tranche freezes only the ES-owned schema envelope, role and
authority split, fail-closed safety intent, fixed identity-check boundary,
access-status state matrix, redaction, and scheduling prohibition in
`.docs/system_overview/remote_alpha_access_contract.md` and its repository
contract test. It does not deliver an executable validator, route, profile
store, key, known-hosts pin, or scheduled check. The v1 schema names are
`es.remote-alpha.access-profile/v1` and
`es.remote-alpha.access-status/v1`.

`Reopened redesign seam`: Tranche B must first freeze the supported OpenSSH
directive grammar, Include closure and precedence, system-configuration
interaction, accepted local filesystem roots and modes, component symlink
policy, agent/Keychain/certificate interpretation, and safe optional
directives in governing documentation and fake/static contract tests before
implementing a validator. Tranche A does not claim that any current local
profile or operator alias conforms to that still-open static subset.

`Temporary compatibility edge`: the operator-owned
`host_to_remote_linux_m75q` alias and the existing operator routes' explicit
`--ssh-target` arguments remain unchanged. The P0s
`es-service-tls-status` and P0t `es-governance-tls-status` names are
interactive status-only compatibility edges using the one dedicated
collector; both renewal counterparts are held before contact. P0v remains a
separate TLS-specific noninteractive status route. None is the new access
check or an authority for its SSH profile semantics.

Tranche A fixes the target separation between operator and monitor profiles,
contact-free static validation intent, fail-closed public-key-only transport,
a future fixed nonroot UID/account observation, safe versioned evidence, and
`scheduled_execution_allowed=false` as a producer-owned v1 constant. The
maintenance-monitor `monitor-eligible` classification below does not
authorize scheduled SSH.
Neither a local profile, `ready` evidence, MA configuration, IM readiness,
foreground SSH success, nor the operator alias can enable it. Changing
scheduled eligibility requires a later explicit ES/MA route decision,
scheduled-context acceptance, a versioned contract change, separate
implementation, host provisioning, validation, and audit.

Subsequent authority decisions remain separate: B first freezes its open
implementation-contract decisions, then implements and fake-tests the ES
validator/check-only route; C provisions local/host access material
under separate sensitive-effect authorization if needed; D lets Maintenance
Agent consume evidence and only later schedule an expressly eligible route;
E migrates Infrastructure Manager's access interpretation while preserving
its current readiness/provenance/diagnostic ownership. No MA or IM contract is
changed in Tranche A. Public-key SSH does not supply sudo authentication.
Access evidence cannot repair the contained ES-to-EGS TLS certificate-validity
failure, establish service health, or prove governed execution.

The operator-authorized operator-healthcheck TLS replacement design tranche is
also docs/static-test only. It records an ES-owned future replacement path in
`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`
with signing/custody hardening in
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`
and an IM-owned profile-lineage refresh counterpart in the Infrastructure
Manager repo. It is not a P0v route implementation, not renewal execution, not
Bridge or Maintenance Agent authority, not CP diagnose execution, and not
profile mutation. It preserves `operator-healthcheck-tls-renew` as
blocked/status-only with `unsupported_signing_topology` because signing
authority, signer custody, key custody, CSR/cert flow, backup/rollback
evidence, redaction, and post-check semantics remain ES unresolved stop
conditions for the `spiffe://execution.internal/operator/local` operator
identity.

The Remote Alpha external TLS single-use incident is a `Bounded slice rule`
recorded in
`.docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md`.
Report-derived evidence indicates certificate-validity failures; a future
read-only inventory must establish the installed prior state. This is docs-only
authority for one proof/support host, incident, and execution. It adds no
executable route or ongoing support, and reusable P0u renewal remains blocked
with `unsupported_signing_topology`. Its default is
`RETIRE_BEFORE_LEAF_EXPIRY`. Inventory, private packet and rollback derivation,
independent audit, foreground execution, any later IM handoff, and terminal
closure remain separate; closure must remove or convert the active entry,
authorization document, incident tests, and P0u cross-references.

The Remote Alpha maintenance-monitor contract alignment slice is docs/static
contract work only. It may codify a future Mac-side maintenance project as a
scheduler, notifier, local-evidence summarizer, and allowlisted ES-command
invoker, but it must not implement that project or create a new repository in
this slice. ES keeps ownership of every Remote Alpha status, renewal, repair,
and route-contract semantic. External schedulers may invoke only documented
allowlisted ES commands and may not define their meaning, infer renewal
eligibility, broaden helper scope, or become ES runtime authority, IM
readiness/provenance authority, CP run-control authority, a hidden remote
reconciler, or broad provisioning automation. Remote Alpha remains bounded
proof/support posture only.

Remote Alpha maintenance route eligibility is fixed for this planning slice:
`es-service-tls-status`, `es-governance-tls-status`,
`operator-healthcheck-tls-status`, binary deployment check, workload-auth
check, and runtime identity summary are read-only monitor-eligible;
`es-service-tls-renew` and `es-governance-tls-renew` are held and have no
monitor or scheduled eligibility until a separate route-specific design, tests,
audit, authorization, and repair contract exist;
`operator-healthcheck-tls-renew` remains blocked/status-only until a signing
topology and operator/local identity renewal authority are documented; binary
deployment apply and workload-auth bootstrap are not monitor auto-renewal
routes.
