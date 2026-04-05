# Execution Lifecycle Implementation

## 1. Purpose and status

This document describes the current ES lifecycle implementation during an active redesign phase.

The current implementation slice is real, exercised by integration tests, and visible directly in the ES Go packages. Public contract semantics live in `.docs/execution_lifecycle/contracts.md`. Lifecycle design and authority boundaries live in `.docs/execution_lifecycle/design.md` and the system overview docs.

This file is specifically about where lifecycle behavior lives in code today: handlers, wiring, call paths, local side effects, and where Nomad becomes authoritative.

## 2. How to read this document

- **Observed current implementation path**: A code path or sequencing rule implemented in the current Go repo.
- **Implementation invariant**: A stable implementation fact future agents must preserve unless they intentionally change the lifecycle slice.
- **Current simplification**: A real implementation shortcut or narrowing choice in the current slice that should not be mistaken for long-term architecture by default.
- **Deliberate absence**: Behavior ES does not currently implement.
- **Reopened implementation seam**: A live implementation seam that the redesign phase keeps open.

These labels matter because implementation shape and public contract are related but not identical.

## 3. Implementation module map

| Module | What it owns | What it does not own | Why it matters to the lifecycle slice |
| --- | --- | --- | --- |
| `es/api/server.go` | HTTP route registration, caller authorization, request decoding, lifecycle path parsing, HTTP error shaping, handler-to-service dispatch | Admission logic, Nomad interaction, lifecycle state | This is where public lifecycle requests first enter ES |
| `es/app/app.go` | App construction, service/server assembly, TLS HTTP server startup/shutdown, startup initialization sequencing | Admission rules, submit logic, lifecycle projection logic | This is the lifecycle slice's top-level wiring entrypoint |
| `es/admission/service.go` | Core service construction, dependency clients, verifier setup, runtime-trust initialization, health snapshot, `Prepare` path, shared fetch/verify helpers | Nomad job construction, logs/cancel projection, runtime token ownership | This is the main admission implementation hub |
| `es/admission/executionpackage.go` | Run-scoped staging layout, container-visible runtime layout, payload staging, and shared mount-spec/wrapper assembly inputs | Artifact verification, lifecycle projection, public DTOs | This localizes the current submit-side package-resolution and staging conventions |
| `es/admission/submit.go` | `Submit`, execution-locator creation, payload fetch, runtime environment assembly, Nomad job spec assembly, Nomad job submission | Lifecycle projection after submission, persistent run ownership | This is where ES crosses from preparation into real execution handoff |
| `es/admission/lifecycle.go` | `Status`, `Logs`, `Cancel`, internal execution-locator resolution, Nomad lookup helpers, projected-allocation policy use | Any ES-owned lifecycle store, retry orchestration, allocation aggregation | This is the post-submit lifecycle projection path |
| `es/admission/runtimeidentity.go` | Reserved runtime path definitions, endpoint env conventions, run-scoped endpoint derivation, overlap validation | Endpoint implementation, token minting, token population | This is the boundary guardrail for runtime-identity handoff |
| `es/admission/mounts.go` | Runtime mount request validation, mount artifact revalidation, mount staging and archive extraction inside the run-scoped execution-package layout | General artifact publication, lifecycle state | This is where mount side effects and mount-specific trust checks live |

Related support files:

- `es/admission/types.go` carries the current request/result/data structs used across prepare, submit, and lifecycle paths.
- `es/api/types.go` currently carries the health response shape rather than lifecycle endpoint payloads.

## 4. Handler-to-service flow

**Observed current implementation path**

- `Server.Handler()` in `es/api/server.go` builds the HTTP mux.
- The mux is wrapped with `observability.WrapHandler("execution", mux)` before serving.
- Route entrypoints are:
  - `handlePrepare -> service.Prepare`
  - `handleSubmit -> service.Submit`
  - `handleLifecycleGet -> service.Status` or `service.Logs`
  - `handleLifecyclePost -> service.Cancel`

Where behavior lives:

- Request decoding for `:prepare` and `:submit` happens in `decodeAuthorizedExecutionRequest`.
- Caller authorization happens in `authorizeExecutionCaller`.
- Lifecycle path parsing for `status`, `logs`, and `cancel` happens in `parseLifecycleRequest`.
- JSON error shaping happens in `writeJSON`.
- Authorization failures use `writeText`.

**Implementation invariants**

- Authorization runs before body decode for execution endpoints.
- Lifecycle GET/POST handlers authorize first, then parse the path, then delegate to the admission service.
- HTTP handlers do not own business logic beyond auth, decode, parse, and response shaping.

Observability placement:

- Inbound request wrapping is applied once at the handler layer.
- Outbound dependency logging is applied when dependency clients are constructed in the admission layer.
- Integration tests confirm trace propagation across ES -> ARS health calls and confirm that edge logging remains separate from business-logic logging.

## 5. Application wiring

`es/app/app.go` is the top-level assembly point.

**Observed current implementation path**

- `app.New` validates config, constructs `admission.Service`, constructs the API server, and builds the TLS HTTP server.
- `App.Start` calls `service.Initialize(ctx)` before the HTTP listener starts serving.
- `service.Initialize` fetches the signed runtime-trust payload from EGS, canonicalizes it, verifies its signature, normalizes it, and caches it in memory.
- `service.Health` checks ARS readiness and combines that check with the cached trust-policy-loaded state.

Dependency wiring:

- `admission.NewService` builds dependency clients for ARS and EGS and captures the validated workload-zone Vault config reference from ES startup config.
- It also builds verifier instances for:
  - TrustModel
  - provenance
  - derivation attestation
  - workload identity binding
- It creates the Nomad client only when submit is configured.
- If submit is configured, it creates the local staging root on startup.

**Implementation invariants**

- ES does not start serving until runtime-trust initialization succeeds.
- ES does not start serving unless `runtime_config.workload_zone_vault_config_ref` validates at startup.
- Readiness after startup depends on:
  - app `started`
  - trust model loaded
  - ARS ready
- Live EGS reachability is not treated as a post-start runtime readiness dependency in the current implementation.
- ES `/health` remains admission-oriented only; the operator bring-up/check path now layers workload-zone Vault runtime-config verification and, for the full profile, ES submit-config, Docker, and Nomad checks on top before declaring submit readiness.

What the app layer delegates:

- App wiring owns process assembly, not lifecycle decisions.
- All request-path lifecycle behavior is delegated into the admission service.

## 6. Prepare path implementation

`Prepare` is implemented in `es/admission/service.go` and is an active code path today.

**Observed current implementation path**

1. Validate the request with `validatePrepareRequest`.
2. Read the currently loaded runtime-trust policy from memory.
3. Read the artifact discovery record from ARS and follow it to the aggregate artifact-evidence blob.
4. Validate the discovery/evidence relationship, verify the evidence seal over the nested evidence claims, enforce EGS runtime-trust signer and artifact policy, cross-check package identity from `claims.package`, cross-check request derivation inputs from the narrow shared `claims.admission.authorization.derivation` surface, and derive only the remaining shared runtime inputs from `claims.admission.execution`: env allowlist, required capabilities, `target_platform`, and `network_access`.
5. Read the workload-zone Vault config reference captured from validated ES startup config.
6. Fetch the workload-zone Vault config blob from ARS using that reference.
7. Decode and validate the workload-zone Vault blob through `contracts/runtimeconfig/v1`, then resolve the workload-vault auth plan from that typed config plus ES `workload_vault_auth.default_mode`.
8. Assemble and return `PrepareResult`.

What `Prepare` reads:

- ARS runtime-facing discovery plus aggregate artifact evidence from ARS
- the validated workload-zone Vault config reference from ES startup config
- Runtime-trust state loaded from EGS at startup

**Implementation invariants**

- `Prepare` does not create a run ID.
- `Prepare` does not build or submit a Nomad job.
- `Prepare` does not create local staging directories.
- `Prepare` returns a bounded result assembled in memory after verification and resolution steps complete.
- The richer signer/workload/workload-vault composition data stays internal to the shared admission helper instead of leaking through the public `PrepareResult`.

## 7. Submit path implementation

`Submit` is implemented in `es/admission/submit.go`.

**Observed current implementation path**

1. Reject submission if the Nomad client is unavailable or submit is not configured.
2. Default omitted mode to `async`.
3. Reject non-async mode.
4. Reuse the shared admission helper that also powers `Prepare`.
5. Enforce submit-time constraints such as `static-script`, supported target platform, and no required runtime capabilities from the prepared artifact data.
6. Fetch payload bytes from ARS using the payload reference carried by the discovery record and cross-checked against aggregate evidence.
7. Generate the current internal execution locator:
  - public `run_id`
  - internal `nomad_job_id = exec-<run_id>`
8. Create the current internal execution-package layout for the new run.
9. Stage the payload locally through that run-scoped layout.
10. Stage runtime mounts through the same layout when mounts are requested.
11. Validate staged mount targets against reserved runtime paths.
12. Build runtime environment variables from the localized runtime layout.
13. Build the Nomad job spec with `buildNomadJobSpec`.
14. Submit the job through `nomadClient.submitJob`.
15. Return the bounded `SubmitResult`.

Where IDs are created:

- The current ES-owned execution locator is created in `newExecutionLocator`.
- That locator currently derives Nomad job ID as `exec-<run_id>`.
- The public `SubmitResult` now returns `run_id` and bounded receipt status only; Nomad IDs remain internal implementation detail.
- The submitted Nomad job also carries `run_id` metadata so internal tooling and tests can resolve the current slice without treating the naming rule as public contract.

Where ES stops and Nomad takes over:

- ES stops at successful `submitJob`.
- After that point, ES reads lifecycle state back from Nomad rather than maintaining its own execution state.

**Implementation invariants**

- `Submit` reuses `Prepare` instead of duplicating the full admission path inline.
- Failed submits remove the staging root immediately through deferred cleanup.
- Successful submits retain their host staging directories only until ES later observes terminal success for that run through the lifecycle path.
- Payload staging, runtime mount staging, wrapper assembly, and base runtime mounts now share one explicit internal execution-package layout instead of rebuilding those conventions across multiple helpers.

## 8. Lifecycle projection implementation

`Status`, `Logs`, and `Cancel` are implemented in `es/admission/lifecycle.go`.

**Observed current implementation path**

- `resolveExecutionLocator` trims and validates `run_id` against `^run-[0-9a-f]{16}$`.
- `resolveExecutionLocator` resolves the current internal locator whose scheduler lookup is `exec-<run_id>`.
- `fetchJob` reads the Nomad job summary.
- `fetchProjectedAllocation` reads the job's allocations and applies the explicit current projected-allocation policy.
- `fetchAllocation` retrieves the detailed allocation record.

Status path:

- Fetch job summary.
- Build a minimal `ExecutionStatusResult`.
- Resolve the currently projected allocation if present.
- Map the current Nomad-backed path into public `status` values:
  - `submitted`
  - `running`
  - `terminal`
- Fill `exit_code` when available.
- Treat "job exists but no allocation yet" as a successful `submitted` view.
- If terminal success is observed, best-effort remove the run-scoped host staging root.

Logs path:

- Fetch job summary.
- Resolve the currently projected allocation.
- Require task `task` to be in `running` or `dead`.
- Fetch stdout via Nomad client FS logs endpoint.
- If the selected task is terminal-successful, best-effort remove the run-scoped host staging root after stdout is fetched.

Cancel path:

- Fetch job summary.
- Stop the job through Nomad with `purge=false`.
- Return bounded cancel receipt without exposing Nomad job identifiers publicly.

**Implementation invariants**

- ES does not consult any ES-owned run store for lifecycle lookup.
- Latest-allocation selection is the only allocation-selection logic in the current implementation.
- Post-submit lifecycle reads are read-through from Nomad rather than reconstructed from staging directories or ES memory.

## 9. Runtime identity and mount implementation

`runtimeidentity.go`, `executionpackage.go`, and `mounts.go` implement the local runtime handoff boundary.

### `runtimeidentity.go`

**Observed current implementation path**

- Defines reserved runtime paths:
  - `/execution/staged`
  - `/execution/run`
  - the current ES-owned runtime-identity workspace root
- Defines the current workload-visible endpoint environment conventions:
  - `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- Derives a run-scoped Unix endpoint URI and backing workspace path under the ES-owned runtime-identity root instead of treating a fixed endpoint path as workload contract.
- Enforces overlap checks with `ValidateReservedRuntimePaths`.
- The current slice-1 implementation target extends this boundary by reserving:
  - helper-private SPIRE path under `/run/es-runtime-identity/<run_id>/internal/`
  - platform-owned runtime assets under `/execution/run/platform/`
  - workload-owned content under `/execution/run/work`

**Implementation invariant**

- ES currently protects the reserved runtime paths backing the discovered endpoint from caller mount overlap.
- The first platform-owned runtime-identity slice must preserve a helper-private raw SPIRE channel and fixed non-root workload launch semantics before any JWT retrieval is considered complete.

**Deliberate absence**

- ES does not become the long-lived runtime credential owner behind the reserved path; runtime-side delivery remains owned by the platform helper launched with the workload.

### `mounts.go`

**Observed current implementation path**

- `validateRuntimeMounts` runs during prepare-time request validation.
- It enforces:
  - max mount count
  - read-only mounts only
  - absolute cleaned target paths
  - target paths under `/execution/mounts`
  - no overlapping mount targets
- `stageRuntimeMounts` runs during submit-time staging.
- For each mount artifact it:
  - re-fetches and revalidates aggregate evidence and trust
  - fetches payload bytes
  - writes a temporary archive through the run-scoped execution-package layout
  - extracts into a per-mount contents directory under that same layout
  - rejects symlinks, hard links, special files, and extraction escapes
  - removes the temporary archive after extraction

**Implementation invariant**

- Runtime mounts are prepared from governed artifacts, not arbitrary host paths.

**Current simplification**

- Mount staging is folded into the submit path instead of being split into a separate artifact-preparation subsystem.

## 10. Filesystem and local side effects

Submission has visible local side effects under the configured staging root.

**Observed current implementation path**

- Startup creates the top-level staging root when submit is configured.
- `stageExecutionInputs` creates the current run-scoped execution-package layout:
  - `<staging_root>/<run_id>/payload`
  - `<staging_root>/<run_id>/run`
- Payload bytes are written to:
  - `<staging_root>/<run_id>/payload/artifact.tar.gz`
- Mount staging uses the same run-scoped layout and creates:
  - `<staging_root>/<run_id>/mounts/<index>/contents`

Runtime-path effects in the Nomad job spec are now assembled from that same internal layout:

- Host `payloadDir` is bind-mounted to `/execution/staged`
- Host `runDir` is bind-mounted to `/execution/run`
- Runtime identity workspace is mounted as tmpfs at the run-scoped workspace derived from the discovered endpoint

Cleanup behavior visible in code:

- Failed submits remove the staged root directory.
- Successful submits retain host staging only while the run may still depend on it.
- ES best-effort removes `execution.staging_root_dir/<run_id>/` after `status` or `logs` observes terminal success for the run.
- Failed, canceled, lost, or otherwise ambiguous outcomes retain their staging root for debugging.
- The runtime-identity workspace is not host-backed by the submit path.

**Current simplification**

- Local staging is a direct filesystem side effect of submit, not a separate managed artifact-execution cache.

## 11. Nomad and Docker interaction

`submit.go` and `lifecycle.go` together define the current Nomad/Docker interaction path.

**Observed current implementation path**

- `buildNomadJobSpec` assembles the Nomad job payload.
- The current job spec is:
  - one batch job
  - one task group
  - one task named `task`
  - Docker driver
- The wrapper shell command:
  - creates `/execution/run/work`
  - creates the runtime-identity workspace path
  - untars the staged artifact into the work directory
  - `chmod +x` on `entrypoint`
  - optionally wraps execution in `timeout`
  - execs `/execution/run/work/entrypoint`

Current job-spec assumptions:

- restart attempts: `0`
- reschedule attempts: `0`
- network mode:
  - `none` when attestation says `network_access=false`
  - `bridge` when `network_access=true`

After submission, ES asks Nomad for:

- job summary
- job allocations
- allocation detail
- task stdout
- job stop

How Docker appears in the implementation:

- Docker is not called directly by ES.
- ES asks Nomad to run a Docker task and later reads Nomad's view of that execution.

**Current simplification**

- The implementation assumes one meaningful job, one meaningful task group, one meaningful task, and one meaningful allocation path in the current slice.

## 12. Test-backed implementation facts

The most important implementation facts are backed by integration tests:

- `es/app/app_integration_test.go` exercises the live `:prepare` path and confirms that ES now returns bounded preflight success without leaking the richer composition data it still assembles internally.
- `es/app/submit_integration_test.go` confirms the live `:submit` wiring into Nomad and Docker, including network-mode selection, runtime-identity tmpfs mounting, environment injection, governed artifact mounts, and lifecycle still working after submission.
- `es/app/operator_scripts_integration_test.go` confirms the primary operator bring-up path can start ARS -> EGS -> AGS -> ES -> Nomad in the current full profile, re-run the unified readiness check, and drive the lifecycle helper through public `run_id` only.
- The same operator-script coverage now also confirms that the readiness helper distinguishes service health, prepare-ready state, and full submit-ready state instead of treating ES `/health` as sufficient on its own.
- Repo-local integration harness workspaces created by `newExecutionWorkspaceTempDir` now live under `.out/<prefix>*` rather than at the repository root; this is a local generated-artifact convention for test and operator inspection, not a public execution contract.
- `es/admission/executionpackage_test.go` confirms the run-scoped execution-package layout localizes host staging, runtime paths, wrapper assembly, and base runtime mounts.
- `es/app/lifecycle_integration_test.go` confirms status/logs/cancel are projected from Nomad through the narrowed public DTOs, that failed workloads still surface through `200` status responses, that logs return `409` before readiness, and that Nomad unavailability surfaces as `503`.
- `es/admission/runtimeidentity_test.go` confirms reserved runtime path overlap is rejected while `/execution/mounts/...` remains allowed.
- `es/app/observability_integration_test.go` confirms inbound request wrapping and outbound dependency-edge logging, including trace propagation across ES -> ARS health checks.
- `es/app/execution_loop_integration_test.go` confirms the end-to-end implementation path can drive publish -> prepare -> submit -> status/logs summaries without an ES-owned run store.

Operator helper ownership in the current slice:

- `scripts/01_bringup.sh` is the primary stack bring-up and shutdown entrypoint.
- `scripts/generate_control_plane_dockerfile.sh` is the source-of-truth generator for the default shared service-image Dockerfile at `.out/Dockerfile`; bring-up regenerates that file before building.
- `.out/` is the repo-local generated-artifact sink in the current slice; tracked source-of-truth inputs remain explicit exceptions such as `.out/Dockerfile`, while kept integration harness workspaces (for example `es-submit-*`) are created beneath `.out/`.
- `scripts/10_health_check.sh` is the unified readiness verifier for service health, runtime-config blob availability, Nomad, and Docker.
- `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, `scripts/50_lifecycle.sh`, and `scripts/60_execute_loop.sh` are operator-facing workflow helpers over the current public AGS and ES APIs; they classify failures into bounded operator categories instead of changing those APIs.
- `scripts/70_diagnostics.sh` is the bounded diagnostics collector for that same operator slice; category bundles gather only the logs/checks already named by the troubleshooting matrix, and `run_id` bundles use the public ES lifecycle endpoints plus local staging inspection when relevant.
- `scripts/71_diagnostics_summary.sh` is the tiny bundle consumer for that same slice; it reads `bundle.json` from `scripts/70_diagnostics.sh` and prints a compact summary of the collected signals.
- `scripts/internal/*.sh` are sourced-only implementation helpers for those top-level commands; they are not separate operator-facing entrypoints in the current slice.
- those later helpers treat `scripts/01_bringup.sh check` and `scripts/10_health_check.sh` as the readiness source of truth for service health, prepare-ready, and submit-ready.
- the bounded operator failure categories are:
  - caller authorization / credential failure
  - trust / evidence / admission failure
  - runtime-config reference or blob failure
  - service health / readiness failure
  - substrate failure (Docker / Nomad / runtime availability)
  - execution failure after successful submit
  - operator misuse / invalid input
- the compact troubleshooting matrix for those categories lives in `/Users/ds/Repositories/Execution-Platform/.runbooks/system/v1_bringup.md`; later helpers point operators there for the matching logs, readiness checks, staging-inspection guidance, and next action
- `scripts/50_lifecycle.sh` now observes execution strictly through public ES lifecycle endpoints rather than through Nomad job/eval IDs.

## 13. Current simplifications

**Current simplifications**

- `Prepare` is a bounded but live code path.
- `Prepare` and `Submit` now share one internal admission helper instead of maintaining separate admission pipelines.
- ES has no lifecycle store and uses one explicit internal execution-locator policy whose current lookup is `run_id -> exec-<run_id>`.
- Lifecycle uses one explicit projected-allocation policy instead of a broader allocation model.
- Log retrieval is a minimal latest-allocation stdout path.
- There is no retry or reschedule machinery in ES.
- Runtime identity handling is reservation and path protection, not token ownership or endpoint implementation.
- Runtime-trust loading is startup-time initialization rather than a live refresh path in the current slice.
- Aggregate evidence is the only first-class admission input for the published artifact path.

These are active implementation choices, not automatically permanent design commitments.

## 14. Deliberate absences

**Deliberate absences**

- No run persistence
- No background lifecycle workers
- No retry or reschedule orchestration
- No multi-allocation aggregation
- No streaming log implementation
- No token minting or token population in the ES runtime-identity workspace
- No scheduler abstraction above Nomad in the current slice

## 15. Current implementation pressure points

**Reopened implementation seams under visible pressure**

- `Prepare` is live and important in code even though it is still described as bounded.
- Admission logic now treats aggregate evidence as canonical with no remaining legacy fact fallback or side path.
- The current execution-locator policy still resolves `run_id -> exec-<run_id>`.
- Latest-allocation selection is simple and coherent only because the slice avoids retries and reschedule.
- Runtime identity handling depends on reserved `/execution/...` path conventions.
- Submit currently depends on runtime-facing payload discoverability plus evidence-claim cross-checks between artifact identity and payload identity.
- The implementation is coherent today as a thin composition and handoff layer, but several of its shortcuts are still under redesign pressure rather than being settled structure.

## 16. Relationship to other docs

Use the companion documents for other kinds of authority:

- `.docs/execution_lifecycle/contracts.md` for public endpoint, response, and error semantics
- `.docs/execution_lifecycle/design.md` for lifecycle design and authority boundaries
- `.docs/system_overview/contracts.md` for cross-service contract context
- `.docs/system_overview/boundaries.md` for service ownership and non-ownership
- `PLANS.md` for redesign sequencing and reopened architectural decisions

This file should stay focused on code paths and side effects.

## 17. Reopened implementation seams

- The implementation role of `Prepare`
- The internal reuse of `Prepare` by `Submit`
- Internal execution-locator policy
- Latest-allocation selection path
- Runtime identity reserved-path handling
- Current execution-package layout and container path conventions behind submit
- The extent to which current lifecycle minimalism is implementation convenience versus durable structure

These seams are active today and intentionally not fixed.

## 18. Decision rules for future edits

- Keep this file implementation-level, not contract-level.
- Do not omit active code paths from the implementation map.
- Public semantics belong in `.docs/execution_lifecycle/contracts.md`.
- System ownership belongs in `.docs/system_overview/boundaries.md`.
- If code and tests disagree with this file, update this file to match reality.
- Label current simplifications explicitly.
- Do not describe an implementation shortcut as a durable invariant without support.
