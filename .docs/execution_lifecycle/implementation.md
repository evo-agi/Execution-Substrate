# Execution Lifecycle Implementation

## 1. Purpose and status

This document describes the current ES lifecycle implementation in the repository's bounded platform phase.

The current implementation slice is real, exercised by integration tests, and visible directly in the ES Go packages. Public contract semantics live in `.docs/execution_lifecycle/contracts.md`. Lifecycle design and authority boundaries live in `.docs/execution_lifecycle/design.md` and the system overview docs.

This file is specifically about where lifecycle behavior lives in code today: handlers, wiring, call paths, local side effects, and where Nomad becomes authoritative.

The target submit idempotency, submit correlation, and recovery contract is
documented in `submit_idempotency_correlation_and_recovery.md`, but that
target runtime contract is not implemented in the current code.
The public opt-in/versioning posture selected there is also future work: the
current server still decodes the current `PrepareRequest` body for submit, and
the current producer declaration has no reliable-submit producer sub-contract.
Current source now includes the first pure, admission-local internal model plus
the private durable-record codec, backend-neutral claim-store port, durable
semantic service, shared conformance tests, and modernc SQLite store source for
that target under `es/admission/internal/reliablesubmit`. Current source also
includes private admission-local contract-adapter foundation helpers for the
reliable request-family vocabulary, submit-key validation, caller/key
safe-reference derivation, composite `ClaimID` construction through the
committed pure-model constructor, and ES-neutral outcome projection. It does not
retain the raw submit key after private strict decode and caller-bound
derivation: the function-local wire surrogate may hold the raw key only during
decode and derivation, while the validated request retains sanitized request
facts plus safe private caller/key/claim references. It does not claim secure
memory erasure, and it does not rely on domain types overriding invalid Go
formatting operations. Full request objects are not safe log payloads. Those
earlier reliable-submit foundation helpers did not themselves include
source-grounded resolved-plan extraction, canonical effective-plan encoding,
`PlanBinding`, a complete witness or durable replay custody. The later bounded
codec-3 path adds only private synthetic custody, still without runtime
orchestration. A separate private admission-local foundation
extracts one source-grounded resolved execution plan for the current legacy
`Submit` path and makes that plan the sole post-freeze source of submit
decisions. It does not call or wire the reliable helpers, construct a reliable
binding or witness, add custody to legacy Submit, or change any public request,
response, producer, lifecycle, or recovery surface. The private reliable store
and foundation helpers remain constructed and exercised only in tests; they
are not wired to submit, prepare, handlers, producer declaration, staging,
lifecycle, results, Nomad behavior, runtime startup, runtime configuration,
public persistence integration, or recovery routes.

A later package-private `buildReliableSubmitAdmissionBinding` now consumes the
actual frozen `resolvedExecution` from the same resolver. It checks signed
mount artifact and payload provenance retained beside the requested source
digest, validates captured primary/support/mount/trust material coherence, and
builds the existing opaque binding and fourteen-category witness under an
explicit synthetic-test key. At PB1 it had no production caller; its only
selected new non-test caller is the private synthetic composer. It has no
runtime key source, provider effect or public DTO. Its output is always
not-effect-ready. The legacy resolver only carries provenance; it does not add
requested-versus-returned mount artifact refusal to live `Submit`. The private
producer's extra sequential bounded mount-archive parse is an unwired memory
and work cost, not part of the prior runtime peak bound. The exact format and
limitations are in `submit_idempotency_correlation_and_recovery.md`.

The private durable source now implements
`reliable-submit-durable-same-operation-replay-repair`. The durable service
derives a complete latest-operation descriptor for new codec-2 rows and every
real v2 mutation, recognizes same-mutation/same-kind/same-input replay before
stale-revision and inactive-state refusal, returns mutation conflict for
same-mutation/different descriptor reuse, reloads CAS losers through replay,
conflict, inactive, and stale classification, and keeps COMMIT-unknown recovery
on full expected-record equality including the descriptor. Historical SQLite
schema v2 remains the codec-2 descriptor source; valid v1 rows migrated as
codec-1 legacy/unbound rows that preserve the
retained mutation reference and fail closed for same-mutation replay instead of
inventing operation semantics. Schema 3 appends a complete immutable codec-3
synthetic claim, same-DB key-use ledger, exclusive sealed-object publisher and
one checked reader. Its admission callback reconstructs the winner-original
facts and recomputes unchanged PB1. Codec-1/2 generic nonempty opaque lengths
and CAS semantics remain intact; only codec-3 requires 32-byte caller/key refs
and 1..256-byte PlanBinding. The private path remains runtime-unwired and
always not-effect-ready. No mutation history is stored.

The private store remains runtime-unwired. This source repair adds no config
field, public producer/request/response source, staging behavior, Nomad
behavior, current submit behavior, HTTP handler behavior, runtime startup, or
public reliable-submit availability.

## Isolated candidate implementation path

`prepareAdmission` deep-copies the caller request into one owned working value,
performs its established artifact, trust, Vault/auth and policy reads and gates,
and retains the successful Vault config reference. After admission succeeds,
`resolveExecutionForSubmit` takes one owned execution/placement configuration
snapshot for subsequent profile, placement and materialization facts, including
both roots. It does not atomically capture earlier admission or all service
configuration reads and does not guarantee unsynchronized concurrent mutation.
The resolver then returns a semantic plan,
captured material, host context and separate custody-placement root pair. Its
successful return is the pre-effect freeze point. `Submit` then assigns a run
locator, qualifies the captured root pair, claims one staging root exclusively,
materializes captured bytes through descriptor-held paths, checks the complete
expected tree, builds typed handoff/job projections and registers once. Results
open staging read-only and publish independent opaque bundles without replacing
existing objects. Lifecycle reads do not remove claimed staging on terminal
success. Failed exclusive leaves, unpublished result/normalization temporaries
and startup capability-probe fixtures remain when a later pathname unlink
cannot prove exact operation ownership. This candidate has no whole-root
reclamation policy. Selected native Linux and test-owned installed-source
evidence is accepted under the original Review-22 identities; actual
running-deployment topology, key exposure and operating capacity/residence
remain unqualified. `PLANS.md` and the lifecycle contract own the development
evidence and separate rollout acceptance boundaries.

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
| `es/admission/policy.go` and `es/admission/policy_payload.go` | ES-local admission policy seam, typed policy context/decision structures, built-in selected static-script content policy, and bounded static-script payload text extraction | CGS/EGS policy-language redesign, OPA/Rego, customer policy config, external policy services, durable policy-decision storage, CP prompt/workspace parsing | This keeps ES final admission policy local and replaceable without turning policy into a broad language or cross-service authority surface |
| `es/admission/executionpackage.go` | Run-scoped staging layout, container-visible runtime layout, payload staging, reserved result-path staging, and shared mount-spec/wrapper assembly inputs | Artifact verification, lifecycle projection, public DTOs | This localizes the current submit-side package-resolution and staging conventions |
| `es/admission/runtimeprofile.go` | Bounded runtime-profile selection, validation, image selection, and non-secret profile environment metadata | Package-kind redesign, lifecycle semantics, secret brokerage | This keeps the Control Plane normal-shell runtime contract explicit without moving CP control behavior into ES |
| `es/admission/authorityhandoff.go` | Bounded non-secret authority handoff DTO assembly and recovery from submitted runtime specs | Live credential state, policy approval state, scheduler identity, lifecycle storage | This keeps the CP-consumable handoff read surface grounded in facts ES selected and injected |
| `es/admission/resolved_execution_plan.go` | Private admitted-request ownership, one pre-side-effect resolved-plan freeze, captured submit material, and narrow typed post-freeze projections | Public DTOs, reliable-submit binding/witness/custody, lifecycle truth, scheduler reconciliation | This prevents submit decisions and material from being re-derived or re-read after side effects begin |
| `es/admission/submit.go` | Post-freeze `Submit` orchestration, execution-locator creation, run projection, retained staging custody, typed Nomad job assembly, one Nomad submission, and unchanged receipt construction | Pre-freeze source resolution, lifecycle projection after submission, persistent run ownership | This is where ES crosses from the frozen private plan into the current real execution handoff |
| `es/admission/lifecycle.go` | `Status`, `Logs`, `Cancel`, internal execution-locator resolution, Nomad lookup helpers, projected-allocation policy use, and terminal-result retention triggers | Any ES-owned lifecycle store, retry orchestration, allocation aggregation | This is the post-submit lifecycle projection path |
| `es/admission/results.go` | Retained result bundle lookup, idempotent tar.gz packaging of `/execution/run/result`, and result endpoint service behavior | Output semantics, Control Plane checkpoint meaning, lifecycle ownership | This keeps the retained-result slice narrow and ES-owned without turning it into orchestration state |
| `es/admission/runtimeidentity.go` | Reserved runtime path definitions, endpoint env conventions, run-scoped endpoint derivation, overlap validation | Endpoint implementation, token minting, token population | This is the boundary guardrail for runtime-identity handoff |
| `es/admission/mounts.go` | Runtime mount request validation, mount artifact revalidation, mount staging and archive extraction inside the run-scoped execution-package layout | General artifact publication, lifecycle state | This is where mount side effects and mount-specific trust checks live |

Related support files:

- `es/admission/types.go` carries the current request/result/data structs used across prepare, submit, and lifecycle paths, including the additive outcome-evidence descriptor structs for status/cancel JSON and successful logs/result metadata.
- `es/api/types.go` currently carries the health response shape rather than lifecycle endpoint payloads.

## 4. Handler-to-service flow

**Observed current implementation path**

- `Server.Handler()` in `es/api/server.go` builds the HTTP mux.
- The mux is wrapped with `observability.WrapHandler("execution", mux)` before serving.
- Route entrypoints are:
  - `handleProducerContract -> service.ProducerContract`
  - `handlePrepare -> service.Prepare`
  - `handleSubmit -> service.Submit`
  - `handleLifecycleGet -> service.Status`, `service.Logs`, or `service.Result`
  - `handleLifecyclePost -> service.Cancel`

Where behavior lives:

- The producer contract handler authorizes the caller, then returns the service-owned static declaration.
- Request decoding for `:prepare` and `:submit` happens in `decodeAuthorizedExecutionRequest`.
- Caller authorization happens in `authorizeExecutionCaller`.
- Lifecycle path parsing for `status`, `logs`, `result`, and `cancel` happens in `parseLifecycleRequest`.
- JSON error shaping happens in `writeJSON`.
- Authorization failures use `writeText`.

**Implementation invariants**

- `GET /v1/executions:contract` uses the same execution-caller authorization helper as prepare, submit, status, logs, result, and cancel.
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
- The Workstream E E0 decision in
  `.docs/system_overview/runtime_config_ownership.md` classifies that startup
  placement as compatibility/config residue on a reopened ownership seam.
  Runtime-config semantics live in `internal/contracts/runtimeconfig/v1`; ARS
  owns blob storage/read by digest only; ES is the current consumer and lookup
  orchestrator.
- It also builds verifier instances for:
  - TrustModel
  - provenance
  - derivation attestation
  - workload identity binding
- The current `verification.derivation_attestation` and
  `verification.workload_identity_binding` config groups remain startup
  verifier residue from earlier admission shapes. In the current hot path they
  do not add active shared-kernel authorization meaning, CGS policy meaning,
  Workstream E runtime-config ownership, or Workstream F runtime-identity
  ownership.
- It creates the Nomad client only when submit is configured.
- If submit is configured, it creates the local staging root and retained-results root on startup.
- The long-lived ES startup path validates the staged runtime-support binary as a service-owned execution input and may validate only the syntax/config shape of `execution.spire_workload_api_socket_path`, but it does not `stat(2)` or traverse the raw host SPIRE Workload API socket directly.
- The configured `execution.spire_workload_api_socket_path` remains a submit/runtime input used to build the helper-private mount model, and operator/readiness tooling remains responsible for proving that host path is a real Unix socket before submit-ready or service-user apply is claimed.
- The runtime helper remains the only current component that consumes the helper-private raw SPIRE path at runtime, and failure to reach or validate that socket stays explicit and fail closed rather than degrading to workload-visible raw SPIRE access.
- The Workstream F F0 decision in
  `.docs/system_overview/runtime_identity_handoff.md` classifies the current
  runtime identity handoff as ES-selected and platform-delivered. ES owns
  handoff selection, env injection, reserved path layout, mounts, and Nomad
  job construction for the current slice. The runtime supervisor/helper owns
  the in-task endpoint implementation, helper-private SPIRE traversal,
  readiness-before-workload, and root-to-workload privilege boundary. SPIRE
  owns JWT-SVID issuance, and Vault owns token, secret, and lease issuance
  after workload-side login.

**Implementation invariants**

- ES does not start serving until runtime-trust initialization succeeds.
- ES does not start serving unless `runtime_config.workload_zone_vault_config_ref` validates at startup.
- That startup rule is a typed reference-availability guarantee, not a startup
  blob-fetch guarantee and not final runtime-config ownership by ES startup
  config.
- Readiness after startup depends on:
  - app `started`
  - trust model loaded
  - ARS ready
- Live EGS reachability is not treated as a post-start runtime readiness dependency in the current implementation.
- ES `/health` remains admission-oriented only; the operator bring-up/check path now layers workload-zone Vault runtime-config verification and, for the full profile, ES submit-config, Docker, required runtime-profile image availability, and Nomad checks on top before declaring submit readiness.
- `GET /v1/executions:contract` is static compatibility metadata assembled from the ES service configuration and the current code-owned outcome-evidence vocabulary. It does not call Nomad, ARS, EGS, Docker, Vault, SPIRE, or any run-specific store.

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
7. Decode and validate the workload-zone Vault blob through `internal/contracts/runtimeconfig/v1`, then resolve the workload-vault auth plan from that typed config plus ES `workload_vault_auth.default_mode`, including optional non-secret Vault CA trust material.
8. Evaluate ES Admission Policy Layer v0 in the same shared admission helper
   used by `Prepare` and `Submit`. If an enabled policy requires payload
   inspection, read only bounded static-script payload text through the
   explicit payload digest already discovered through ARS and cross-checked
   against aggregate evidence.
9. Assemble and return `PrepareResult`.

There is no ACS hop in this runtime-config path.

What `Prepare` reads:

- ARS runtime-facing discovery plus aggregate artifact evidence from ARS
- the validated workload-zone Vault config reference from ES startup config
- Runtime-trust state loaded from EGS at startup
- bounded static-script payload text from ARS only when an enabled ES
  admission policy requires that input class
- CGS is not a current read dependency of `Prepare` or `Submit`

**Implementation invariants**

- `Prepare` does not create a run ID.
- `Prepare` does not build or submit a Nomad job.
- `Prepare` does not create local staging directories.
- `Prepare` does not call CGS or consume a CGS authorize response.
- `Prepare` may read bounded payload bytes for policy input only through the
  explicit ARS payload digest carried by the already validated
  discovery/evidence relationship; it does not treat `artifact_digest` as a
  payload locator.
- Policy denials use stable reason codes and safe messages only. The
  implementation must not log or return raw payload text, matched content, CP
  prompt/workspace material, model output, logs, retained bundles, support
  bundles, credentials, environment values, DB contents, process records, or
  cert/key/TLS/SPIFFE/Vault/WebAuthn/passkey/API-key material.
- `Prepare` returns a bounded result assembled in memory after verification and resolution steps complete.
- The richer signer/workload/workload-vault composition data stays internal to the shared admission helper instead of leaking through the public `PrepareResult`.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.

## 7. Submit path implementation

`Submit` is implemented in `es/admission/submit.go`.

**Observed current implementation path**

1. Reject submission if the Nomad client is unavailable or submit is not configured.
2. Reuse the shared admission helper that also powers `Prepare`. It borrows the
   caller request, immediately deep-copies every mutable member, and applies one
   private Prepare-versus-Submit intent to that owned working copy.
3. For Submit intent, default omitted mode to `async` and reject non-async mode
   before dependency I/O. Prepare intent preserves current blank/async/sync
   handling. The admission-owned copy is the only mutable authority for mode,
   schema defaulting, validation, and normalization; successful admission
   returns one frozen authoritative snapshot. Immutable defensive transfer
   copies remain permitted.
   The caller retains ownership until the initial copy completes and must keep
   the request and every reachable mutable member race-free through that copy.
   Concurrent unsynchronized mutation while copying is a caller data race, not
   an ES synchronization guarantee. After the owned copy completes, later
   caller mutation cannot change admitted or submitted state, and downstream
   defensive copies do not create a second mutable authority.
4. Continue the shared path, including ES
   Admission Policy Layer v0, and retain the exact workload-zone Vault config
   reference that selected the successfully fetched config and auth plan.
5. Capture one private immutable submit/config snapshot immediately after
   admission.
6. Resolve all remaining source-grounded facts before side effects, in this
   order: submit gates; resources; primary payload bytes; runtime-support bytes
   and content identity; governed mount discovery/evidence/payload plus one
   bounded gzip/tar traversal; normalized Vault and combined trust bytes;
   platform-state owner; and the complete plan, material, and host context.
7. Build one typed runtime command and the private semantic plan. The plan owns
   schemas/mode/timeout/resources, profile/image and semantic environment
   inputs, the command, distinct artifact/payload/derivation/output identities,
   mounts, network permission, unconditional authority inputs,
   runtime-support digest, runtime-identity tmpfs size, and the fixed semantic
   envelope. Material owns captured bytes. Host context contains only the
   cleaned absolute staging root, qualified owner, cleaned absolute SPIRE
   source, and trimmed non-empty datacenter. The results root is normalized for
   current ES service/custody qualification but remains outside the semantic
   plan, host context, provider-job projection, and B1 binding.
8. Return the private resolved execution. This successful return is the
   freeze point: no run ID, filesystem write, ownership mutation, or Nomad
   registration occurs before it, and no submit decision is re-derived after it.
9. Generate the current internal execution locator:
  - public `run_id`
  - internal `nomad_job_id = exec-<run_id>`
10. Derive the run projection from only the plan, captured host context, and
    locator. The semantic plan is admitted semantic truth only; this host/run
    projection adds additional execution-shaping facts: owner/run/endpoint
    environment, host/staged paths, datacenter, endpoint, and other derived run
    facts. Create its staging root exclusively as the first filesystem mutation. Refuse every pre-existing object type, open the
    new root no-follow, and hold its parent/root identities.
11. Materialize only captured payload, runtime-support, mount, and trust bytes
    through descriptor-relative custody operations. Revalidate the complete
    expected tree immediately before handoff.
12. Assemble the bounded non-secret `authority_handoff` and one Nomad job spec
    from narrow typed plan/host/run projections. Do not reread request,
    prepared admission, live config/service fields, profile maps, dependency
    sources, owner state, SPIRE source, or datacenter after freeze.
13. Submit the job once through `nomadClient.submitJob`.
14. Return the unchanged bounded `SubmitResult`.

The semantic plan is admitted semantic truth only, while host/run projection
adds additional execution-shaping facts. Tranche B2 now completes its bounded
privacy and independent-assurance refinement. The selected operational-cause
families expose only `workload-zone vault configuration is invalid`,
`derive execution host context failed`,
`stage workload vault trust material failed`,
`derive execution platform state owner failed`, or
`execution submission failed`, while preserving their routes, HTTP statuses,
codes, DTO fields, precedence, and successful behavior. The three governed
result-retention log calls emit only
`es result retention failed run_id=%s` with the validated public run ID; that
claim is bounded to those calls and is not process-wide log noninterference.
Reliable keyed-submit runtime remains unwired, and native Linux runtime
validation remains pending.

Where IDs are created:

- The current ES-owned execution locator is created in `newExecutionLocator`.
- That locator currently derives Nomad job ID as `exec-<run_id>`.
- The public `SubmitResult` now returns `run_id` and bounded receipt status only; Nomad IDs remain internal implementation detail.
- The submitted Nomad job also carries `run_id` metadata so internal tooling and tests can resolve the current slice without treating the naming rule as public contract.
- The submitted Nomad job carries narrow ES handoff metadata for `authority_handoff` status recovery. That metadata is an internal evidence carrier for non-secret runtime handoff facts, not a public scheduler identifier surface.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority, live credential truth, or token/lease truth.

Where ES stops and Nomad takes over:

- ES stops at successful `submitJob`.
- After that point, ES reads lifecycle state back from Nomad rather than maintaining its own execution state.

**Implementation invariants**

- `Prepare` and `Submit` use the same admission helper. Each path owns one
  mutable admission working copy and returns one frozen authoritative snapshot;
  immutable defensive copies do not create another authority. Caller use must
  remain race-free until the initial copy completes; unsynchronized concurrent
  mutation during copying is a caller data race, not an ES synchronization
  guarantee. Post-copy caller mutation cannot alter admitted or submitted
  state.
- `Submit` cannot bypass the policy evaluation path used by `Prepare`; policy
  denial happens before run ID creation, payload staging, mount staging, and
  Nomad submission.
- Once exclusive run-root creation succeeds, all Submit returns retain the
  visible root and close descriptors best-effort. This includes partial
  materialization, ordinary failure, ambiguous Nomad registration, and accepted
  registration. Close failures never replace the primary error or accepted
  receipt. No marker, reopening, adoption, quarantine, scan, or recursive
  whole-root deletion exists.
- Payload staging, runtime mount staging, and base runtime mounts share one
  explicit internal execution-package layout. The complete runtime executable
  and supervisor argument grammar instead live in one private
  `resolvedRuntimeCommand` constructed before freeze and copied through typed
  projections; the layout and tests do not rebuild that grammar.
- Current authority handoff is unconditionally applicable for successful
  Submit. Structural presence of the authority plan represents applicability;
  only Codex credential-location metadata remains an optional subcomponent.
- The source-grounded payload digest retained by the plan comes only from the
  discovery/evidence relationship already cross-checked by admission. Raw
  payload bytes remain material and the digest is not added to public or Nomad
  projections.
- Semantic-plan equality across qualified host contexts is not provider-job,
  dispatch, replay, restart, or provider-effect equality. Host context and
  run/provider projection remain additional execution-shaping facts whose
  treatment in the later private v1 binding is separate captured placement,
  not semantic PlanBinding input or retained topology proof.
- Submit-time staging, mount staging, trust-material staging, retained-result expectations, and internal `EXEC_PLATFORM_STATE_OWNER_*` injection now require `execution.staging_root_dir` and `execution.results_root_dir` to resolve to the same target owner UID:GID before ES will submit the run.
- Submit-time runtime mount assembly uses the configured SPIRE socket source directory as a string input to the helper-private mount model; it does not require the long-lived ES process itself to open the raw host SPIRE socket.
- If the resolved workload-zone Vault config carries CA trust material, submit staging writes `/execution/run/platform/workload-vault-ca.pem`, writes a combined runtime TLS bundle at `/execution/run/platform/workload-ca-bundle.pem`, and injects `VAULT_CACERT` plus `SSL_CERT_FILE` for workload-side Vault TLS verification.
- `control-plane-normal-shell/v1` uses the same execution-package layout, runtime helper, runtime identity endpoint, and retained-result path as the current `static-script` slice. The selected profile changes the runtime image and adds non-secret runtime metadata; it does not add ES-owned CP lifecycle or result semantics.
- The `authority_handoff` returned by submit is assembled from submit-time facts only. It does not observe whether the workload later uses the endpoint, receives a JWT-SVID, logs in to Vault, reads Codex credential material, or holds a live lease.
- `Submit` does not call CGS, and `authority_handoff` remains assembled from
  ES-selected runtime facts rather than CGS authorize output or policy-approval
  state.
- `Submit` does not broker Vault tokens, Vault secrets, JWT-SVID payloads,
  leases, Codex credential material, or credential payloads.

**Current keyed-recovery absence**

- The detailed target contract is
  `submit_idempotency_correlation_and_recovery.md`.
- Current source includes the internal package
  `es/admission/internal/reliablesubmit`. Its pure model in `model.go` models
  local phase, opaque `RunRef`, disclosure, progression, replay, conflict,
  privacy, and effective-plan completeness invariants. The same package now
  contains private durable-record, backend-neutral port, durable-service, shared
  conformance-test, and SQLite-store source.
- That package is not wired to current `Submit` and is not lifecycle truth.
  It does not implement the producer sub-contract, reliable request DTO,
  staging, Nomad reconciliation, recovery lookup, public error vocabulary,
  runtime configuration, or runtime startup integration.
- The admission-local v1 binding producer is present, package-private,
  runtime-unwired and always not-effect-ready. It consumes the real resolver
  tuple and constructs a binding and witness only after its own source/material
  checks. It does not make keyed recovery or reliable submit available.
- Current package `admission` now also contains private
  `reliable_submit_*` foundation helpers. They select the reliable request
  schema `execution-substrate.reliable-submit-request/v1`, reliable contract
  `execution-substrate.reliable-submit/v1`, top-level discriminator
  `reliable_submit`, submit-key syntax, SPIFFE caller/key safe-reference
  derivation, composite `ClaimID` construction through the committed pure-model
  constructor, and ES-neutral outcome projection. Their raw-key-bearing wire
  surrogate is function-local to private strict decode; decoded key bytes are
  consumed for caller-bound derivation and are not retained in the validated
  request. The validated representation retains sanitized request facts plus
  safe private references only. This is not a secure-memory-erasure guarantee
  and not a claim that invalid Go `%w` formatting of non-error values can be
  made override-safe with formatting hooks. They do not themselves implement
  source-grounded resolved execution-plan extraction, canonical effective-plan
  encoding, `PlanBinding` construction from admitted facts, complete
  effective-plan witness construction, durable replay-envelope custody, or
  runtime orchestration. They are not exported, not public DTOs, and not called
  by current handlers or `Submit`; the separate current legacy-submit resolved
  plan foundation neither imports nor invokes them.
- The private durable service implements the
  `reliable-submit-durable-same-operation-replay-repair` latest-operation-only
  source repair. It persists a descriptor made of mutation reference, closed
  private operation kind, and versioned safe input-binding digest for codec-2
  rows. A same mutation reference with different kind or binding is mutation
  conflict; an older operation after later progression is stale or superseded,
  not exact replay. Migrated codec-1 rows remain legacy/unbound and fail closed
  for same-mutation replay. This remains a private runtime-unwired source
  repair, not reliable-submit config/store lifecycle wiring, producer
  enablement, or public runtime enablement.
- The pure model cannot enforce one winning assignment across stale or
  concurrent snapshots. The private persistence and compare-and-swap layer owns
  the authoritative caller/key claim and assigned `run_id` transition. Later
  reliable-submit tranches must consume this package or explicitly stop and
  revise it; no second unused abstraction tranche may be layered on top without
  a concrete consumer.
- The persistence and concurrency ADR
  `reliable_submit_persistence_and_concurrency.md` selects local embedded SQLite
  as the first storage backend, preserves the current `CGO_ENABLED=0` build
  posture, selects `modernc.org/sqlite v1.54.0` with exact
  `modernc.org/libc v1.74.1` coupling, and selects private same-package
  persistence hydration inside `es/admission/internal/reliablesubmit`. It now
  preserves the private SQLite schema-v2 latest-operation descriptor and
  legacy/unbound migration posture while schema 3 adds immutable synthetic
  custody in the same DB. The historical v1 migration
  source and metadata remain retained and verified, valid v1 databases migrate
  through v2 to v3 in one grouped transaction, and migrated rows remain
  codec-1 legacy/unbound until a later
  valid distinct mutation upgrades the row. It adds no config field, public
  producer/request/response source, staging behavior, Nomad behavior, runtime
  behavior, or public reliable-submit availability.
- Current `Submit` has no submit idempotency key input, no submit correlation
  key, no exact replay path, no conflicting reuse path, no pending outcome
  path, no durable submit-correlation record, and no recovery lookup by
  caller key.
- Current `SubmitResult` has no replay or submit-correlation vocabulary. It is
  the current bounded unkeyed receipt after confirmed Nomad response.
- Current `handleSubmit` still decodes the current `PrepareRequest` body and
  delegates that request to `Submit`; no handler discrimination, public
  reliable request DTO, reliable runtime decoder, or reliable submit path is
  implemented.
- The current producer contract declaration still has the current outer
  `execution-substrate.producer-contract/v1` identity and current
  `governed-execution-producer/v1` governed-execution identity only. No
  reliable-submit producer sub-contract field or DTO is implemented.
- Current code can be ambiguous at the caller-to-ES boundary when ES accepts a
  submission and produces a `run_id` but the caller or adapter loses the
  response.
- Current code can also be ambiguous at the ES-to-Nomad boundary when ES sends
  a Nomad registration request but cannot confirm whether Nomad accepted it.
  Current non-confirmation returns the existing `submission_failed` behavior
  and retains the complete staging root; that is not a reliable proof that no
  provider effect was accepted.
- The target reliable keyed-submit runtime contract is not implemented here and
  must not be described as current behavior.
- The selected future public shape remains: one additive narrow reliable-submit
  producer sub-contract, the existing `POST /v1/executions:submit` route, a
  distinct submit-specific reliable request family, producer-declaration
  preflight plus in-band request discrimination, no header-only opt-in, and no
  silent fallback to current unkeyed submit.

## 8. Lifecycle projection implementation

`Status`, `Logs`, and `Cancel` are implemented in `es/admission/lifecycle.go`.

**Observed current implementation path**

- `resolveExecutionLocator` trims and validates `run_id` against `^run-[0-9a-f]{16}$`.
- `resolveExecutionLocator` resolves the current internal locator whose scheduler lookup is `exec-<run_id>`.
- `fetchJob` reads the Nomad job summary.
- `fetchProjectedAllocation` reads the job's allocations and applies the explicit current projected-allocation policy.
- `fetchAllocation` retrieves the detailed allocation record.
- The status path derives the public `lifecycle_projection` fact from implementation-private Nomad lifecycle observation inputs, without exposing Nomad job IDs, allocation IDs, or backend revision structure.
- The lifecycle/result paths attach additive outcome-evidence descriptors for current response facts without exposing Nomad IDs, task IDs, host paths, result filesystem paths, or result payload contents.

Status path:

- Fetch job summary.
- Build a minimal `ExecutionStatusResult` with `lifecycle_projection.source = "nomad"` and an opaque same-run read-coordination `lifecycle_projection.revision`.
- Add `outcome_evidence` with `source = "nomad"`, the current observation label (`nomad_job_projection`, `nomad_projected_allocation`, or `nomad_task_state_projection`), the same lifecycle projection token, and whether provider terminal state was observed.
- Recover `authority_handoff` from the submitted runtime spec when the internal ES handoff metadata and submitted environment are present.
- Resolve the currently projected allocation if present.
- Map the current Nomad-backed path into public `status` values:
  - `submitted`
  - `running`
  - `terminal`
- Fill `exit_code` when available.
- Treat "job exists but no allocation yet" as a successful `submitted` view.
- Terminal observation controls lifecycle projection and result-attempt timing
  only. No provider state, task state, or exit code authorizes staging mutation.

Logs path:

- Fetch job summary.
- Resolve the currently projected allocation.
- Require task `task` to be in `running` or `dead`.
- Fetch stdout via Nomad client FS logs endpoint.
- Return stdout bytes with outcome evidence that labels the body as `nomad_task_stdout`, access class `plaintext_stdout`, and whether terminal state was observed during the lookup.
- If the selected task is terminal, fetch stdout and attempt result retention;
  leave staging retained regardless of the result attempt.

Cancel path:

- Fetch job summary.
- Stop the job through Nomad with `purge=false`.
- Return bounded cancel receipt with outcome evidence `nomad_stop_request_accepted` and `provider_terminal_observed = false`, without exposing Nomad job identifiers publicly or claiming the workload has stopped.

**Implementation invariants**

- ES does not consult any ES-owned run store for lifecycle lookup.
- Latest-allocation selection is the only allocation-selection logic in the current implementation.
- Post-submit lifecycle reads are read-through from Nomad rather than reconstructed from staging directories or ES memory.
- The lifecycle projection revision is a same-run status read token only; callers may compare it for the same run, and no lifecycle write path accepts it as a precondition.
- Outcome-evidence descriptors are response labels only; no lifecycle write path accepts them as preconditions and no descriptor is a scheduler identifier.
- Status `authority_handoff` recovery is also read-through from the submitted runtime spec. It does not add ES run persistence, and it does not expose backend job/allocation IDs.

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
- The current supervisor/helper implementation owns endpoint serving,
  helper-private SPIRE traversal, readiness-before-workload, helper death
  handling, and fixed root-to-workload privilege boundary enforcement.
- SPIRE owns JWT-SVID issuance behind the helper. Vault owns token, secret,
  and lease issuance after workload-side login.

**Implementation invariant**

- ES currently protects the reserved runtime paths backing the discovered endpoint from caller mount overlap.
- The first platform-owned runtime-identity slice must preserve a helper-private raw SPIRE channel and fixed non-root workload launch semantics before any JWT retrieval is considered complete.
- The runtime helper now retries its first bounded JWT-SVID fetch within the existing readiness timeout so transient helper-private SPIRE socket startup races fail less often without widening the workload-visible contract or bypassing helper readiness.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is bounded workload-visible discovery
  only. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- Current helper start as `0:0`, Nomad task `User: "0:0"`, fixed workload
  `10000:10000`, helper-private SPIRE traversal, and reserved-path surfaces
  are bounded or compatibility-heavy implementation surfaces, not final
  generalized architecture.
- `authority_handoff`, `outcome_evidence`, retained bundles, support bundles,
  logs, traces, reports, profiles, and `.out` artifacts remain
  non-authority evidence/projection rather than runtime-identity or
  credential authority.

**Deliberate absence**

- ES does not become the long-lived runtime credential owner behind the reserved path; runtime-side delivery remains owned by the platform helper launched with the workload.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.

### `mounts.go`

**Observed current implementation path**

- `validateRuntimeMounts` runs during prepare-time request validation.
- It enforces:
  - max mount count
  - read-only mounts only
  - absolute cleaned target paths
  - target paths under `/execution/mounts`
  - no overlapping mount targets
- Submit resolution validates mount archives before freeze. For each mount
  artifact it:
  - re-fetches and revalidates aggregate evidence and trust
  - fetches payload bytes within the smaller of the 8 MiB per-mount transport
    budget and remaining 32 MiB aggregate transport budget
  - performs exactly one gzip/tar traversal through a limiter placed between
    gzip and tar: 16 MiB per mount and 64 MiB aggregate across mounts
  - counts tar headers, PAX/GNU extension records, resolved names, padding,
    entry bodies, end/trailer records, and trailing decompressed bytes within
    that same whole-stream budget; the compressed transport budget separately
    includes gzip framing and trailer bytes
  - validates regular-body declared size against the 8 MiB per-mount and
    32 MiB aggregate body budgets before creating a checked allocation size
  - preserves PAX local-header and GNU long-name support under the stream
    budget, without a separate 4096-entry or 4096-byte-name rule
  - validates entry types and archive-relative paths before transferring file
    contents into private material
- Post-freeze mount materialization does not parse gzip or tar. It:
  - retains the transferred compressed buffer only within governed material
    accounting and does not write or reparse it
  - materializes only the already validated ordered directory/file entries
    through the held run-root descriptor into a per-mount contents directory,
    using no-follow ancestor traversal and exclusive file creation
  - rejects symlinks, hard links, special files, and extraction escapes
  - verifies type, device, link count, owner, and mode on opened objects rather
    than relying on later path lookup
- A mount-specific mode normalizer retains only executable intent from an
  archive: mount directories are `0755`, ordinary files `0644`, and executable
  files `0755`. The narrow custody file writer uses mount-directory mode for
  its parents while registering the exact owner, object identity and mode in
  the same expected tree. The claimed run root remains `0750`; generic payload,
  runtime-support, platform, trust, result-auth and other non-mount staging
  keep private modes. The provider bind remains read-only. This source repair
  does not observe or qualify the later Docker/Nomad mount topology.
- Review-07 repairs the independently found CUSTODY-MODE-01 check without
  changing those creation modes. Expected-tree handoff validation and the
  claimed-root check compare raw Unix mode under `S_IFMT | 07777`: file type,
  ordinary permissions, setuid, setgid, and sticky bits. They do not compare
  size, timestamps, or unrelated flags. The object-identity predicate remains
  separate so controlled ownership/mode transitions can still prove they refer
  to the same object. A recorded-mode mismatch fails closed before Nomad
  registration and does not repair or remove the retained object. Source and
  synthetic tests do not qualify a native runtime or mounted topology.
- Review-08 closes the registration-time REGISTRATION-MODE-01 gap by checking
  each newly created child directory and regular file against its intended
  Unix type and complete `07777` mode after controlled `Fchown`/`Fchmod` and,
  for files, content write and `Fsync`, before recording the descriptor stat in
  the expected tree. The check uses the same narrow recorded-mode relation;
  object-only pathname binding and within-pass stat stability remain separate.
  A mismatch leaves the child unregistered and retained under the claimed root,
  without chmod, chown, unlink, replacement, or provider submission. A later
  handoff sees the retained child as unexpected. At that Review-08 source
  stage, independent assessment and native runtime evidence remained open;
  missing historical Review-08 runtime records are not reconstructed by later
  selected evidence.
- No temporary mount archive is written or removed during staging. A claimed
  root remains retained even when materialization fails partway through.

**Implementation invariant**

- Runtime mounts are prepared from governed artifacts, not arbitrary host paths.

**Current simplification**

- Mount staging is folded into the submit path instead of being split into a separate artifact-preparation subsystem.

## 10. Filesystem and local side effects

Submission has visible local side effects under the configured staging root.

**Observed current implementation path**

- When submit is configured, startup qualifies staging and results as one
  descriptor-held root pair, provisions each missing configured-root component
  only through the currently qualified parent, reacquires the pair after every
  component, probes staging and results primitives separately, and performs a
  final re-observation before readiness.
- `Service.Submit` is the only production caller of
  `resolveExecutionForSubmit`; after that resolver freezes the typed plan,
  Submit qualifies a fresh root pair, compares the held owner with the frozen
  owner, reobserves immediately before claim, and transfers the qualified
  staging descriptor to `claimStagingCustodyFromQualifiedRoot`.
  `materializeExecutionInputs` then consumes only the resolved run, host, and
  material projections plus that claimed custody to create the current
  run-scoped execution-package layout:
  - `<staging_root>/<run_id>/payload`
  - `<staging_root>/<run_id>/run`
  - `<staging_root>/<run_id>/run/result`
- Payload bytes are written to:
  - `<staging_root>/<run_id>/payload/artifact.tar.gz`
- Mount staging uses the same run-scoped layout and creates:
  - `<staging_root>/<run_id>/mounts/<index>/contents`
- Retained result bundles are written outside staging under:
  - `<results_root>/<run_id>/result.tar.gz`

Runtime-path effects in the Nomad job spec are now assembled from that same internal layout:

- Host `payloadDir` is bind-mounted to `/execution/staged`
- Host `runDir` is bind-mounted to `/execution/run`
- The reserved workload result directory is visible as `/execution/run/result`
- The directory containing the configured SPIRE Workload API socket is bind-mounted under the helper-private runtime-identity internal subtree, and the runtime supervisor materializes the fixed helper-private socket alias from that mounted source directory
- Runtime identity workspace is mounted as tmpfs at the run-scoped workspace derived from the discovered endpoint

Staging custody and retention visible in code:

- No run-scoped filesystem side effect starts before resolved-plan freeze.
- Exclusive `mkdirat` of `<staging_root>/<run_id>` is the first filesystem
  mutation. A pre-existing object of any type refuses the claim and is never
  adopted or reopened.
- The claimed directory is opened no-follow, verified by device/inode identity,
  normalized through descriptor-based owner/mode operations, and held with its
  parent descriptor until the complete expected tree is revalidated immediately
  before handoff. Expected ownership is an invocation-local hierarchy: the root
  and every expected directory own only their direct-child maps, and each
  parent-to-child edge owns its segment bytes and identity once. No cumulative
  path or second full-path index is retained. Revalidation keeps a directory's
  identity descriptor separate, opens a fresh independent no-follow open-file
  description at `"."`, proves the fresh description identifies the expected
  directory, and uses that fresh description directly as the enumeration
  stream. It rejects missing, duplicate, malformed, or unexpected names and
  rechecks every expected child's no-follow type, device, retained identity,
  owner/group, mode, and link-count policy. Construction is linear in traversed
  path-segment occurrences; retained variable data is linear in unique
  edge-segment bytes plus expected nodes; validation uses the expected tree plus
  one fixed enumeration batch. These are structural bounds, not exact Go heap,
  allocator, stack, descriptor, RSS, or secure-erasure claims. Enumeration is
  bounded operation-local completeness validation, not reusable residue
  discovery or reclamation scanning.
- Regular expected children require link count exactly one. Expected
  directories require a positive link count because their count may grow as
  expected child directories are materialized.
- Payload, runtime-support, trust, and mount descendants are created through
  the held descriptor. Direct staging `MkdirAll`, `WriteFile`, path-separated
  `Lstat`/`Lchown`/`Chmod`, and post-hoc `EvalSymlinks` containment are not used.
- Every post-claim return retains the visible run root. Failed or partial
  materialization, ambiguous or successful registration, all lifecycle states,
  and all retained-result outcomes have the same retention consequence.
- Incomplete exclusive leaves, unpublished result or normalization temporaries,
  and startup capability-probe fixtures remain retained when exact effect-time
  object identity cannot be proved. No pathname-based cleanup, scan, or
  whole-root reclamation is selected.
- ES attempts idempotent retained-result capture from `<staging_root>/<run_id>/run/result` when `status`, `logs`, or `result` observes terminal execution.
- Result capture may use `openStagingTree` to reopen a retained root read-only
  solely for packaging. The handle exposes verification, read-only directory
  opening, and close operations only; it has no mutation, deletion, adoption,
  cleanup, quarantine, or reclamation method. Result capture never reopens a
  staging root for deletion and never authorizes staging mutation.
- The runtime-identity workspace is not host-backed by the submit path.
- Retained result bundles are stored independently under `execution.results_root_dir`.

**Current simplification**

- Local staging is a direct filesystem side effect of submit, not a separate managed artifact-execution cache.

### Filesystem capability and trust boundary

Startup qualifies configured staging/results roots and the local syscall
mechanism by behavior. The probe is small, local, stateless, and fail-closed.
Submit and retained-result effects perform fresh visible-object and topology
re-observation at their named boundaries; lifecycle does not repeat the startup
behavior probe.

- Linux uses `openat2` with beneath/no-symlink/no-cross-device resolution and
  `renameat2(RENAME_NOREPLACE)`.
- Darwin uses component no-follow-any opens, device verification, and
  `renameatx_np` with exclusive/no-follow-any flags.
- There is no runtime OS-label selection or silent fallback.

The ES service UID is one trusted security principal. The implementation
detects accidental same-UID identity changes, but Unix does not provide a fully
conditional final unlink against an actively malicious same-UID process or
root. Hostile same-UID/root mutation is outside this bounded contract. Linux
mount-crossing behavior requires real governed-host validation; Darwin tests
and Linux cross-compilation are not substitutes.

### Resource acquisition and material ownership

Dependency JSON bodies are limited to 256 KiB before strict decoding. The
Admission Policy Layer payload remains 256 KiB, the primary Submit payload is
32 MiB, and mount transport is 8 MiB per mount/32 MiB aggregate. Runtime
support is a stable no-follow regular file limited to 32 MiB. Normalized Vault
CA and system CA sources are each 256 KiB; the combined bundle is at most
524,289 bytes.

Accepted bulk buffers transfer into `resolvedExecutionMaterial`; material
construction does not recopy primary payload, runtime support, compressed mount
buffers, parsed entry bodies, or trust bundles. Vault and selected system CA
inputs are normalized once, and combined-bundle assembly consumes those
normalized inputs directly rather than normalizing or copying either input
again. The portable retained variable byte-content ceiling is 168,558,593
bytes, with 168,820,737 bytes as the peak accounted content during trust
assembly: retained material plus the one temporary normalized system-CA input.
These are explicit byte-accounting contracts, not exact Go heap/RSS
guarantees.

## 11. Nomad and Docker interaction

`submit.go` and `lifecycle.go` together define the current Nomad/Docker interaction path.

**Observed current implementation path**

- `buildNomadJobSpec` assembles the Nomad job payload.
- The current job spec is:
  - one batch job
  - one task group
  - one task named `task`
  - Docker driver
- One pre-freeze private typed command selects executable
  `/execution/run/platform/es-runtime-support` and the fixed supervisor
  arguments for payload archive, work directory, result directory, entrypoint,
  effective timeout, separator, and original workload argv. The runtime helper
  performs the existing unpack/setup/launch behavior. No execution-package or
  test helper owns a second full supervisor grammar.
- B1 protects the complete default-profile job with one source-distinct direct
  literal expected job, a direct pointer-owned token/template ledger expanded
  only in the expected tree, the unmodified actual tree, and a separate direct
  literal public authority-handoff expected object through real
  `Service.Submit`. A finite package-local direct-call closure plus exact
  producer, freeze, validation, payload-projection, and metadata inventories
  and bounded mutants make no whole-program proof claim. Tranche B2 now
  completes a separate source-distinct direct literal job and authority-handoff
  golden for `control-plane-normal-shell/v1`; it is ES profile-coverage
  evidence, not a snapshot of the current Control Plane request or a transfer
  of CP authority. The dedicated B2 assurance remains finite, explicit,
  source-bounded, and reviewable rather than a general source, logging, alias,
  taint, SSA, or whole-program analyzer.

Structured Nomad registration, projected-allocation-list, and
allocation-detail responses use the existing 256 KiB control-JSON boundary
and exactly one compatible JSON document. Unknown provider fields remain
accepted, and non-success bodies are neither consumed into public errors nor
ordinary logs. Job-summary reads remain explicitly unbounded but
one-document because admitted caller-environment aggregates are currently
unbounded and Nomad echoes `Task.Env`. Successful authenticated public Logs
remain unbounded opaque workload-output bytes. B2 selects neither a universal
provider-response limit nor a workload-output limit. `preparedAdmission`
ordinary formatting is fixed-redacted and ordinary JSON remains `{}`; this is
bounded defense in depth, not reflection, `unsafe`, malicious same-package,
arbitrary-serializer, or secure-erasure protection. Reliable keyed-submit
runtime remains unwired, and native Linux runtime validation remains pending.

The rejected 2.9 MB position-indexed B2 guard is not accepted assurance. The
compact replacement is behavior-first, uses directly authored position-
independent local reflection and a narrow named-file golden AST check, and
constructs cancellation directly with the exact non-purging query
`purge=false`; no private purge option or generic query-options seam remains.
Its field inventory fixes current public execution JSON and only the eight
Nomad decode shapes and fields production consumes. It does not reject unknown
incoming provider fields. `preparedAdmission` claims are limited to ordinary
formatting, formatted standard-library logging, ordinary JSON, marker
placement, and field visibility. Existing `fetchJob` and authenticated public
Logs exceptions are unchanged. Provenance proves byte identity only.

Arbitrary expected-literal honesty, aliases, helper flows, secondary cause or
logging flows, custom logging sinks, same-package aggregate conversion, and
whole-runtime reliable-submit nonwiring remain fresh-audit obligations. No
positional records, replacement-output workflow, package source graph, source
fingerprint, generated inventory, or general analyzer is selected. The private
reliable-submit foundation remains present and runtime-unwired, and public
Submit remains unkeyed.

Current job-spec assumptions:

- restart attempts: `0`
- reschedule attempts: `0`
- network mode:
  - `none` when signed aggregate evidence execution claims carry
    `network_access=false`
  - `bridge` when signed aggregate evidence execution claims carry
    `network_access=true`
- image:
  - default executions use `execution.base_image`
  - `control-plane-normal-shell/v1` executions use `execution.runtime_profiles.control_plane_normal_shell.image`
- For repo-owned readiness checks, an enabled `control-plane-normal-shell/v1` profile also requires the configured image to be present in the Docker daemon used by Nomad before `submit-ready` is claimed. This is a substrate/tooling readiness check; it does not change ES result-retention semantics.
- For that supported-local runtime-profile surface, readiness also requires Nomad's Docker client options to report `docker.cleanup.image=false`. The configured profile image is local proof/runtime material, so ES-supported readiness must not claim repeated-run durability while Nomad can remove that image after stopped allocations.

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

## 12. Retained result implementation

`results.go`, `lifecycle.go`, and `executionpackage.go` together implement the current retained-result slice.

**Observed current implementation path**

- `executionpackage.go` reserves host path `<staging_root>/<run_id>/run/result` and container path `/execution/run/result`.
- The runtime supervisor creates the result directory as workload-writable before launching the fixed non-root workload process, temporarily widens only the bind-mounted `/execution/run` traversal and the workload-facing non-secret trust-file readability needed for the current `10000:10000` no-supplemental-groups boundary, then performs the current post-workload normalization phase after workload exit.
- That post-workload normalization phase now restores the helper-managed host-backed `run/work` and `run/result` trees to the target owner carried in reserved internal `EXEC_PLATFORM_STATE_OWNER_*` runtime env when present, otherwise falling back to the current process owner, keeps `run/platform` as the stable marker authority, and emits `run/platform/ownership-normalization.json` only after the phase succeeds.
- The same post-workload normalization phase also restores the active runtime widening on the bind-mounted `/execution/run` parent and the staged non-secret trust files under `run/platform` before ES retained-result preflight reads that tree.
- If marker write or marker validation fails after normalization, the supervisor treats the post-workload normalization phase as failed.
- The shared ownership-normalization validator now exposes two documented modes: current Alpha compatibility mode allows missing marker and accepts structurally valid present-marker evidence without requiring target-owner proof, while future non-root-required mode requires marker presence plus expected-owner verification against `target_uid` and `target_gid`.
- `Status` attempts retention whenever it observes terminal execution.
- `Logs` attempts retention whenever it observes a terminal task.
- `Result` first serves an already retained bundle if one exists, then falls back to Nomad-backed terminal lookup and one idempotent retention attempt.
- Terminal retention itself authenticates an existing complete pair before
  traversing staging or making a candidate. A valid pair remains the selected
  bytes after staging changes or disappearance; a partial or invalid pair
  fails closed. Only already prepared concurrent candidates can leave a
  publication loser temporary under the no-uncertain-unlink rule.
- Retention now performs a repo-local filesystem preflight before bundle creation so unreadable or unsupported result trees fail closed before ES writes a retained bundle.
- That retained-result preflight now also validates the ownership-normalization marker when the marker is present under `run/platform`, but current Alpha-compatible behavior still accepts a missing marker and does not require expected owner verification by default.
- Retention derives the target owner from the qualified results-root handle, packages result contents into `<results_root>/<run_id>/result.tar.gz`, and preserves validated normalization evidence independently. The selected R1 refinement hashes the compressed writer output, keeps and rechecks the candidate descriptor, verifies the installed winner, and exclusively publishes a bounded authenticated `result.commit.v1` record. A public reader authenticates the record and its exact buffered result bytes before success. An unmarked pre-existing final is unavailable and never adopted; existing objects are checked without mutation. Submit requires a qualified staging/results pair with a matching owner model before claim.
- Repeat retained-result reads validate existing result directories, bundles and normalization evidence without ownership or mode syscalls, root provisioning, arbitrary-tree recursion or bundle-content interpretation.
- The private key is loaded once from an explicit qualified no-follow regular file at configured-submit startup, including the canonical supported-local `BRINGUP_PROFILE=prepare-only` sequence because its generated ES config retains Submit fields. Synthetic tests can exercise the byte protocol; file shape/ownership checks do not prove deployment key isolation. No key is sent to a workload, provider or public response. A genuinely Submit-disabled service has no verifier, and retained result reads remain fail-closed.
- Key exclusion uses the normalized effective roots, while the configured
  canonical key path and its derived parent retain significant component
  whitespace during no-follow opening. Internal ancestry re-observation of a
  qualified parent, and descriptor-presentation rewalk, use the same exact
  component spelling without a second outer-whitespace trim. The held result descriptor is checked
  against the full metadata policy before response buffering.
- The configured key path must have a non-root parent directory. The loader
  uses that parent as a qualified no-follow directory and refuses `/key` before
  any credential read or execution-root provisioning. Supported-local setup
  renders stable non-secret store/key IDs and an external key-file reference
  into ES configuration only after a lexical preflight; the wrapper forwards
  the reference to the guest without reading or transferring key bytes.
  The wrapper's `bash -s -- setup` transport must dispatch the unmodified
  setup file once with explicit repository-root input. File invocation also
  dispatches; sourcing exposes functions without setup effects. Wrapper
  preflight requires a clean single-leading-slash non-root spelling for owned
  proof, bootstrap, repository and host collection scopes. It rejects
  key/scope overlap before the host proof existence check, any workspace write,
  guest contact, or EXIT finalizer.
- A newly created result run directory is used only if its natural owner and mode already match the required values; a restrictive umask or unexpected owner fails closed without chown/chmod repair. Failed result temporaries remain under that directory when pathname ownership cannot be proven for deletion.
- Configured Submit startup probes that natural `0750` result run-directory
  behavior under the active process mask using an exclusive synthetic child
  under the qualified results root. It never chowns or chmods the child and
  retains the fixture under the no-uncertain-unlink rule; genuinely
  Submit-disabled service startup does not probe. The selected supported-local
  root-service profile provisions only the two fresh configured roots as
  UID:GID `0:0`, exact `0755` directory mode. Its static bring-up check does
  not replace this later behavioral probe or qualify a future container view.
  Full-profile submit-readiness and diagnostics consume the same read-only
  static validator, including proof binding, selected image and Dockerfile,
  owner/mode/identity, and exact same-path read-write mounts. Only this
  validated profile omits the ordinary operator's write test; generic
  readiness still requires existing caller-writable roots and creates none.
  Setup retains only a fixed safe projection of its static configured-root
  check, without raw root paths, key contents, or a container-capability claim.
  The setup helper keeps each newly opened child descriptor from the
  pre-mutation name/device/inode/type check through owner/mode normalization
  and final pair revalidation. It closes all held descriptors on refusal and
  leaves partial objects in place under the existing no-uncertain-cleanup
  rule. The proof parent remains operator-owned; `mkdir` and subsequent
  descriptor acquisition are separate operations, so this source check does
  not qualify arbitrary concurrent pre-acquisition substitution.
- Empty or missing result directories do not produce a bundle.
- The isolated candidate does not perform successful-stage cleanup or a cleanup-readiness preflight.
- When future non-root-required expectations are supplied, the same preflights also require marker presence, require `target_uid` and `target_gid` to match the expected ES owner, and require stat-based proof that the packaged or deleted tree is owned by that same expected ES UID:GID.
- The former Remote Alpha writable-state readiness and ES service-user helper
  modes are retired. Archived v1 output is historical evidence only; it cannot
  authorize current readiness, migration, drain, reclamation, or mutation.
- The retained bundle is served as `application/gzip` with outcome evidence that labels the source as the ES retained-result store, observation as `retained_result_bundle`, and access class as `opaque_result_bundle`.

**Implementation invariants**

- Retention is keyed by public `run_id` but does not create a durable lifecycle record.
- Retention is idempotent and safe across repeated `status`, `logs`, and `result` calls.
- Result bundles are opaque to ES; ES does not parse workload-authored files for Control Plane semantics.
- Result outcome evidence does not include host paths, archive entry lists, payload interpretation, or provider terminal proof when the request can be served from an already retained bundle without runtime lookup.
- Result retention and staging retention are independent; result behavior never authorizes staging deletion.

**Current simplification**

- There is no background result-retention worker. The current slice captures results synchronously during lifecycle/result observations.

## 13. Test-backed implementation facts

The most important implementation facts are backed by integration tests:

- `es/app/app_integration_test.go` exercises the live `:prepare` path and confirms that ES now returns bounded preflight success without leaking the richer composition data it still assembles internally.
- `es/app/submit_integration_test.go` confirms the live `:submit` wiring into Nomad and Docker, including network-mode selection, runtime-identity tmpfs mounting, environment injection, governed artifact mounts, and lifecycle still working after submission. Its failed-allocation assertion includes bounded test-owned stdout and stderr when available, without treating logs as success authority.
- `es/admission/writablestate_readiness_test.go` covers repo-local non-root writable-state readiness using owner-only temp-dir permissions as the future `es:es` stand-in, including submit-side staging, retained-result fail-closed behavior, successful, failed, lost, and canceled terminal-state staging semantics, repeat retained-result reads without staging mutation, preserved independent normalization evidence, pre-dispatch custody refusal without partial deletion, current Alpha-compatible ownership-normalization marker validation, and future non-root-required marker plus expected-owner enforcement.
- The submit-side staging implementation now reconciles the run-scoped stage root itself to the owner model derived from `execution.staging_root_dir`; future writable-state readiness depends on `<staging_root>/<run_id>` being ES-traversable and ES-deletable, not only on the child `run/platform`, `run/work`, and `run/result` directories.
- The existing-host writable-state ownership-preparation route at `scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh` is a fixed, effect-free exit-2 tombstone. It performs no current host or artifact inspection, mutation, repair, quarantine, or evidence production. The six retired internal routes and their unchanged public-wrapper delegators are bounded by `.docs/system_overview/remote_alpha_beta_es_writable_state_ownership.md`; no v2 replacement or current existing-host migration authority exists for this family. Historical ownership-normalization artifacts and old helper tests grant no current operational permission.
- ES still validates existing result objects and normalization evidence without in-place metadata repair, and it may initialize owner and mode on newly created unpublished result temporaries, records, and normalization evidence. Existing-object repair and deletion based on an uncertain pathname are unsupported; retained staging and result-side proof do not grant a later cleanup or quarantine authority.
- `es/app/operator_scripts_integration_test.go` confirms the primary operator bring-up path can start ARS -> EGS -> AGS -> ES -> Nomad in the current full profile, re-run the unified readiness check, and drive the lifecycle helper through public `run_id` only.
- The same operator-script coverage now also confirms that the readiness helper distinguishes service health, prepare-ready state, full submit-ready state, and missing configured runtime-profile images instead of treating ES `/health` as sufficient on its own.
- Repo-local integration harness workspaces created by `newExecutionWorkspaceTempDir` now live under `.out/<prefix>*` rather than at the repository root; this is a local generated-artifact convention for test and operator inspection, not a public execution contract.
- `es/admission/executionpackage_test.go` confirms the run-scoped execution-package layout localizes host staging, runtime paths, wrapper assembly, and base runtime mounts.
- Runtime-profile unit coverage confirms `control-plane-normal-shell/v1` is rejected when unknown/disabled or when network access is absent, and confirms the selected profile injects only non-secret Codex metadata while selecting the configured profile image.
- `es/app/lifecycle_integration_test.go` confirms status/logs/cancel are projected from Nomad through the narrowed public DTOs, that failed workloads still surface through `200` status responses, that logs return `409` before readiness, and that Nomad unavailability surfaces as `503`.
- Result integration coverage confirms the Control Plane caller can submit a current-slice static-script workload, wait for terminal status, fetch the retained result bundle while the same staging root remains, receive `404 result_not_found` for terminal runs with no result files, receive `403` as a disallowed caller, and repeat result fetches idempotently.
- `es/admission/runtimeidentity_test.go` confirms reserved runtime path overlap is rejected while `/execution/mounts/...` remains allowed.
- `es/app/observability_integration_test.go` confirms inbound request wrapping and outbound dependency-edge logging, including trace propagation across ES -> ARS health checks.
- `es/app/execution_loop_integration_test.go` confirms the end-to-end implementation path can drive publish -> prepare -> submit -> status/logs summaries without an ES-owned run store.
- The supported-local proof scripts now build and configure the repo-owned Control Plane normal-shell runtime-profile image with the proof-only Codex shim realization, include the proof Vault CA bundle in the workload-zone Vault runtime-config blob, seed proof-scoped Codex credential material in Vault, run a profile-selected CP-shaped runtime-contract workload, fetch the retained result bundle, and validate the expected proof artifacts. That proof validates the profile image/tooling guarantee, workload-side credential acquisition over verified Vault TLS, proof Codex invocation through `EXEC_CODEX_CLI_PATH`, deterministic workspace mutation, a retained workspace diff that includes tracked changes and proof-created untracked files, and retained-result delivery, but it intentionally does not prove real upstream Codex service behavior.

Operator helper ownership in the current slice:

- `scripts/01_bringup.sh` is the primary stack bring-up and shutdown entrypoint.
- `scripts/generate_control_plane_dockerfile.sh` is the source-of-truth generator for the default shared service-image Dockerfile projection at `.out/Dockerfile`; bring-up regenerates that file before building, and the generator integration test fails if the tracked projection drifts from fresh output.
- `.out/` is the repo-local generated-artifact sink in the current slice; `.out/Dockerfile` is the only tracked generated projection there and must not be treated as independent runtime authority, while kept integration harness workspaces (for example `es-submit-*`) are created beneath `.out/`.
- `scripts/10_health_check.sh` is the unified readiness verifier for service health, runtime-config blob availability including any supplied Vault CA bundle shape, Nomad, Docker, and required enabled runtime-profile images.
- For enabled runtime-profile images, the same readiness verifier also checks the supported-local Nomad Docker image-cleanup guardrail before claiming submit-ready.
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
- the compact troubleshooting matrix for those categories lives in `.runbooks/system/v1_bringup.md`; later helpers point operators there for the matching logs, readiness checks, staging-inspection guidance, and next action
- `scripts/50_lifecycle.sh` now observes execution strictly through public ES lifecycle endpoints rather than through Nomad job/eval IDs.

## 14. Current simplifications

**Current simplifications**

- `Prepare` is a bounded but live code path.
- `Prepare` and `Submit` now share one internal admission helper instead of maintaining separate admission pipelines.
- ES has no lifecycle store and uses one explicit internal execution-locator policy whose current lookup is `run_id -> exec-<run_id>`.
- Lifecycle uses one explicit projected-allocation policy instead of a broader allocation model.
- Log retrieval is a minimal latest-allocation stdout path.
- Result retrieval is a retained tar.gz bundle path for `/execution/run/result`, not a broad output platform.
- Outcome-evidence descriptors are additive labels for current response sources, not a broad evidence store or revision model.
- There is no retry or reschedule machinery in ES.
- Runtime identity handling is reservation and path protection, not token ownership or endpoint implementation.
- Authority handoff reporting is non-secret submit/status read evidence, not a live credential observer.
- Runtime-trust loading is startup-time initialization rather than a live refresh path in the current slice.
- The private operational handoff path, which has no production caller, confirms its commissioned trust with EGS before a retained first effect and refuses when the last confirmation is older than 30 seconds. It does not adopt new trust while running, and ordinary Submit does not confirm.
- Aggregate evidence is the only first-class admission input for the published artifact path.

These are active implementation choices, not automatically permanent design commitments.

## 15. Deliberate absences

**Deliberate absences**

- No run persistence
- No background lifecycle workers
- No retry or reschedule orchestration
- No multi-allocation aggregation
- No streaming log implementation
- No streaming result implementation
- No result-content interpretation by ES
- No ES-owned checkpoint or terminal decision persistence
- No token minting or token population in the ES runtime-identity workspace
- No scheduler abstraction above Nomad in the current slice

## 16. Current implementation pressure points

**Reopened implementation seams under visible pressure**

- `Prepare` is live and important in code even though it is still described as bounded.
- Admission logic now treats aggregate evidence as canonical with no remaining legacy fact fallback or side path.
- The current execution-locator policy still resolves `run_id -> exec-<run_id>`.
- Latest-allocation selection is simple and coherent only because the slice avoids retries and reschedule.
- Runtime identity handling and retained-result materialization both depend on reserved `/execution/...` path conventions.
- Submit currently depends on runtime-facing payload discoverability plus evidence-claim cross-checks between artifact identity and payload identity.
- The implementation is coherent today as a thin composition and handoff layer, but several of its shortcuts are still under redesign pressure rather than being settled structure.

## 17. Relationship to other docs

Use the companion documents for other kinds of authority:

- `.docs/execution_lifecycle/contracts.md` for public endpoint, response, and error semantics
- `.docs/execution_lifecycle/design.md` for lifecycle design and authority boundaries
- `.docs/system_overview/contracts.md` for cross-service contract context
- `.docs/system_overview/boundaries.md` for service ownership and non-ownership
- `PLANS.md` for redesign sequencing and reopened architectural decisions

This file should stay focused on code paths and side effects.

## 18. Reopened implementation seams

- The implementation role of `Prepare`
- The internal reuse of `Prepare` by `Submit`
- Internal execution-locator policy
- Latest-allocation selection path
- Runtime identity reserved-path handling
- Current execution-package layout and container path conventions behind submit
- Current retained-result packaging and `/execution/run/result` convention
- The extent to which current lifecycle minimalism is implementation convenience versus durable structure

These seams are active today and intentionally not fixed.

## 19. Decision rules for future edits

- Keep this file implementation-level, not contract-level.
- Do not omit active code paths from the implementation map.
- Public semantics belong in `.docs/execution_lifecycle/contracts.md`.
- System ownership belongs in `.docs/system_overview/boundaries.md`.
- If code and tests disagree with this file, update this file to match reality.
- Label current simplifications explicitly.
- Do not describe an implementation shortcut as a durable invariant without support.

## 20. Final-audit repair implementation details

`mounts.go` validates each archive namespace with an invocation-local
compressed byte-radix ledger. Production work accounting is optional and
private, and increments only at actual probe, byte-comparison, child-lookup,
node/map/branch allocation, and commit sites. Traversal and commit are
iterative; labels are retained-name substring views; no per-segment node set,
prefix reconstruction, recursive walk, or accumulated-map descendant scan is
used. Entry registration remains after all fallible work so the established
error order is unchanged.

`execution_roots.go` owns the portable operation-local pair state, descriptor
ownership, missing-suffix intent, revalidation schedule, and idempotent close.
`execution_roots_linux.go` binds `fstat` to complete `statx` identity,
canonical `/proc/self/fd` presentation, strict no-follow rewalk, and a stable
bounded mount-ID-selected mountinfo snapshot. The parser accepts unknown
bounded optional fields, parents outside the visible root, and one unique `/`
top self-parent. Its tagged root representation distinguishes canonical
pathname roots from opaque `nsfs` namespace-object roots. The latter accept
only the upstream operation names `mnt`, `net`, `uts`, `ipc`, `pid`, `user`,
`cgroup`, and `time` with a canonical decimal inode envelope; the digits are
not parsed and receive no limit beyond the existing bounded record. All such
records stay in count, uniqueness, graph, stacking, and descendant checks.
Only pathname roots reach source-coordinate joining. A selected opaque root
returns a dedicated refusal before device comparison or path arithmetic, and
the implementation never manufactures a path or substitutes mountpoint or
configuration. The parser continues rejecting duplicate IDs, nontrivial
cycles, non-top self-parent records, malformed paths/labels/escapes, unsupported
non-path classes, incomplete masks, mismatched devices, and ambiguous/unstable
input. `execution_roots_darwin.go` binds `F_GETPATH`,
no-follow rewalk, `fstatfs`, and bounded `getfsstat`; same-FSID distinct
presentations are intentionally unsupported.

Startup plans both roots before mutation, creates one missing staging component
at a time, reacquires the pair after each creation, proves again before the
first results component, repeats that schedule for results, probes both
selected filesystems, and performs a final acquisition. Submit acquires after
the resolved-plan freeze, compares the held owner with the frozen owner,
reobserves immediately before claim, and transfers the qualified staging
descriptor to the production claim constructor. The path-taking claim wrapper
is test-only.

Result paths open one pair and revalidate before current named descriptor-
bound directory creation, temporary creation, new-object initialization,
no-replace final/record publication, and authenticated read/check. `Fchown` and
`Fchmod` initialize newly created unpublished result temporaries/records and
newly created normalization evidence; they do not repair existing directories,
finals, or evidence. Pair proof is a prerequisite for those operations, not an
independent deletion or metadata-repair authority. No result pathname cleanup
or existing-object reconciliation is selected; incomplete leaves and uncertain
temporaries remain. Streamed reads/writes on an already-held descriptor do not
reacquire topology. Retained-first reads accept missing staging intent, never
create a missing results root, and never convert a topology error into Nomad
fallback. An existing final is publicly eligible only with its authenticated
completion record; an invalid or unmarked pair is refused without adoption.

The current stable-service-namespace/trusted-operator assumption is explicit:
the last check is not atomic against a privileged mount or hostile same-UID
rename in the final syscall window, and concealed backing-store aliasing is not
claimed. Modeled tests are not mounted-topology evidence. C's selected native
observations remain historical exact-source evidence, not an execution of the
then-unaccepted integration. Focused changed-interaction review/validation and
a separately authorized commit were pending at that gate; PR #8 later
completed source publication only. Deployment observation, mounted
fixtures, native Linux validation, and key/capacity/residence/reclamation
requirements remain operational gates for claimed environments; they are not
a blanket local source-preservation or integration commit gate.
