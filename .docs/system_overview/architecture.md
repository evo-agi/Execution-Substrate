# System Architecture Map

## 1. Purpose and status

This document is the top-level architecture map for the Go repository.

It describes the current system in the repository's bounded platform phase. The architecture documented here is real and implemented, but several major seams are intentionally reopened in `PLANS.md` and must not be treated as settled merely because they are active today.

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

## 3A. Program orientation

Execution Substrate is the primary governed execution system in this repository. The current foundational boundary and contract work is part of the ES program because it determines what ES can admit, run, project, retain, and expose safely.

Control Plane is a first non-operator consumer, not an owner of ES core contracts. CP-facing compatibility is important and must remain explicit, but CP documents, probes, examples, or proof-harness expectations do not define ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness semantics.

The next milestone package is ES-owned: Workstream A and Workstream B clarify the shared-kernel and AGS/ARS input boundaries that ES consumes, while Workstream C delivers the ES admission and runtime-boundary realignment.

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
- ES status exposes a bounded `lifecycle_projection` fact derived from Nomad observation so consumers can compare status reads without inferring scheduler identifiers or ES-owned run persistence.
- ES submit/status expose a bounded non-secret `authority_handoff` fact when ES can state the submitted runtime authority path from facts it selected and handed off. This is not live credential state or scheduler identity.
- The Workstream E E0 runtime-config ownership decision lives in
  `.docs/system_overview/runtime_config_ownership.md`: runtime-config
  semantics live in the runtime-config contract surface, ARS owns blob
  storage/read by digest only, and ES is the current consumer and lookup
  orchestrator.
- The Workstream F F0 runtime-identity handoff ownership decision lives in
  `.docs/system_overview/runtime_identity_handoff.md`: runtime identity
  handoff is currently ES-selected and platform-delivered,
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract, the runtime supervisor/helper owns the in-task endpoint
  implementation and helper-private SPIRE traversal, SPIRE owns JWT-SVID
  issuance, and Vault owns token/secret/lease issuance after workload-side
  login.
- Docker is the container runtime used underneath Nomad in the current slice.
- The current slice-0 operator topology runs ARS, EGS, AGS, and ES as containers on one Linux host/VM, while Nomad server/client and Docker run on that same host.
- Those hot-path service containers currently use Docker host networking as temporary compatibility-heavy scaffolding so the existing `127.0.0.1` dependency URLs and ES staging-path locality remain valid during slice 0.
- That one-host Linux topology has now been functionally proved through the real ES -> Nomad -> Docker path on a real Linux VM, and the current supported local reference profile on this Apple Silicon Mac is Lima `qemu` + Ubuntu 24.04 arm64 with pre-managed non-dev Nomad and positive natural `cpu.totalcompute`.
- The previously investigated Ubuntu 24.04 VMware/aarch64 and Lima `vz` Ubuntu 24.04 arm64 local profiles remain unsupported on this Mac because the real service path still leaves natural `cpu.totalcompute=0`.
- Those local qualification results are environment/profile-specific, not evidence that Linux or Docker/Nomad are the wrong platform direction for this bounded phase.
- The supported-environment story for that topology is narrower than the original all-in-one local bring-up convenience path: the intended supported slice-0 environment is a Linux host/VM with a pre-managed non-dev Nomad client/server that is naturally schedulable without `cpu_total_compute` override, while the script-managed local Nomad startup path remains bounded fallback/troubleshooting scaffolding.
- `internal/contracts/evidence/v1` is now the active shared kernel for the primary AGS-published artifact path into ES.
- `internal/contracts/runtimeconfig/v1` is the active shared runtime-config surface for the workload-zone Vault config reference and blob schema.
- ES startup config currently carries the required workload-zone Vault
  runtime-config reference as compatibility/config residue on a reopened
  ownership seam; the startup guarantee is the typed reference, not a new
  startup blob-fetch guarantee.
- `internal/httpx` is cross-cutting transport support for strict JSON request decoding and consistent HTTP response writing.
- `internal/observability` is cross-cutting support, not a system boundary.
- `internal/callerauth` is cross-cutting caller authentication shared by all five services; authorization stays in each service.
- `internal/callerallowlist` is the cross-cutting path-prefix allowlist rule shared by ARS, AGS, and ES: which configured prefixes are valid and how a caller's path matches one. Each of those services owns its own allowlist.

## 5. Primary system flows

### Publication flow

AGS accepts publish requests in the current evidence-native grammar, derives artifact identity from package-facing identity inputs anchored to the payload digest, assembles the current aggregate artifact-evidence record with separate package claims, narrow derivation request-binding authorization claims, a smaller shared execution/runtime contract, and seal, signs that evidence, and writes the canonical publication record through ARS.

ARS then becomes the storage and retrieval boundary for the published artifact material. The current publication flow is `AGS -> ARS`, and downstream consumers do not bypass ARS for published artifact data.

The aggregate evidence model in `internal/contracts/evidence/v1` matters here because AGS emits the first-class publication record that ES later verifies. ARS then exposes a smaller runtime-facing discovery record for ES, while descriptor and manifest support data remain secondary publication discoverability rather than the primary hot-path object.

### Admission / preparation / submission flow

ES is the current admission and submission composition point.

At a high level, ES:

- declares its current governed-execution producer compatibility contract through a narrow read-only `:contract` surface
- accepts execution requests through bounded preflight `:prepare` and primary submission `:submit`
- reads aggregate artifact evidence and payloads from ARS through the primary runtime-facing discovery record
- reads the workload-zone Vault config blob from ARS using the startup-configured `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`
- does that runtime-config lookup directly, with no ACS hop
- loads and enforces the EGS trust model
- stages payload and mount data locally
- hands execution off to Nomad

ES does not own artifact publication, artifact storage, trust publication, or scheduler state. It composes those inputs into a bounded execution decision and submission.

For the workload-zone Vault runtime-config path, ES is the current consumer and
lookup orchestrator only. `internal/contracts/runtimeconfig/v1` owns the typed
semantics, ARS owns blob storage/read by digest, and the current digest-only
reference plus ES startup-config placement remain active compatibility/config
surfaces rather than final architecture.

For the main AGS-published artifact path, ES now requires the aggregate `internal/contracts/evidence/v1` record. Missing or corrupt aggregate evidence is an admission failure, not a reason to re-enter the legacy fact family.

### Lifecycle flow

Lifecycle is Nomad-backed after submission.

ES exposes lifecycle and log endpoints, but it does so by deriving state from Nomad job and allocation data. ES does not keep its own lifecycle store, does not run reconciliation loops, and does not create a separate execution-state authority above Nomad.

### Policy / authorization flow

EGS and CGS occupy different roles today.

- EGS publishes signed runtime trust for signer and artifact trust only, plus
  separate EGS-owned publication metadata outside the signed payload.
- CGS provides a direct authorize-only surface backed by authenticated
  caller/workload identity matching and explicit `id.conf` subject records.
- CGS responses remain bounded to decision and audit facts; they do not become
  runtime auth plans or ES runtime handoff facts.
- The current `GET /v1/trust-model` and `POST /v1/credential/authorize`
  surfaces are v1 compatibility surfaces. `publication.version` and
  `audit.policy_version` are service-owned metadata, not trust-contract or
  transport/API versioning.
- D1 preserves that ES consumes no CGS facts. If a later slice lets ES consume
  CGS output, it must do so through a separately versioned, bounded
  authorization fact such as allow/deny plus opaque decision reference and
  expiry, not through the current CGS v1 subject grammar, role/audit fields,
  runtime auth plans, workload-vault fields, runtime-config refs, credential
  material, or identity-handoff facts.
- D1b keeps any future CGS v2 authorize contract design-only. If later
  implemented, that versioned fact is limited to allow/deny, opaque decision
  reference, and expiry or another bounded freshness indicator if justified,
  with audit/evaluation metadata remaining non-authoritative outside CGS.
- That hypothetical future fact must not carry Vault token material,
  JWT-SVIDs, credential payloads, scheduler facts, ES lifecycle/admission
  facts, workload-zone Vault ownership facts, or Control Plane
  review/approval/checkpoint/finalization semantics.
- D1c keeps any future EGS versioned runtime-trust wrapper design-only. The
  current `GET /v1/trust-model` route plus wrapper/payload shape remain the
  EGS v1 compatibility surface until an explicitly versioned replacement
  exists.
- Any future EGS versioned trust wrapper must distinguish signed
  runtime-trust payload facts, unsigned publication/discovery metadata,
  compatibility routing or API version, and non-authoritative service
  metadata.
- That hypothetical future wrapper must not carry CGS authorization
  decisions, Control Plane review/approval/checkpoint/finalization semantics,
  runtime auth plans, Vault token material, JWT-SVIDs, credential payloads,
  scheduler truth, ES lifecycle/admission truth, runtime-config refs,
  workload-zone Vault ownership facts, runtime identity handoff facts, or
  AGS/ARS artifact-publication authority.
- D1c keeps ES consuming EGS only for signer/artifact runtime trust from the
  signed payload and keeps ES consuming no CGS facts. D1c does not change the
  accepted Workstream B artifact publication/storage/discoverability
  semantics, does not change the accepted Workstream C ES admission/runtime
  public model, and does not settle Workstream E runtime-config ownership or
  Workstream F runtime-identity handoff ownership.
- D1d keeps `id.conf`, the current CGS v1 subject grammar, and
  `policy.id_conf_path` as current-CGS-v1 compatibility/config residue local
  to CGS v1 evaluation only. They are not a shared policy language, not ES
  admission policy input, not EGS trust input, not Control Plane
  review/approval/checkpoint/finalization policy input, and not
  Infrastructure Manager readiness/profile/support-bundle authority input.
- D1d keeps `id.conf` out of Workstream E runtime-config ownership and
  Workstream F runtime-identity handoff. Future policy-input redesign requires
  explicit Workstream D follow-up and a versioned CGS contract if CGS
  semantics change.
- D1b does not expand EGS beyond signer/artifact runtime-trust publication.

CGS is active, but it is intentionally not part of the current ES hot path.

This current split clarifies today’s boundary only. It does not settle
Workstream E runtime-config ownership or Workstream F runtime-identity handoff
ownership.

### Runtime identity / execution handoff flow

ES stages execution inputs, injects the current workload identity endpoint environment variable as the bounded workload-visible handoff, protects the ES-owned runtime subtree that backs the discovered endpoint from caller overlap, and carries a bounded workload-vault handoff derived from workload-zone vault runtime fields plus its default auth mode and optional Vault CA trust material.

The current bounded slice now proves platform-owned runtime identity delivery behind that discovery contract through a same-container supervisor/helper: the helper is the only SPIRE-facing runtime component, the raw SPIRE channel remains helper-private, the workload runs as fixed non-root `10000:10000`, and helper death is task-fatal. ES still stops short of becoming the owner of runtime token minting, runtime identity endpoint implementation inside the workload, or a broader runtime credential lifecycle. ES owns the handoff boundary, not the full runtime credential system.

The `authority_handoff` read fact reports the non-secret handoff path ES submitted: selected runtime profile, workload identity endpoint URI/env, workload-vault auth metadata, selected workload-zone Vault config digest, and bounded profile credential-location metadata when applicable. It does not claim that the workload successfully fetched or currently holds credential material.

The checked-in workload-authored runtime-identity reference remains scaffolding only. It exercises older contract compatibility without defining current ownership. The current bounded runtime-identity slice now also proves useful credential flow through the existing discovery contract: one workload can use the platform-owned endpoint plus the bounded workload-vault metadata to authenticate to a proof-scoped real Vault dev/test target and read one secret without making ES a Vault token broker. Supported-host qualification for the Linux Nomad/Docker substrate is now also proved on the current local reference host, and the canonical repo-owned proof path now records the resulting evidence under `.out/es-proof-<id>/`.

F0 records this current ownership split without making helper/root/Nomad task
user/SPIRE traversal/reserved-path surfaces final generalized architecture.
`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is not raw SPIRE socket exposure, Vault token
brokerage, runtime-config authority, or a secret payload.

## 6. Architectural invariants

**Current architectural invariants**

- ARS is the storage and retrieval boundary for published artifacts in the current system.
- AGS is a write-time publication service, not an execution-time dependency.
- ES is a composition boundary for admission and submission, not a scheduler.
- Nomad is authoritative for submitted execution lifecycle.
- Docker is the task runtime under Nomad in the current bounded execution slice.
- EGS publishes policy; it does not publish runtime state or own artifact execution.
- CGS is a separate authorization boundary and is not in the current ES hot path.
- `internal/contracts/evidence/v1` is the only active shared artifact kernel in the current repo, and its scope must stay intentional rather than expanding casually.
- `internal/contracts/runtimeconfig/v1` is the current typed runtime-config
  schema surface for workload-zone Vault config semantics. ARS blob mechanics,
  ES startup placement, CGS, EGS publication metadata, IM profiles, support
  bundles, CP orchestration state, and evidence/report artifacts are not
  runtime-config authority.
- ES must not bypass upstream ownership boundaries for artifact storage, trust publication, or lifecycle authority.
- ES lifecycle projection revisions are read-coordination facts only; they do not create ES-owned lifecycle state or write preconditions.
- ES-owned contracts are defined by this repository's `PLANS.md` and `.docs/` pages. Control Plane consumption docs may rely on accepted ES surfaces, but they do not widen or own ES core semantics.
- Runtime identity handoff is currently ES-selected and platform-delivered.
  ES owns current handoff selection, env injection, reserved path layout,
  mounts, and Nomad job construction; the supervisor/helper owns the in-task
  endpoint implementation and helper-private SPIRE traversal; SPIRE owns
  JWT-SVID issuance; Vault owns token, secret, and lease issuance after
  workload-side login.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.

## 7. Deliberate absences

**Deliberate absences**

- There is no standalone Deployment service boundary in this Go repo.
- There is no standalone IGS boundary in this Go repo.
- ES does not own a lifecycle-state store.
- There is no general-purpose execution orchestrator above Nomad.
- ES does not own runtime token minting.
- ES does not expose raw SPIRE sockets to workloads and does not own Vault
  token, secret, or lease issuance.
- There is no separate artifact-translation or read-indirection service beyond the current ARS role plus startup-configured runtime-config references.
- The current Go repo does not define a separate lifecycle authority beyond ES projecting Nomad state.

These are current architectural absences, not omissions to fill automatically.

## 8. Current architectural pressure points

**Reopened redesign seams under active pressure**

- `internal/contracts/evidence/v1` is now the only active shared artifact kernel for the AGS -> ARS -> ES path.
- The current named workload-zone Vault config reference and workload-zone Vault blob schema now live in `internal/contracts/runtimeconfig/v1` rather than in ES-local ad hoc shapes.
- ARS currently combines storage integrity, registration, index shape, and canonical artifact retrieval in a way that influences AGS and ES choreography.
- AGS currently owns publication plus evidence and fact assembly for the active artifact model, which makes its publish surface a high-pressure architectural seam.
- ES currently carries the main request and runtime handoff composition burden, though its submit-side package resolution and staging conventions now live behind one explicit internal execution-package layout instead of drifting across helpers.
- EGS currently publishes a specific runtime-trust form that directly shapes execution-time enforcement.
- CGS currently exposes an authorize and policy-input shape closely tied to explicit `id.conf` subject records and caller/workload identity interpretation.
- Runtime identity handoff currently depends on reserved runtime workspace and path conventions that are active but not settled.

## 9. Temporary compatibility-heavy conventions

**Temporary compatibility-heavy conventions**

- `GET /v1/executions:contract` is active today as a narrow producer compatibility declaration for the current CP governed-execution path. It is not a broad capability registry or readiness substitute.
- `POST /v1/executions:prepare` is active today but explicitly bounded as a small preflight-success surface rather than declared as the permanent execution API shape.
- ES startup-config placement of
  `runtime_config.workload_zone_vault_config_ref`, the digest-only ref shape,
  and `workload_vault_auth.default_mode` are compatibility/config residue or
  bounded current surfaces for Workstream E; they must not be treated as final
  runtime-config architecture by inertia.
- ES currently relies on `/execution/...` runtime path conventions for staged data and run data, while the runtime-identity endpoint itself is now run-scoped under an ES-owned runtime subtree.
- ES currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-visible runtime identity contract.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract only. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- Helper start as `0:0`, Nomad task `User: "0:0"`, fixed workload
  `10000:10000`, helper-private SPIRE traversal, and current reserved runtime
  paths are bounded or compatibility-heavy first-slice surfaces.
- The containerized hot path currently relies on Docker host networking for control-plane reachability during slice 0; that is a temporary compatibility-heavy deployment convention, not the final control-plane network model.
- Slice 0 by itself proves the Linux substrate and governed execution handoff only. The current bounded slice reaches strong workload identity through slice `1A` and slice `1B`, and the canonical supported-local proof path now exercises that runtime identity through a real SPIRE-backed JWT-SVID plus bounded Vault dev/test login.
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

- The shared-kernel role and long-term scope of `internal/contracts/evidence/v1`
- The ownership shape of the workload-zone Vault runtime-config reference and blob schema
- The storage and discoverability shape of ARS
- The publication and fact-assembly shape of AGS
- The admission, package-resolution, and runtime-handoff shape of ES
- The policy-publication shape of EGS
- The authorize and policy-input shape of CGS
- The current runtime identity handoff conventions
- The long-term runtime-identity owner, helper/root/task-user model, SPIRE
  selector posture, Vault posture, and reserved-path architecture

These seams are active today and intentionally not fixed.

## 12. Decision rules for future edits

- Keep this file high-level and architecture-oriented.
- Move detailed cross-service rules into `.docs/system_overview/contracts.md`.
- Move ownership and non-ownership detail into `.docs/system_overview/boundaries.md`.
- Do not describe a seam as settled unless `PLANS.md` says it is settled.
- Document deliberate absences explicitly instead of implying them.
- If code and tests disagree with this file, update this file to match reality.
