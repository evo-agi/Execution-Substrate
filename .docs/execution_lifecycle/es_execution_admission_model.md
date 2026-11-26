# ES Execution Admission Model Decision

## 1. Purpose and scope

This document records the bounded Workstream C ES public admission/execution
model decision for Milestone 2C.1.

It answers only the questions needed to keep ES public admission, execution
handoff, lifecycle projection, retained-result ownership, runtime handoff, and
current CP compatibility explicit for the current governed execution path. It
does not settle:

- Workstream D policy/authorization redesign
- Workstream E runtime-config ownership redesign beyond the E0
  docs/tests-only ownership decision in
  `.docs/system_overview/runtime_config_ownership.md`
- Workstream F runtime-identity redesign beyond the F0 docs/tests-only
  ownership decision in `.docs/system_overview/runtime_identity_handoff.md`
- Control Plane orchestration, review, checkpoint, escalation, or finalization
  semantics
- Infrastructure Manager bootstrap, readiness, or support-bundle ownership

### PR #12 private retained-admission refinement

The published codec-5 handoff omitted current ES admission on retained first
effects. Its repair is a re-derivation on the reliable-submit
**Reopened redesign seam**, owned by the
[operational handoff contract](reliable_submit_operational_handoff.md). Ordinary
unkeyed Submit and public keyed refusal remain **Current invariants**. Fresh
admission still owns one effectful resolution and verifies ARS discovery, the
complete signed artifact evidence, current startup-loaded EGS TrustModel and
the ES local policy. A private immutable owned evidence carrier on
`preparedArtifact` and separately on `resolvedExecution` transports the same
successful record to the v2 original builder; it does not enter the plan,
material, PB1, provider projection or ordinary public result. The carrier's
256 KiB sealing limit applies only to new private operational originals.

For retained unmarked effects, "current admission" has three parts. The
store holds one durable admission row: installation, epoch, admission
generation, admission digest and an enabled or withdrawn state. Service owns
a view installed at most once by commissioning or advancing that row: the
returned admission token with deep copies of the normalized trust lists, the
provenance verifier and the supported built-in policy entries. And the
process must have confirmed that view's trust with EGS within 30 seconds.
The verified trust owner pointer prevents a copied Service from
commissioning the same startup proof, and trust JSON remains within the
existing 256 KiB dependency response bound. The view is held by the admission
state package behind its own lock, read under that lock and evaluated locally
over authenticated frozen inputs at each protected cut, after the store has
compared its token with the row under the SQLite writer lock. The ordinary
replaceable `AdmissionPolicyEvaluator` remains available to ordinary
admission; the private SQLite writer accepts only an exact inspected
`admissionPolicySet` of supported built-ins, refusing unknown or nested
implementations before calling them. Nil uses the validated configuration
default. Replacing trust, verifier or policy does not change the epoch. A
restarted process advances the generation; a process holding an older token
commits no further first-effect write, and in-flight claims are judged again
by the new content. Withdrawal is durable and domain-wide. The private path
confirms trust before first effects; it does not refresh or adopt trust while
running, and a confirmation that differs latches the process closed. There is
no public commissioner or external policy service. Receipt-only and positive
marked reconciliation never consult mutable execution admission.
`operational_local_v1` is removed; no compatibility edge is retained on this
path, so §4C gains no row.

For the private proof, exact typed production inventories require zero
references to the Service commissioning, advance and withdrawal methods,
exactly one reference to each of the three store operations that write the
admission row, from the Service method of the same purpose, zero non-test
configuration of `Service.operationalProof` and its callbacks, one reference
to the confirmation with three invocation sites, and the sole
view construction in the install method of the admission state, which only
the one function that installs the view calls. The view, the withdrawal and
supersession latches and the confirmation time are one unexported struct of
`es/admission/internal/admissionstate`. Other packages hold handles they
cannot open, so naming, copying or restoring that state does not compile
outside the package, and every exported function of the package has an exact
call-site inventory. The protected
Service trust-owner, verified, state-handle and proof fields, all state and
view fields inside that package, and handoff-owner
Service/view links have exact typed read/write/initializer site inventories,
which also count whole-value construction, assignment, conversion and
declaration of each owning type. The existing
`Service.mu` protects mutable Service state and the lock of the admission
state protects the latches and the confirmation time; the view is immutable
after one-shot construction, and final owner entry samples it under the
documented owner-to-state lock order. A finite reference count alone is not a lock
correctness proof. The nil-default `contextObserved` test hook sees a detached
completed retained policy context immediately before the existing built-in
evaluation; it cannot change inputs or a decision and has no non-test
configuration caller. An independent signed-v2 byte oracle, the published v1
bytes as a negative vector, validly signed contradictions, populated
policy-context observation, two and three Services on one domain, two
processes on one database and a fake signed EGS are maintained acceptance
evidence.

## 2. Decision summary

- C0 is the docs and docs-contract-test gate only. It makes no runtime
  implementation changes, and Workstream C implementation must not start until
  C0 docs and docs-contract tests pass.
- C1 is the focused code-facing guardrail slice over this accepted model. It
  strengthens tests for bounded `:prepare` preflight non-effects, ARS
  discovery/evidence/payload/package-identity consumption, signed evidence and
  narrow execution/runtime claim enforcement, AGS/ARS support/CP grammar
  exclusion, payload-digest versus package-identity mismatch separation,
  current compatibility surfaces, and `authority_handoff`/`outcome_evidence`
  non-authority. It does not redesign runtime behavior.
- C2 is the focused tests/docs guardrail slice over submit and lifecycle
  projection. It proves `POST /v1/executions:submit` remains the ES-owned
  async execution handoff through Nomad, the receipt remains bounded and free
  of Control Plane attempt/review/checkpoint/finalization/intervention,
  approval, hold/resume/reject, Temporal, or workflow grammar,
  `authority_handoff` remains non-secret handoff evidence only,
  `lifecycle_projection` remains Nomad-backed with `source=nomad` and an
  opaque same-run read-coordination `revision`, current
  status/logs/result/cancel compatibility remains unchanged, and
  `control-plane-normal-shell/v1`
  compatibility remains unchanged. It does not redesign runtime behavior,
  retained results, runtime identity, Vault handoff, Nomad integration, or
  Control Plane behavior.
- Submit idempotency, submit correlation, and recovery are a target-only
  reopened seam documented in
  `.docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md`.
  Current no-key submit remains the stable current handoff behavior, current
  public DTOs remain unchanged, and current `run_id` lifecycle lookup remains
  the current compatibility path. The target reliable keyed-submit contract is
  not implemented and does not add a current request field, response field,
  header, route, durable store, error vocabulary, Nomad behavior, Coordinator
  behavior, or Bridge behavior.
- The selected `resolved-execution-plan-extraction-foundation` is a bounded
  Workstream C refinement and re-derivation of the reopened internal
  prepare/submit resolution seam. It changes current Submit internals only: one
  admission-owned mutable request and exact successful workload-zone Vault
  reference feed one snapshotted, effectful pre-freeze resolver. Admission
  deep-copies before mode/default/validation/normalization work and returns one
  frozen authoritative snapshot; immutable defensive copies remain permitted.
  The caller retains ownership until the initial copy completes and must keep
  the request and reachable mutable members race-free through that copy;
  concurrent unsynchronized mutation during copying is a caller data race, not
  an ES synchronization guarantee. After the owned copy completes, later
  caller mutation cannot change admitted or submitted state, and defensive
  copies do not create a second mutable authority.
  Its private plan is admitted semantic truth only and owns admitted semantic
  facts, including distinct payload identity, runtime-identity tmpfs size, and
  one typed command. Separate
  material owns payload/runtime-support/mount/trust bytes; separate captured
  host context contains only the cleaned absolute staging root, qualified
  numeric owner, cleaned absolute SPIRE source, and trimmed non-empty
  datacenter. The normalized absolute results root remains current ES
  service/custody placement outside the semantic plan, captured host context,
  provider-job projection, and B1 binding;
  run/provider projections add additional execution-shaping facts. Current
  authority handoff is unconditional. It adds no public reliable submit,
  canonical binding, persistence, recovery, or Coordinator behavior. Tranche
  B2 now completes its bounded privacy and independent-assurance refinement.
  The selected public operational-cause messages are exactly
  `workload-zone vault configuration is invalid`,
  `derive execution host context failed`,
  `stage workload vault trust material failed`,
  `derive execution platform state owner failed`, and
  `execution submission failed`; routes, HTTP statuses, codes, DTO fields,
  precedence, and successful behavior remain unchanged. Reliable keyed-submit
  runtime remains unwired, and native Linux runtime validation remains pending.
- `ES-PRIVATE-ADMISSION-BINDING-V1-20261115-01` is a later bounded
  ES-private refinement of the reopened canonical-binding/completeness seam.
  It carries signature-verified returned mount artifact and payload identities
  beside the distinct requested artifact identity without changing legacy
  admission policy or fetch counts. Its unwired producer consumes the actual
  frozen resolver tuple, refuses requested/verified mount mismatch and captured
  byte/digest or parsed-entry drift, and constructs the existing fourteen
  resolved witness categories plus an opaque HMAC-SHA-256 `PlanBinding`.
  Assessment is always not-effect-ready. At PB1 it had no production caller;
  the later bounded codec-3 synthetic composer is its only selected private
  non-test caller. There is no public/runtime semantic or new model mask. The
  live resolver's own requested-versus-returned mount artifact refusal came
  later, with ARS blob byte verification (contracts section 5A).
  Exact format and future retry prerequisites are owned by
  `submit_idempotency_correlation_and_recovery.md`.
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
- C6 is ES Admission Policy Layer v0. C6 is a Workstream C admission
  extension, not the Workstream D CGS/EGS policy-language redesign. ES owns
  final admission policy for ES-bound executions. Control Plane may later
  preflight or render ES policy decisions, but CP is not the final ES
  admission gate. IM remains readiness, provenance, and diagnostics only.
  C6 adds a small ES-local, replaceable policy-evaluation seam in the shared
  `:prepare`/`:submit` admission path with typed context, decision, policy ID,
  reason-code, safe-message, and input-class labels.
- The first built-in ES policy is
  `execution-substrate.admission.selected-destructive-shell-command/v1`.
  Its deny reason code is `destructive_shell_command_denied`, and its safe
  deny message is `destructive shell command denied by admission policy`.
  If required policy input cannot be safely inspected, ES fails closed with
  reason code `admission_policy_input_unavailable` and safe message
  `admission policy input unavailable`.
  The policy claim is only that ES rejects selected destructive shell-pattern
  content in inspected static-script payload text surfaces during admission.
  It is not universal malware detection, complete command sandboxing, proof
  that all destructive behavior is impossible, production endpoint security
  proof, runtime identity or Vault proof, IM support-bundle proof, public/demo
  readiness proof, independent audit proof, cancel/failure/intervention
  proof, CP-owned final ES policy, IM-owned policy authority, or semantic
  understanding of all Control Plane prompts, workspaces, scripts, retained
  bundles, logs, model outputs, or generated artifacts.
- The configurable-input follow-up to C6 adds a second built-in ES policy:
  `execution-substrate.admission.configured-static-script-literal-deny/v1`.
  Its deny reason code is `configured_static_script_content_denied`, and its
  safe deny message is
  `static script content denied by admission policy`. It is configurable input
  for a built-in ES admission policy, not a broad policy engine. ES
  deployment/admin config may set mode `disabled` or `enforce` and provide a
  bounded list of literal deny entries with safe entry IDs and the fixed input
  class `static_script_payload_text`. CP does not define or supply these
  inputs, IM remains readiness/provenance/diagnostics only, and requests cannot
  carry policy entries. The current validation limits are at
  most 32 entries, at most 256 bytes per literal, at most 64 bytes per entry
  ID, valid UTF-8 printable non-control literal text only, no whitespace-only
  literals, unique safe entry IDs, and only the `static_script_payload_text`
  input class. `enforce` mode requires at least one entry; `disabled` mode does
  not enforce entries.
  Regex-looking text is treated as literal text; no regex, glob, shell
  expression, Boolean policy language, OPA/Rego, DSL, customer policy bundle,
  external evaluator service, user-defined reason code, user-defined API
  message, CGS `id.conf` reuse, CP policy input, or request-supplied policy
  entry is added. Denials remain redacted and must not expose the configured
  literal, matched content, or raw payload text.
- `:prepare` may perform bounded payload-byte reads when an enabled ES
  admission policy requires payload inspection. That read must use the
  explicit ARS payload digest carried by the discovery/evidence relationship
  already cross-checked by admission. ES must not treat `artifact_digest` as a
  payload locator by hidden equality. Static-script payload text inspection is
  an ES-visible input class only; it is not CP prompt parsing, CP workspace
  parsing, a package-grammar redesign, arbitrary binary inspection, or
  recursive workspace archive decoding.
- Current `static-script` policy inspection requires exactly one effective
  regular top-level `entrypoint` after trimming pathname whitespace and
  cleaning slash-separated tar paths. A lone alias is accepted, but duplicate
  canonical regular destinations (even identical bodies), file/directory and
  implicit-parent conflicts, traversal, links and special entries reject.
  Admission completes a bounded archive scan before allowing: 256 KiB maximum
  compressed payload, 64 KiB entrypoint text, 64 tar entries and 16 MiB for the
  whole decoded tar stream including headers, ignored bodies and trailing
  bytes. Nonzero decoded tar tail and additional compressed gzip members or
  bytes reject. Runtime extraction shares the destination/collision and tail
  interpretation, independently refuses overwrite before launch, and keeps
  generic packages without a top-level entrypoint valid. This is a bounded
  input restriction, not nested archive inspection or universal script safety.
- The bounded current static-script input rejects GNU sparse representation:
  old GNU sparse type and every returned header with a `GNU.sparse.*` PAX
  record, including recognized 0.0/0.1/1.0, all-hole, and unknown keys.
  Rejection follows Go tar `Next` metadata parsing but precedes logical body
  reading, policy discard, and runtime file creation. The 16 MiB policy budget
  counts gzip-emitted tar bytes, not tar.Reader-synthesized holes; no generic
  runtime archive-size cap is added. Ordinary PAX/GNU long names remain valid.
  The effective raw tar name is trimmed once and slash-cleaned once; the
  resulting canonical destination is passed unchanged to the runtime path
  resolver. `./ entrypoint` and `entrypoint` are distinct destinations because
  the former cleans to ` entrypoint` with significant leading component space.
  This is an ES static-script compatibility narrowing and interpretation fix,
  not a new package grammar or policy language.
- Policy denials are redacted. Public API errors expose only the existing
  error envelope with safe message and reason code where the current contract
  supports those fields. Policy denials must not expose raw payload text,
  matched content, prompts, workspaces, model output, logs, retained bundles,
  support bundles, credentials, environment values, DB contents, local process
  records, cert/key/TLS/SPIFFE/Vault/WebAuthn/passkey/API-key material, or
  generated artifact contents.
- ES owns admission composition, prepare-time preflight, submit-time execution
  handoff, Nomad-backed lifecycle projection, retained opaque result-bundle
  ownership, and runtime handoff boundary enforcement.
- ES owns the public admission model, prepare model, submit model,
  Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- `GET /v1/executions:contract` and `POST /v1/executions:prepare` remain
  active bounded compatibility surfaces. Neither surface becomes health,
  readiness, run authority, or hidden orchestration.
- `GET /v1/executions:contract` remains a narrow producer compatibility
  declaration, not health, submit readiness, run authority, or a general
  capability registry.
- `POST /v1/executions:prepare` remains bounded preflight and creates no run
  object or scheduler handoff.
- `POST /v1/executions:submit` is the real ES-owned execution handoff surface.
  Its current behavior remains async-only and returns a bounded receipt rather
  than a durable ES lifecycle record.
- `POST /v1/executions:submit` remains the MVP execution handoff surface:
  async, bounded receipt, and Nomad submission through ES.
- Reliable keyed submit remains a target-only reopened seam. The detailed
  target contract for submit idempotency key handling, submit correlation,
  exact replay, conflicting reuse, pending outcome, ambiguous outcome, narrow
  durable submit-correlation records, caller isolation, caller-to-ES response
  loss, and ES-to-Nomad registration-response uncertainty lives in
  `.docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md`.
  It preserves the current no-key submit DTOs and current `run_id` lifecycle
  routes until a later versioned implementation exists. The selected target
  public shape keeps the existing `POST /v1/executions:submit` route while
  requiring a future submit-specific reliable request family or envelope
  distinct from `PrepareRequest`, with an in-band structural discriminator that
  current strict decoding rejects. A changed current `schema_version` value
  alone is not the selected reliable discriminator.
- Future reliable clients must use both producer-declaration preflight and
  in-band request discrimination. The additive reliable-submit producer
  sub-contract remains narrow and versioned under the current
  governed-execution declaration; it is not a generic capability registry,
  health check, submit-readiness proof, admission proof, run authority,
  lifecycle truth, scheduler API, or execution permission.
- Nomad remains authoritative for submitted execution lifecycle. ES projects
  status, logs, and cancel observations from Nomad and serves retained opaque
  result bundles from ES-owned retained storage through the current bounded
  result path.
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- The current documented projection source is `nomad`; any future projection
  source must be documented before it appears in public status JSON.
- `lifecycle_projection.revision` is not a Nomad allocation id, scheduler id,
  CP workflow version or revision, result-reference id, write guard, or proof
  of global freshness outside the documented same-run status read model.
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- ES admission composition consumes designed ARS discovery plus
  evidence/payload references, aggregate evidence verification, the narrow
  shared execution/runtime claims in `internal/contracts/evidence/v1`, EGS
  runtime-trust output, the configured workload-zone Vault runtime-config
  reference/blob, and caller authentication plus the configured SPIFFE
  allowlist.
- For the workload-zone Vault runtime-config path, E0 records that
  `internal/contracts/runtimeconfig/v1` owns the typed semantics, ARS owns blob
  storage/read by digest only, and ES is the current consumer and lookup
  orchestrator during `:prepare` and `:submit`. There is no ACS hop.
- ES startup-config placement of the required runtime-config ref is
  compatibility/config residue on a reopened Workstream E ownership seam. The
  startup guarantee is that the typed ref is configured and validated before ES
  serves governed execution traffic, not that E0 adds a startup blob-fetch
  behavior.
- ES admission composition remains CGS-independent in the current hot path.
  D1a preserves that ES consumes no CGS facts. Workstream D may later redesign
  policy/authorization ownership, but any later ES-consumed authorization fact
  must be separately versioned and bounded rather than a reuse of the current
  CGS v1 authorize shape, subject grammar, or audit fields. This decision does
  not settle Workstream E runtime-config ownership or Workstream F
  runtime-identity handoff ownership.
- D1b keeps any future CGS v2 authorize contract design-only. That
  hypothetical future fact is limited to allow/deny, opaque decision
  reference, and expiry or another bounded freshness indicator if justified,
  with audit/evaluation metadata remaining non-authoritative outside CGS. It
  must not carry runtime auth plans, scheduler facts, ES lifecycle/admission
  facts, runtime-config refs, workload-zone Vault ownership facts,
  identity-handoff facts, or Control Plane
  review/approval/checkpoint/finalization semantics.
- D1c keeps any future EGS versioned runtime-trust wrapper design-only. ES
  continues to consume EGS only for signed signer/artifact runtime trust, and
  EGS publication metadata remains outside the signed payload and outside ES
  hot-path admission facts.
- Any future EGS semantic expansion must use explicit
  wrapper/payload/versioning before implementation and must not import CGS
  decisions, runtime-config ownership, runtime identity handoff, AGS/ARS
  artifact-publication authority, or Control Plane orchestration semantics
  into the EGS trust surface.
- D1c does not change the accepted Workstream B artifact
  publication/storage/discoverability semantics or the accepted Workstream C
  ES admission/runtime public model. This decision still does not settle
  Workstream E runtime-config ownership or Workstream F runtime-identity
  handoff ownership.
- D1d keeps `id.conf`, the current CGS v1 subject grammar, and
  `policy.id_conf_path` outside the ES admission model. They remain
  CGS-local current-v1 compatibility/config residue, not ES admission policy
  truth, runtime-config ownership input, or runtime-identity handoff input.
- D1d does not implement CGS v2, does not change EGS trust semantics, does
  not change ES admission behavior, and still does not settle Workstream E
  runtime-config ownership or Workstream F runtime-identity handoff
  ownership.
- F0 records that runtime identity handoff is currently ES-selected and
  platform-delivered. ES owns current handoff selection, env injection,
  reserved path layout, mounts, and Nomad job construction; the runtime
  supervisor/helper owns in-task endpoint implementation, helper-private SPIRE
  traversal, readiness-before-workload, and root-to-workload privilege
  boundary; SPIRE owns JWT-SVID issuance; Vault owns token, secret, and lease
  issuance after workload-side login.
- F0 classifies `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the bounded
  workload-visible discovery contract only. It is not raw SPIRE socket
  exposure, Vault token brokerage, runtime-config authority, or a secret
  payload.
- F0 does not change runtime-config ownership from E0/E1, does not consume or
  promote D seams, and does not widen CP, IM, support-bundle, report, trace,
  retained-bundle, profile, log, or `.out` authority.
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- ES does not own AGS publish-time fact assembly/signing, ARS blob
  storage/registration/discoverability authority, EGS trust publication, CP
  orchestration semantics, runtime credential minting/brokerage/storage, or
  semantic interpretation of retained result contents.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- ES must not absorb CP attempt/review/checkpoint/finalization semantics.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
- ES must not become a Vault token broker, Codex credential broker, IM
  readiness authority, CP run-control authority, or maintenance-agent
  authority.
- Generated evidence, `.out`, reports, traces, logs, summaries, support
  bundles, retained bundles, proof artifacts, and maintenance summaries remain
  non-authoritative evidence/projection.
- ES resolves payload bytes through designed ARS discovery and explicit
  evidence/payload relationships. It does not treat `artifact_digest` as the
  payload locator by hidden equality.
- `invocation.annotations["execution_substrate.runtime_profile"]` and the
  bounded `control-plane-normal-shell/v1` profile remain explicit compatibility
  edges on a reopened ES runtime/package seam.
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- `lifecycle_projection`, `authority_handoff`, and `outcome_evidence` remain
  bounded additive read surfaces. They do not become scheduler identity, write
  coordination, credential truth, approval truth, or CP lifecycle state.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only.
  It is not runtime-config authority, live credential truth, or a source of
  workload-zone Vault semantics.
- ES retained results remain opaque output bundles. They do not become CP
  checkpoint, review, finalization, or orchestration state.
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.

## 3. Surface classes used here

| Class | Meaning for Workstream C |
| --- | --- |
| `stable contract` | An ES-owned public or ownership rule that this package now treats as an explicit current invariant and that must not change silently. |
| `bounded slice rule` | Active public behavior that is real today but intentionally narrow and not automatically the long-term architectural endpoint. |
| `temporary compatibility edge` | An active compatibility-heavy surface retained for continuity; it is real today but must not be preserved by inertia. |
| `implementation-only/current-slice detail` | A current runtime, lookup, or storage mechanic that must not be mistaken for ES public contract or ownership truth. |
| `reopened seam` | An active architecture-defining surface that remains intentionally open in `PLANS.md` and is not settled by this decision. |

## 4. Classified current surfaces

### 4A. Public execution surfaces

| Surface | Class | Current rule | Explicit non-claim |
| --- | --- | --- | --- |
| `GET /v1/executions:contract` | `temporary compatibility edge` | Narrow read-only producer compatibility declaration for the current governed-execution consumer path. | Not service health, submit readiness, artifact admission proof, run authority, run existence proof, lifecycle truth, credential truth, policy truth, or scheduler API. |
| `POST /v1/executions:prepare` | `temporary compatibility edge` | Bounded preflight success surface for the current execution request family. | Not run creation, scheduler handoff, proto-execution state, durable ES lifecycle state, or public composition detail. |
| `POST /v1/executions:submit` | `stable contract` | Real ES-owned execution handoff surface that reuses the full prepare path and returns a bounded async receipt. | Not sync execution, durable ES lifecycle ownership, retry/reschedule policy, or backend scheduler ID exposure. |
| `GET /v1/executions/{run_id}/status` | `stable contract` | Nomad-backed lifecycle projection surface centered on `submitted`, `running`, and `terminal`. | Not a parallel lifecycle store, scheduler identifier surface, or richer CP lifecycle model. |
| `GET /v1/executions/{run_id}/logs` | `bounded slice rule` | Current projected-allocation stdout retrieval surface through ES. | Not streaming, pagination, stderr aggregation, multi-allocation merge, or log authority beyond the served bytes. |
| `GET /v1/executions/{run_id}/result` | `temporary compatibility edge` | Current retained-result retrieval route for ES-owned opaque bundles keyed by public `run_id`. | Not a logs wrapper, checkpoint API, finalization record, semantic result interpretation surface, artifact-serving authority, or CP materialization authority. |
| `POST /v1/executions/{run_id}:cancel` | `bounded slice rule` | Bounded Nomad stop-request receipt through ES. | Not cancel-completion truth, purge authority, or a broad orchestration/cancellation state model. |

### 4B. Admission, handoff, and projection ownership surfaces

| Surface | Class | Current rule |
| --- | --- | --- |
| ES admission composition at `:prepare`/`:submit` | `stable contract` | ES composes ARS discovery plus evidence/payload refs, aggregate evidence verification, narrow shared execution/runtime claims from `internal/contracts/evidence/v1`, EGS runtime-trust output, the configured workload-zone Vault runtime-config reference/blob, and caller authentication plus configured SPIFFE allowlist authorization. CGS authorize remains outside the current hot path. |
| ES Admission Policy Layer v0 | `bounded slice rule` | ES evaluates a package-local policy seam during the shared `:prepare`/`:submit` admission path. Deny decisions carry stable policy ID, reason code, safe message, and inspected input classes as internal safe metadata, while the public API keeps the current redacted error envelope. The configurable-input follow-up allows ES deployment/admin config to provide bounded literal inputs to built-in ES policies only; it does not add a policy language, evaluator injection, CP-supplied inputs, request-supplied entries, CGS `id.conf` reuse, or an external policy service. |
| Private resolved current-Submit plan | `bounded slice rule` | One effectful read resolver freezes one admission-owned request, exact admission-source lineage, admitted semantic facts, separate owned byte material, and separate captured host context before run assignment, filesystem mutation, or Nomad registration. Caller use is race-free through the initial copy; unsynchronized concurrent mutation while copying is a caller data race, not an ES guarantee. The semantic plan is admitted semantic truth only and owns schemas/mode/timeout/resources, profile/image and semantic environment inputs, one typed command, distinct artifact/payload/derivation/output identities, mounts, network permission, unconditional current authority inputs, runtime-support digest, runtime-identity tmpfs size, and the fixed semantic envelope. Host context contains the cleaned absolute staging root, qualified numeric owner, cleaned absolute SPIRE source, and trimmed non-empty datacenter; normalized results-root service/custody placement remains outside it and B1 binding. Run/provider projections add locator, owner/run/endpoint environment, staged/host paths, endpoint, and provider placement as additional execution-shaping facts. After freeze, legacy Submit consumes only typed projections. Semantic-plan equality is not provider-effect/replay identity. This is not canonical encoding, `PlanBinding`, a witness, durable custody, host-context binding/replay treatment, reliable runtime wiring, or public grammar. B2 privacy and independent assurance are complete within their bounded source scope; reliable keyed-submit runtime remains unwired and native Linux runtime validation remains pending. |
| Private admission binding and synthetic codec-3 replay | `bounded slice rule` on a `reopened redesign seam` | The package-private PB1 producer reads the actual frozen `resolvedExecution`, checks fourteen model categories plus material/support/trust/job facts, and returns an opaque keyed binding and complete witness. The only selected new caller is the runtime-unwired same-delivery private synthetic composer; its admission-owned reload callback reconstructs winner-original facts and recomputes PB1. The producer still checks requested versus verified mount identity, signed payload versus captured bytes and parsed entries; legacy Submit does not add that live rejection. Synthetic image/placement and sealed custody are not a genuine provider image pin, qualified host or effect permit. |
| Scheduler handoff after `:submit` | `stable contract` | Successful submit hands execution to Nomad. ES keeps only the bounded receipt and read-through projection responsibilities after that handoff. |
| `lifecycle_projection` | `bounded slice rule` | The current documented `source` is `nomad`; `revision` is an opaque same-run read-coordination fact derived from Nomad observation only, not a scheduler id, Nomad allocation id, CP workflow version, write guard, result-reference id, or global freshness proof. |
| Payload/runtime package resolution | `stable contract` | ES resolves payload bytes through designed ARS discovery plus explicit evidence/payload relationships, cross-checks those facts against aggregate evidence, and keeps descriptor/manifest support outside ES hot-path public grammar. |
| Workload-zone Vault runtime-config lookup | `bounded slice rule` | ES is the current consumer and lookup orchestrator during `:prepare` and `:submit`: it reads the validated startup ref, fetches the ARS blob by digest, and decodes typed `internal/contracts/runtimeconfig/v1` data. Runtime-config semantics live in that contract surface, ARS owns blob read by digest only, and no ACS hop exists. |
| Current `/execution/...` runtime path conventions | `temporary compatibility edge` | `/execution/staged`, `/execution/run`, `/execution/run/result`, and the run-scoped runtime-identity backing tree remain current runtime/package conventions only. |
| Runtime-profile selection | `temporary compatibility edge` | `invocation.annotations["execution_substrate.runtime_profile"]` plus `control-plane-normal-shell/v1` remains the current opt-in `static-script` runtime overlay. Omitted or empty annotation resolves to the current default `static-script/default` runtime name; unsupported or disabled non-empty selection fails `:prepare`/`:submit`. |
| `authority_handoff` read surface | `bounded slice rule` | Additive non-secret runtime handoff evidence on submit/status for facts ES selected and handed off. |
| `outcome_evidence` read surface | `bounded slice rule` | Additive response evidence on status/cancel JSON and successful logs/result responses for current Nomad or retained-result observations. |
| Retained opaque result bundles | `stable contract` | ES retains opaque output bundles outside staging and serves them through the current bounded result surface without interpreting their contents as CP state. |
| Current CP governed path consumption | `temporary compatibility edge` | Preserve AGS publish plus ES contract/prepare/submit/status/logs/result/cancel over HTTPS+mTLS for the current CP consumer path without importing CP orchestration grammar into ES. |
| Runtime identity handoff ownership | `bounded slice rule` | Current handoff is ES-selected and platform-delivered. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is bounded workload-visible discovery only; the supervisor/helper implements the endpoint; SPIRE owns JWT-SVID issuance; Vault owns token/secret/lease issuance after workload-side login. |

ES does not own:

- AGS publish-time fact assembly or signing
- ARS blob storage, registration, or discoverability authority
- EGS trust model publication
- CP orchestration, review, checkpoint, hold/resume/reject, escalation, or finalization semantics
- runtime credential minting, brokerage, storage, or lease truth
- semantic interpretation of retained result contents

### 4C. Temporary compatibility edge metadata

| Edge | Reason | Scope | Affected contract or boundary | Visibility | Removal condition |
| --- | --- | --- | --- | --- | --- |
| Current CP governed execution consumer path | Preserve the first repo-owned non-operator governed execution path while Workstream C clarifies ES-owned public semantics. | AGS publish plus ES `GET /v1/executions:contract`, `POST /v1/executions:prepare`, `POST /v1/executions:submit`, `GET /v1/executions/{run_id}/status`, `GET /v1/executions/{run_id}/logs`, `GET /v1/executions/{run_id}/result`, and `POST /v1/executions/{run_id}:cancel` over HTTPS+mTLS for the current CP consumer path only. | ES public execution contract and ES/CP consumer boundary. | `system-visible` | Remove or change only with an explicit compatibility, drain, migration, or versioning plan that documents the replacement consumer path first. |
| `GET /v1/executions:contract` producer declaration | Preserve the current producer-side compatibility gate without promoting it into broad runtime authority. | Read-only declaration of the current governed-execution producer contract, runtime-profile enablement, and mandatory outcome-evidence carriers only. | ES public execution contract and ES/CP/IM compatibility boundary. | `system-visible` | Remove or change only after a replacement compatibility-gate surface or explicit versioning/deprecation plan is documented first. |
| `POST /v1/executions:prepare` bounded preflight surface | Preserve artifact-specific preflight proof without widening it into hidden orchestration or proto-run creation. | Request validation, upstream composition, evidence/trust/runtime-config verification, and bounded preflight success only. | ES public execution contract and ES admission boundary. | `system-visible` | Remove or change only after a documented replacement preparation model, deprecation path, or explicit versioning plan exists. |
| `invocation.annotations["execution_substrate.runtime_profile"]` plus `control-plane-normal-shell/v1` and the current `static-script` overlay | Preserve the accepted CP normal-shell runtime selection path without widening it into a package-kind redesign or CP control-plane transfer. | Annotation-selected ES runtime-profile choice and the bounded `static-script` runtime overlay for the current CP normal-shell attempt slice only. | ES request contract and ES runtime-boundary contract. | `system-visible` | Remove or change only after an ES-owned replacement runtime-profile/package-selection contract and coordinated compatibility/versioning plan are documented first. |
| Current `/execution/staged`, `/execution/run`, `/execution/run/result`, and run-scoped runtime-identity path conventions | Preserve the current execution-package/runtime layout while the runtime/package seam remains reopened. | Current container-visible runtime paths, retained-result directory convention, and runtime-identity backing-tree conventions only. | ES runtime package boundary and ES runtime handoff boundary. | `local-runtime-only` | Remove or change only after a documented runtime-boundary redesign re-derives the execution-package layout and reserved-path conventions first. |
| Current `authority_handoff` field names and evidence-source labels | Preserve the current CP/IM-consumable runtime handoff evidence vocabulary while the request/runtime-identity seam remains open. | Submit/status `authority_handoff` JSON field names, nested shape, and evidence labels only. | ES public execution contract and ES runtime handoff boundary. | `system-visible` | Remove or change only after a documented replacement handoff vocabulary and explicit compatibility/versioning plan exist. |
| Current `authority_handoff.runtime_config_refs` digest evidence | Preserve the non-secret handoff evidence that identifies which workload-zone Vault config digest ES selected without promoting it into authority. | `authority_handoff.runtime_config_refs.workload_zone_vault_config.digest` only. It is evidence, not runtime-config authority, live credential truth, or token/lease truth. | ES public execution contract, Workstream E runtime-config boundary, and ES runtime handoff boundary. | `system-visible` | Remove or change only after a documented replacement handoff-evidence vocabulary and explicit compatibility/versioning plan exist. |
| Current `outcome_evidence` JSON field layout and successful logs/result evidence headers | Preserve the current consumer evidence-parsing vocabulary while lifecycle observation remains bounded to the current Nomad/retained-result slice. | Status/cancel JSON `outcome_evidence`, successful logs/result outcome headers, and the current observation/access-class labels only. | ES public lifecycle contract. | `system-visible` | Remove or change only after a documented replacement observation vocabulary and explicit compatibility/versioning plan exist. |
| Current `GET /v1/executions/{run_id}/result` route plus retained `application/gzip` bundles keyed by public `run_id` | Preserve the current retained-result retrieval path while the longer-term result-materialization seam remains open. | Public result-route path, `run_id`-keyed lookup, `application/gzip` media type, opaque tar.gz result-bundle behavior, and the current CP-consumed result retrieval path only. | ES public result contract, retained-result boundary, and ES/CP consumer boundary. | `system-visible` | Remove or change only after a documented replacement result-retrieval surface or explicit compatibility/versioning plan exists. |

### 4D. Current relationship map

1. An allowed caller may use `GET /v1/executions:contract` as an early
   compatibility gate only.
2. `POST /v1/executions:prepare` validates the request, follows ARS discovery
   to aggregate evidence and payload references, verifies the narrow shared
   execution/runtime claims plus EGS trust/runtime-config inputs, evaluates
   ES Admission Policy Layer v0, and returns bounded preflight success only.
   When an enabled ES admission policy requires payload inspection, `:prepare`
   may read bounded static-script payload text through the explicit ARS
   payload digest already cross-checked by admission. It still creates no run
   object, staging root, scheduler handoff, or proto-execution state.
3. `POST /v1/executions:submit` reuses the full prepare path, whose private
   intent applies Submit mode policy only after admission owns its deep copy.
   Caller use must be race-free through that initial copy: unsynchronized
   concurrent mutation during copying is a caller data race, not an ES
   synchronization guarantee. Later caller mutation cannot affect the owned
   admitted snapshot or submitted state.
   Submit resolves and freezes one private semantic plan, owned material, and
   captured host context before run assignment. The plan retains the
   source-grounded payload digest but no raw payload bytes or host placement
   facts. A run projection combines plan, host context, and locator, then
   stages the current execution package, assembles bounded
   `authority_handoff` facts, submits one Nomad batch job, and returns a
   bounded receipt. Submit cannot bypass the admission policy path used by
   prepare. Policy denial occurs before payload staging or Nomad submission.
   More generally, admission/prefreeze failure occurs before run assignment,
   payload staging, or Nomad submission. Right after the freeze and before run
   assignment, Submit checks that Nomad enforces access control (ES's token
   resolves as a client token, ACLs are enabled, no anonymous policy); a
   failed check refuses with the fixed `execution_runtime_unavailable`
   access-control message and creates no run, staging or job. Admission
   refusals therefore keep their precedence over runtime unavailability. The
   first post-freeze filesystem
   mutation is exclusive run-root creation. The opened identity is held and
   verified through descriptor-relative materialization and complete
   expected-tree revalidation immediately before the one Nomad registration.
   Every post-claim return closes descriptors and retains the visible root.
   One pre-freeze typed runtime command supplies the unchanged executable and
   arguments; no layout helper owns a second grammar. The semantic plan is
   admitted semantic truth only; host/run projection adds additional
   execution-shaping facts. One complete direct literal default-profile
   expected job, direct pointer-owned token/template ledger expanded only in
   the expected tree, unmodified actual job tree, separate literal handoff,
   finite direct-call closure, and exact B1 inventories protect this shape.
   Tranche B2 now completes prepared-admission ordinary redaction, the five
   fixed public messages, bounded result-retention logging, selected structured
   Nomad response handling, and the second literal profile golden. The three
   governed logs use only `es result retention failed run_id=%s` and the
   validated run ID. Registration, projected-allocation-list, and
   allocation-detail JSON use a 256 KiB one-document boundary with unknown
   fields allowed and non-success bodies suppressed. `fetchJob` remains
   explicitly unbounded but one-document because caller-environment aggregates
   remain unbounded; successful authenticated public Logs remain unbounded
   opaque bytes. This is not a universal provider-response or workload-output
   limit. `preparedAdmission` ordinary formatting is fixed-redacted and its
   ordinary JSON is `{}`; the protection does not claim reflection, `unsafe`,
   malicious same-package, arbitrary-serialization, or secure-erasure safety.
   The rejected 2.9 MB position-indexed B2 guard is not accepted assurance.
   Permanent B2 assurance is behavior-first, locally position-independent when
   structural, and production-by-construction where cancellation now has no
   private purge option and emits exactly `purge=false`. The directly authored
   compact inventory fixes current public execution JSON fields and only the
   Nomad decode fields production consumes; it still accepts unknown incoming
   provider fields. `preparedAdmission` claims cover ordinary formatting,
   formatted standard-library logging, ordinary JSON, marker placement, and
   field visibility only. The selected `fetchJob` and authenticated public Logs
   exceptions do not change. Provenance proves byte identity only.
   Expected-literal honesty and open-world source-flow questions remain fresh-
   audit obligations. No positional records, replacement-output workflow,
   package source graph, source fingerprint, generated inventory, or general
   analyzer is selected. This assurance does not claim arbitrary alias/helper
   flow detection, custom logging-sink coverage, arbitrary same-package
   aggregate conversion, whole-program noninterference, or whole-runtime
   reliable-submit nonwiring. Reliable keyed-submit runtime remains unwired;
   the private foundation remains present, current public Submit remains
   unkeyed, and native Linux runtime validation remains pending.
4. `GET /v1/executions/{run_id}/status`,
   `GET /v1/executions/{run_id}/logs`, and
   `POST /v1/executions/{run_id}:cancel` read through Nomad. `GET
   /v1/executions/{run_id}/result` reads the retained bundle first and
   otherwise uses the same bounded terminal observation model before retention.
5. `lifecycle_projection`, `authority_handoff`, and `outcome_evidence` remain
   additive read surfaces over ES-owned observation/handoff facts only. They do
   not create ES-owned lifecycle authority, scheduler identity, or CP state.

The run-root claim is host-local descriptor custody, not a new lifecycle
object. It has no marker, reopening/adoption state, cleanup eligibility, or
automatic whole-root reclamation. Every exclusively created root is retained,
including partial, failed, ambiguous, accepted, terminal, and result-publication
outcomes. Dependency and material acquisition before freeze is explicitly bounded: 256 KiB dependency
JSON, 32 MiB primary payload, 8/32 MiB compressed mounts, 16/64 MiB complete
decompressed mount streams, 8/32 MiB regular mount bodies, 32 MiB runtime
support, and 256 KiB per trust source. These bounds do not change request or
receipt grammar.
### Isolated candidate classification

The private resolved plan is a bounded refinement of the reopened Submit
resolution seam. Captured material and the custody-placement root pair remain
outside semantic execution facts. The current invariant is one authoritative
admission and one Nomad handoff for successful unkeyed Submit. Bounded slice
rules add per-submission material limits, root qualification, exclusive claim,
descriptor-relative staging, complete pre-dispatch tree validation and
no-replace retained-result publication. All-claimed-root retention is a
temporary compatibility edge pending capacity and reclamation policy. It grants
no durable lifecycle or retry authority. The selected native Linux and
test-owned installed-source evidence is accepted under its original source
and command identities. Actual running-deployment topology, key exposure and
capacity/residence enforcement remain environment-bound operational/rollout
gates. `.docs/standing_rules/execution_admission_and_custody.md` and the lifecycle contract own the development-source and
local-preservation distinction; no admission or Submit authority changes here.

### Private replay progress candidate classification

Private original replay with durable claim progress is a **Bounded
slice rule extension** on the reliable-submit **Reopened redesign seam**.
The current codec-3 custody scope remains an immutable private original.
The candidate's codec-4 scope `synthetic_progress_nonoperational_v1` is
fixture-only and effect-ineligible at every phase, including accepted with a
fixture receipt. One authenticated original and one claim row retain the
existing caller/key occupation across codecs. Admission owns typed original
interpretation, intent presence and PB1 verification. Custody owns sealed
bytes, key/grant evidence and the shared scope-1/scope-2 object allocator.
SQLite enforces persisted shape, CAS and storage deltas. The existing
durable service owns semantic transition checks. Codec-4 reconciliation
retains one earlier observation of the same attempt. An explicit new
fixture marker uses fresh authentication and the exact current-row CAS
predicate. Independent positive same-run evidence is required for terminal
resolution. A later current-state read or explicit command leaves the
earlier invocation's write disposition unchanged. The operational
Validated No-Dispatch Evidence requirement remains unchanged and its
cross-restart authority lies outside this fixture slice.

The private composer may consume the typed original and staged-in-model
facts defined by the submit contract §6B and persistence ADR §15B.
The two internal fixture terminal constructors explicitly associate
outcome and, for Accepted, the receipt with the same attempt. The
durable service validates that association. The constructor sites belong
to fixture tests and confer no provider authority. The known disposition of
a losing establishment survives failed winner disclosure. The external
admission lost-response witness uses a test-only bridge and the same
no-effect observation boundary. Those
facts confer zero staging, provider, runtime, publication or lifecycle
authority. Static guards restrict the composer and its internal imports to
the selected private call graph. Public structural reliable-request refusal,
unkeyed Submit, authentication-before-existence-disclosure, conflict privacy
and bounded CP compatibility remain current invariants. ES owns admission and
runtime facts and Nomad owns the current accepted-execution lifecycle.
Coordinator durable programme progression is a separate strategic
responsibility. IM and MA are supplementary. Bridge does not establish run
truth. Operational startup, public ingress and first-effect authorization
remain outside this candidate.

### 4E. Reopened seams

| Surface | Class | What remains open |
| --- | --- | --- |
| Long-term request DTO and submit receipt vocabulary | `reopened seam` | The reliable keyed-submit public opt-in/versioning tranche selects the shape class for the future reliable submit path: existing `POST /v1/executions:submit` route, additive narrow reliable-submit producer sub-contract, producer preflight plus structural body discrimination, and a submit-specific reliable request family distinct from `PrepareRequest`. The private reliable request schema `execution-substrate.reliable-submit-request/v1` and nested `reliable_submit.contract = execution-substrate.reliable-submit/v1` are selected; public receipt vocabulary, error vocabulary and recovery route remain open. |
| Long-term role of `POST /v1/executions:prepare` | `reopened seam` | `:prepare` remains active today, but whether it survives unchanged as part of a later public execution model remains open. |
| Long-term ES admission policy model | `reopened seam` | C6 proves only a replaceable ES-owned policy seam and one built-in bounded content policy. It does not settle a broad policy language, customer policy distribution, CGS/EGS policy redesign, external policy service, audit model, or durable policy-decision store. |
| Runtime-profile selection vocabulary and whether it remains annotation based | `reopened seam` | The current annotation plus profile name are compatibility edges, not the final ES runtime-selection model. |
| Lifecycle vocabulary beyond the current projection | `reopened seam` | Current public status remains centered on the bounded Nomad-backed projection; any richer lifecycle vocabulary must be re-derived before becoming public contract. |
| Internal execution-locator and projected-allocation policies | `reopened seam` | `run_id -> exec-<run_id>` and latest-allocation selection remain active current-slice lookup mechanics, not settled lifecycle architecture. |
| Long-term execution-package layout and `/execution/...` conventions | `reopened seam` | The current runtime package layout is localized inside ES, but its long-term path and reserved-directory conventions remain open. |
| Retained-result route evolution and result-reference vocabulary | `reopened seam` | The current public lookup is `GET /v1/executions/{run_id}/result`; any later result reference vocabulary must be a documented safe handle scoped to `run_id` or another explicit result reference, not a raw path, scheduler ID, support/proof path, or artifact-discovery/index leak. |
| Result payload identity, artifact identity, and CP materialization semantics | `reopened seam` | Retained bundle bytes remain ES-owned opaque output material. This decision does not settle whether future result payload identity differs from artifact identity, how artifact discovery/index should expose result material, or how CP materializes retrieved content beyond CP-owned review/checkpoint/finalization semantics. |
| Governed staging reclamation | `reopened seam` | Automatic whole-run-root reclamation is not implemented. A future ES-owned design must address authority, safety, disk/capacity pressure, sensitive-material residence, and operator burden without inferring deletion authority from lifecycle or result facts. |
| Long-term runtime identity handoff owner behind the public endpoint | `reopened seam` | Workstream C preserves the ES-owned handoff boundary only; Workstream F remains the place to settle the final runtime-identity ownership model. |
| Long-term workload-zone Vault runtime-config owner | `reopened seam` | Workstream C preserves consumption of the current runtime-config reference/blob, but Workstream E remains the place to settle the long-term owner. |
| ES startup-config placement of workload-zone Vault runtime-config ref | `reopened seam` | E0 classifies the current placement as compatibility/config residue; a later Workstream E slice must decide whether the startup guarantee moves to another owner. |

## 5. Guardrails for future edits

- Do not widen `GET /v1/executions:contract` into health, readiness, run
  authority, or scheduler API semantics.
- Do not widen `POST /v1/executions:prepare` into hidden orchestration,
  scheduler metadata creation, or proto-run state.
- Do not let ES Admission Policy Layer v0 become OPA/Rego, a DSL, customer
  regex config, CGS `id.conf`, signed policy bundles, external policy
  decision service, or durable policy-decision storage by drift.
- Do not let configurable inputs for built-in ES policies become evaluator
  injection, arbitrary regex/glob/shell-expression configuration,
  customer-authored policy bundles, request-supplied entries, CP-defined ES
  policy, an external evaluator service, user-defined reason codes,
  user-defined API messages, or CGS `id.conf` reuse.
- Do not let the selected static-script content policy claim universal malware
  detection, complete command sandboxing, endpoint security, independent
  audit, public/demo readiness, runtime identity/Vault proof, IM
  support-bundle proof, or Control Plane prompt/workspace semantics.
- Do not include raw payload text or matched content in API responses, logs,
  docs, test names, test failure helpers, reports, traces, retained bundles,
  support bundles, or generated artifacts.
- Do not expose Nomad job IDs, allocation IDs, task IDs, staging paths, result
  filesystem paths, or bundle internals as public lifecycle authority.
- Do not bypass ARS storage/discoverability authority, EGS runtime-trust
  publication, or configured runtime-config ownership to make admission easier.
- Do not treat ARS blob mechanics, ES startup placement, CGS authorize output,
  EGS publication metadata, IM profiles, support bundles, logs, traces,
  reports, retained bundles, `.out` artifacts, CP
  review/approval/checkpoint/finalization state, `authority_handoff`, or
  `outcome_evidence` as runtime-config authority.
- Do not treat CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, runtime-config refs, `authority_handoff.runtime_config_refs`,
  ARS blob mechanics, digest-only runtime-config refs,
  `workload_vault_auth.default_mode`, retained bundles, `outcome_evidence`,
  `authority_handoff`, IM profiles, support bundles, logs, traces, reports,
  `.out` artifacts, or CP review/approval/checkpoint/finalization state as
  runtime-identity or credential authority.
- Do not reinterpret `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as raw SPIRE socket
  exposure, Vault token brokerage, runtime-config authority, or a secret
  payload.
- Do not turn the current runtime-profile compatibility edges into a general
  package-kind redesign or transfer CP control semantics into ES.
- Do not turn retained result bundles into CP checkpoint/review/finalization
  state or ES-owned orchestration state.
- Any change that breaks the current CP path, runtime-profile annotation/path,
  `authority_handoff` vocabulary, `outcome_evidence` vocabulary, or current
  result-route path/lookup/`application/gzip` bundle behavior requires an explicit
  compatibility, drain, migration, or versioning plan first.

## 6. Code-facing guardrail posture

C1 guardrail tests are intentionally narrow. They may assert current ES route
shapes, request decoding, admission composition, evidence verification, payload
and package identity checks, non-authority response vocabulary, and preserved
compatibility edges, but they must not make `:prepare` create run truth,
scheduler handoff, provider run IDs, retained results, CP workflow state, or
lifecycle-store mutation.

They also must not make ES public grammar depend on AGS publication fields,
ARS descriptor/manifest/index/support tuple fields, or CP
attempt/review/checkpoint/finalization fields. These tests are evidence that
the accepted C0 boundary remains aligned during the C1 implementation slice;
they are not a migration plan for the reopened long-term request,
runtime-profile, lifecycle, retained-result, runtime-config, or
runtime-identity seams.

C2 guardrail tests are also intentionally narrow. They may assert submit
receipt shape, ES-to-Nomad handoff, Nomad-backed status/logs/result/cancel
compatibility, bounded `authority_handoff` evidence, and opaque
`lifecycle_projection` read-coordination posture. They must not make submit
create CP run-control truth, review state, checkpoint state, finalization
state, intervention state, Temporal workflow state, CP workflow revisions,
retained-result identity, scheduler IDs as public lifecycle authority, write
guards, or a parallel ES lifecycle store.

C2 does not redesign runtime behavior, retained-result materialization,
runtime identity, Vault handoff, logs/result/cancel behavior, Nomad
integration, AGS, ARS, Control Plane, or Infrastructure Manager behavior.

C3 guardrail tests are intentionally narrow. They may assert retained result
ownership, result-route compatibility shape, public result and
authority-handoff grammar exclusions, bounded `outcome_evidence` label
compatibility, non-secret `authority_handoff` posture, runtime identity/Vault
handoff non-broker posture, and `control-plane-normal-shell/v1` compatibility.
They must not redesign retained results, runtime identity, Vault handoff, Nomad
integration, Control Plane behavior, logs/result/cancel behavior, AGS, ARS, or
Infrastructure Manager behavior.

C4 guardrail tests are intentionally narrow. They may assert runtime identity
and Vault handoff public DTO exclusions, non-secret `authority_handoff`
credential-location/configuration metadata, workload-zone Vault config as
non-secret metadata, `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-facing
endpoint contract, Remote Alpha workload-auth evidence as evidence/projection
only, and unchanged `control-plane-normal-shell/v1` compatibility. They must
not redesign runtime identity, Vault handoff, retained results, lifecycle,
Nomad integration, AGS, ARS, Control Plane, Infrastructure Manager, or
Maintenance Agent behavior, and they must not run live Vault, SPIRE,
reset/unseal, workload-auth, renewal, CP proof, IM refresh, support-bundle,
binary deployment, or remote mutation helpers.

C5 guardrail tests are intentionally narrow. They may assert current
status/logs/result/cancel response envelopes, successful logs/result
outcome-evidence headers, bounded `outcome_evidence` label compatibility,
opaque `lifecycle_projection` read-coordination posture, backend-ID
non-authority, non-secret `authority_handoff` posture where it appears near
status/cancel, raw logs/result payload opacity, generated-artifact
non-authority, and unchanged `control-plane-normal-shell/v1` compatibility.
They must not redesign status, logs, result, cancel, retained results,
runtime identity, Vault handoff, lifecycle, submit, Nomad integration, AGS,
ARS, Control Plane, Infrastructure Manager, or Maintenance Agent behavior.
They must not require new sanitization or interpretation of raw logs/result
payloads, and they must not run live proof, remote validation, Vault, SPIRE,
reset/unseal, workload-auth, renewal, CP proof, IM refresh, support-bundle,
binary deployment, or remote mutation helpers.

## 7. Resolved-plan truth and finite source inventories

This section closes the active resolved-plan documentation-truth and finite
source-inventory obligation. It records current source reality; it does not add
production behavior.

The current `Service.Submit` resolution, custody, and staging rules below are
`Current invariant` behavior inside the selected bounded Workstream C/Tranche
B1 slice. The exact finite inventories are `Bounded slice rule` guardrails:
they may change only through an explicit doc-first refinement with matching
source tests. The retired operator aliases are a `Temporary compatibility
edge`, not a promise to preserve the aliases indefinitely. The private v1
canonical reliable-plan encoding and `PlanBinding` producer are now selected as
an unwired bounded slice on the `Reopened redesign seam`. Bounded synthetic
codec-3 replay custody and claim-commit ambiguity classification are present
as runtime-unwired source proofs. Operational/effect-capable durable replay
custody, provider-effect ambiguity recovery, deployed key authority, public
reliable submit and runtime wiring remain open.

### 7.1 Resolved-plan authority and consumers

`Service.resolveExecutionForSubmit` is the one production resolver. It invokes
the shared `prepareAdmission` path, captures one immutable configuration
snapshot, normalizes placement, resolves the artifact, runtime profile,
resources, payload, runtime-support bytes, governed mounts and their parsed
entries, workload trust, and platform owner, and then constructs the plan,
material, and host context. Successful return is the pre-effect freeze point.

The private `resolvedExecutionPlan` is authoritative only for admitted
semantics. Its exact semantic categories are request and invocation schema,
mode, timeout, CPU and memory, runtime-profile name and selected image,
artifact/payload/derivation/output identities, one typed runtime command,
semantic environment, ordered governed mounts, network access, current
authority inputs, runtime-support digest, runtime-identity tmpfs size, and the
fixed job envelope. Its authority plan contains runtime-profile identity, the
genuinely optional Codex credential-location subcomponent, workload Vault plan,
configuration digest, and trust-presence facts.

Raw payload, runtime-support, parsed mount, and trust bytes are owned by the
separate private `resolvedExecutionMaterial`. Cleaned staging root, qualified
owner UID/GID, cleaned SPIRE source directory, and Nomad datacenter are owned
by the separate private `hostMaterializationContext`. The normalized results
root participates in current service/custody qualification but is outside the
semantic plan, host context, provider-job projection, and B1 binding.

After the freeze, `Service.Submit` first runs the Nomad access-control check
(no run, staging or job on refusal), then assigns one locator and calls
`newResolvedRunProjection` with the plan, host context, and locator. Narrow
typed projections then supply `materializeExecutionInputs`, authority handoff,
`buildNomadJobSpec`, handoff revalidation, and the one Nomad submission. No
other production plan consumer or resolver exists. The plan is ephemeral and
package-private: it is not lifecycle truth, scheduler truth, retained-result
truth, a replay identity, a witness, a commitment, a `PlanBinding`, or hidden
run truth. Retained authority-handoff metadata and the Nomad job are bounded
derived projections; lifecycle remains Nomad-backed and retained results remain
opaque bundles.

### 7.2 Exact production `ReadDir` inventory

The complete production `es/admission` inventory, including Darwin- and
Linux-selected source, contains exactly two direct positive-literal `ReadDir`
calls:

| Source and symbol | Literal | Purpose |
| --- | ---: | --- |
| `es/admission/staging_custody.go:validateExpectedDirectoryEntries` | `1` | Expected-tree validation reads at most the expected child count plus one and immediately rejects an unexpected entry. |
| `es/admission/staging_custody.go:readDirectoryEntries` | `64` | Retained-result deterministic traversal reads bounded batches; this is not expected-tree validation. |

The platform-specific custody files contain no alternate `ReadDir`; they
provide only the selected no-follow descriptor open/stat primitives. Test-only
references are `(*scriptedDirectoryEntryReader).ReadDir` and the direct
`duplicate.ReadDir(1)` check in
`TestStagingCustodyValidationUsesFreshCursorAndIsRepeatable`, both in
`staging_custody_test.go`; they are not production entry points. Guardrail
mutants reject zero, negative, nonliteral, aliased, hidden-helper,
method-value, and extra-callsite forms.

### 7.3 Exact custody claim and materialization inventories

`es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot` is the
sole constructor on a production path that returns `*stagingCustody`, and
`es/admission/submit.go:Service.Submit` is its sole production caller. Submit
transfers the staging descriptor from the qualified execution-root pair into
that constructor. The path-taking `claimStagingCustody` wrapper is test-only
and has no production caller. The retained
`probeStagingCustodyCapabilities` helper is also unwired; startup instead calls
`qualifiedExecutionRoots.probeCapabilities`, which probes the already
qualified staging and results descriptors. The staging-custody Darwin and
Linux files provide only `platformOpenAtNoFollow`,
`platformRenameNoReplace`, and `platformStatSnapshotStable`; neither defines
another claim entry point. Execution-root platform observation remains in the
separate build-selected `execution_roots_{darwin,linux}.go` files.

`es/admission/executionpackage.go:materializeExecutionInputs` is the only
production function that returns or constructs `stagedExecutionInputs`, and
`Service.Submit` is its only production caller. Its reviewed mutation graph is
exactly `executionPackageLayout.stagePayload`,
`executionPackageLayout.stageCapturedRuntimeSupportBinary`,
`executionPackageLayout.stageWorkloadVaultTrustMaterial`,
`materializeValidatedRuntimeMounts`, `materializeValidatedMountEntries`,
`stagingCustody.ensureDirectory`, and `stagingCustody.writeFile`. Typed
production inventories also freeze every direct caller and every custody
acceptor, constructor, creation primitive, write primitive, and destructive
primitive across the selected Darwin/Linux builds.

The test-only custody helper is
`es/admission/staging_custody_test.go:claimTestStagingCustody`. The test-only
historical adapter is
`es/admission/executionpackage_test.go:(*Service).stageExecutionInputs`; it
claims custody and materializes inputs only for tests. The remaining direct
test-only callers of `claimStagingCustody` are exactly:

- `lifecycle_test.go:TestDescriptorCloseRetainsSuccessfulRunRoot`;
- `resolved_execution_plan_test.go:TestResolvedExecutionMaterialOwnsBytesBeforeHostMaterialization`;
- `resolved_execution_plan_test.go:TestRuntimeSupportMaterialIdentityMatchesCapturedBytes`;
- `staging_custody_test.go:TestPhysicalTestTempDirPreservesIntentionalSymlinkRefusal`;
- `staging_custody_test.go:TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt`;
- `writablestate_readiness_test.go:newSyntheticNormalizedRunFixture`.

The direct test-only callers of `materializeExecutionInputs` are exactly:

- `executionpackage_test.go:TestTrancheB2TrustMaterializationCauseUsesFixedPublicError`;
- `executionpackage_test.go:(*Service).stageExecutionInputs`;
- `resolved_execution_plan_test.go:TestResolvedExecutionMaterialOwnsBytesBeforeHostMaterialization`;
- `resolved_execution_plan_test.go:TestRuntimeSupportMaterialIdentityMatchesCapturedBytes`.

Synthetic source strings in guardrail mutation tests are validator fixtures,
not executable package entry points. After a production claim, every return
closes descriptors and retains the visible run root. Incomplete leaves, temporaries, and capability-probe fixtures remain
when exact effect-time deletion identity is unproved; no pathname cleanup,
whole run-root reclamation, adoption, or alternate claim path is selected.

### 7.4 Exact synchronized mutable-state inventory

The non-test production source under `./es/...` and `./cmd/es/...` contains
55 structurally synchronization-bearing fields: eight direct lock fields,
four `atomic.Bool` fields, and 43 transitive reference, request or wrapper
fields. The private fixture code is included in this source inventory. The
private replay path remains runtime-unwired.
`OperationalCustody.prestageProof` and `operationalProvider.exchangeEntry` are
nil-default, instance-scoped proof function fields. They add no primitive lock,
atomic field, shared registry or durable state; only the existing custody lock
protects proof configuration.

| Category | Exact field and type | Protected fact | Writers | Readers | Lifetime |
| --- | --- | --- | --- | --- | --- |
| Lock | `es/admission:Service.mu:sync.RWMutex` | `trustModel *egscontract.RuntimeTrustPolicy`, verified startup state, and the order of a trust load against the install of the one-shot operational view | `Service.Initialize`, `Service.installOperationalAdmission` | `Service.Health`, `Service.currentTrustModel`, `Service.installOperationalAdmission` | Admission service instance |
| Lock | `es/admission/internal/admissionstate:state.mu:sync.RWMutex` | The one-shot operational view of one Service, its monotonic withdrawal and supersession latches, and the last confirmation time | `State.Install`, `State.Withdraw`, `State.Confirm` | `State.Commissioned`, `State.Installable`, `State.Confirmable`, `State.Current`, `State.Inspect` | Admission service instance |
| Lock | `es/app:App.mu:sync.RWMutex` | `started bool`, `listener net.Listener` | `App.Start` writes both. `App.Shutdown` writes `started`. | `App.Started` reads `started`. `App.Addr` reads `listener`. | App instance |
| Lock | `es/runtimehelper:helperServer.mu:sync.RWMutex` | `token cachedToken` | `helperServer.fetchAndStoreToken` | `helperServer.currentToken` | Runtime-helper process |
| Lock | `es/admission/internal/reliablesubmit:privateSealPermit.mu:sync.Mutex` | One permit's `used bool` burn latch | `privateSealPermit.consume`, `privateSealPermit.burn` | `privateSealPermit.consume`, `privateSealPermit.matchesAllocation` | One reservation and publication attempt |
| Lock | `es/admission/internal/reliablesubmit:PrivateReplayProgressCustody.mu:sync.RWMutex` | Scope-2 custody handle, its closed state and coordination with issuer qualification | `OpenPrivateReplayProgressCustody` initializes before publication. `PrivateReplayProgressCustody.Close` clears custody under the write lock. | The read-locked lookup, freeze, reserve, publish, establish, original load, confirmation, progress read and mutation paths qualify through `PrivateReplayProgressCustody.qualified` before using the handle. | One issuing custody handle |
| Lock | `es/admission/internal/reliablesubmit:OperationalCustody.mu:sync.RWMutex` | Open custody and held original borrows | `OperationalCustody.Close` | `OperationalCustody.WithOperationalOriginal`, `OperationalCustody.EstablishOperational`, `OperationalCustody.operationalAdmissionWrite`, `OperationalCustody.ConfigureOperationalCommitFaultForProof`, `OperationalCustody.ConfigureOperationalPrestageProofForProof`, `OperationalCustody.ConfigureOperationalReleaseProofForProof` | One issuing custody handle. `WithOperationalOriginal`, `EstablishOperational` and `operationalAdmissionWrite` (commission, advance and withdrawal) hold it in read mode; `Close` and the three proof configuration methods hold it in write mode. The lock is not reentrant, so `operationalAdmissionWrite` must not be reached from a callback of a borrow on the same handle. The proof methods configure only nil-default, instance-scoped proof within the test lifetime |
| Lock | `es/admission:handoffOwner.mu:sync.Mutex` | One callback's open and marker-to-send decision | `handoffOwner.close`, `liveSender.consume` | `liveSender.consume` before transport entry | One synchronous handoff owner |
| Atomic | `es/admission/internal/reliablesubmit:OperationalAccess.busy:atomic.Bool` | Exclusive use of one authenticated access during a command | `OperationalAccess.Prestage`, `OperationalAccess.applyOperational`, `OperationalAccess.BindVerifiedOperationalObservation`, `OperationalAccess.canBind`, `OperationalAccess.VerifyOperationalReceipt` | The same compare-and-swap operations | One authenticated original borrow |
| Atomic | `es/admission/internal/reliablesubmit:progressAccessState.used:atomic.Bool` | One authenticated access consumption | `PrivateReplayProgressCustody.consumeProgressAccess` atomically checks and sets | The same compare-and-swap | One callback borrow |
| Atomic | `es/admission/internal/reliablesubmit:progressAttemptState.used:atomic.Bool` | One establishment confirmation attempt | `PrivateReplayProgressCustody.WithAuthenticatedProgressOriginal` atomically checks and sets | The same compare-and-swap | One establishment invocation |
| Atomic | `es/admission/internal/reliablesubmit:progressOriginalLifetime.closed:atomic.Bool` | Expiration of one original view or access borrow | Deferred stores in `verifyProgressOriginalMatch` and `PrivateReplayProgressCustody.WithAuthenticatedProgressOriginal` | `progressOriginalLifetime.live` for typed fields and progress use, together with caller-context checks | One verifier or authenticated-use callback |

| Category | Exact field and type | Reference target, creation and use |
| --- | --- | --- |
| Reference | `es/admission/internal/admissionstate:State.s:*admissionstate.state` | Names the admission state of one Service. The constructor sets it once for that Service, which rejects copied or foreign Service authority; the zero handle is closed. |
| Reference | `es/admission/internal/reliablesubmit:OperationalIntentInput.access:*reliablesubmit.OperationalAccess` | Limits the intent input to its authenticated original. |
| Reference | `es/admission/internal/reliablesubmit:OperationalIntentInput.self:*reliablesubmit.OperationalIntentInput` | Checks the original issued intent capsule. |
| Reference | `es/admission/internal/reliablesubmit:OperationalStageProof.access:*reliablesubmit.OperationalAccess` | Limits the held stage proof to one access. |
| Reference | `es/admission/internal/reliablesubmit:OperationalStageProof.self:*reliablesubmit.OperationalStageProof` | Checks the original issued stage capsule. |
| Reference | `es/admission/internal/reliablesubmit:operationalStepShape.stage:*reliablesubmit.OperationalStageProof` | Carries the live stage capsule into the writer and post-commit qualification. |
| Reference | `es/admission/internal/reliablesubmit:OperationalMarkerCandidate.self:*reliablesubmit.OperationalMarkerCandidate` | Checks the original issued marker candidate. |
| Reference | `es/admission/internal/reliablesubmit:OperationalMarkerCandidate.stage:*reliablesubmit.OperationalStageProof` | Binds marker application to the checked stamp and live stage. |
| Reference | `es/admission/internal/reliablesubmit:OperationalPositiveProof.self:*reliablesubmit.OperationalPositiveProof` | Checks the original issued acceptance command. |
| Reference | `es/admission/internal/reliablesubmit:OperationalAccess.issuer:*reliablesubmit.OperationalCustody` | Binds reads and commands to the same issuing custody. |
| Reference | `es/admission/internal/reliablesubmit:OperationalAccess.life:*reliablesubmit.progressOriginalLifetime` | Limits commands and receipt use to the authenticated callback. |
| Reference | `es/admission/internal/reliablesubmit:OperationalAccess.self:*reliablesubmit.OperationalAccess` | Prevents a copied access from issuing a command or constructing a proof. |
| Reference | `es/admission/internal/reliablesubmit:OperationalCustody.self:*reliablesubmit.OperationalCustody` | Binds the open handle identity before issuing access. |
| Reference | `es/admission/internal/reliablesubmit:OperationalOriginalView.life:*reliablesubmit.progressOriginalLifetime` | Expires the same decoder field borrows when verification returns. |
| Reference | `es/admission/internal/reliablesubmit:OperationalPositiveProof.access:*reliablesubmit.OperationalAccess` | Binds the observation proof to the callback access and exact marker projection. |
| Reference | `es/admission:liveSender.owner:*admission.handoffOwner` | Binds the single sender to its callback owner. |
| Reference | `es/admission:liveSender.self:*admission.liveSender` | Rejects a copy of the marker continuation. |
| Reference | `es/admission:Service.trustModelOwner:*admission.Service` | Binds the verified startup trust publication to its original Service before private commissioning. |
| Reference | `es/admission:handoffOwner.service:*admission.Service` | Samples that Service's latches and confirmation deadline before transport entry. |
| Reference | `es/admission/internal/reliablesubmit:PrivateReplayProgressCustody.self:*reliablesubmit.PrivateReplayProgressCustody` | The issuer sets its own identity once at open. Close, lookup and qualification check it for that handle's lifetime. |
| Reference | `es/admission/internal/reliablesubmit:PrivateReplaySealPermit.permit:*reliablesubmit.privateSealPermit` | Carries the same operation-local burn latch through either scope. See the permit roles below. |
| Reference | `es/admission/internal/reliablesubmit:ProgressAccess.state:*reliablesubmit.progressAccessState` | Authentication issues the access state. Progress consumption checks it during that callback. |
| Reference | `es/admission/internal/reliablesubmit:ProgressAttempt.token:*reliablesubmit.progressAttemptState` | Establishment issues the attempt state. Original authentication consumes it within that invocation. |
| Reference | `es/admission/internal/reliablesubmit:ProgressFrozen.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Freeze binds the issuer. Reserve, publish and establish check it within the opening lookup's invocation. |
| Reference | `es/admission/internal/reliablesubmit:ProgressLookup.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Lookup binds the issuer. Lookup accessors, freeze and authentication check it within the lookup invocation. |
| Reference | `es/admission/internal/reliablesubmit:ProgressOriginalField.life:*reliablesubmit.progressOriginalLifetime` | Typed field construction carries the original view's lifetime. Field readers check it on each use in the verifier callback. |
| Reference | `es/admission/internal/reliablesubmit:ProgressOriginalView.life:*reliablesubmit.progressOriginalLifetime` | Original view construction attaches the verifier callback's lifetime. View readers check it or pass it to typed fields. |
| Reference | `es/admission/internal/reliablesubmit:ProgressPublication.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Publication binds the issuer. Establishment checks it for the same publication attempt. |
| Reference | `es/admission/internal/reliablesubmit:ProgressSealPermit.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Scope-2 reservation binds the issuer. Scope-2 publication checks it for the same permit attempt. |
| Reference | `es/admission/internal/reliablesubmit:ProgressSealPermit.permit:reliablesubmit.PrivateReplaySealPermit` | Carries the inner permit wrapper during the scope-2 attempt. See the permit roles below. |
| Reference | `es/admission/internal/reliablesubmit:progressAccessState.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Authentication binds the issuer. Consumption, reload, mutation and recovery check or use it during the access callback. |
| Reference | `es/admission/internal/reliablesubmit:progressAccessState.life:*reliablesubmit.progressOriginalLifetime` | Authentication attaches the callback lifetime. Consumption, reload, mutation and recovery check it. |
| Reference | `es/admission/internal/reliablesubmit:progressAccessState.self:*reliablesubmit.ProgressAccess` | Authentication binds the exact access instance. Consumption checks identity during that access callback. |
| Reference | `es/admission/internal/reliablesubmit:progressAttemptState.issuer:*reliablesubmit.PrivateReplayProgressCustody` | Establishment binds the issuer. Original authentication checks it within the establishment invocation. |
| Reference | `es/admission/internal/reliablesubmit:acceptWithReceiptRequest.progress:*reliablesubmit.progressAccessState` | Acceptance request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:assignRunRequest.progress:*reliablesubmit.progressAccessState` | Run-assignment request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:mutationRequest.progress:*reliablesubmit.progressAccessState` | Each semantic operation forwards its request's access. The mutation service uses it for reload, validation, CAS and recovery during that command. |
| Reference | `es/admission/internal/reliablesubmit:recordProvablyNotAcceptedRequest.progress:*reliablesubmit.progressAccessState` | Not-accepted request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:recordProviderCallObservationRequest.progress:*reliablesubmit.progressAccessState` | Provider-observation request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:recordProviderDispatchAttemptRequest.progress:*reliablesubmit.progressAccessState` | Fixture marker request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:recordProviderEffectIntentRequest.progress:*reliablesubmit.progressAccessState` | Effect-intent request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:recordReconciliationEvidenceRequest.progress:*reliablesubmit.progressAccessState` | Reconciliation request carries access to the common mutation request during one fixture command. |
| Reference | `es/admission/internal/reliablesubmit:recordStagingEvidenceRequest.progress:*reliablesubmit.progressAccessState` | Staging-evidence request carries access to the common mutation request during one fixture command. |

| Permit field | Writes or construction | Reads |
| --- | --- | --- |
| `PrivateReplaySealPermit.permit` | `PrivateReplayCustody.ReserveSealUse`, `PrivateReplayProgressCustody.ReserveProgressSealUse`, `OperationalCustody.EstablishOperational` | `PrivateReplayCustody.publishReplayOriginal`, `PrivateReplayProgressCustody.PublishProgressOriginal` |
| `ProgressSealPermit.permit` | `PrivateReplayProgressCustody.ReserveProgressSealUse` | `PrivateReplayProgressCustody.PublishProgressOriginal` |
| `privateSealPermit.used` | `privateSealPermit.consume`, `privateSealPermit.burn` | `privateSealPermit.consume`, `privateSealPermit.matchesAllocation` |

Scope 1 enters shared publication through `PrivateReplayCustody.PublishSealedSynthetic`.
Scope 2 forwards the inner wrapper through `PrivateReplayProgressCustody.PublishProgressOriginal`
and burns it on scope-2 precondition refusal. The shared publisher uses
`privateSealPermit.matchesAllocation` during allocation preflight and applies
the existing consume and burn rules. Persistence ADR §15B.5A owns the shared
allocator and permit preflight ordering.

`currentTrustModel` and `currentToken` return request-local copies. The sole
package map, `reservedRuntimeEnvKeys`, is static lookup vocabulary. There is no package-level synchronization authority. The structural map scan
follows three invocation-local references into the existing descriptor tree:
`handoffOwner.stage`, `liveSender.owner`, and `liveSender.self`. They retain
the held stage for revalidation and do not introduce a stage registry. SQLite owns committed claim, progress, key and grant/use state.
The private primitives protect handle and invocation lifetimes and one-use
consumption. Reference carriers convey those same protections without
independent authority. These fields confer no durable run truth, process-global
state, lease, registry, poison subsystem, worker, or staging/results-root
authority. The rejected A3 topology in §7.5 remains excluded.

### Selected operational composition and ownership

The integrated candidate adds one custody read/write lock around the held
database and replay root, and one atomic per-access command latch around the
held original. The synchronous handoff owner has an invocation-local lifetime. Its mutex protects the open/send/close decision for that callback. The sender carries a self pointer and its
exact handoff owner pointer. The final owner-protected context sample
immediately precedes the synchronous transport call. The stage rechecks its
commissioned parent without changing the ordinary staging identity comparator.
`OperationalOriginalView` reuses the bounded
field decoding and close latch without exposing a fixture operation bearer.
`OperationalPositiveProof` binds the authenticated original access and the
verified observation to the single acceptance writer. The SQLite opener
remains behind the internal package. The operational admission test has one
disposable SQLite connection for synthetic key setup and row observations.

The [Operational Handoff](reliable_submit_operational_handoff.md) defines the bounded
private composition over the existing durable service, exclusive staging custody
and typed provider boundary. `Service.composeOperationalOriginal` is one direct
resolver caller. `verifyOperationalOriginal` directly reconstructs the plan,
material and host context from the retained original. `Service.advanceOperational`
directly projects the run and materializes its inputs on a held stage, and
`operationalDomain.createOperationalStage` directly claims that stage.
Before the claim, `operationalProvider.fits` directly projects the run once
more, with a stage, a job name and a correlation value of the lengths every
run has, only to measure Job0 and the POST body; it sends nothing. The stage measurement
directly calls the existing held-tree revalidation twice before recording or using the stamp.
The private `operationalProvider.project` uses the existing job renderer once and verifies the complete result against its separately commissioned template. Ordinary Submit retains its existing resolver and Nomad registration path. Current §7.4 describes current source. Public routing, startup and the rejected A3 topology remain outside the selection.

### 7.5 Rejected A3 topology inventory

The rejected A3 design is a process-lifetime namespace lease or registry keyed
by, or coupling, staging/results-root pairs, including a package/global
registry or map guarded by synchronization/atomics, a filesystem lock or
marker named `.execution-substrate-namespace-lease-v1`, or persistent
mutation-poison state. It is rejected because process-local authority cannot
prove multi-process ownership, root-pair coupling would create hidden lifecycle
authority, and poison/lease persistence conflicts with per-operation
descriptor custody and the documented retention rule.

Production source inventories therefore reject `unix.Flock`, any unreviewed
package-level mutable map or synchronization object, any map beside a
synchronization field, and the exact normalized token set
`.execution-substrate-namespace-lease-v1`, `namespacelease`,
`namespaceregistry`, `stagingregistry`, `resultsregistry`,
`processlifetimelease`, `rootpair`, `mutationpoison`, and `poisonstate`.

### 7.6 Retired operator aliases

The exact retired Remote Alpha route, nested-alias, flag, privacy-order, and
tombstone inventory is owned by
`.docs/system_overview/remote_supported_host_alpha.md`. Source tests compare
the complete handler and scanner text, exact dispatch and symbol occurrence
counts, and absence outside the reviewed inventories. This admission/lifecycle
closure does not add an external current-schema package consumer, copy external
schema bytes into Git, pin an external path or hash, resurrect the retired
current-schema checker, or create a replacement facade schema.

### 7.7 Final-audit finite repair inventories

The mount-archive validator's authoritative namespace inventory is the private
compressed byte-radix constructor, probe, constant-size commit plan, commit,
and optional work ledger. Work counters are attached to actual production
comparison, lookup, allocation, and commit sites. The exact reachable suite
covers namespace/error semantics, 32,768 EOF-terminated empty headers at the
16-MiB boundary, parser-reachable PAX/GNU deep and shared-prefix names, and
separately labeled dependency refusals above the pinned reader's hidden
special-file limit.

The execution-root inventory is the `qualifiedExecutionRoots` planner,
provisioner, reobserver, verifier, descriptor transfers, platform observation
helpers, sole Linux mountinfo read, and sole Darwin `Fstatfs`/`Getfsstat`
sites. Each named result effect has an explicit verification edge. These are
operation-local custody surfaces, not a shared kernel, durable root registry,
lease, cache, or content enumerator.

The Linux mountinfo finite inventory also covers the tagged root-value class,
filesystem type, and proof-eligibility branch. Canonical pathname roots remain
coordinate inputs. Exact source-grounded `nsfs` namespace-object envelopes are
opaque records retained through limits, ID/parent/cycle integrity, stacking,
and descendant classification; selection of one refuses before device
shortcuts, coordinate construction, or effects. Malformed labels, child-view
aliases, unsupported kinds, and other non-path classes remain negative cases.
No fixture may drop an opaque record or rewrite its label as a path.

The path-taking `claimStagingCustody` wrapper is test-only. Its exact direct
test call inventory is eight enclosing functions: the execution-package test
adapter; `TestDescriptorCloseRetainsSuccessfulRunRoot`; the two named
resolved-plan tests; `claimTestStagingCustody`;
`TestPhysicalTestTempDirPreservesIntentionalSymlinkRefusal`;
`TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt`; and
`newSyntheticNormalizedRunFixture`. Production uses the distinct
descriptor-taking constructor, verified by typed object identity rather than
source text or a count-only oracle.

Source tests use a test-local fail-closed accepted grammar for
`reject_secret_args` and `reject_retired_operator_evidence_args`. It consumes
every protected-body token and admits only the reviewed local declarations and
assignments, predicates, `if`/`for`/`case` structure, `continue`, exact
`nocasematch` query/enable/restore operations, and exact privacy or retirement-
handler calls. Unknown executable syntax, command/arithmetic/process
substitutions, redirections, and heredocs are rejected, including in
assignments or double-quoted words. A separate prefix check requires those
scanner calls to be the first two nontrivia statements of `parse_args`, in
privacy-first order. Formatting, comments, and unreferenced fresh locals
initialized only from inert literals remain tolerated. This is bounded static
assurance for the two scanners and entry prefix, not a general Bash parser,
whole-script effect analysis, or comparison of complete handler or scanner raw
text.

Local modeled root records remain modeled. The deferred running-deployment
observation, actual mounted repaired-helper cases, native Linux lanes, and
fresh independent audit remain pending and are not replaced by local success.
