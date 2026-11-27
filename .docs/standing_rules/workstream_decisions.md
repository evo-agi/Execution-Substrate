# Workstream Decision Records

These are the decision records of redesign Workstreams A to F: the current
bounded decision status or planning direction that each workstream has reached,
with the slices it accepted and what remains open in it. They moved here
unreworded from the `PLANS.md` sections of Workstreams A to F at `trunk_dev`
commit `0b9278ca74404b46b5e9f0e1701874b52687f5e8`, so that `PLANS.md` holds
intent and order: each workstream's purpose, target files and packages, success
condition and dependencies stay there, and its section there points to its
record here.

Edit a rule here in place when it changes. Do not add dated status entries: say
what a change did in its pull request description. Cite this file by section
heading, never by line number.

## Workstream A decision record

Current bounded decision status for Milestone 2A.1:

- The Workstream A shared-kernel decision is recorded in `.docs/system_overview/shared_kernel.md`.
- `internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel for the current `AGS -> ARS -> ES` path, but it is not a standalone service boundary.
- Kernel-level shared meaning stays limited to package identity, narrow derivation request-binding authorization, narrow execution/runtime claims ES actually enforces, and evidence canonicalization plus `seal` verification.
- AGS publication claims, ARS discoverability/index shapes, ES public execution/lifecycle grammar, and the long-term workload-zone Vault runtime-config owner remain service-owned or reopened elsewhere; Workstream A does not widen them into the kernel.
- `internal/contracts/evidence/v1` is not a cross-service semantic dumping ground. Fields, helper DTOs, proof outputs, generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts do not become shared-kernel authority by proximity to the shared evidence package.
- Workstream A0 preserves the current `execution_substrate.runtime_profile` annotation and bounded `control-plane-normal-shell/v1` compatibility edge. It does not change the runtime path, runtime-profile selection mechanism, or `static-script` overlay behavior.

## Workstream B decision record

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

## Workstream C decision record

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

## Workstream D decision record

Current bounded planning direction:

- D2, the re-derivation the project owner decided, is
  `.docs/system_overview/policy_governance_contract.md`.
- D2 supersedes the limits below that keep a future EGS contract to signer
  and artifact trust (D1b and D1c): EGS v2 signs publisher admissions under
  the owner's standing policy, as a new versioned contract.
- D2 retires CGS, so the future CGS v2 authorize contract that D1b describes
  is not built.
- The EGS v1 and CGS v1 surfaces below stay current behavior until D2's build
  steps 7 and 1 remove them.
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

## Workstream E decision record

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

## Workstream F decision record

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
  owner. Its caller refusal (WI-3a) is implemented; the rest is not yet
  implemented. The decision is section 11 of
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
