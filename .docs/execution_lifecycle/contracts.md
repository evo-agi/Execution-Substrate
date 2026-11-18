# Execution Lifecycle Contracts

## H/C/T integration candidate status and exact boundary (historical construction scope)

The following construction-stage disposition predates accepted integration I
and the completed original-checkout local cutover. It is retained for its
original source/evidence limits, not as today's source acceptance status. The
private admission binding v1 candidate is a separate, unaccepted and
runtime-unwired source slice; current public reliable-submit refusal and legacy
Submit behavior remain unchanged.

This uncommitted source is unaccepted. C's dated exact-source development acceptance and selected native evidence retain their original identities and limits; T is a preservation-only WIP, and its consumed one-time checkpoint exception confers no qualification or commit authority. This candidate requires changed-interaction review. Historical process `PARTIAL`, modeled ownership, compile-only results, operational key/topology/capacity/residence/reclamation gates, and publication limits remain open. Reliable submit remains runtime-unwired and unavailable.

For current unkeyed Submit, one execution/placement snapshot is captured after successful `prepareAdmission` and reused through resolution, materialization, and handoff, including one staging/results pair. It does not promise atomic concurrent configuration capture, a snapshot of earlier admission/trust/Vault/policy reads, or lifetime consistency for later Status/Logs/Result calls. Artifact, capability, target, and profile gates precede placement errors. T's semantic plan is admission-owned and separate from placement. C's complete archive scan, exact mount and custody modes, retained incomplete leaves/probe fixtures, mandatory result authenticator, authenticated final/record pair, and no in-place metadata repair govern this candidate. Result refuses an invalid existing pair without Nomad fallback or a success body; Status and Logs retain their documented Nomad projections and best-effort retention attempts. The three retention failure events contain the fixed message and validated public run ID only.

The paired-root topology contract is a **Bounded slice rule pending integrated review**. Retained roots and probe fixtures are a **Temporary compatibility edge** with capacity and sensitive-material residence costs. Governed whole-root reclamation is a **Reopened redesign seam** and remains unavailable. The six existing-host ES helper routes are retired tombstones; the separate operator-facade evidence cutoff does not retire underlying owner-local producers.

## 1. Purpose and status

This document defines the current ES lifecycle and public execution contract in the repository's bounded platform phase.

Some lifecycle endpoints are live today but intentionally bounded. This file is authoritative for current endpoint, response, error, and lookup semantics. `.docs/execution_lifecycle/design.md` is the higher-level lifecycle design map, and `.docs/execution_lifecycle/implementation.md` records lower-level implementation behavior.

The authoritative Workstream C classification of ES public execution surfaces,
admission composition, compatibility edges, and reopened seams lives in
`es_execution_admission_model.md`.

The target submit idempotency, correlation and recovery contract seam is in
`submit_idempotency_correlation_and_recovery.md`. Its public/operational rules
remain target-only. Its bounded private codec-3 synthetic custody is source
behavior but changes no current endpoint, request/response, route, header,
error code, Nomad behavior or reliable keyed-submit availability.

The private `resolved-execution-plan-extraction-foundation` changes only the
internal current-Submit resolution boundary. It does not add or change a public
request field, response field, route, status, code, fixed error message,
producer declaration, configuration field, or reliable-submit behavior.

C0 is the docs and docs-contract-test gate for the ES-owned public
execution/admission/runtime model. It makes no runtime implementation changes,
and Workstream C implementation must not start until C0 docs and docs-contract
tests pass.

C2 is the tests/docs guardrail slice for submit and lifecycle projection. It
keeps `POST /v1/executions:submit` as the ES-owned async handoff through
Nomad, keeps the submit receipt bounded and free of Control Plane
attempt/review/checkpoint/finalization/intervention, approval,
hold/resume/reject, Temporal, or workflow grammar, keeps
`lifecycle_projection.source=nomad` with an opaque same-run
read-coordination `revision`, and preserves current status/logs/result/cancel
plus `control-plane-normal-shell/v1` compatibility. It does not redesign
runtime behavior.

C3 is the focused tests/docs guardrail slice for retained-result and
`authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
C3 pins that retained result bundles remain ES-owned opaque output artifacts
and that CP may materialize, review, checkpoint, and finalize retained result
contents semantically, but CP does not own the retained bundle as run-control
state. Retained result references, paths, manifests, archives, `.out` copies,
and materialized workspaces are evidence/projection or implementation detail,
not orchestration authority. `GET /v1/executions/{run_id}/result`
compatibility shape remains unchanged unless an explicit migration/versioning
plan exists. `authority_handoff` remains bounded non-secret runtime handoff
evidence only. `authority_handoff` never carries or implies live credentials,
Vault tokens, Codex credentials, leases, approvals, operator authorization, CP
workflow state, scheduler truth, or retained-result authority. Runtime
identity/Vault handoff remains workload-side and non-secret; ES does not
become a Vault token broker or Codex credential broker. `outcome_evidence`
remains bounded evidence/projection; current labels remain compatibility
surfaces. `control-plane-normal-shell/v1` and
`execution_substrate.runtime_profile` compatibility remain preserved unless an
explicit migration/versioning plan exists.

C4 is the focused tests/docs guardrail slice for runtime identity and Vault
handoff boundaries. C4 is guardrail work, not runtime redesign and not live
helper execution. Runtime identity acquisition is workload-side or
helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
non-secret runtime identity and Vault configuration metadata, but ES must not
mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES must
not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies, private
keys, API keys, proof secrets, root tokens, unseal keys, Vault client tokens,
or secret payloads through public DTOs, lifecycle responses, retained-result
metadata, summaries, logs, reports, `.out`, support bundles, or proof
artifacts. `authority_handoff` may include non-secret credential-location and
configuration metadata only. `authority_handoff` must not carry live
credentials, leases, approvals, Vault tokens, Codex credentials, JWT-SVIDs,
API keys, or scheduler truth. Workload-side Vault auth remains workload-side;
Vault owns token, secret, and lease authority. SPIRE owns identity issuance
and SVID material. ES must not expose raw SPIRE socket access to workloads as
public ES grammar. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the
workload-facing identity endpoint contract rather than raw SPIRE socket
access. Runtime identity and Vault handoff evidence remains non-authoritative
and redacted. CP may consume runtime identity/Vault handoff evidence, but CP
does not own credential acquisition, Vault tokens, SPIRE identity issuance, or
ES runtime handoff boundaries. IM and Maintenance Agent may report
diagnostics/readiness/status, but do not own runtime identity or Vault
authority. `control-plane-normal-shell/v1` and
`execution_substrate.runtime_profile` compatibility remain preserved unless an
explicit migration/versioning plan exists. Existing workload-auth Remote Alpha
helpers remain bounded operator/support surfaces, not ES token brokerage or
production Vault readiness.

The supported-local host `.out` proof directory is evidence-only and private
`0700`. Task-owned bootstrap/transport scratch is separate from that directory,
the repository, guest scopes, deployed state, and the externally provisioned
retained-result key. Only an identity-revalidated exact scratch cleanup may
remove it; unproven cleanup retains it. The host source snapshot is built from
guarded Git's explicit tracked and non-ignored untracked source set, with
bounded deterministic files, a source manifest, and a snapshot digest. Its
archive and other transport inputs never become host proof evidence.

Guest evidence admits only fixed-schema non-secret projections. Raw
Nomad/Docker/systemd configuration, service logs, arbitrary execution
responses, workdirs, and opaque result bundles are not retained. A bounded
exact-schema validation of the controlled normal-shell result emits only
non-secret member hashes, sizes, and fixed proof assertions. Guest collection
publishes exclusive setup, final, or failure generations, without merge or
overwrite. A labeled capture writes only its own summary, status, and fixed
execution projections, so a partial second capture cannot mix base lineage.
Its summary and fixed execution projection retain the exact validated public
`run-[0-9a-f]{16}` run ID, derived `exec-<run_id>` job ID, and bounded Nomad
allocation ID. An unlabeled capture alone writes the base forms.
For the bounded normal-shell proof, capture verifies that its copied summary
names the selected private workdir and that workdir's `result.tar.gz` exactly.
Result-validation uses that captured summary, not a new latest-workdir scan or
a proof-root raw-result alias. It requires a successful terminal exit-zero run,
`result_available=true`, a positive compressed byte count within the existing
16 MiB bound, and the matching fixed Nomad run/job/allocation projection with
successful observation booleans. Result-validation parses both captured JSON
inputs strictly, rejecting duplicate object keys and nonstandard constants.
The workdir must be a clean absolute direct
child of this proof's private `workdirs/`; the result path must name its own
`result.tar.gz`. Held no-follow directory and file reads require an unchanged
original workdir summary and a stable regular single-link bundle of the
declared size. The existing exact result schema validates those same buffered
bytes before the fixed safe result-evidence JSON is created exclusively.
Missing, mismatched, or rejected input fails result-validation; no other
workdir or legacy alias is selected. Raw bytes and workdir paths remain private
guest data and outside host evidence. This is a bounded proof-consumer rule,
not result authentication or ES/CP lifecycle authority.
For each unique supported-local proof job, the proof wrapper requires exactly
one allocation in the Nomad allocation list before observing and retaining its
ID. The complete allocation-list response must be strict JSON: nonstandard
`NaN`, `Infinity`, and `-Infinity` constants fail with a fixed safe error even
inside unknown or nested fields, before allocation selection or observation.
Zero or multiple allocations, a malformed entry, or an invalid ID fail
closed without a Nomad execution projection or a successful proof. Honest
summary, status, and log-assertion projections may remain as partial failure
evidence in the exclusive failure generation. This is a bounded proof rule,
not a general Nomad retry, reschedule, or multi-allocation policy; it does not
change ES's internal latest-`ModifyIndex` allocation-selection rule. A proof
contract for multiple meaningful allocations requires explicit redesign.
Node-detail admission parses a loopback-only URL with explicit port and no
userinfo, query, fragment, or non-root path; responses are individually and
aggregately bounded and reduced to fixed counters without retaining raw node
details. The deterministic final host manifest is the root evidence record:
its `self_excluded` field is true, and its rows cover every other retained
proof file, excluding the manifest itself. The manifest is reopened through
the held directory descriptor, verified, and reported by SHA-256 without a
digest sidecar. Unclassified material is rejected. Failure finalization preserves the
primary proof status and never falls back to recursive copying. These
manifests and projections are evidence, not ES, Nomad, result-authentication,
or lifecycle authority. The external retained-result key is never copied or
cleaned by this proof scope.

C5 is the focused tests/docs guardrail slice for current
status/logs/result/cancel compatibility and non-authority posture. C5 is
guardrail work, not runtime redesign, live proof, or remote validation.
Status remains Nomad-backed lifecycle projection and evidence, not CP workflow
truth or ES lifecycle-store truth. Logs remain a bounded current
compatibility/evidence surface, not final log architecture, CP run-control
truth, or scheduler authority. Result remains opaque ES-retained output
delivery, not CP checkpoint, finalization, or review state. Cancel remains a
bounded ES/Nomad cancellation handoff, not CP intervention authority,
operator approval authority, or Temporal workflow truth. Status/cancel JSON
envelopes and successful logs/result headers must exclude CP run-control
grammar and live credential/security fields; logs/result bodies remain
payload/output surfaces governed by the existing compatibility contract and
must not be newly sanitized, interpreted, or promoted into authority.

C6 is ES Admission Policy Layer v0. It is a Workstream C admission extension
and keeps ES as the final admission-policy gate for ES-bound executions. CP
may later preflight or render ES policy decisions, but CP is not the final ES
gate. IM remains readiness, provenance, and diagnostics only. C6 adds a small
ES-local replaceable policy seam to the shared `:prepare`/`:submit` admission
path and one built-in selected-pattern static-script content policy. Policy
denials use the existing redacted ES error envelope with safe reason code and
message only. The v0 policy claim is not universal malware detection, complete
command sandboxing, proof that all destructive behavior is impossible,
production endpoint security proof, runtime identity or Vault proof, IM
support-bundle proof, public/demo readiness proof, independent audit proof,
cancel/failure/intervention proof, CP-owned final ES policy, IM-owned policy
authority, or semantic understanding of all Control Plane prompts, workspaces,
scripts, retained bundles, logs, model outputs, or generated artifacts.

The C6 configurable-input follow-up adds ES deployment/admin configuration for
inputs to built-in ES admission policies only. It adds
`execution-substrate.admission.configured-static-script-literal-deny/v1` with
mode `disabled` or `enforce`, safe entry IDs, a bounded literal-entry list, and
the fixed input class `static_script_payload_text`. The deny reason code is
`configured_static_script_content_denied`, and the safe public message is
`static script content denied by admission policy`. This is not a broad policy
engine, evaluator injection, OPA/Rego, DSL, regex engine, glob or shell
expression engine, customer-authored policy bundle path, external evaluator
service, CGS `id.conf` reuse, CP-defined ES policy input, request-supplied
policy entry path, user-defined reason-code path, or user-defined API-message
path. Denials remain redacted.

Control Plane may consume the accepted lifecycle surface, including the bounded `control-plane-normal-shell/v1` runtime-profile path, but CP documents, probes, examples, and proof harnesses do not define ES lifecycle contracts. Any widening or breaking change must be planned in `PLANS.md` and the ES docs before implementation spreads outward.
Control Plane owns orchestration, Temporal workflow state, review, checkpoint,
finalization, intervention, and operator-facing control semantics. CP consumes
accepted ES surfaces but does not define ES core contracts.
IM readiness/profile/support-bundle/provenance artifacts remain
evidence/projection/diagnostics only; they do not become ES or CP authority.
Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
only and do not define ES route semantics.

## 2. How to read this document

- **Observed current contract**: A public endpoint, response, error, or lookup rule enforced by the current Go code and tests.
- **Current contract invariant**: A current rule callers and upstream docs can rely on and that must not change silently.
- **Bounded slice contract**: A live contract rule that is intentionally narrow and should not be treated as permanent architecture by default.
- **Deliberate absence**: A lifecycle capability or response surface the current slice intentionally does not offer.
- **Reopened lifecycle seam**: An active lifecycle surface that `PLANS.md` and the redesign-phase docs explicitly keep open.

These labels are intentionally different. A contract may be live today, relied on now, and still explicitly bounded or reopened.

## 3. Endpoint inventory

| Endpoint | Purpose | Current status | Response type | High-level ownership note |
| --- | --- | --- | --- | --- |
| `GET /v1/executions:contract` | Return the narrow producer compatibility declaration for the current governed-execution contract | Active and bounded | `200` JSON `ProducerContractDeclaration` | ES-owned static compatibility declaration, not readiness or run authority |
| `POST /v1/executions:prepare` | Return bounded preflight success without creating execution state | Active and bounded | `200` JSON `PrepareResult` | ES-owned admission composition surface |
| `POST /v1/executions:submit` | Perform real execution submission | Active and bounded | `202` JSON `SubmitResult` | ES hands off to Nomad |
| `GET /v1/executions/{run_id}/status` | Return current execution status view plus bounded projection revision | Active | `200` JSON `ExecutionStatusResult` | Nomad-backed status projection through ES |
| `GET /v1/executions/{run_id}/logs` | Return execution logs | Active and bounded | `200` `text/plain` | Nomad-backed stdout retrieval through ES |
| `GET /v1/executions/{run_id}/result` | Return retained terminal result bundle | Active and bounded | `200` `application/gzip` | ES-owned retained opaque bundle for current static-script slice |
| `POST /v1/executions/{run_id}:cancel` | Request cancellation of a submitted execution | Active and bounded | `200` JSON `ExecutionCancelResult` | Bounded Nomad stop request through ES |

`POST /v1/executions:prepare` is a live public endpoint in the current repo. It must not be omitted from contract documentation just because it is bounded.

## 4. Caller authorization contract

**Observed current contract**

- All lifecycle/execution endpoints require an authenticated caller identity.
- Bootstrap PKI callers are rejected for execution operations.
- Accepted caller identities are the SPIFFE paths whose prefixes match `authorization.allowed_spiffe_path_prefixes` in ES config.
- Prefix matching is exact-or-subpath: a caller path is accepted only when it
  equals a configured prefix or starts with that prefix followed by `/`.
- ES startup config validation keeps those prefixes narrow. Each configured
  prefix must be a relative SPIFFE path prefix with at least two non-empty path
  segments, no leading or trailing slash, and no `.` or `..` segment.
- Single-segment prefixes such as `service` or `operator`, root-like prefixes
  such as `/`, and traversal-like prefixes are rejected because exact-or-subpath
  matching would make them broad namespace grants.
- The current repo-owned runbooks, proofs, and generated helper configs keep that allowlist operator-only:
  - `spiffe://execution.internal/operator/local`
- The first repo-owned non-operator caller activation path is Control Plane at:
  - `spiffe://execution.internal/service/control-plane`
- The current prefix-based allowlist model is sufficient for that activation when configured narrowly with `service/control-plane`; a broad `service/` allowlist is not required
- The repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`, paired with `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- The current governed sequencing for that caller is producer contract compatibility check, AGS publish, ES `:prepare`, ES `:submit`, and then status/logs/result/cancel only for submitted runs.
- The current direct helper remains a lower-level compatibility helper: it still performs publish and submit directly by default, and submit reuses ES admission internally. The helper does not define CP policy ownership and does not imply submit can bypass prepare/admission.
- When that direct example waits for terminal status outside explicit cancel mode, it now fails fast if ES reports a terminal nonzero workload exit instead of printing a false success marker
- On this Mac, the supported-local guest path is the grounded positive verification path for that bounded `logs` step
- The focused app integration harness at `es/app/control_plane_integration_path_test.go` remains the repo-owned verification layer for the same direct API path, including disallowed-caller failures, while staying bounded to publish, submit, status, and cancel coverage in the host-local harness
- The runbooks, proofs, and helper scripts remain operator-only by default
- These caller rules apply to:
  - `:contract`
  - `:prepare`
  - `:submit`
  - `status`
  - `logs`
  - `result`
  - `cancel`

**Current contract invariants**

- Missing authenticated caller identity returns `401`.
- Bootstrap PKI callers return `403`.
- Authenticated callers outside the configured allowlist return `403`.

**Response semantics**

- Authorization failures are plain-text responses, not JSON lifecycle error payloads.
- Once authorization succeeds, endpoint failures are returned as JSON `ErrorResponse` payloads except for successful `logs`, which returns `text/plain`, and successful `result`, which returns binary `application/gzip`.

## 4A. Producer Contract Declaration

### Purpose

`GET /v1/executions:contract` returns a non-secret, non-run-specific declaration for the current governed-execution producer compatibility surface.

It exists so Control Plane or an infrastructure manager can fail fast when a pointed-at ES instance does not declare the current producer contract before a high-value run is submitted.
`GET /v1/executions:contract` remains a narrow producer compatibility
declaration, not health, submit readiness, run authority, or a general
capability registry.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these fields:

- `schema_version = "execution-substrate.producer-contract/v1"`
- `service = "execution"`
- `governed_execution`
  - `contract = "governed-execution-producer/v1"`
  - `enabled`
  - optional `disabled_reason`
  - `runtime_profiles`
  - `outcome_evidence`
- `non_authority`

The `outcome_evidence` declaration says that the current governed-execution producer contract requires:

- status JSON to include `outcome_evidence`
- cancel JSON to include `outcome_evidence`
- successful logs responses to preserve `text/plain; charset=utf-8` and expose outcome evidence through `Execution-Substrate-Outcome-*` headers
- successful result responses to preserve `application/gzip` and expose outcome evidence through `Execution-Substrate-Outcome-*` headers

The declared evidence labels are the current bounded vocabulary:

- status observations from Nomad: `nomad_job_projection`, `nomad_projected_allocation`, and `nomad_task_state_projection`
- cancel receipt observation from Nomad: `nomad_stop_request_accepted`
- logs observation from Nomad: `nomad_task_stdout` with access class `plaintext_stdout`
- result observation from the ES retained-result store: `retained_result_bundle` with access class `opaque_result_bundle`

When ES submit configuration is absent, `governed_execution.enabled` is `false` with `disabled_reason = "submit_not_configured"`. This is an early compatibility failure for current live governed-execution clients; it is not a health failure.

Runtime-profile entries are configuration-aware:

- `static-script/default` is `enabled` only when submit is configured
- `control-plane-normal-shell/v1` is `enabled` only when submit is configured and `execution.runtime_profiles.control_plane_normal_shell.enabled=true`

Runtime-profile disabled reasons are part of the current declaration shape:

- when submit configuration is absent, governed execution is disabled with `disabled_reason = "submit_not_configured"` and each declared runtime-profile entry is disabled for the same reason
- when submit configuration is present but the bounded Control Plane normal-shell profile is not enabled, that profile entry is disabled with `disabled_reason = "profile_not_enabled"`

### Current contract invariants

- The declaration is read-only and non-secret.
- The declaration is served only after the same authenticated caller and configured SPIFFE allowlist check used by the execution and lifecycle API.
- The declaration is not service health, submit readiness, artifact-specific admission proof, run existence proof, lifecycle state, lifecycle write coordination, credential possession, policy approval, or scheduler API.
- The current `non_authority` classifications include `not_service_health`, `not_submit_readiness`, `not_artifact_admission_proof`, `not_run_authority`, `not_run_existence_proof`, `not_lifecycle_truth`, `not_lifecycle_write_coordination`, `not_credential_truth`, `not_policy_truth`, and `not_scheduler_api`.
- The declaration must not expose Nomad job IDs, allocation IDs, task IDs, host paths, result filesystem paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, or policy approval state.
- Consumers may use the declaration as an early compatibility gate by requiring `governed_execution.contract = "governed-execution-producer/v1"`, `governed_execution.enabled = true`, and mandatory status/cancel/logs/result outcome-evidence surfaces.
- Consumers that require the bounded Control Plane normal-shell path must also require an enabled `control-plane-normal-shell/v1` runtime-profile entry.
- Consumers must still use `/health`, submit-readiness checks, and `:prepare` for service health, environment readiness, and artifact-specific admission proof.

### Target reliable-submit producer sub-contract selection

**Target-only public selection; not implemented by the current server**

The current producer-contract outer identity remains
`execution-substrate.producer-contract/v1`, and the current governed-execution
contract remains `governed-execution-producer/v1`.

A later implementation may add one explicitly named and versioned
reliable-submit producer sub-contract under the governed-execution declaration.
That addition is narrow and additive to the current declaration. It declares
only the reliable-submit contract family/version supported, whether reliable
submit is enabled for this installation, a bounded safe unavailable or disabled
reason, request and response schema identifiers, the minimum safe
request-contract discriminator required by a reliable client, supported
recovery modes, and non-authority labels.

The target reliable-submit producer sub-contract name is `reliable_submit`.
The reliable contract identifier is
`execution-substrate.reliable-submit/v1`. The reliable request schema
identifier is `execution-substrate.reliable-submit-request/v1`. The mandatory
request-body discriminator is the top-level `reliable_submit` object. The
later producer declaration should follow the current narrow style with fields
for `contract`, `enabled`, `disabled_reason` when disabled, request and
response schema identifiers, required discriminator, supported recovery modes,
and non-authority labels. It must not freeze a redundant
enabled/status/reason triple, and transient store health must not become
producer-contract truth.

The reliable-submit producer sub-contract is not a generic `capabilities` map,
feature registry, plugin registry, cross-service probing framework, health
check, submit-readiness proof, admission proof, run authority, run existence
proof, lifecycle truth, scheduler API, or execution permission.

Reliable clients must treat this declaration as a preflight compatibility gate
only. They must authenticate, read the producer declaration, require the exact
reliable-submit sub-contract and enabled status, and then submit a structurally
distinct reliable request body. The declaration alone is not sufficient opt-in;
the request body discriminator remains an independent fail-closed gate.

The exact public response schema string, public error vocabulary, recovery
route shape, and runtime enablement behavior remain open for later tranches.
The current producer declaration has no implemented reliable-submit
sub-contract.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |

### Bounded slice notes

**Bounded slice contract**

- The declaration is a narrow compatibility-gate surface for the current CP governed-execution producer path.
- It describes the current producer contract; it does not create a broad capability registry or a cross-service probing framework.
- It does not replace the existing submit-ready operator checks.

### Reopened seams

**Reopened lifecycle seams**

- The long-term ES public execution shape remains reopened.
- The declaration is retained as current compatibility support while the request, runtime-profile, lifecycle, and evidence vocabularies remain bounded.

## 4B. Runtime profile compatibility matrix

This matrix records the current runtime-profile vocabulary and adjacent
runtime-profile-looking values. It is a compatibility cleanup, not a final
runtime-selection design.

| Surface or value | Current classification | Current behavior | Non-claim |
| --- | --- | --- | --- |
| `execution_substrate.runtime_profile` | `Temporary compatibility edge` | The only current request annotation key for opt-in runtime-profile selection. Omitted or empty keeps the default current `static-script` runtime behavior. | Not the final runtime-profile selection model, not a shared-kernel grammar, and not CP workflow authority. |
| omitted or empty `execution_substrate.runtime_profile` | `Bounded slice rule` | Accepted. Resolves to the current default runtime name `static-script/default`, uses `execution.base_image`, and injects no profile-specific Codex credential-location metadata. | Not a package-kind redesign, not proof that every advertised runtime profile can prepare, and not a final default-runtime vocabulary. |
| `static-script/default` | `Bounded slice rule` | The current default runtime name used in producer declarations, submit metadata, and `authority_handoff`. It is selected by omitting the annotation or leaving it empty; current source does not treat a non-empty annotation value of `static-script/default` as a separate opt-in selector. | Not the final package model and not a promise that the explicit annotation value is accepted unless a future ES-owned migration documents that change. |
| `control-plane-normal-shell/v1` | `Temporary compatibility edge` | Accepted only as an explicit opt-in annotation when submit is configured, `execution.runtime_profiles.control_plane_normal_shell.enabled=true`, the artifact is `static-script`, and signed evidence has `network_access=true`. | Not the default runtime model, not a package-kind redesign, not a general image/tool marketplace, and not a transfer of CP orchestration, review, checkpoint, or finalization semantics into ES. |
| `execution.runtime_profiles.control_plane_normal_shell.*` | `Bounded slice rule` | ES deployment/admin config for enabling and parameterizing the bounded Control Plane normal-shell profile image, Codex CLI path metadata, and workload-Vault credential-location metadata. | Not a public runtime-profile name, not credential material, not credential brokerage, and not runtime identity ownership. |
| `execution-substrate/control-plane-normal-shell:supported-local`, `execution-substrate/control-plane-normal-shell:local`, and the supported-local proof Codex shim | `Proof-only or bounded local proof` | Runtime support image/shim values that can realize the configured Control Plane normal-shell profile in local proof paths. They are not accepted runtime-profile annotation values. | Not production Codex availability, not a runtime-profile vocabulary entry, not submit readiness by itself, and not a long-term image lifecycle architecture. |
| unsupported or unknown non-empty profile values | `Rejected/unsupported` | Rejected by `:prepare` and by the configured `:submit` path as `unsupported_runtime_profile` before run ID creation, staging, scheduler handoff, or CP run failure. | No fallback profile is selected and no CP review/checkpoint/finalization state is created. |
| long-term runtime-profile vocabulary, runtime identity handoff owner, and workload-zone runtime-config owner | `Reopened redesign seam` | Remain open beyond the bounded CP normal-shell compatibility edge and the current default runtime behavior. | This cleanup does not settle final package layout, DTOs, runtime identity, workload-zone config, credential acquisition, or final runtime vocabulary. |

Runtime-profile public surfaces remain non-secret. Producer declarations expose
only profile names, status, disabled reasons, and outcome-evidence declarations.
`authority_handoff` may expose only the documented non-secret runtime profile,
workload identity endpoint, workload-Vault metadata, runtime-config digest, and
Codex credential-location labels. Runtime-profile fields must not expose
private keys, PEM bodies, raw cert bodies, env values, endpoint secrets,
TLS/SPIFFE/Vault material beyond documented safe labels, raw logs,
support/retained/proof payloads, unsafe paths, or CP workflow, review,
checkpoint, and finalization fields.

## 5. Prepare contract

### Purpose

`POST /v1/executions:prepare` returns bounded preflight success for a requested artifact execution without creating execution state.
`POST /v1/executions:prepare` remains bounded preflight and creates no run
object or scheduler handoff.

### Request contract

**Observed current contract**

- Request body is JSON using the current shared execution request shape also used by `:submit`.
- The current top-level request includes:
  - `schema_version`
  - `invocation`
  - `mode`
  - `timeout_seconds`
  - `resources`
- The current invocation payload includes:
  - `schema_version`
  - `artifact_digest`
  - `derivation_spec_digest`
  - `output_id`
  - optional `argv`
  - optional `env`
  - optional `mounts`
  - optional `annotations`
- The only currently defined runtime-profile annotation is `execution_substrate.runtime_profile`. Omitted or empty keeps the default current `static-script` runtime behavior; `control-plane-normal-shell/v1` opts in to the bounded Control Plane normal-shell runtime profile.

**Current contract invariants**

- `invocation.artifact_digest` must be a labeled SHA-256 digest.
- `invocation.derivation_spec_digest` must be a labeled SHA-256 digest.
- `invocation.output_id` is required.
- `invocation.derivation_spec_digest` and `invocation.output_id` are the only currently shared derivation authorization inputs ES compares against aggregate artifact evidence during `:prepare`.
- `timeout_seconds` must be non-negative.
- If `resources` is present, both CPU and memory must be greater than zero.
- If `mode` is present, it must be `sync` or `async`.
- Environment keys must not use reserved runtime/control-plane keys.
- If the manifest runtime interface declares allowed environment keys, provided keys must stay within that set.
- If mounts are provided, they must satisfy the current mount contract:
  - artifact-backed
  - read-only
  - absolute cleaned target paths
  - target paths under `/execution/mounts`
  - no overlap between mount targets
- If `execution_substrate.runtime_profile` is present, it must name a runtime profile ES supports and has enabled in config. Unsupported or disabled profile selections fail during `:prepare` before any run ID exists.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these contract fields:

- `success`

### Current invariants

**Current contract invariants**

- `:prepare` reads the registered artifact discovery record from ARS and follows it to the aggregate artifact-evidence blob.
- `:prepare` treats the ARS discovery record as an upstream discoverability
  input, not as ES public execution grammar.
- `:prepare` requires aggregate artifact evidence and verifies that record before success.
- `:prepare` does not require ARS descriptor or manifest support data on the
  current hot path.
- `:prepare` verifies publish-time evidence and EGS runtime-trust constraints before success.
- `:prepare` uses only the narrow shared execution/runtime claims ES currently enforces from aggregate artifact evidence: runtime env allowlist, required capabilities, `target_platform`, and `network_access`.
- `:prepare` resolves workload-zone vault information through the configured workload-zone Vault config reference and ARS before success.
- `:prepare` evaluates ES Admission Policy Layer v0 before success. When an
  enabled policy requires payload inspection, `:prepare` may fetch bounded
  payload bytes through the explicit ARS payload digest carried by the
  discovery/evidence relationship already cross-checked by admission.
- The Workstream E E0 decision in
  `.docs/system_overview/runtime_config_ownership.md` classifies this path:
  runtime-config semantics live in `internal/contracts/runtimeconfig/v1`, ARS
  owns blob storage/read by digest only, ES is the current consumer and lookup
  orchestrator, and no ACS hop exists.
- ES startup-config placement of the required runtime-config reference is
  compatibility/config residue on a reopened ownership seam, while startup
  validation still guarantees the typed reference is configured before ES
  serves governed execution traffic.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.
- `.docs/system_overview/artifact_publication_storage.md` records the authoritative Workstream B publication/storage/discoverability decision that this prepare contract consumes. On the current hot path ES follows ARS discovery plus explicit evidence/payload references, keeps descriptor/manifest support paths as secondary compatibility support rather than ES public grammar, and preserves the explicit separation between `artifact_digest` and `payload_digest`.
- `:prepare` does not surface EGS publication metadata or internal composition detail as part of its preparation result.
- `:prepare` does not treat Control Plane orchestration, review, checkpoint, finalization, task-attempt, or proof-harness metadata as shared admission facts.
- Static-script payload text inspection is an ES-visible input class only. It
  is not CP prompt parsing, CP workspace parsing, CP package grammar, decoded
  workspace archive inspection, binary payload inspection, retained bundle
  scanning, support-bundle scanning, raw log scanning, model-output scanning,
  or generated-artifact scanning.
- The built-in selected-pattern content policy has policy ID
  `execution-substrate.admission.selected-destructive-shell-command/v1`,
  deny reason code `destructive_shell_command_denied`, and safe deny message
  `destructive shell command denied by admission policy`.
- The built-in configured literal content policy has policy ID
  `execution-substrate.admission.configured-static-script-literal-deny/v1`,
  deny reason code `configured_static_script_content_denied`, and safe deny
  message `static script content denied by admission policy`.
- Configurable admission policy inputs are ES deployment/admin config only.
  CP does not define or supply ES admission-policy inputs, requests cannot
  carry policy entries, and IM remains readiness/provenance/diagnostics only.
  The current config shape supports only mode `disabled` or `enforce`, safe
  entry IDs, valid UTF-8 printable non-control literal deny entries that are not
  whitespace-only, and input class `static_script_payload_text`; `enforce` mode
  requires at least one entry;
  regex, glob, shell expressions, Boolean policy logic, OPA/Rego, DSLs,
  customer policy bundles, external evaluators, user-defined reason codes,
  user-defined API messages, and CGS `id.conf` reuse remain deliberate
  absences.
- If required policy input cannot be safely inspected, ES fails closed with
  reason code `admission_policy_input_unavailable` and safe message
  `admission policy input unavailable`.
- For the current `static-script` policy input, ES requires one effective
  regular top-level `entrypoint` after trimming pathname whitespace and
  cleaning slash-separated tar paths. A lone normalized alias is supported.
  The entire archive must have no duplicate regular destination (including
  identical-body duplicates), file/directory or implicit-parent conflict,
  traversal, link, special entry, nonzero decoded tar tail, or additional
  compressed gzip member/bytes. An ambiguous or malformed archive fails with
  `admission_policy_input_unavailable` before policy allow, Submit run
  assignment, materialization, or provider registration. Inspection retains
  the 256 KiB compressed payload, 64 KiB entrypoint text and 64 tar-entry
  limits, and limits the whole decoded tar stream, including headers, skipped
  bodies and trailing bytes, to 16 MiB. Runtime extraction independently
  enforces the same canonical destination and stream-tail integrity before
  launch; generic runtime archives need not contain a top-level entrypoint.
  This bounded rule does not inspect nested workspace archives or establish
  universal script safety. Extraction failure may leave temporary files already
  written; it never authorizes a workload launch.
- GNU sparse representations are outside the current static-script archive
  contract: the old GNU sparse type and any effective header carrying a
  `GNU.sparse.*` PAX record reject before policy body reading or runtime
  destination creation, including recognized 0.0/0.1/1.0, all-hole, and
  unknown sparse metadata. Go's tar reader may parse bounded sparse metadata
  during `Next` before ES checks the returned header. The 16 MiB policy
  decoded-stream budget counts physical gzip-emitted tar bytes, not logical
  sparse holes, so ES does not read those holes. This does not add a 16 MiB cap
  to generic runtime extraction or exclude ordinary PAX/GNU long names.
  Canonical destination interpretation trims the raw effective tar name once
  and then cleans slash-separated components once. Both namespace registration
  and runtime placement use that same value without re-trimming it. Significant
  component whitespace exposed by cleaning remains: `./ entrypoint` becomes
  ` entrypoint`, distinct from `entrypoint`. True aliases and collisions still
  reject; runtime containment and exclusive file creation still apply.
- Policy denial responses must not expose raw payload text, matched content,
  prompts, workspaces, model outputs, logs, retained bundles, support bundles,
  credentials, environment values, DB contents, local process records,
  cert/key/TLS/SPIFFE/Vault/WebAuthn/passkey/API-key material, or generated
  artifact contents.
- Successful `:prepare` returns bounded preflight success only, not execution state.

### Explicit non-effects

- No `run_id` is created.
- No Nomad job or eval ID is returned.
- No scheduler handoff occurs.
- No proto-execution state or durable ES execution record is created.
- No workload-vault plan, signer detail, or workload identity detail is returned.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Malformed request body, invalid request fields, or request/fact mismatch | `400` | `invalid_request` |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Aggregate artifact evidence is structurally invalid or fails signature verification | `403` | `artifact_evidence_invalid` |
| Signer not allowed | `403` | `signer_not_allowed` |
| Signer revoked | `403` | `signer_revoked` |
| Artifact revoked | `403` | `artifact_revoked` |
| Aggregate artifact evidence not registered for the artifact | `404` | `artifact_evidence_not_found` |
| Trust model unavailable | `503` | `trust_model_unavailable` |
| Aggregate artifact evidence blob or response is unavailable after registration | `503` | `artifact_evidence_unavailable` |
| Workload-zone vault lookup or blob unavailable | `503` | `workload_zone_vault_unavailable` |
| Unsupported, disabled, or invalid runtime profile selection | `400` | `unsupported_runtime_profile` |
| ES admission policy denial | `403` | policy reason code, such as `destructive_shell_command_denied` or `configured_static_script_content_denied` |
| Required ES admission policy input unavailable | `403` | `admission_policy_input_unavailable` |
| Dependency payload invalid or dependency request failed | `503` | current endpoint-specific code is preserved and the logical class remains the same as the missing dependency |

### Bounded slice notes

**Bounded slice contract**

- `POST /v1/executions:prepare` is an active milestone surface, not a declared long-term public execution API.
- `:prepare` is active today but intentionally bounded.
- It proves preflight success only.
- It does not create a long-lived execution object, scheduler record, or wider lifecycle surface.

### Reopened seams

**Reopened lifecycle seams**

- The public role and future of `:prepare`
- The long-term shape of the preparation result
- The extent to which preflight success should remain part of a public execution contract

## 6. Submit contract

### Purpose

`POST /v1/executions:submit` performs real execution submission in the current slice.
`POST /v1/executions:submit` remains the MVP execution handoff surface: async,
bounded receipt, and Nomad submission through ES.

### Request contract

**Observed current contract**

- Request body uses the same JSON execution request shape as `:prepare`.
- The request is revalidated through the full preparation path before submission proceeds.
- The shared admission path borrows the caller request and immediately
  deep-copies every mutable member. One private Prepare-versus-Submit intent
  makes that admission-owned working copy the sole mutable authority for mode
  handling, schema defaulting, validation, and normalization. Successful
  admission returns one frozen authoritative snapshot; immutable defensive
  transfer copies are permitted and are not competing authorities.
- The caller retains ownership until the initial admission copy completes and
  must keep the request and every reachable mutable member race-free through
  that copy. Concurrent unsynchronized mutation during copying is a caller
  data race, not an ES synchronization guarantee. After the owned copy
  completes, later caller mutation cannot change admitted or submitted state;
  downstream defensive copies do not create a second mutable authority.

**Current contract invariants**

- Omitted `mode` defaults to `async`.
- Only `async` submission is supported in the current slice.
- The current execution slice only accepts:
  - `static-script` artifacts
  - no required runtime capabilities
  - `target_platform` unset or `docker`
- `invocation.annotations["execution_substrate.runtime_profile"]="control-plane-normal-shell/v1"` selects the bounded Control Plane normal-shell runtime profile. That profile remains a `static-script` overlay and additionally requires:
  - explicit ES config under `execution.runtime_profiles.control_plane_normal_shell`
  - `network_access=true`
  - a configured profile image
  - an absolute configured Codex CLI path metadata value
  - configured workload-vault secret path and field metadata for Codex credential material
- In the repo-owned supported-local runtime surface, submit-readiness for that enabled profile also requires the configured image to be present and Nomad Docker image cleanup to be disabled through `docker.cleanup.image=false`, so repeated client runs from the same prepared environment are not invalidated merely by Nomad's stopped-task image cleanup.
- Runtime mounts, when present, must satisfy both the prepare-time mount request rules and submit-time reserved-path checks.
- Submit resolves payload bytes through the explicit payload digest carried in aggregate evidence.
- Submit reuses the same ES Admission Policy Layer v0 path as `:prepare` and
  cannot bypass a policy that `:prepare` would deny.
- Policy denial happens before payload staging, mount staging, run ID creation,
  and Nomad submission.
- Current submit resolves and freezes one private source-grounded semantic plan
  plus owned payload/runtime-support/mount/trust material before assigning its
  run ID. Successful resolver return is the freeze point. There is no staging
  directory creation, file write, ownership mutation, or Nomad registration before
  that point.
- The private `resolvedExecutionPlan` is admitted semantic truth. It owns
  request/invocation schema facts, effective mode and timeout, CPU and memory,
  runtime-profile identity and selected image, semantic profile/caller
  environment inputs, one typed runtime command, distinct
  artifact/payload/derivation/output identities, ordered governed mounts,
  network permission, current authority inputs, runtime-support digest,
  runtime-identity tmpfs size, and the fixed semantic job envelope. The
  source-grounded payload digest comes only from the discovery/evidence
  relationship already cross-checked by admission; raw payload bytes remain
  material and do not enter the plan or public/Nomad projections.
- Captured host context contains only normalized qualified values: the cleaned
  absolute staging root, qualified owner UID/GID, cleaned absolute SPIRE source
  directory, and trimmed non-empty Nomad datacenter. The results root is
  trimmed, cleaned, and required absolute for current ES service/custody
  qualification, but remains outside the semantic plan, captured host context,
  provider-job projection, and B1 binding. The plan owns none of those
  placement facts and owns no run/job identity, owner-derived environment,
  endpoint URI, staged path, workspace path, or other derived host/run path.
  Runtime-identity tmpfs size remains
  semantic plan state because it changes the workload resource contract.
- After freeze, the run projection combines only the semantic plan, captured
  host context, and assigned locator. It adds run/job identity,
  owner/run/endpoint environment, host/staged mount sources, datacenter,
  endpoint, and derived run paths. Submit builders consume those typed
  projections and do not reread request, prepared admission, live service
  config, runtime-profile maps, workload-Vault/trust/ARS sources, filesystem
  owner state, SPIRE source, or datacenter.
- Current authority handoff is structurally present and unconditional for every
  successful current Submit. There is no plan-level applicability flag; the
  Codex credential-location subcomponent remains genuinely optional.
- The semantic plan is admitted semantic truth only. Semantic-plan equality
  across qualified host contexts is not provider-job, dispatch, replay,
  restart, safe-host-substitution, or provider-effect identity. Captured host
  context and run/provider projection add additional execution-shaping facts.
  The later private v1 `PlanBinding` producer now binds admitted semantics and
  captured material identities while keeping host/run facts outside semantic
  binding as later prerequisites. Historical B1 selected no canonical
  encoding, witness, replay, restart, or host-context binding treatment.
- One private typed runtime command is constructed before freeze and copied
  through plan, run, and provider projections. No execution-package or test
  helper owns a second complete supervisor grammar. A complete
  source-distinct literal default-profile expected job, direct pointer-owned
  token/template ledger expanded only in the expected tree, unmodified actual
  job tree, and separate literal authority-handoff expected object reached
  through real `Service.Submit` protect current successful behavior. A finite
  package-local direct-call closure plus exact producer, freeze, validation,
  payload-projection, and metadata inventories protect the B1 shape without
  claiming whole-program noninterference or general analysis. Tranche B2 now
  completes fixed public operational messages, prepared-admission ordinary
  redaction, bounded result-retention logs, selected structured Nomad response
  bounds, an explicit unbounded job-summary and public-Logs compatibility
  policy, a second source-distinct control-plane-profile golden, and dedicated
  finite assurance. Reliable keyed-submit runtime remains unwired, and native
  Linux runtime validation remains pending.
- After the freeze, exclusive creation of the run-scoped staging root is the
  first filesystem mutation. ES holds and verifies the parent/root descriptors,
  refuses every pre-existing object type, never adopts or mutates a pre-existing
  name, and revalidates the complete expected tree immediately before the one
  Nomad registration. Expected ownership is an invocation-local hierarchy in
  which each directory owns only its direct-child map and each unique edge owns
  its segment bytes and expected identity once. No cumulative path or second
  full-path index is retained. Revalidation keeps the identity descriptor and
  opens a fresh independent no-follow open-file description for enumeration at
  position zero. That fresh description is used directly, and its observed
  direct-child set must equal the owning node's map exactly. Each expected child
  is then checked descriptor-relative and no-follow for type, device,
  retained identity, owner/group, mode, and link-count policy. Missing,
  replaced, malformed, duplicate, unexpected, symlink, special-file, or
  cross-device state fails closed before Nomad without changing the entry.
  Regular expected children require link count exactly one. Expected
  directories require a positive link count because their count may grow as
  expected child directories are materialized.
  Construction is linear in traversed path-segment occurrences; retained
  variable data is linear in unique edge-segment bytes plus expected nodes;
  validation uses the expected tree plus one fixed enumeration batch. These
  are structural bounds, not exact Go heap, allocator, stack, descriptor, RSS,
  or secure-erasure claims.
  Once creation succeeds, every return closes descriptors and retains the
  visible root. Descriptor-close failure cannot replace a primary error or
  convert an accepted registration into a public failure.
- Payload staging, mount staging, and runtime-ready package assembly are now localized behind one internal ES-owned execution-package layout rather than being public contract.
- Successful and failed post-claim staging remains retained. Terminal result files written under the bounded reserved runtime result directory may also be retained outside staging, but result publication never authorizes staging mutation.

### Tranche A resource and filesystem custody contract

The following are active `Bounded slice rule` and compatibility/security
requirements for current Submit:

| Resource | ES consumer limit | Accounting boundary |
| --- | ---: | --- |
| discovery, evidence, workload-zone runtime-config, and trust-model JSON | 256 KiB each | response bytes before strict JSON decode |
| admission-policy payload | 256 KiB | response bytes before archive inspection |
| primary Submit payload | 32 MiB | response bytes before resolved material ownership |
| governed mount transport | 8 MiB per mount; 32 MiB aggregate | response bytes, including unknown/chunked bodies |
| complete decompressed mount stream | 16 MiB per mount; 64 MiB aggregate | bytes between gzip and tar, including metadata, headers, padding, bodies, end records, and trailing bytes |
| extracted regular-file bodies | 8 MiB per mount; 32 MiB aggregate | declared and consumed regular body bytes before allocation |
| runtime-support binary | 32 MiB | stable no-follow regular-file capture |
| normalized Vault CA; selected system CA | 256 KiB each | normalized captured bytes |
| combined workload trust bundle | 524,289 bytes | two bounded inputs plus at most one separator |

Every bounded response rejects `Content-Length` above its effective limit
before reading, reads at most effective-limit-plus-one for all other cases, and
accepts equality only with EOF. A governed mount read receives the smaller of
its per-mount limit and remaining aggregate transport budget. The archive
stream budget is installed before `tar.NewReader`, and the remaining gzip
stream is drained through the same budget after logical tar EOF. PAX local
headers and GNU long names remain supported under that stream budget. There is
no separate ES entry-count or resolved-name-length limit. Zero remaining
aggregate regular-body budget still permits directories and empty regular
files when compressed and whole-stream budgets remain available; any positive
regular-file body is rejected before allocation. The parser itself performs no
body allocation: it converts a checked header size to a closed internal token,
and a narrow reader allocates only from that token.

The staging parent and results root are opened without following any configured
path component. The run root is claimed with exclusive directory creation and
held by descriptor plus device/inode identity. Descendant creation is
descriptor-relative, no-follow, exclusive for files, and verified for type,
device, link count, owner, and mode on the opened object. There is no claim
marker, cleanup eligibility state, mutation/adoption reopening path,
quarantine rename, general residue or cleanup scan, or recursive whole-root
deletion. The bounded pre-handoff enumeration above is operation-local
completeness validation only and cannot be reused for discovery, adoption,
cleanup, quarantine, or reclamation.

Result packaging may call `openStagingTree` to reopen a retained root read-only.
That read-only handle exposes only visibility verification, no-follow directory
opening, and descriptor closure. It exposes no write, unlink, rename, mutation,
adoption, cleanup, quarantine, or reclamation method. Result publication,
terminal status, failure, cancellation, loss, or ambiguity grants no staging
deletion authority.

A post-claim failure preserves its existing primary public error, closes held
descriptors best-effort, and retains all partial invocation-owned state. An
ambiguous Nomad response retains the complete root and preserves the existing
`503 submission_failed` behavior. Successful registration retains the root and
returns the unchanged receipt. Exactly one registration remains.

Incomplete exclusive leaves, unpublished result and normalization temporaries,
and startup capability-probe fixtures remain when exact effect-time identity
for deletion is unproved. Pathname reuse is insufficient. No scan, recursive
cleanup, or later residue-reclamation owner is selected. Automatic whole-run-root reclamation is not implemented;
governed reclamation is an ES-owned `Reopened redesign seam`.
- Governed runtime-mount staging uses a distinct normalized workload-visibility rule: the complete mount subtree has `0755` directories, `0644` non-executable regular files, and `0755` executable regular files. Ownership stays with the selected execution-platform state owner; only executable intent survives archive-mode normalization. The claimed `0750` run-root ancestry and generic private payload, runtime-support, platform, trust, result-auth, and non-mount modes do not change. Exact custody identity registration and complete-tree pre-dispatch validation apply to these mount modes, and the Nomad/Docker mount stays read-only. This candidate-only source rule does not prove the later live Docker bind or native runtime success.
- The Review-07 CUSTODY-MODE-01 repair requires pre-dispatch expected-tree validation to compare the recorded and observed Unix file type, ordinary `0777` permissions, setuid, setgid, and sticky bits exactly. The claimed run root receives the same exact recorded-mode check. A mismatch fails before provider submission without chmod, chown, deletion, or replacement. Object-identity comparisons used for pathname binding and controlled metadata transitions retain their separate meaning.
- The Review-08 REGISTRATION-MODE-01 repair requires each newly created staging child directory and file, after its controlled ownership, mode, and file-content operations, to match the intended Unix file type and all `07777` mode bits before its identity enters the expected tree. A registration mismatch retains the unregistered child and claimed root without metadata repair or deletion and prevents provider submission. Later complete-tree handoff still validates the exact recorded state. This Review-08 source-stage correction required independent re-audit and did not by itself qualify native runtime or deployment behavior; missing historical Review-08 runtime records are not reconstructed by later selected evidence.
- The isolated candidate retains every successfully claimed run root, including terminal success and post-claim failure. Terminal result files remain opaque bundles outside staging; whole-root reclamation remains a pending environment-bound operational/rollout acceptance decision. No reclamation implementation or authority is selected by development-source acceptance.
- For the current `static-script` slice, ES reserves `/execution/run/result` as a writable workload-authored terminal output directory. The workload may write result files there, and ES treats those files as opaque bundle content rather than interpreting their semantics.

### Isolated resolved-plan and custody candidate

This local candidate refines the reopened internal Submit seam and bounded
slice rules; it is not accepted for rollout. `prepareAdmission` owns a copied
request and performs its established artifact, trust, Vault/auth and policy
reads and gates. Following successful admission, `Submit` takes one owned
execution/placement configuration snapshot for subsequent profile, placement
and materialization facts. This is not an atomic snapshot of earlier admission
or all service-configuration reads. Artifact, capability, target and profile gates
precede placement validation; runtime-unavailable still precedes mode rejection,
and sync rejection precedes dependency admission. Policy denial precedes run
assignment, run-specific materialization and Nomad dispatch. Material capture
may now reject before run assignment. A private semantic plan owns admitted
execution meaning and one typed command; private captured material owns bytes,
private host context owns qualified host facts, and a separate custody-placement
value owns both staging and results roots from the same snapshot. The results
root is absent from the semantic plan, host context, job and private v1 binding.

Per-submission byte limits: 256 KiB for each dependency JSON body and admission
policy payload; 32 MiB for primary Submit payload; 8 MiB per governed mount and
32 MiB aggregate compressed transport; 8 MiB per mount and 32 MiB aggregate
extracted regular-file bodies; 16 MiB per mount and 64 MiB aggregate for the
complete decompressed tar stream, including headers and trailing bytes; 32 MiB
for a stable no-follow runtime-support file; 256 KiB each for normalized Vault
and system CA input; 524,289 bytes for the combined bundle. Limits are checked
before unsafe allocation or accumulation. No global concurrency/capacity budget
or new ES mount entry/name cap is selected. Oversize material, unstable files,
invalid roots, unavailable filesystem capabilities, malformed archives and
unsafe links now reject. Startup fails when configured Submit cannot prove a
required capability; prepare-only does not acquire run/staging effects. Two
missing roots in the same deepest existing lookup context reject before
provisioning. Roots with provably disjoint existing parents may be provisioned
one component at a time, with the pair requalified after each creation. Linux
qualification binds the held descriptor to fstat/statx mount ID, canonical
`/proc/self/fd` presentation and bounded mountinfo selection; an opaque
selected namespace root or unprovable mount topology rejects. Darwin binds
F_GETPATH/fstatfs/getfsstat and refuses unprovable same-FSID presentations.
These are implementation requirements, not native Linux qualification evidence.

Exclusive descriptor-held claim refuses every pre-existing run-root object.
Materialization uses captured bytes and verifies the complete expected tree
before one Nomad registration. Every successfully claimed root is retained,
including partial materialization, failed/ambiguous registration, terminal
success and result-publication failure. Cleanup requires effect-time proof of
the exact operation-created object. Incomplete leaves and unpublished result or
normalization temporaries remain when pathname reuse prevents that proof.
Current capability-probe fixtures also remain because their names do not prove
exact-object ownership at unlink time. No cleanup scans or recurses.
Materialization preserves validated archive component names,
including whitespace within a component. Complete-tree pre-dispatch validation
must not retain a descriptor per sibling directory. Existing result directories
and normalization evidence are validated without chown, chmod or adoption.
Fresh pair/topology qualification is a prerequisite for named result operations,
not independent cleanup or existing-object metadata-repair authority. New
unpublished result temporaries/records and newly created normalization
evidence receive their selected owner/mode on creation; existing directories,
finals, and evidence are only checked. Result packaging reopens staging
read-only and uses no-replace publication.
The isolated R1 refinement requires a writer-derived compressed-byte
commitment, held-candidate and installed-winner validation, and a private
authenticated completion record before public result bytes are eligible.
Existing final objects require identity, owner, mode, link-count, size, digest
and stable-path validation. A pre-existing unmarked final is never signed or
adopted on retry. No whole-
root reclamation policy is implemented;
capacity use and sensitive-material residence increase. Captured in-memory
bytes are not durable replay custody, and a held descriptor/tree check does not
prove the later Nomad/Docker mount topology. Image tags do not prove immutable
content. One registration per unkeyed Submit does not deduplicate retries.
The following Review-20/21/22 source-stage fixture requirements and supplied
report outcomes are historical; the dated current evidence overlay follows.
Review-19 independently accepted the bounded A2/material-capture and focused
composition source interaction only. The Review-20 test-owned governed-mount
fixture must later prove actual installed directory and selected file identity
in one live, correlated, bounded native single-host allocation, with a held
pre-registration source anchor and a qualified common filesystem domain.
Failure teardown attempts barrier release or container stop and exact captured
test-owned Nomad job cancellation before closing held source anchors.
Offline modeled comparisons, Nomad/Docker source strings, and equal contents
do not close that gate. A running-deployment topology observation, native
architecture qualification, deployed key isolation, capacity and retention
decisions, and final acceptance remain separate.
The Review-21 test-only repair orders fixed workload readiness after supervisor
preparation, admitted-container identity before effects, installed-object
observation while held, release, and exact-allocation terminal success. The
observer cannot release before readiness or act on a rejected Docker candidate.
Its bounded selected-field Nomad job and terminal reads use fixed safe failures
without raw response bodies, logs, task messages, or allocation formatting.
Control-request success alone is not observed termination. This is a bounded
qualification-fixture rule, not a production lifecycle or authority change.
The test-only `test-mounted-source-identity/v2` projection records anchor,
ready, installed-object observation, release and terminal times separately.
The Review-22 test-owned task-label prerequisite correction applies only to
the fresh installed-identity fixture agent. Its Docker plugin requests exactly
`extra_labels = ["task_name"]`, with volumes enabled and image cleanup disabled
in one profile; ordinary and capability-probe agents retain their prior
configuration. This is a Bounded slice rule for the qualification fixture,
not an unconditional Nomad label guarantee or a production ES contract. The
task driver derives the label from its task identity, and the observer still
requires the actual immutable ID, running state, allocation label and task
label before adoption or any Docker effect. The supplied Review-21 native N4
attempt refused before readiness and installed-object observation and emitted
no v2 identity record; N5 and arm64 did not run. Separately reported N1-N3
amd64 passes remain report-supported pending safe-package inspection. The
repair changes fixture-agent configuration only; native receipt of the label
and installed-object identity require a future witness. Running-deployment,
key, retention, architecture and final acceptance gates remain open.

### Development-source foundation and acceptance boundaries

The 2026-11-13 `DEVELOPMENT_SOURCE_FOUNDATION_ACCEPTED` disposition in
`PLANS.md` binds the exact authenticated Review-22 implementation archive and
canonical source manifest to the accepted source reviews, selected linux/amd64
and linux/arm64 N1-N5 native programme, and bounded original-byte Review-17
proof contribution. The documentation-only successor preserves the reviewed
implementation bytes; its new all-file manifest is not a historical native
execution identity. Earlier refusals, missing records, supplied-record limits
and process PARTIAL remain historical. The test-owned installed-source witness
does not observe a running deployment or create a production Nomad label rule.

Development-qualified source foundation is an engineering evidence state, not
final product or environment acceptance. It grants no standing workload or
feature/producer enablement, reliable-submit availability, general platform
support, isolated qualification task, staging, cleanup, commit, integration,
merge, publication or deployment authority. Current admission, startup
capability, key-load, no-follow/ownership and authenticated result-byte rules
remain unchanged and fail closed.

A local source-preservation commit is a separate, explicitly authorized effect.
It may be considered after the governing amendment and focused document tests
are reviewed and the exact candidate, index and intended commit contents are
reauthenticated. Development evidence alone grants no Git effect. Integration
into another checkout/branch, merge, remote publication and rollout require
their own authority and applicable checks; a local tracking ref is not current
remote truth. The unresolved publication/remote-owner policy is not selected
here. Absence of a selected production environment alone does not forbid
consideration of a separately authorized local preservation gate.

Environment-bound operational/rollout acceptance remains open. Before expanded
or unattended workload operation it requires a named environment and
architecture; observed actual service/operator/workload trust and permission
relationships; actual running mount/source paths and backing objects; actual
key exposure and isolation, including physical aliases and relevant same-UID
contexts; selected and enforced accumulated-root/result/probe capacity and
sensitive-material residence bounds; and an explicit reclamation owner,
authority and implementation or enforceable bounded operating disposition.
The current-source/environment supported-local consumer interaction must be
qualified when claimed. The selected native programme and test-owned witness
do not replace these observations. Qualification scratch caps, including the
4 GiB task cap and 8 GiB free-space gate, are not an ES product retention
policy. Existing retained test material remains resident and protected pending
its own disposition. No target, trust model, TTL, numeric product cap, cleanup
authority or successful deployment-key-isolation result is selected here.

Selected Submit-path fixed operational messages are `workload-zone vault
configuration is invalid`, `derive execution host context failed`, `stage
workload vault trust material failed`, `derive execution platform state owner
failed` and `execution submission failed`. Registration response JSON is
limited to 256 KiB and one compatible document; unknown provider fields remain
accepted. Raw provider bodies, host paths and request values are not public
error messages. Private admission formatting redacts ordinary output. No
universal provider-response or logs limit is selected. Successful public
receipt, job and handoff shapes stay compatible. Blank schema/version defaults
to v1; explicit nonblank legacy versions remain accepted; mode defaults async,
timeout zero and omitted CPU/memory to 10/128. Empty environment allowlist
meaning and caller/profile/platform precedence stay unchanged. Structural
`reliable_submit` bodies remain strictly rejected. The selected private schema
is `execution-substrate.reliable-submit-request/v1` with nested
`reliable_submit.contract = execution-substrate.reliable-submit/v1`; reliable
runtime and producer remain unavailable.

### Response contract

**Observed current contract**

Successful response is `202` JSON with these fields:

- `success`
- `submitted`
- `run_id`
- `status`
- `authority_handoff`

**Current contract invariants**

- Successful `:submit` returns a bounded submission receipt.
- The receipt confirms execution handoff through `run_id`, not durable ES lifecycle ownership.
- Current successful receipts use `status = "submitted"`.
- Successful receipts include the bounded non-secret `authority_handoff` facts ES selected for the submitted runtime handoff.

### Explicit non-effects

- No durable ES lifecycle record is created.
- No sync execution result is returned.
- No retry or reschedule policy is created.
- No richer scheduler abstraction is exposed.
- No live Vault, Codex, SPIRE, lease, token-expiry, or approval state is returned.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Malformed or invalid request body | `400` | `invalid_request` |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Prepare-time validation or trust errors | same as `:prepare` | propagated |
| ES admission policy denial | `403` | policy reason code, such as `destructive_shell_command_denied` or `configured_static_script_content_denied` |
| Required ES admission policy input unavailable | `403` | `admission_policy_input_unavailable` |
| Unsupported submission mode | `400` | `unsupported_execution_mode` |
| Unsupported artifact type or target platform | `400` | `unsupported_artifact_type` |
| Unsupported required capabilities | `400` | `unsupported_capabilities` |
| Unsupported, disabled, or invalid runtime profile selection | `400` | `unsupported_runtime_profile` |
| Mount conflict or reserved-path overlap | `409` | `mount_conflict` |
| Invalid or unusable mount artifact | `409` | `mount_artifact_invalid` |
| Payload unavailable | `503` | `payload_unavailable` |
| Execution runtime unavailable | `503` | `execution_runtime_unavailable` |
| Nomad submission failed | `503` | `submission_failed` |

B2 preserves every status and code above and the public
`{success,error,code}` DTO. The selected cause-bearing messages are fixed:

| Cause family | HTTP | Code | Exact public message |
| --- | --- | --- | --- |
| Workload-zone Vault resolution | `503` | `workload_zone_vault_unavailable` | `workload-zone vault configuration is invalid` |
| Host-context derivation | `500` | `submission_failed` | `derive execution host context failed` |
| Workload Vault trust capture or materialization | `500` | `submission_failed` | `stage workload vault trust material failed` |
| Platform-state owner derivation | `500` | `submission_failed` | `derive execution platform state owner failed` |
| Nomad submission transport, bounded read, decode, trailing document, or missing EvalID | `503` | `submission_failed` | `execution submission failed` |

No underlying cause, provider body, cause field, diagnostic field, or new code
is included. Existing safe specific errors outside these families remain
unchanged.

### Bounded slice notes

**Bounded slice contract**

- `:submit` is the real execution surface, but it is intentionally narrow.
- It is async-only.
- Its response is a bounded receipt, not a durable run model.
- The Nomad registration response is limited to 256 KiB before buffering and
  must be exactly one unknown-field-compatible JSON document. Exact limit is
  accepted; limit plus one, fixed-length truncation or surplus, malformed or
  trailing JSON, and missing EvalID fail with the fixed submission message.
  Non-success response bodies are not read or exposed.
- It uses the explicit payload reference carried by the ARS discovery record and cross-checks that reference against aggregate evidence rather than treating `artifact_digest` as the payload locator.
- `control-plane-normal-shell/v1` is a bounded runtime contract for the CP-owned normal-shell attempt path, not an ES-owned orchestration, review, checkpoint, or finalization contract.

### Reopened seams

**Reopened lifecycle seams**

- The long-term receipt shape of `:submit`
- The current async-only public contract
- The current execution-package layout and container path conventions behind submission

### Target reliable keyed-submit contract

The current submit contract above remains implemented behavior. A future
reliable keyed submit mode is an opt-in target contract only, governed by
`submit_idempotency_correlation_and_recovery.md`.

That target contract keeps current unkeyed submit valid while defining the
future ES-owned semantics for submit idempotency key handling, submit
correlation, exact replay, conflicting reuse, pending outcome, ambiguous
outcome, expiry, caller isolation, and response-loss recovery.

The target contract covers both ambiguity boundaries:

- caller or adapter to ES response loss after ES may have accepted a
  submission and produced a `run_id`;
- ES to Nomad registration-response uncertainty where ES attempted an
  execution-producing provider effect but cannot prove whether Nomad accepted
  or rejected it.

The target contract reserves only a narrow ES-owned durable
submit-correlation record. It must not become an allocation history, runtime
status timeline, log index, result-content store, cancellation-completion
truth, runtime retry or reschedule policy store, semantic work store,
Coordinator desired state, or Nomad mirror.

The target public opt-in/versioning selection uses the existing
`POST /v1/executions:submit` route for both the current legacy variant and the
future reliable variant. The reliable variant uses the submit-specific request
schema `execution-substrate.reliable-submit-request/v1`, distinct from
`PrepareRequest`. It carries the mandatory top-level structural discriminator
`reliable_submit`, whose nested `contract` field must equal
`execution-substrate.reliable-submit/v1` and whose nested `submit_key` field
carries the caller-provided reliable submit key. Current strict
`PrepareRequest` decoding rejects that discriminator before current `Submit`
behavior can run. A changed value in the current `schema_version` field alone is
not the selected discriminator.

Reliable clients must pass two independent fail-closed gates: producer
declaration preflight requiring the exact enabled reliable-submit sub-contract,
and in-band request discrimination. Header-only reliable opt-in is rejected
because current servers may ignore unknown headers and execute the current
unkeyed body. A future supplemental header remains unselected and could only be
supplemental to the required body discriminator.

If reliable support is absent, incompatible, disabled, or unavailable, a
reliable Coordinator or adapter stops before submit. If a reliable body reaches
a future server where reliable mode is disabled or unsupported, that server must
reject before admission is treated as successful, before effect-capable `run_id`
assignment, before execution-package staging, before Nomad registration, and
before fallback to current unkeyed submit.

The target contract leaves public response field names, recovery route,
state-path configuration, TTL, tombstone handling, HTTP status mapping, public
error strings, Nomad reconciliation mechanism, and `run_id` generation strategy
open. The private admission-local foundation selects request-family names,
submit-key syntax, caller/key derivation, composite `ClaimID` construction
through the committed pure-model constructor, and ES-neutral submission-outcome
semantics, but current handlers do not call that foundation. It does not select
or implement source-grounded resolved effective-plan extraction, canonical
effective-plan encoding, `PlanBinding` construction from admitted facts, complete
effective-plan witness construction, durable replay-envelope custody, or runtime
orchestration. The later private PB1 producer and codec-3 synthetic custody
implement only the runtime-unwired internal binding/reload subset; they do
not change this public target contract or create a RunRef/effect permit.

## 7. Status contract

### Purpose

`GET /v1/executions/{run_id}/status` returns the current status projection for a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` is required in the path.
- ES validates `run_id` before any runtime lookup.
- ES resolves `run_id` through an explicit internal execution-locator policy before reading Nomad.
- Status is read from Nomad job and allocation state.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these current fields:

- `success`
- `run_id`
- `status`
- `lifecycle_projection`
  - `source`
  - `revision`
- `outcome_evidence`
  - `source`
  - `observation`
  - `lifecycle_projection`
    - `source`
    - `revision`
  - `provider_terminal_observed`
- optional `authority_handoff`
- optional `exit_code`
- `terminal`

**Current contract invariants**

- Status is a Nomad-backed projection.
- `lifecycle_projection.source` is `nomad` in the current contract because Nomad is the submitted-execution lifecycle authority.
- No alternate successful `lifecycle_projection.source` value is currently documented. Any future projection source must be recorded in `PLANS.md` and this lifecycle contract before it appears in public status JSON.
- `lifecycle_projection.revision` is an opaque same-run read-coordination token produced by ES from implementation-private lifecycle observation inputs while serving the status request.
- Callers may compare `lifecycle_projection.revision` values for the same `run_id` to detect that ES observed a different lifecycle projection.
- Callers must not parse or order `lifecycle_projection.revision`, infer scheduler or backend state from it, treat it as a Nomad job/allocation identifier or index, or use it as a write precondition for `logs`, `result`, or `cancel`.
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- `lifecycle_projection.revision` is not a Control Plane workflow version or
  revision, scheduler allocation id, result-reference id, or proof of global
  freshness outside the documented same-run status read model.
- `authority_handoff`, when present, is recovered from the submitted runtime spec and remains a bounded non-secret read fact. It does not make status a run store, scheduler abstraction, live credential observation, or Control Plane orchestration record.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only.
  It is not runtime-config authority, live credential truth, token or lease
  truth, or workload-zone Vault semantic ownership.
- The status JSON envelope remains lifecycle projection and evidence only. It
  must not add Control Plane run-control grammar such as review, checkpoint,
  finalization, intervention, approval, hold/resume/reject, Temporal, or
  workflow, and it must not add live credential or security fields such as
  Vault tokens, client/root tokens, unseal keys, JWT-SVIDs, X.509 SVIDs,
  private keys, API keys, proof secrets, secret payloads, lease IDs, or lease
  durations.
- If the job exists but no allocation is yet selected, status still succeeds with `status = "submitted"`.
- Once an allocation is selected and not terminal, status returns `status = "running"`.
- Once the selected job/allocation path reaches a terminal state, status returns `status = "terminal"`.
- Failed workloads still return `200`; failure is expressed through terminal state plus `exit_code` when available.
- ES must not synthesize richer lifecycle phases than the current Nomad-backed projection exposes.
- `outcome_evidence` is an additive read-only descriptor for the status observation ES just served. In the current slice its `source` is `nomad`; its `observation` label is one of `nomad_job_projection`, `nomad_projected_allocation`, or `nomad_task_state_projection`; its nested `lifecycle_projection` repeats the opaque status read token; and `provider_terminal_observed` says whether this status read observed a terminal provider state.
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- When status observes terminal execution, ES first attempts idempotent retention of any files under `/execution/run/result`.
- Lifecycle projection and result-attempt timing have no staging-mutation
  consequence. Successful, failed, canceled, lost, running, unknown, missing,
  and contradictory provider evidence all leave the same run root retained.

### Authority handoff read surface

**Observed current contract**

`authority_handoff` is present on successful `:submit` responses for new submissions and may be present on `status` responses when ES can recover the submitted handoff facts.

Current shape:

- `authority_path`
- `runtime_profile`
  - `name`
- `identity_handoff`
  - `mode`
  - `endpoint_env`
  - `endpoint_uri`
  - `jwt_svid_target`
- `workload_vault`
  - `auth_mode`
  - `address`
  - `auth_mount`
  - `auth_role`
  - `jwt_audience`
  - optional `ca_cert_env`
  - optional `ca_cert_path`
  - optional `tls_bundle_env`
  - optional `tls_bundle_path`
- `runtime_config_refs`
  - `workload_zone_vault_config`
    - `digest`
- optional `codex_credential_location` for `control-plane-normal-shell/v1`
  - `cli_path`
  - `credential_source`
  - `vault_secret_path`
  - `vault_secret_field`
- `evidence`
  - `source`
  - `runtime_profile`
  - `identity_handoff`
  - `workload_vault`
  - `runtime_config_refs`
  - optional `codex_credential_location`

**Current contract invariants**

- `authority_handoff` is additive and read-only.
- It contains only non-secret handoff facts ES selected, derived, or injected at admission/runtime handoff time.
- It must not expose Nomad job IDs, allocation IDs, task IDs, raw SPIRE socket source paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, token expirations, or rich policy/approval state.
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- Its evidence labels identify the bounded source family for each fact; they are not write preconditions and not ordering tokens.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only.
- `runtime_config_refs` inside `authority_handoff` identifies the selected
  workload-zone Vault config digest as evidence only. It must not be used as
  runtime-config authority or live credential truth.
- F0 classifies `authority_handoff` as non-secret runtime-handoff evidence
  only. It is not runtime-identity authority, credential authority, proof of
  live JWT-SVID/Vault token/secret/lease possession, or Control Plane
  review/approval/checkpoint/finalization state.

**Bounded slice contract**

- The current `authority_path` is `workload_identity_endpoint/workload_vault`.
- The current identity handoff mode is `workload_identity_endpoint`.
- The current JWT-SVID target label is `workload_vault`.
- The current workload-vault auth mode is `vault_identity_jwt`.
- The current `control-plane-normal-shell/v1` profile may include non-secret Codex credential-location metadata whose credential source is `workload_vault`.

**Deliberate absences**

- No claim that the workload has successfully used the endpoint.
- No claim that a JWT-SVID, Vault token, Codex token, or lease exists or is still valid.
- No claim that ES has observed or approved Control Plane review/checkpoint/finalization state.
- No claim that the submitted scheduler job or selected allocation identifiers are public contract.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- Status is intentionally minimal.
- Projected-allocation list and allocation-detail responses use the 256 KiB
  one-document compatible JSON boundary. Unknown provider fields remain
  accepted; non-success bodies are not read for diagnostics.
- Job lookup remains explicitly unbounded but exactly one compatible JSON
  document. This preserves currently valid submissions whose allowed caller
  environment makes Nomad's echoed `Task.Env` exceed 256 KiB. A universal job-
  summary cap requires a separate caller-environment count/value/aggregate
  budget decision.
- The contract is built around current Nomad projection rather than a richer ES-owned execution model.
- The public response no longer carries scheduler job/allocation identifiers or task-state detail.
- The projection revision is the only current status lifecycle read-coordination fact; it does not imply an ES-owned lifecycle-state store.
- `authority_handoff`, when present, is a separate runtime-handoff evidence fact, not a lifecycle revision or write-coordination token.
- `outcome_evidence` is a current-slice status evidence descriptor. It does not make Nomad job IDs, allocation IDs, task IDs, task-state detail, or the current latest-allocation rule public contract.
- Lifecycle vocabulary beyond this current Nomad-backed projection, execution
  locator/allocation projection, retained-result route evolution, runtime
  identity handoff ownership, workload-zone runtime-config ownership, and ARS
  discovery/index long-term shape remain reopened seams unless a future source
  explicitly re-derives them.

### Reopened seams

**Reopened lifecycle seams**

- The internal execution-locator policy behind `run_id` lookup
- The current status projection depth
- The extent to which minimal status projection is durable versus slice-bounded

## 8. Logs contract

### Purpose

`GET /v1/executions/{run_id}/logs` returns current execution logs for the selected runtime allocation.

### Lookup contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status`.
- ES resolves logs through the currently projected allocation.

### Response contract

**Observed current contract**

Successful response is:

- `200`
- `Content-Type: text/plain; charset=utf-8`
- stdout payload bytes only
- `Execution-Substrate-Outcome-Source: nomad`
- `Execution-Substrate-Outcome-Observation: nomad_task_stdout`
- `Execution-Substrate-Outcome-Access-Class: plaintext_stdout`
- `Execution-Substrate-Provider-Terminal-Observed: true|false`

**Current contract invariants**

- Logs are resolved from the currently projected allocation only.
- Task name is fixed to `task`.
- Output source is stdout only.
- Successful `200` responses may still carry an empty stdout body if the selected allocation has not produced visible stdout bytes yet.
- The successful response headers are additive descriptors for the bytes being returned. They say ES fetched current stdout through the bounded Nomad log path for the selected task; they are not pagination cursors, log revisions, scheduler IDs, stderr indicators, or write preconditions.
- The successful response headers remain the logs envelope. They must not add
  Control Plane run-control grammar or live credential/security fields. The
  stdout body remains payload content under the existing compatibility
  contract; ES does not sanitize, interpret, or promote raw log content into
  scheduler, CP run-control, credential, or policy authority.
- No streaming, pagination, tailing, stderr aggregation, or multi-allocation merge exists in the current contract.
- If logs observes a terminal task, ES first attempts idempotent retention of any files under `/execution/run/result`.
- Logs retrieval and its result-retention attempt never authorize staging
  deletion or any other staging mutation.
- Successful Logs bytes are intentionally unbounded opaque authenticated
  workload output. They remain byte-identical, including empty bodies and
  bodies larger than 256 KiB; ES selects no truncation, partial-success,
  normalization, or oversize status/code in B2. “Bounded Nomad log path” above
  means the current slice-bounded task/allocation selection, not a byte limit.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Allocation or logs not ready | `409` | `logs_unavailable` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- Latest-allocation-only lookup is a bounded rule.
- The logs contract is intentionally narrow:
  - task `task`
  - stdout only
  - `text/plain`
  - no streaming
  - no pagination
  - no stderr aggregation
- It is explicitly outside the structured Nomad control-JSON boundary.

### Reopened seams

**Reopened lifecycle seams**

- The internal projected-allocation rule used for log selection
- Current logs minimalism
- The current single-task, stdout-only log contract

## 9. Result contract

### Purpose

`GET /v1/executions/{run_id}/result` returns the retained terminal result bundle for a submitted execution when the current bounded `static-script` workload wrote files under the reserved runtime result directory.

### Runtime output convention

**Bounded slice contract**

- The current `static-script` slice reserves `/execution/run/result` as the workload-authored terminal output directory.
- The workload may create arbitrary regular result files and directories there.
- ES packages retained result content opaquely and does not parse Control Plane semantics, checkpoint decisions, review outcomes, or finalization metadata from those files.
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.
- Host staging paths, Nomad allocation IDs, and Docker bind-mount sources are not part of the client-facing result contract.

**Reopened lifecycle seam**

- `/execution/run/result` is active for this bounded result-materialization slice, but it remains part of the reopened execution-package and runtime path convention surface.

### Lookup and retention contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status` and `logs`.
- Retained result bundles are stored outside `execution.staging_root_dir` under `execution.results_root_dir`.
- Retained bundles are keyed by `run_id`.
- The only public retained-result lookup reference documented today is the `run_id` in `GET /v1/executions/{run_id}/result`.
- Any later retained-result reference vocabulary must be documented as a safe handle scoped to a `run_id` or another explicitly documented result reference. It must not expose retention filesystem paths, host paths, scheduler IDs, Nomad allocation IDs, support-bundle paths, proof paths, or artifact-discovery/index internals as public lookup material.
- The retained bundle is a tar.gz archive of the reserved result directory contents.
- The current route shape, public `run_id` lookup, `application/gzip` encoding, and successful outcome-evidence headers are the active bounded compatibility retrieval path for those ES-owned bundles.
- Result retention is idempotent:
  - repeated terminal `status`, `logs`, and `result` calls are safe
  - if an authenticated bundle/record pair already exists, ES reuses it before
    staging traversal or temporary publication, even if retained staging later
    changes or disappears; no refresh or newest-result rule applies
  - a partial or invalid pair fails closed; only an absent final and record
    allows new publication, while already prepared competing candidates retain
    their no-overwrite conflict rule and possible unpublished residue
  - retained bundles are independent of retained staging
- If no retained bundle exists yet, `result` uses the same bounded Nomad-backed terminal observation model as `status` to decide whether retention can be attempted.
- Result availability is evidence/projection for the ES-retained output surface. `result_not_found` means ES has no retained bundle for that `run_id`; it is not, by itself, Control Plane workflow failure, review failure, checkpoint failure, finalization failure, or Temporal run-control truth.

**Selected isolated R1 byte-eligibility contract.** Configured Submit requires
`execution.retained_result_auth.store_id`, `key_id`, and `key_file` at startup.
The first two are stable, non-secret identifiers of 1–32 ASCII bytes matching
`[a-z][a-z0-9_-]{0,31}`. `key_file` is an explicitly configured, clean absolute
path with a non-root parent directory, outside staging/results storage, to exactly 32 raw bytes of independent
HMAC-SHA-256 key material. There is no default, generator, fallback, keyring,
rotation or automatic recovery. ES reads the key once into private service
memory at configured-Submit initialization. A genuinely Submit-disabled
service does not require or read it; `BRINGUP_PROFILE=prepare-only` does not
remove the canonical supported-local Submit configuration or its startup key
and root-capability prerequisites. Retained reads without a configured verifier fail closed. Static file checks
cannot establish deployment isolation against an arbitrary same-UID process.
Actual key isolation and exposure remain environment-bound
operational/rollout acceptance gates. Development-source acceptance does not
establish deployment isolation or remove those gates.
Key exclusion uses the same effective `Clean(TrimSpace(root))` staging and
results paths as root custody; an already canonical key path and every
component of its derived parent are opened exactly, without another trim.
The supported-local setup and proof wrapper accept the two non-secret IDs and
an external guest-local key-file reference from a trusted operator. They reject
lexically unsafe placement before setup effects, and neither provisions nor
reads the key bytes. Raw key bytes never enter environment variables, argv,
proof assets, workload environment, Nomad, authority handoff or public output.
This lexical fence does not prove physical alias or same-UID isolation.
Owned proof, bootstrap, repository, host collection and cleanup scopes require
clean single-leading-slash absolute non-root paths; root and either direction
of key/scope containment are rejected before wrapper effects or finalizer
registration. The setup helper dispatches direct-file and canonical stdin
invocations once, while sourcing it for production-function reuse has no setup
effect. Neither rule changes ES key custody or result-publication authority.

For the bounded supported-local `service-root-v1` rootful identity-mapped
profile, canonical setup is the sole creator of the two fresh configured
execution roots, with owner `0:0` and exact mode `0755`. The generated env
selects one static, no-repair read-only validator for prepare-only bring-up,
the ES launcher, and full-profile submit-readiness through the direct health
check and diagnostics consumer. The validator checks proof binding, generated
config, service image and Dockerfile, root owner/mode/identity, and exact
same-path read-write mounts before the ordinary operator's own write access is
omitted from the readiness test. Generic callers without that profile retain
their prior caller-writable check of existing roots; unknown profiles refuse.
Readiness does not create roots or write staging-invariant evidence. This
profile does not alter ES's natural `0750` per-run
directory rule, prove the future container's identity or mapping, or approve
rootless/non-root variants.
Within this bounded setup profile, the privileged helper checks each new
fixed child against its held no-follow descriptor before owner/mode mutation,
retains both held identities through a final visible pair and proof-root
binding check, and refuses substitution without adoption or cleanup. This
establishes that successful visible roots are the objects the helper held and
initialized. The operator-owned proof parent does not make `mkdir` plus
subsequent `open` atomic: an arbitrary concurrent replacement before
descriptor acquisition cannot be ruled out by a later pathname stat. A
protected creation namespace would be a separate authority decision, not a
claim of this bounded repair.
The retained `execution-roots-setup-safe.json` projection reports only the
fixed profile and successful static configured-root owner/mode check, with no
root paths or key data. Its explicit container-capability-false field is not
a substitute for ES's later behavioral qualification or live proof.

The private record is `<results_root>/<run_id>/result.commit.v1`, mode `0600`,
separate from `ownership-normalization.json`. It is at most 512 bytes and has
exactly ten LF-terminated ASCII lines, with no extra bytes:

```text
es-retained-result-commit-v1
store_id=<identifier>
key_id=<identifier>
run_id=run-<16 lowercase hex digits>
root=<16 lowercase hex device>:<16 lowercase hex inode>:d
run_dir=<16 lowercase hex device>:<16 lowercase hex inode>:d
final=<16 lowercase hex device>:<16 lowercase hex inode>:f
length=<16 lowercase hex digits>
sha256=<64 lowercase hex digits>
mac=<64 lowercase hex digits>
```

All integer fields are unsigned, fixed-width hexadecimal, most significant
digit first. The `d`/`f` suffix is the observed directory/regular-file type.
The HMAC covers every byte through the `sha256` line's LF, including the
domain/version first line; `mac` is the lowercase hex encoding of that 32-byte
HMAC. The bounded reader verifies the HMAC with `crypto/hmac.Equal` before
parsing semantic fields or using a stored length for allocation. It then
requires this exact canonical grammar and rejects unknown versions, duplicate
or extra fields, trailing data, uppercase hex, and wrong run/store/key or
root/run/final identity context. The HMAC key never appears in this record.
Object identities are local custody context, not portable content identity.
The restart claim covers reopening the same backing store/objects with the
same key; it does not promise relocation, backup restore, host migration,
reboot-independent device identity or power-loss durability.

The producer hashes/counts compressed bytes as the archive writer emits them,
including successful compressor close, and compares the synced held candidate
descriptor against that independent commitment. Successful no-replace
installation is not completion. The winner must reopen the final no-follow,
prove it is the held candidate object, and validate metadata, size and digest.
Only then may it exclusively publish a complete authenticated record. A later
or competing publisher that finds an unmarked pre-existing final must not
sign, rebuild-and-endorse or adopt it. It may observe a completed matching
pair, but cannot overwrite or endorse conflicting bytes. Uncertain objects
remain in place; no name-based cleanup or metadata repair is authorized.

Before `Service.Result` succeeds, ES authenticates the record for the requested
run/store and qualified object context, reads the final through the existing
non-mutating no-follow path under the authenticated length and existing size
limit, and compares the length/SHA-256 of the *buffered response bytes* with
the record. It does not validate one pathname read and serve another. The held
final descriptor must itself satisfy the required owner, mode,
link-count, device, regular-file and size policy before any response read;
visible-path identity alone is insufficient. No final and no record retains
the existing terminal lookup/retention behavior. A final
without a valid record, a record without a matching final, altered bytes or
malformed/forged/context-mismatched evidence returns fixed `409
result_unavailable` without Nomad-backed endorsement or repair. Genuine
terminal no-output retains `404 result_not_found`. A record that became valid
before a publisher error may still authorize a matching read. This protocol
authenticates bytes but is not anti-rollback or a lifecycle truth source.
Legacy unmarked finals and crash-interrupted final-only states stay unavailable
until a separately selected migration/recovery policy exists.

### Response contract

**Observed current contract**

Successful response is:

- `200`
- `Content-Type: application/gzip`
- retained tar.gz bundle bytes
- `Execution-Substrate-Outcome-Source: es_retained_result_store`
- `Execution-Substrate-Outcome-Observation: retained_result_bundle`
- `Execution-Substrate-Outcome-Access-Class: opaque_result_bundle`

**Current contract invariants**

- The result endpoint is a retained output retrieval surface, not a lifecycle-state registry.
- ES does not synthesize Control Plane checkpoints, review decisions, or task-finalization outcomes from retained result files.
- ES does not require callers to know host staging paths, Nomad allocation IDs, or Docker bind-mount sources.
- The successful response headers label the body as an opaque ES-retained result bundle. They do not reveal bundle contents, host paths, retention filesystem paths, or any semantic interpretation of the files inside the archive.
- The successful response headers remain the result envelope. They must not add
  Control Plane run-control grammar or live credential/security fields. The
  bundle body remains opaque output content under the existing compatibility
  contract; ES does not sanitize, parse, or promote bundle contents into CP
  checkpoint, finalization, review, scheduler, credential, or policy authority.
- ES does not add raw logs, proof payloads, support bundle payloads, retained-internal metadata, credentials, environment values, TLS/SPIFFE/Vault material, PEM/cert/key
  bodies, endpoint secrets, unsafe paths, scheduler IDs, CP workflow fields,
  review fields, checkpoint fields, or finalization fields to the result
  response envelope. The private completion record contains only
  the bounded authentication fields specified above; its key and key-file
  path are never recorded. No retained-internal metadata enters the public
  response envelope.
  Workload-authored files under `/execution/run/result` remain opaque bundle
  content; this is not a sanitization guarantee over those workload-authored
  bytes.
- The result route is not a CP artifact-serving authority. CP may consume and
  interpret retrieved bytes semantically, but ES storage layout, retention
  mechanics, and result availability do not become CP materialization,
  checkpoint, review, finalization, or run-control state.
- Logs are not the result contract; stdout remains a separate narrow logs surface.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Execution is not terminal or retained bundle is not ready | `409` | `result_unavailable` |
| Execution is terminal but no retained result bundle exists | `404` | `result_not_found` |
| Nomad unavailable or unusable runtime response while the endpoint still needs terminal lookup | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- The result endpoint is intentionally limited to retained opaque bundles for the current `static-script` slice.
- It does not introduce background lifecycle reconciliation, callbacks, streaming output, or a broad runtime-output platform.
- It does not change ES into the orchestration owner.
- Retained-result route evolution, result-reference vocabulary, result payload
  identity versus artifact identity, CP materialization semantics, and
  artifact discovery/index long-term shape remain reopened seams unless a
  future source explicitly re-derives them.

## 10. Cancel contract

### Purpose

`POST /v1/executions/{run_id}:cancel` requests cancellation of a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status`.
- ES confirms the job exists, then issues a stop request to Nomad.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these fields:

- `success`
- `run_id`
- `status`
- `outcome_evidence`
  - `source`
  - `observation`
  - `provider_terminal_observed`

**Current contract invariants**

- Current successful cancel receipts use `status = "cancel_requested"`.
- Cancel is a bounded Nomad stop request, not a wider cancellation model.
- `outcome_evidence.source` is `nomad`, `outcome_evidence.observation` is `nomad_stop_request_accepted`, and `outcome_evidence.provider_terminal_observed` is `false` on the current successful receipt because ES has only observed Nomad accepting the stop request, not provider termination.
- The cancel JSON envelope remains a bounded ES/Nomad handoff receipt. It must
  not add Control Plane intervention, approval, hold/resume/reject, Temporal,
  workflow, review, checkpoint, finalization, operator-approval, scheduler
  authority, or live credential/security fields.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Explicit non-effects

- Cancel does not create a richer cancellation state model.
- Cancel does not purge the Nomad job.
- Cancel does not create a durable ES cancellation record.
- Cancel does not return proof that the workload has stopped. Callers must use status reads for later terminal observation.

### Reopened seams

**Reopened lifecycle seams**

- The current bounded cancellation receipt shape
- The long-term scope of the public cancel surface

## 11. Run-ID and scheduler lookup contract

**Observed current contract**

- `run_id` must match `run-[0-9a-f]{16}`.
- ES owns one explicit internal execution-locator policy for lifecycle lookup.
- The current locator resolves scheduler lookup as `nomad_job_id = exec-<run_id>`.
- Status, logs, and cancel all depend on this derivation today.
- Status responses expose `lifecycle_projection.revision` instead of exposing that internal scheduler lookup target.

**Current contract invariant**

- This internal locator policy is currently authoritative for lifecycle lookup because ES does not own a separate run registry or lifecycle store.
- The status projection revision is produced after this lookup from implementation-private Nomad observation inputs, and it does not make the locator mapping public contract.

**What this contract does not imply**

- It does not imply ES owns a richer lifecycle namespace.
- It does not imply the current mapping is architecturally untouchable.
- It does not imply a durable ES execution record exists behind `run_id`.

**Reopened lifecycle seam**

- The mapping is active and meaningful today, but it remains explicitly reopened in the redesign phase.

## 12. Allocation-selection contract

**Observed current contract**

- ES uses one explicit internal projected-allocation policy that currently selects the latest Nomad allocation by `ModifyIndex` for detailed status/log lookup.

**Current contract invariant**

- Current logs and detailed status fields are derived from that selected allocation.
- That allocation-selection rule does not define public `lifecycle_projection.revision` semantics or a scheduler ordering promise.

**Bounded slice contract**

- This rule is valid only because retries and reschedule are out of scope in the current slice.
- It is not a general multi-allocation lifecycle model.

**Reopened lifecycle seam**

- If multiple meaningful allocations become normal, this rule must be revisited explicitly before contract changes land.

## 13. Failure and status-code matrix

| Outcome | Endpoints | HTTP | Response form | Current code / note |
| --- | --- | --- | --- | --- |
| Successful prepare | `:prepare` | `200` | JSON | `PrepareResult` |
| Successful submit | `:submit` | `202` | JSON | `SubmitResult`, bounded receipt |
| Successful status | `status` | `200` | JSON | `ExecutionStatusResult` |
| Successful logs | `logs` | `200` | `text/plain` | stdout only |
| Successful result | `result` | `200` | `application/gzip` | retained opaque tar.gz result bundle |
| Successful cancel | `cancel` | `200` | JSON | `ExecutionCancelResult` |
| Invalid request body, request validation failure, or request/fact mismatch | `:prepare`, `:submit` | `400` | JSON | `invalid_request` |
| Unsupported, disabled, or invalid runtime profile selection | `:prepare`, `:submit` | `400` | JSON | `unsupported_runtime_profile` |
| Unauthorized caller | all lifecycle/execution endpoints | `401` | plain text | authenticated caller identity required |
| Forbidden caller | all lifecycle/execution endpoints | `403` | plain text | bootstrap or disallowed identity |
| Aggregate artifact evidence invalid during admission | `:prepare`, `:submit` | `403` | JSON | `artifact_evidence_invalid` |
| Aggregate artifact evidence not registered for admission | `:prepare`, `:submit` | `404` | JSON | `artifact_evidence_not_found` |
| Invalid `run_id` | `status`, `logs`, `result`, `cancel` | `400` | JSON | `invalid_run_id` |
| Execution not found | `status`, `logs`, `result`, `cancel` | `404` | JSON | `execution_not_found` |
| Logs not ready | `logs` | `409` | JSON | `logs_unavailable` |
| Result not ready | `result` | `409` | JSON | `result_unavailable` |
| Terminal execution has no retained result bundle | `result` | `404` | JSON | `result_not_found` |
| Aggregate artifact evidence unavailable after registration | `:prepare`, `:submit` | `503` | JSON | `artifact_evidence_unavailable` |
| Nomad unavailable or malformed runtime response | `status`, `logs`, `result` when it still needs terminal lookup, `cancel`, and submit runtime path | `503` | JSON | `execution_runtime_unavailable` or `submission_failed` depending on operation |
| Workload failure reflected in status | `status` | `200` | JSON | failure is expressed in Nomad-derived fields, not a separate HTTP error |

`execution_not_found` is a lifecycle observation absence on the current Nomad-backed lookup for the supplied `run_id`. It is not a producer declaration incompatibility and not, by itself, a submit-readiness or substrate-health result.

## 14. Runtime identity and lifecycle edge

**Observed current contract-adjacent conventions**

- The Workstream F F0 ownership decision lives in
  `.docs/system_overview/runtime_identity_handoff.md`.
- Runtime identity handoff is currently ES-selected and platform-delivered.
  ES owns handoff selection, env injection, reserved path layout, mounts, and
  Nomad job construction for the current slice.
- ES injects the current endpoint-discovery environment conventions:
  - canonical `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://<ES-owned run-scoped endpoint>`
- ES also injects the current non-secret workload-vault runtime inputs derived from the resolved workload-vault auth plan.
  - `VAULT_ADDR`
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`
  - when configured, `VAULT_CACERT=/execution/run/platform/workload-vault-ca.pem`
  - when configured, `SSL_CERT_FILE=/execution/run/platform/workload-ca-bundle.pem`
- For `control-plane-normal-shell/v1` only, ES injects non-secret Codex credential-location metadata:
  - `EXEC_CODEX_CLI_PATH`
  - `EXEC_CODEX_CREDENTIAL_SOURCE=workload_vault`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD`
- The runtime-identity workspace is mounted as writable tmpfs in the current submit slice.
- The bounded slice-1 implementation keeps the workload-visible endpoint but
  puts the runtime-side owner behind it in a platform-owned helper launched by
  a platform-owned supervisor.
- The runtime supervisor/helper owns the in-task endpoint implementation,
  helper-private SPIRE traversal, readiness-before-workload, and
  root-to-workload privilege boundary for the current implementation.
- SPIRE owns JWT-SVID issuance.
- Vault owns token, secret, and lease issuance after workload-side login.
- ES exposes the same bounded non-secret facts through `authority_handoff` on submit/status when available. That read surface is evidence of the submitted runtime handoff, not evidence of live credential possession.

**Current contract invariants**

- Caller runtime mounts must not overlap the ES-owned subtree that backs the discovered endpoint.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract only. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- ES derives the bounded workload-vault handoff from workload-zone vault runtime fields plus `workload_vault_auth.default_mode`.
- If that runtime config supplies Vault CA trust material, ES stages it as workload-visible trust files and uses standard TLS environment rather than disabling verification.
- ES does not turn runtime identity or Vault-auth failures into a distinct ES lifecycle phase.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads. The selected workload is
  responsible for using the existing identity endpoint and workload-vault
  metadata to read material it is allowed to read.
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- ES does not expose live runtime credential state through `authority_handoff`.
- The supported-local proof realization may provide a proof-only deterministic Codex shim at `EXEC_CODEX_CLI_PATH` inside the configured profile image. That shim is proof tooling, not a new ES product API or a claim that ES owns Codex service invocation semantics.
- The first platform-owned runtime-identity slice is intentionally limited to platform-controlled non-root workloads with no privilege-escalation path.
- The public runtime identity endpoint must remain a bounded platform endpoint, not a raw SPIRE proxy.
- Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces
  are bounded or compatibility-heavy, not final generalized architecture.
- Runtime-config refs, `authority_handoff.runtime_config_refs`, ARS blob
  storage/read mechanics, digest-only runtime-config refs, and
  `workload_vault_auth.default_mode` are not runtime-identity or credential
  authority.
- CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, retained bundles, `outcome_evidence`,
  `authority_handoff`, IM profiles, support bundles, logs, traces, reports,
  `.out` artifacts, and CP review/approval/checkpoint/finalization state are
  not runtime-identity or credential authority.

**Reopened lifecycle seams**

- The reserved-path conventions
- The endpoint environment convention
- The extent to which runtime identity handoff should remain part of the public execution contract
- The long-term runtime-identity owner, helper/root/task-user model, SPIRE
  selector posture, Vault posture, and reserved-path architecture

## 15. Bounded slice rules

**Bounded slice contract**

- `:prepare` is active today but bounded.
- `:submit` is bounded async-only submission.
- Latest-allocation selection is a slice rule, not a general lifecycle model.
- Status is a minimal Nomad-backed projection.
- Logs are a minimal latest-allocation stdout contract.
- Result retrieval is a bounded retained opaque bundle contract for `/execution/run/result` in the current `static-script` slice.
- `control-plane-normal-shell/v1` is a bounded runtime-profile slice rule layered on the current `static-script` package/runtime path.
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- No retry or reschedule policy is exposed.
- No rich ES-owned lifecycle model is exposed.

These rules are active today, but they should not be preserved by inertia.

## 16. Deliberate absences

**Deliberate absences**

- No ES-owned run persistence
- No ES-owned lifecycle-state store
- No retry or reschedule control surface
- No multi-allocation aggregation API
- No streaming logs contract
- No stderr or multi-task log contract
- No ES interpretation of retained result bundle semantics
- No ES-owned checkpoint, review, or terminal-finalization model
- No synthetic ES lifecycle phases
- No public contract for runtime token minting
- ES must not absorb CP attempt/review/checkpoint/finalization semantics.
- ES must not become a Vault token broker, Codex credential broker, IM
  readiness authority, CP run-control authority, or maintenance-agent
  authority.

## 17. Reopened lifecycle seams

- The public role of `:prepare`
- The bounded receipt shape of `:submit`
- The internal execution-locator policy behind `run_id` lookup
- Latest-allocation selection
- Runtime identity reserved-path conventions
- Current logs minimalism
- Current retained-result bundle convention and `/execution/run/result` runtime path
- Current runtime-profile annotation and the bounded `control-plane-normal-shell/v1` overlay
- The extent to which lifecycle minimalism is durable versus slice-bounded

These seams are active today and intentionally not fixed.

## 18. Decision rules for future edits

- Do not omit active endpoints from this contract document.
- Label bounded slice rules as bounded.
- Keep public response and error semantics here instead of leaving them only in code comments.
- Move implementation detail into `.docs/execution_lifecycle/implementation.md`.
- Keep high-level lifecycle ownership in `.docs/execution_lifecycle/design.md`.
- If code and tests disagree with this file, update this file to match reality.
- Do not describe a contract as fixed unless that decision is explicit and intentional.

## 19. Final-audit archive and execution-root contract refinements

Each runtime mount archive uses one invocation-local iterative compressed
byte-radix namespace ledger. Its non-root labels are substring views into
normalized names already retained by the ordered validated entries; branches
are keyed by the next byte, terminals distinguish directory and regular file,
and the ledger creates nodes only for accepted terminals and required branch
points. It does not split per path segment, copy cumulative prefixes, recurse,
or build a second full-name index. File ancestry is recognized only across a
`/` boundary. Probe precedes type/body work where required by existing error
precedence, while commit occurs only after every fallible per-entry check and
the ordered entry append.

This structural repair preserves repeated directories, implicit-parent
completion, normalized-alias behavior, duplicate/file-directory/ancestor
refusals, entry order, and all existing compressed, body, aggregate, and
complete decompressed-stream limits. Reachable PAX/GNU deep/shared-prefix
fixtures and the exact 32,768-header EOF boundary instrument real production
probe, comparison, lookup, allocation, and commit sites. The pinned Go
`archive/tar` reader's 1-MiB hidden special-file processing limit is inherited
dependency behavior; it is not a new ES resolved-name or entry-count limit and
dependency refusal is not radix coverage.

`execution.staging_root_dir` and `execution.results_root_dir` are one
operation-local qualified root set. Lexical non-overlap is an early shape
check, not physical proof. Canonical descriptor identity and platform topology
must reject equality and either-direction ancestry before startup provisioning,
Submit claim, or every named retained-result mutation. Linux derives source
coordinates from the held descriptor presentation and its mount-ID-selected
bounded mountinfo record only when that record has canonical pathname-root
semantics. Complete source-valid `nsfs` records with opaque namespace-object
roots remain in snapshot integrity and descendant checks, but an opaque
selected root refuses before coordinate arithmetic or effects; its mountpoint
and the configured spelling are never substitute coordinates. The accepted
opaque envelope is an exact `mnt|net|uts|ipc|pid|user|cgroup|time` kind plus a
canonical decimal inode label, without numeric interpretation or a separate
ES width limit. Malformed or other non-path roots reject, and recognizing such
records does not authorize `nsfs` as a configured execution-root filesystem.
Darwin uses `F_GETPATH`/`fstatfs`/bounded
`getfsstat` and rejects same-FSID distinct presentations. Ambiguous
dual-missing roots fail closed. Existing retained bundles remain readable when
staging is absent; missing results are not provisioned by reads, and topology
failure does not fall through to Nomad.

Modeled topology tests do not claim an actual bind or casefold mount. C's
selected native observations remain historical evidence for exact C source and
its environments, not executions of the then-unaccepted integrated tree; T and
that candidate did not inherit C's development acceptance. At that gate, local
source or integration acceptance required focused candidate-specific
changed-interaction assessment and validation, followed by separate explicit
commit authority. PR #8 later completed source publication of the accepted
tree, without operational qualification.

Running-deployment topology observation for a claimed Remote Alpha environment,
real repaired-helper mounted-alias fixtures where the operational claim depends
on them, and native syscall and mount-crossing evidence for each claimed Linux
operating architecture remain environment-bound qualification requirements.
They are not an independent blanket prerequisite to a separately authorized
local commit. A concrete uncovered changed interaction or operating claim may
require a separately selected bounded witness; merge ancestry alone does not
create a blanket native campaign. No integrated native observation,
supported-host qualification, or rollout readiness is inferred here. Operational topology,
key exposure, capacity, sensitive-material residence, reclamation, and
publication gates remain open for their operational scope. See `PLANS.md` under
"Current paired-root custody and acceptance scope" and the current gates in
`.docs/system_overview/remote_supported_host_alpha.md` and
`.docs/system_overview/supported_linux_host_qualification.md`.
