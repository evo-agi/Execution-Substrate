# Submit Idempotency, Correlation, And Recovery Target Contract

## 1. Status And Purpose

TARGET-ONLY: submit idempotency, correlation, and recovery in this document are target contract direction only.

CURRENT-UNCHANGED: current unkeyed submit remains the implemented behavior.

This record freezes the target ES-owned contract seam for future reliable keyed submit. It does not implement runtime behavior, does not select final request fields, does not select a response shape, does not select a persistence implementation, and does not enable Coordinator-backed dispatch. Current `POST /v1/executions:submit` remains the current unkeyed submit contract.

This document now selects only the public opt-in and versioning posture for a future implementation: the existing submit route is retained, the future reliable request is a submit-specific request family distinct from `PrepareRequest`, producer-declaration preflight and an in-band structural request discriminator are both required, header-only opt-in is rejected, and silent downgrade to current unkeyed submit is forbidden. No current request field, response DTO field, producer field, handler behavior, query route, durable store, migration, Nomad behavior, or runtime behavior is implemented by this document.

## 2. Current Implementation Reality

The current submit request body is the current `PrepareRequest` body. Its top-level fields are `schema_version`, `invocation`, `mode`, `timeout_seconds`, and `resources`. The nested invocation carries `schema_version`, `artifact_digest`, `derivation_spec_digest`, `output_id`, optional `argv`, optional `env`, optional `mounts`, and optional `annotations`.

Current body decoding is strict. Unknown request-body fields are rejected by the current JSON decoder, so adding a body field for reliable keyed submit would be a versioning event.

Current submit reuses the prepare/admission request shape. It has no caller-provided submit idempotency key, submit correlation key, dispatch command identity, exact replay contract, replay vocabulary, conflicting reuse vocabulary, pending outcome vocabulary, lookup route, or response-loss recovery semantics.

Current no-key submit has no exact replay contract.

Current no-key submit has no recovery lookup.

Current `validatePrepareRequest` defaults a blank `schema_version` to the current compatibility value. A changed value in that existing `schema_version` field is not, by itself, the selected reliable-submit discriminator.

ES currently assigns a random public `run_id` and then uses the current internal execution locator whose Nomad job ID is `exec-<run_id>`. The current locator is an implementation rule for the active slice, not a final run identifier strategy.

Current `run_id` creation happens before execution-package staging. Execution-package staging happens before Nomad registration. Current submit returns a bounded `202` `SubmitResult` only after ES has confirmed a Nomad registration response. The current successful receipt contains `run_id`, and status, logs, cancel, and result lookup currently require `run_id`.

Current ES has no broad durable run registry and no ES-owned lifecycle store. Status is projected from Nomad. Retained results are ES-owned opaque bundles keyed by `run_id`, not lifecycle truth.

On an in-process non-submitted return after staging, current submit removes the staged root through its current cleanup path. That cleanup behavior is current implementation reality; it is not proof that no external execution-producing effect happened when a Nomad response is uncertain.

## 3. Dual Ambiguity Model

### A. Caller-To-ES Ambiguity

ES may accept a submission, assign or select a `run_id`, stage execution inputs, submit through Nomad, and produce a bounded `202` receipt; the caller or adapter may lose the response before receiving that `run_id`.

Current unkeyed submit gives that caller no public recovery key. Retrying the same semantic command through current unkeyed submit can create another random `run_id`, another stage package, and another Nomad submission.

Reliable keyed submit must close this caller-to-ES ambiguity without making an adapter durable authority and without turning transport redelivery into a new semantic execution.

### B. ES-To-Nomad Ambiguity

ES may send a Nomad registration request. Nomad may accept it. ES may then receive a transport error, timeout, malformed response, missing response, unreadable response, or another outcome that does not prove rejection.

Current code confirms `submitted` only after a successful Nomad response. If the response is not confirmed, current code may return `submission_failed` and may clean staging because submitted was not confirmed.

Reliable keyed submit must not equate an uncertain Nomad response with proof that no job was accepted. It must also not automatically send a second Nomad registration merely because the immediate response was uncertain.

Both ambiguity windows are ES-owned contract problems. Coordinator and adapters must not solve them by scraping Nomad, storing parallel runtime lifecycle truth, treating trace IDs or request IDs as recovery authority, or becoming a second execution substrate.

## 4. Authority And Identity Ownership

The authenticated caller identity owns the initial namespace boundary for a submit idempotency key.

Submit idempotency is not authorization, admission, or execution permission. A matching key and private request binding prove only replay identity for the reliable keyed submit protocol.

ES owns the reliable-submit protocol, the assigned ES `run_id`, the bounded submit receipt, and the narrow submit-correlation record when implemented. Nomad owns submitted execution lifecycle after a job is accepted. Coordinator owns its own semantic attempt and dispatch-command identities. An adapter owns only ephemeral transport or session identity. Git and validating runtimes retain their own fact ownership.

ES need not understand Coordinator work-item or attempt semantics. A future Coordinator may map one opaque dispatch identity to the ES submit idempotency key, but that mapping is not ES public grammar.

## 5. Reliable Keyed-Submit Invariant

Reliable keyed submit is explicitly opt-in.

One authenticated-caller namespace and submit idempotency key identifies one reliable-submit claim. If that claim becomes capable of execution-producing staging or Nomad registration, ES assigns exactly one immutable `run_id` before the first execution-producing effect and later returns or recovers that same handle for the same claim.

Exact retry cannot create another stage package, another execution package, or another Nomad job. Concurrent exact retries converge on the same submit correlation outcome.

The same caller and key used with a non-equivalent request is conflicting reuse. Conflicting reuse must be detected before another execution-producing side effect.

A different authenticated caller cannot probe, reuse, conflict with, or learn the existence of another caller's key.

A transport retry is not a new semantic execution. A new semantic execution requires a new caller key.

The final `run_id` generation algorithm remains open.

## run_id Phase And Disclosure Invariants

The target reliable-submit contract is state-specific. Later request, receipt, recovery, Coordinator, and persistence models must preserve these phase-dependent `run_id` rules rather than treating `run_id` as one broadly optional field.

| State | Internal `run_id` presence | Public disclosure to the same authenticated and authorized caller | Coordinator lifecycle progression |
| --- | --- | --- | --- |
| Pre-claim rejection | Not created. Authentication, authorization, validation, or admission rejection before reliable-claim establishment does not allocate a `run_id`. | Forbidden. | Prohibited. |
| Optional non-effect-capable claim before run assignment | Not created. This phase is optional as an implementation choice; while present, no execution-producing staging or provider effect is permitted. | Forbidden. | Prohibited. |
| Effect-capable claim after run assignment | Required and immutable. Before any execution-producing staging or Nomad registration, the claim has exactly one ES-assigned immutable `run_id`; "at most one `run_id`" is insufficient for this phase, and no second `run_id` may ever be assigned to the same caller/key claim. | Intentionally open pending later public-shape decision until an outcome class requires disclosure. | Prohibited until the Coordinator has a correlated `run_id` and an outcome that permits lifecycle progression. |
| Pending before assignment | Not created. No effect-producing operation may have begun. | Forbidden. | Prohibited. |
| Pending after assignment | Required and immutable. | Required. Recovery to the same authorized caller preserves and exposes that same `run_id`; its presence does not prove Nomad acceptance, and the separate outcome class remains pending. | Prohibited. |
| Ambiguous before assignment | Not created. No provider effect may be inferred. | Forbidden. | Prohibited. |
| Ambiguous after assignment or possible provider effect | Required and immutable. | Required. Recovery to the same authorized caller preserves and exposes that same `run_id`; `run_id` presence does not prove provider acceptance, and the outcome remains ambiguous until ES-owned reconciliation. | Prohibited. |
| Accepted | Required and immutable. | Required. The bounded submit receipt carries the same `run_id`. | Permitted only after Coordinator has correlated and persisted that immutable ES external reference. |
| Exact replay | Existing-claim dependent. Exact replay preserves the underlying claim phase; accepted or post-assignment replay requires the same `run_id`, while pre-assignment replay leaves `run_id` not created. Exact replay never creates another `run_id` or execution-producing effect. | Existing-claim dependent under the underlying phase and outcome. | Permitted only according to the underlying recovered outcome, never merely because a replay occurred. |
| Recovered accepted | Required and immutable. | Required. The recovered accepted outcome carries the original `run_id`. | Permitted only with that recovered stable ES reference. |
| Provably not accepted after assignment | Required and immutable as an internal claim binding. It must not be represented as an accepted execution. | Intentionally open pending later public-shape decision, but any disclosure must preserve the non-accepted outcome and no-reuse invariant. | Prohibited. |
| Conflict | Existing-claim dependent for the original claim. The conflicting request creates no new `run_id` and no new execution-producing effect. | Forbidden for the conflicting request; it must not receive the existing claim's `run_id`. | Prohibited for the conflicting request. |
| Expired or unavailable correlation | Retention-policy dependent while preserving historical-assignment truth. Expiry is not evidence that no historical `run_id` or execution existed, and generic absence must not be modeled as "no run existed." | Forbidden by guessing or key reuse. Later public shape may disclose only bounded unavailable-correlation facts. | Prohibited. |
| Unauthorized | Not applicable to the caller. The underlying claim may exist, but authorization failure exposes nothing. | Forbidden. No existence or `run_id` disclosure. | Prohibited. |

Pre-claim rejection never creates or discloses `run_id`.

If an implementation chooses a non-effect-capable claim phase before run assignment, that phase cannot stage, submit, or otherwise begin an execution-producing operation. Coordinator lifecycle progression is prohibited while the claim remains pre-assignment.

Once a reliable claim becomes effect-capable, exactly one immutable ES `run_id` is assigned before the first execution-producing effect. "At most one `run_id`" is insufficient for effect-capable state because later recovery, reconciliation, and Coordinator correlation require one stable external reference.

Pending and ambiguous outcomes are split by assignment phase. Pending or ambiguous before assignment has no `run_id` and no provider effect may be inferred. Pending or ambiguous after assignment retains the stable `run_id`; disclosing that `run_id` to the same authorized caller does not claim Nomad accepted the job, and the separate submission outcome class continues to carry that distinction.

Conflict creates no new `run_id` and no new effect. The conflicting request must not receive the existing claim's `run_id`; the original claim retains whichever phase it already had.

For provably not accepted after assignment, the already assigned `run_id` remains internally bound to the claim. That outcome is not accepted execution, and the old semantic command does not silently reuse the same key.

Expiry is not evidence that no historical `run_id` or execution existed. The same semantic command must use a new key and must not infer that old-key reuse is safe.

Unauthorized recovery or replay discloses no existence and no `run_id`.

Coordinator must not enter submitted, running, cancellation, logs, result, or other lifecycle-bearing progression without a correlated `run_id`. While `run_id` is unknown to Coordinator, Coordinator remains in an unresolved submit/correlation state keyed by its own durable dispatch identity and the ES submit key. An adapter acknowledgement is not a substitute for `run_id`. The `run_id` is an ES-owned external reference, not Coordinator semantic attempt identity.

Later models must not represent every phase as one undifferentiated record with a broadly optional `run_id` field. State-specific records, discriminated outcomes, phase-specific constructors, persistence constraints, or equivalent invariants must make invalid `run_id` and outcome combinations unrepresentable. The exact model technique remains open.

## Effective Execution Plan And Field Requiredness

Conflicting reuse and reliable replay require a private canonical request and effective-plan binding.

Every Coordinator-managed reliable execution has one complete resolved effective execution plan before the first execution-producing staging or Nomad-registration effect. The binding covers effective values, not only sparse transport input or caller-controlled JSON.

Execution-shaping values may originate from user intent, model planning, standing policy, Coordinator derivation, ES-owned compatibility or default resolution, the selected runtime profile, and artifact or package metadata. Origin does not change requiredness for the reliable path.

Once a reliable claim becomes effect-capable, exact retry and recovery use the originally bound effective values. Mutable defaults, current policy, runtime-profile revisions, environment changes, or service configuration must not silently alter the replayed execution. The later design may bind values directly or use immutable or versioned references sufficient to reproduce and conflict-check the effective plan.

Provider-generated volatile facts such as Nomad allocation IDs or EvalID are not part of the caller plan and do not become replay authority.

An empty argument-addition list, environment-addition map, or mount list is a concrete bound value. An inapplicable capability such as authority handoff must be explicitly inapplicable rather than ambiguously omitted. Absent sparse input may be valid for the legacy API, but the effective value used by Coordinator-managed reliable dispatch must be resolved and bound.

### Required Field And Fact Matrix

| Field or fact | Authoritative/defaulting owner | Allowed source or origin | Phase where required | Phase where forbidden or inapplicable | Immutability point | Replay-binding treatment | Public/private treatment | Validation authority | Redaction or projection treatment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Request schema or version | ES request/versioning contract | Caller transport, versioned DTO, or ES compatibility default | Before reliable claim validation and before effect | Not applicable outside a request or recovery model | Bound before the claim becomes effect-capable | Included as an effective resolved value or immutable reference | Public request grammar when selected; private binding material stays private | ES | Public shape remains open; no raw private binding disclosure |
| Execution mode | ES admission | Caller intent or ES compatibility default | Before effect | Unsupported modes fail before effect | Bound before the claim becomes effect-capable | Included in effective-plan binding | Public only through selected request/receipt shape | ES | Project only bounded receipt facts |
| Timeout policy and effective timeout semantics | ES admission/runtime policy | Caller intent, standing policy, ES default, or runtime profile | Before effect | Not applicable only when an explicitly selected mode has no timeout concept | Bound before the claim becomes effect-capable | Included without selecting an exact timeout value here | Public shape open; private binding required | ES | Do not expose sensitive policy internals |
| Effective CPU | ES admission/runtime policy | Caller intent, standing policy, ES default, or runtime profile | Before effect | Inapplicable only if a future runtime has no CPU resource concept and says so explicitly | Bound before the claim becomes effect-capable | Included without selecting an exact CPU value here | Public shape open; private binding required | ES | Project only bounded receipt or handoff facts when selected |
| Effective memory | ES admission/runtime policy | Caller intent, standing policy, ES default, or runtime profile | Before effect | Inapplicable only if a future runtime has no memory resource concept and says so explicitly | Bound before the claim becomes effect-capable | Included without selecting an exact memory value here | Public shape open; private binding required | ES | Project only bounded receipt or handoff facts when selected |
| Runtime profile | ES runtime-profile compatibility boundary | Caller intent, Coordinator derivation, ES default, or selected profile | Before effect | Forbidden when unsupported or incompatible | Bound before the claim becomes effect-capable | Included as effective selected profile or immutable profile reference | Public only as selected bounded receipt or handoff evidence | ES | Do not expose credentials or hidden profile internals |
| Artifact digest | ES admission over artifact authority | Caller or Coordinator boundary request, artifact/package metadata | Before admission and before effect | Forbidden when malformed, unavailable, or rejected | Bound before the claim becomes effect-capable | Included exactly or by immutable artifact reference | Public only where existing or future contract selects it | ES with artifact service facts | No raw artifact contents in recovery authority |
| Derivation-spec digest | ES admission over derivation evidence | Caller or Coordinator boundary request, artifact/package metadata | Before admission and before effect | Forbidden when malformed, unavailable, or rejected | Bound before the claim becomes effect-capable | Included exactly or by immutable derivation reference | Public only where existing or future contract selects it | ES with evidence service facts | No raw derivation content in public recovery |
| Output identity | ES admission/result boundary | Caller or Coordinator boundary request, artifact/package metadata | Before effect when the execution writes a named output | Inapplicable for a future execution type without output identity only if explicit | Bound before the claim becomes effect-capable | Included as effective resolved output identity | Public only where selected | ES | No raw paths or storage internals |
| Effective command and argument vector | ES execution-package/runtime boundary | Artifact/package metadata, user intent, model planning, Coordinator derivation, or ES package rules | Before effect | Forbidden when unsupported or policy-rejected | Bound before the claim becomes effect-capable | Included after resolving effective command and empty argument additions as concrete | Private unless selected bounded projection exists | ES | Avoid raw prompts, secrets, or sensitive command material in public recovery |
| Environment additions | ES runtime boundary | Caller intent, model planning, Coordinator derivation, ES defaults, runtime profile, or policy | Before effect | Explicitly empty is allowed; forbidden for rejected or secret-leaking entries | Bound before the claim becomes effect-capable | Included as concrete map, including empty map; mutable environment defaults cannot drift | Private unless selected bounded handoff evidence exists | ES | Raw environment values and credentials are redacted from public recovery |
| Mounts | ES execution-package/runtime boundary | Caller intent, Coordinator derivation, artifact/package metadata, policy, or ES defaults | Before effect | Explicitly empty is allowed; forbidden when invalid or policy-rejected | Bound before the claim becomes effect-capable | Included as concrete list, including empty list | Private unless selected bounded projection exists | ES | No local absolute paths or sensitive mount material in public recovery |
| Network posture | ES admission/runtime policy | Artifact/package metadata, caller intent, policy, runtime profile, or ES default | Before effect | Forbidden when unsupported or policy-rejected | Bound before the claim becomes effect-capable | Included as effective resolved posture | Public only if selected as bounded evidence | ES | Do not expose hidden endpoints or credentials |
| Authority-handoff applicability | ES runtime authority boundary | Runtime profile, policy, artifact/package metadata, or ES default | Before effect | Explicitly inapplicable when no handoff applies; unresolved is forbidden | Bound before the claim becomes effect-capable | Included as applicable or explicitly inapplicable | Public only through bounded `authority_handoff` when selected | ES | No live credentials, leases, trust material, or secret payloads |
| Submit idempotency key | Authenticated caller namespace and ES reliable-submit protocol | Caller or Coordinator-owned opaque dispatch mapping | Before establishing a reliable claim | Forbidden for current unkeyed compatibility submit unless a future opt-in selects it | Bound at reliable-claim establishment | Identifies the claim with caller namespace; raw key need not be stored or disclosed | Private or safe representation only | ES authentication/authorization and reliable-submit protocol | Raw key is redacted from logs, reports, receipts, and errors |
| Private request/effective-plan binding | ES reliable-submit protocol | Canonical effective values or immutable/versioned references | Before the claim becomes effect-capable | Not public recovery authority | Bound before effect and immutable for the claim | Exact retry and conflict detection compare against it | Private | ES | Raw requests, environment values, credentials, and sensitive material are not exposed |
| Assigned `run_id` | ES reliable-submit protocol | ES assignment algorithm, deterministic or random still open | Follows the `run_id` phase table; required before effect-capable operations | Not created before assignment; disclosure forbidden for unauthorized and conflicting requests | Assigned exactly once before first execution-producing effect | Same claim always reuses the same `run_id`; no second assignment | Public only where the phase table requires or later shape allows | ES | Safe external reference, not lifecycle truth or Coordinator identity |
| Cancellation identity or cancellation-command correlation | ES cancellation boundary plus caller/Coordinator command identity | Caller cancellation request or Coordinator durable cancellation intent | Required only when a cancellation effect is requested | Not a submit-time field by default | Bound before cancellation effect | Must not create a second submit or alter original plan | Public shape open; safe correlation only | ES for runtime cancellation request, Coordinator for semantic cancellation intent | No scheduler IDs or hidden lifecycle truth |
| Retained-result reference | ES retained-result boundary | ES retained opaque result bundle when one exists | Required only when retained result facts exist | Not an execution-input field and absent before result exists | Bound when ES retains or observes the result reference | Recovery may reference bounded result facts without changing submit plan | Public only through selected result route/reference | ES | Opaque bundle/reference only; no raw paths or result-content interpretation |
| Validation-evidence reference | Validation/evidence owner for the selected flow | Validator, evidence service, ES observation, or Coordinator semantic acceptance record where applicable | Required only when validation evidence exists | Not an execution-input field by default | Bound when the evidence fact exists | Not part of submit replay unless the selected execution plan explicitly depends on it | Public/private per evidence contract | Owning validator or evidence authority | Project safe references only; no raw logs, prompts, credentials, or secrets |

This matrix does not choose exact timeout, CPU, memory, runtime-profile value, final field layout, or final transport shape.

The general legacy ES transport may continue to accept compatibility defaults and does not need to expose every effective value explicitly. For Coordinator-managed reliable submit, every execution-shaping value must still be concrete and bound before effect.

Schema or version, mode, timeout semantics, resources, runtime profile, artifact, derivation, output, effective command, environment, mounts, network, and authority-handoff applicability must be resolved before effect. The reliable submit key is required before establishing the reliable claim. The private effective-plan binding is required before the claim becomes effect-capable. `run_id` follows the phase-requiredness table.

Cancellation identity is required only when a cancellation effect is requested. Result and validation references are required only when those external facts exist; they are not execution-input fields. Empty collections are concrete values. Explicitly inapplicable values are distinct from unresolved values.

Requiredness at the boundary does not mean every ES field becomes a native first-class Coordinator database column or Coordinator domain field. Coordinator may retain an immutable execution-plan reference, safe binding, or typed boundary value while ES remains validation and execution-admission authority. The complete boundary request must nevertheless be resolved before dispatch. Coordinator must not reimplement ES defaulting, admission, or runtime-profile semantics merely to make fields "mandatory."

The `run_id` phase matrix and field-requiredness/effective-plan matrix are binding local-gate inputs to later ES request, receipt, and error models and to Coordinator dispatch, command, and observation models. Those model tranches must not begin until they can make the required and forbidden combinations unrepresentable or fail closed. This is a local dependency gate for those model tranches, not a prerequisite for unrelated project work.

## 7. Narrow Durable Correlation Semantics

Reliable keyed submit requires ES-owned durable recovery evidence sufficient to survive ES restart.

The narrow submit-correlation record may semantically retain only what is necessary to bind:

- authenticated caller namespace;
- opaque submit idempotency key or safe private representation;
- private request binding;
- assigned `run_id`;
- bounded submission outcome class;
- bounded original submit receipt or sufficient data to reproduce it;
- retention and expiry information when selected.

The narrow submit-correlation record must not become:

- an allocation history;
- a runtime status timeline;
- a log index;
- a result-content store;
- cancellation-completion truth;
- a runtime retry or reschedule policy store;
- a semantic work or attempt store;
- Coordinator desired state;
- a Nomad mirror.

This document does not select database, table, file, lock, migration, transaction API, or storage implementation shape.

## 8. Ordering And Concurrency Invariants

Caller authentication and authorization occur before existence disclosure. Request validation and conflict determination fail closed.

One authenticated-caller/key claim wins under concurrent first delivery. A durable key claim and assigned `run_id` exist before any execution-producing staging or Nomad registration effect.

External I/O does not occur inside the narrow durable-state transaction. Exact redelivery observes the existing claim rather than producing a second effect.

Acknowledgement of the key claim is not Nomad acceptance. A Nomad response is not semantic work acceptance. Unknown remains unknown until reconciled. Retrying transport is not creating a new semantic execution.

No particular transaction API is prescribed here.

## 9. ES-To-Nomad Reconciliation

ES may use its own stable assigned `run_id` and internal job locator to reconcile the submit effect.

Coordinator and adapters must not scrape Nomad. Nomad metadata, allocation IDs, EvalID, trace IDs, and request IDs do not become caller recovery authority.

An uncertain Nomad response must not automatically trigger a second Nomad submission. Recovery may determine accepted, provably not accepted, still pending, or ambiguous.

Absence is not sufficient proof of no acceptance when an external execution-producing effect was attempted and could have been accepted.

Stage or other recovery material required for reconciliation must not be destroyed merely because the immediate Nomad response was uncertain.

This document does not define the final Nomad query or reconciliation algorithm and does not rely on undocumented Nomad re-registration behavior.

## 10. Semantic Outcome Classes

The target contract defines semantic submission outcome classes without selecting exact JSON names, HTTP status codes, route shapes, or error strings.

- accepted: one execution was accepted; recover the stable `run_id` and bounded receipt.
- exact replay: return the same known outcome without another execution-producing effect.
- conflict: the same caller/key was used for a non-equivalent request; perform no new effect.
- pending: the keyed submission is still being processed or reconciled; perform no duplicate effect.
- provably not accepted: ES has positive evidence that no execution-producing provider effect was accepted.
- ambiguous: ES cannot yet prove accepted or not accepted; caller must not automatically issue a new semantic execution.
- expired or unavailable correlation: the prior correlation can no longer be recovered; this is not proof that no execution existed and does not silently permit reuse of the old semantic command.
- unauthorized: deny without disclosing whether the correlation exists.

Exact public vocabulary remains open.

## 11. Replay, Authorization, And Admission

Idempotency does not authorize execution.

First submission still passes authentication, authorization, admission, runtime-profile compatibility, and existing ES policy boundaries.

Replay and lookup remain caller-authorized operations. Revoked or unauthorized callers do not gain access merely by knowing a key.

Exact replay cannot widen originally accepted execution effects. The contract must distinguish returning a prior receipt from admitting a new execution.

Whether mutable admission policy is re-evaluated for read-only receipt recovery remains open. No replay may create a wider second effect.

## 12. Retention And Expiry

Retention must cover the supported duplicate-delivery and recovery window.

Deletion or expiry cannot be represented as proof that no prior execution existed. Automatic key reuse after expiry is not allowed by inference. A new semantic attempt uses a new key.

Exact TTL, tombstone, garbage-collection, and archival behavior remain open. Retained correlation metadata remains bounded and non-lifecycle.

## 13. Compatibility And Opt-In Treatment

Current submit without the new key remains valid current behavior. Current no-key submit does not gain reliable replay or recovery claims.

Reliable Coordinator-backed dispatch must use the future explicit opt-in. `control-plane-normal-shell/v1` remains unchanged. Current submit, status, logs, result, cancel, `authority_handoff`, and `outcome_evidence` compatibility remain unchanged by this tranche.

The existing producer declaration keeps its current outer identity:

- `schema_version = "execution-substrate.producer-contract/v1"`;
- `governed_execution.contract = "governed-execution-producer/v1"`.

The future declaration adds one explicitly named and versioned reliable-submit producer sub-contract under the governed-execution declaration. That additive sub-contract is narrow: it semantically declares only the reliable-submit contract family/version supported, whether reliable submit is enabled for the installation, a bounded safe unavailable or disabled reason, and the minimum safe request-contract discriminator required by a reliable client. It is not a generic `capabilities` map, feature registry, plugin registry, or cross-service probing framework. Exact JSON field names and exact reliable-submit contract/version strings remain open.

A future reliable client must use two independent fail-closed gates:

1. authenticate and read the producer declaration, then require the exact reliable-submit sub-contract and enabled status;
2. send a structurally distinct reliable-submit request variant.

The producer declaration alone is not execution authorization, admission, run existence, lifecycle truth, submit readiness, or proof that a specific request will be accepted. The request discriminator alone does not replace producer compatibility negotiation.

The target reliable request uses the existing `POST /v1/executions:submit` route. This tranche does not select a new route. A separate route remains a possible later fallback only if future concrete security or compatibility evidence invalidates the same-route design. Recovery-by-key or query-route shape remains open.

The current unkeyed compatibility variant remains the current `PrepareRequest`-compatible request body. The reliable variant uses a future submit-specific request family or envelope and must not remain merely an optional semantic interpretation of `PrepareRequest`.

The reliable envelope must carry a required in-band structural reliable-submit discriminator or nested reliable-submit marker that is unknown to the current `PrepareRequest` decoder. Because current body decoding is strict, a current server rejects the future reliable body before calling current `Submit` behavior. A changed value in the existing `schema_version` field alone is not the selected discriminator.

Header-only reliable-submit opt-in is rejected. A current server may ignore an unknown header and execute the current unkeyed body, violating fail-closed reliable semantics. A future header may be supplemental only when the body still carries the required structural reliable discriminator; this tranche selects no supplemental header.

When the reliable sub-contract is absent, incompatible, disabled, or unavailable, a reliable Coordinator or adapter must stop before submit. When a reliable body reaches a future server on which reliable mode is disabled or unsupported, the server must reject it before admission is treated as successful, before effect-capable `run_id` assignment, before execution-package staging, before Nomad registration, and before any fallback to current unkeyed `Submit`.

Disabling the future reliable mode must fail closed for reliable dispatch, not silently fall back to unkeyed submission.

Current `POST /v1/executions:prepare` remains the current bounded preflight surface. This tranche does not select a reliable prepare variant, claim creation during prepare, `run_id` allocation during prepare, persistence during prepare, or prepare-to-submit claim transfer.

Current CP/demo and `control-plane-normal-shell/v1` compatibility remains unchanged. Current CP and IM consumers may ignore the additive reliable-submit sub-declaration, while future reliable clients must require it explicitly. CP and IM compatibility evidence does not make CP or IM part of the target autonomous-development topology.

## 14. Safe Projection And Privacy

Routine public logs must not contain the raw submit idempotency key.

Public recovery surfaces must not expose raw request bodies, environment values, credentials, trust material, local paths, scheduler IDs, allocation IDs, EvalID, trace IDs, or request IDs as recovery authority.

Public recovery surfaces return only bounded submit correlation and receipt facts. Existence must not leak across authenticated caller namespaces. Correlation facts remain evidence and protocol state, not Coordinator or runtime lifecycle truth.

## 15. Explicit Non-Claims

This target contract makes these explicit non-claims:

- no runtime behavior implemented;
- no producer declaration field implemented;
- no request DTO implemented;
- no handler or decoder implemented;
- no route implementation;
- no persistence;
- no schema or migration;
- no exact HTTP code selected;
- no error string selected;
- no persistent receipt-store implementation;
- no final reliable request field names;
- no final reliable schema/version strings;
- no final `run_id` generation strategy;
- no deterministic `run_id` decision;
- no recovery query selected;
- no supplemental header selected;
- no reliable prepare selected;
- no Nomad registration retry decision;
- no Nomad behavior implemented;
- no broad lifecycle store;
- no scheduler;
- no Coordinator schema;
- no Bridge widening;
- no gateway service;
- no connector dependency;
- no Development Program prerequisite;
- no direct local Codex target path;
- no CP target topology;
- no general capability registry;
- no silent unkeyed fallback;
- no automatic merge or deployment behavior.

## 16. Required-Before-Implementation Gates

Implementation requires these local gates before runtime behavior changes:

- preserved public opt-in and versioning docs-contract coverage;
- reliable request and producer sub-contract model tests;
- private request-equivalence and plan-binding decision;
- narrow persistence and concurrency decision;
- ES-to-Nomad uncertain-outcome reconciliation decision;
- retention and expiry decision;
- security and privacy review;
- request, receipt, and error model tests;
- compatibility tests;
- implementation provenance and independent audit.

## 17. Open Seams

The following seams remain open:

- exact reliable producer sub-contract JSON field names;
- exact reliable producer sub-contract family/version strings;
- exact reliable request envelope field names;
- exact reliable request schema/version strings;
- submit key field name;
- recovery field names;
- replay-only versus query route;
- exact outcome and error vocabulary;
- storage implementation;
- lock and concurrency implementation;
- TTL, tombstone, and garbage collection;
- canonicalization;
- private binding mechanism;
- plan snapshot versus immutable references;
- Nomad reconciliation mechanism;
- deterministic versus random assigned `run_id`;
- bootstrap exception;
- caller namespace refinement beyond authenticated identity;
- later Coordinator consumer mapping.
