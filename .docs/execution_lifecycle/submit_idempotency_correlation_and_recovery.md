# Submit Idempotency, Correlation, And Recovery Target Contract

The accepted resolved-plan source makes legacy unkeyed `Submit` a consumer of
private admitted semantic facts. The separate admission-local binding/witness
producer remains always not-effect-ready. The bounded private codec-3 synthetic
replay path composes that producer from one actual resolved delivery, seals
original intent/effective facts/material and verifies it on reload. This is
runtime-unwired and does not qualify a real image/host, reconcile ambiguous
provider effects or deduplicate public caller retries.
The private schema
`execution-substrate.reliable-submit-request/v1` and nested contract
`execution-substrate.reliable-submit/v1` are selected; a structural reliable
body remains rejected by the current public decoder.

## 1. Status And Purpose

TARGET-ONLY: public/operational submit idempotency, correlation, and recovery in
this document remain target direction. Section 6A is a real bounded private
synthetic source rule, not public or effect authority.

CURRENT-UNCHANGED: current unkeyed submit remains the implemented behavior.

This record freezes the target ES-owned contract seam for future reliable keyed
submit. It does not implement runtime behavior, does not select HTTP status
mapping or public error strings, does not add public response DTOs, and does
not enable Coordinator-backed dispatch. The persistence and concurrency ADR in
`reliable_submit_persistence_and_concurrency.md` now selects local embedded
SQLite as the first storage backend, `modernc.org/sqlite v1.54.0` as the
CGO-free driver, private same-package durable-store source, and the target
durable latest-operation replay repair contract while leaving runtime
integration open. Current `POST /v1/executions:submit` remains the current
unkeyed submit contract.

This document now selects the public opt-in/versioning posture and delegates the
persistence/concurrency decision to
`reliable_submit_persistence_and_concurrency.md`: the existing submit route is
retained, the future reliable request is a submit-specific request family
distinct from `PrepareRequest`, producer-declaration preflight and an in-band
structural request discriminator are both required, header-only opt-in is
rejected, and silent downgrade to current unkeyed submit is forbidden. The
unavailable contract-adapter foundation also selects the private reliable
request-family vocabulary, submit-key syntax, caller/key derivation, composite
`ClaimID` construction through the committed pure-model constructor, and
ES-neutral outcome semantics. Those earlier adapter/store tranches did not
implement source-grounded plan extraction, canonical binding, a complete
witness or replay custody. The separate private
`resolved-execution-plan-extraction-foundation` resolves current legacy Submit
from admitted facts before effect. The private v1 producer constructs a binding
and witness from that frozen tuple; the codec-3 private synthetic composer is
its only new non-test caller and still confers no effect permission. No source
wires reliable submit. No current public
request field, public response DTO field, producer field, handler behavior,
query route, Nomad behavior, runtime configuration, or runtime behavior is
implemented by this document, the private store tranche, or the unavailable
contract-adapter foundation.

The source-bearing reliable-submit package is now present as the admission-local
internal Go package `es/admission/internal/reliablesubmit`. Its pure model in
`model.go` models local phase validity, opaque claim identity, opaque
effective-plan binding, completeness witnesses, replay views, conflict,
unauthorized, unavailable-correlation, same-caller run-reference disclosure
policy, and Coordinator-progression eligibility. The private persistence source
in the same package adds a backend-neutral claim-store port, durable semantic
service, durable-record codec, shared conformance suite, and SQLite
implementation. It is not wired to current submit. It implements no public DTO,
producer declaration field, staging behavior, Nomad behavior, recovery route,
runtime configuration, or runtime integration.

The pure model validates one supplied current snapshot at a time. It can reject
invalid phase shapes, reject missing effective-plan binding before
effect-capable assignment, treat reassignment with the same opaque `RunRef` as
idempotent, and fail closed on reassignment with a different `RunRef`. It
cannot enforce one globally winning caller/key assignment across stale copied
pre-assignment values, process restarts, or concurrent writers. That authority
belongs to the private persistence/concurrency layer with uniqueness rules and
compare-and-swap transaction semantics.

Later transport and reconciliation code must consume rather than bypass this
package. If a later reliable-submit tranche cannot consume it coherently, that
tranche must stop and revise the model instead of layering a second unused
abstraction on top.

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

On every post-claim return, current submit closes held descriptors and retains
the visible staged root. This includes an uncertain Nomad response and is not
proof that no external execution-producing effect happened.

Current source now also contains the unwired pure internal package
`es/admission/internal/reliablesubmit`. Current `Submit`, current `Prepare`,
current handlers, the current producer declaration, the current execution
locator, staging, lifecycle projection, results, and Nomad interaction do not
import or use that package.

Current source also contains admission-local private reliable-submit foundation
helpers in package `admission`. They define the private reliable request-family
shape and validation, caller/key safe-reference derivation, composite `ClaimID`
construction through the committed pure-model constructor, and ES-neutral
submission-outcome projection. They remain separate from the source-grounded
resolved-execution-plan extraction already implemented for current Submit and
do not canonically encode or bind that plan, construct its complete reliable
witness, or orchestrate reliable runtime behavior. The later codec-3 private
synthetic path owns bounded durable replay-envelope custody separately. Those
helpers are not exported public DTOs, are not wired to
handlers, and are not called by current submit.

Current legacy Submit now also consumes a separate private
`resolvedExecutionPlan` extracted from the real shared admission and
submit-resolution path. `prepareAdmission` borrows the caller request,
immediately deep-copies mutable members, and applies one private
Prepare-versus-Submit intent. Its owned working copy is the sole mutable
authority for mode/default/validation/normalization; successful admission
returns one frozen authoritative snapshot and may make immutable defensive
copies. The caller retains ownership until the initial copy completes and must
keep the request and every reachable
mutable member race-free through that copy. Concurrent unsynchronized mutation
while copying is a caller data race, not an ES synchronization guarantee.
After the owned copy completes, later caller mutation cannot change admitted
or submitted state, and downstream defensive copies do not create a second
mutable authority. It also retains the exact workload-zone Vault reference
used for the successful fetch and auth-plan resolution. Submit snapshots its required
configuration once, captures payload/runtime-support/mount/trust bytes, parses
each mount archive exactly once with bounded allocation, resolves the qualified
platform-state owner as the final variable host observation, and freezes on
successful resolver return. No run ID, staging write, ownership mutation, or
Nomad call precedes that freeze.

The current plan owns admitted semantic facts, including a source-grounded
payload digest distinct from artifact/derivation/output identity, one typed
runtime command, runtime-identity tmpfs size, and unconditional authority
inputs. Captured host context contains only normalized qualified values: the
cleaned absolute staging root, qualified owner, cleaned absolute SPIRE source,
and trimmed non-empty datacenter. The normalized absolute results root remains
current ES service/custody placement outside the semantic plan, host context,
provider-job projection, and B1 binding. After freeze, legacy Submit derives
owner/run/endpoint environment, host/staged paths, datacenter, endpoint, and other run
facts from typed plan/host/run projections only, exclusively creates one run
root, and retains that root on every post-claim return. The payload digest is
not public or Nomad metadata, and raw payload bytes remain material.
Current successful Submit always constructs `authority_handoff`; structural
presence of the current plan authority inputs therefore means applicable.

The current private `buildReliableSubmitAdmissionBinding` producer accepts the
actual frozen `resolvedExecution` and a validated private reliable-family
marker. It checks the fourteen category facts and additional material,
runtime-support, job-envelope and trust facts before constructing the existing
opaque `PlanBinding`, witness and `BoundPlan`. The result is always
not-effect-ready; the private synthetic same-delivery composer is its only
non-test caller and no runtime call path uses it. For each governed mount,
the resolver now carries both the requested source artifact digest and the
signature-verified returned artifact and signed payload digests. This is a
private provenance carry-through only. Legacy mount admission does not
separately compare requested and returned artifact identity and can still
accept a discovery for a different signed artifact if its other checks pass.
The unwired producer requires those artifact identities to match and checks
captured compressed bytes against the signed payload digest. Live admission
hardening remains a distinct later decision.

The semantic plan is admitted semantic truth only, while host/run projection
adds additional execution-shaping facts. Tranche B2 now completes its bounded
privacy and independent-assurance refinement. The selected public messages are
exactly `workload-zone vault configuration is invalid`,
`derive execution host context failed`,
`stage workload vault trust material failed`,
`derive execution platform state owner failed`, and
`execution submission failed`; their routes, HTTP statuses, codes, DTO fields,
precedence, and successful behavior remain unchanged. This changes no reliable
submit correlation, replay, recovery, or outcome vocabulary. Reliable
keyed-submit runtime remains unwired, and native Linux runtime validation remains
pending.

Current private durable source implements latest-operation same-operation
replay. The general mutation path derives and compares a complete private
latest-operation descriptor before stale-revision and inactive-state refusal.
Same mutation plus same operation kind and input binding replays the committed
result without another CAS. Same mutation plus different descriptor conflicts.
Migrated legacy/unbound rows preserve only the retained mutation reference and
fail closed for same-mutation replay rather than inventing operation semantics.
The store persists no mutation history. The private store remains
runtime-unwired, so no current public execution behavior is affected.

## 3. Dual Ambiguity Model

### A. Caller-To-ES Ambiguity

ES may accept a submission, assign or select a `run_id`, stage execution inputs, submit through Nomad, and produce a bounded `202` receipt; the caller or adapter may lose the response before receiving that `run_id`.

Current unkeyed submit gives that caller no public recovery key. Retrying the same semantic command through current unkeyed submit can create another random `run_id`, another stage package, and another Nomad submission.

Reliable keyed submit must close this caller-to-ES ambiguity without making an adapter durable authority and without turning transport redelivery into a new semantic execution.

### B. ES-To-Nomad Ambiguity

ES may send a Nomad registration request. Nomad may accept it. ES may then receive a transport error, timeout, malformed response, missing response, unreadable response, or another outcome that does not prove rejection.

Current code returns `submission_failed` when the Nomad response is not confirmed,
closes held descriptors best-effort, and retains the complete staging root. It
does not treat an uncertain response as cleanup authority.

Reliable keyed submit must not equate an uncertain Nomad response with proof that no job was accepted. It must also not automatically send a second Nomad registration merely because the immediate response was uncertain.

Both ambiguity windows are ES-owned contract problems. Coordinator and adapters must not solve them by scraping Nomad, storing parallel runtime lifecycle truth, treating trace IDs or request IDs as recovery authority, or becoming a second execution substrate.

## 4. Authority And Identity Ownership

The authenticated caller identity owns the initial namespace boundary for a submit idempotency key.

Submit idempotency is not authorization, admission, or execution permission. A matching key and private request binding prove only replay identity for the reliable keyed submit protocol.

ES owns the reliable-submit protocol, the assigned ES `run_id`, the bounded submit receipt, and the narrow submit-correlation record when implemented. Nomad owns submitted execution lifecycle after a job is accepted. Coordinator owns its own semantic attempt and dispatch-command identities. An adapter owns only ephemeral transport or session identity. Git and validating runtimes retain their own fact ownership.

ES need not understand Coordinator work-item or attempt semantics. A future Coordinator may map one opaque dispatch identity to the ES submit idempotency key, but that mapping is not ES public grammar.

The public `submit_key` syntax is base64url without padding, exactly 43 ASCII
characters, and decodes canonically to exactly 32 bytes. The client contract is
that those 32 bytes are generated with a cryptographically secure random
generator. The server validates encoding, canonical form, and length only; it
does not prove entropy.

The future authenticated request boundary supplies the exact canonical SPIFFE
URI selected from the verified client certificate. This tranche does not wire
certificate parsing. The canonical SPIFFE URI is the caller-namespace source;
authorization path prefixes alone, issuer common names, raw certificate bytes,
Coordinator IDs, CP IDs, Bridge/session/report IDs, trace IDs, and request IDs
are not reliable-submit identity inputs.

Admission-local safe references are derived with domain-separated SHA-256:

- `caller_ref_bytes = SHA256("es/reliable-submit/caller-ref/v1\0" || canonical_spiffe_uri)`
- `submit_key_ref_bytes = SHA256("es/reliable-submit/submit-key-ref/v1\0" || caller_ref_bytes || raw_submit_key_bytes)`

The private adapter constructs `reliablesubmit.CallerRef` from
`caller_ref_bytes`, `reliablesubmit.SubmitKeyRef` from
`submit_key_ref_bytes`, and `reliablesubmit.ClaimID` by calling
`reliablesubmit.NewClaimID(callerRef, submitKeyRef)`. It does not hash or
invent a third claim-ID representation. Raw submit-key bytes are not logged,
formatted, returned, or stored as public recovery authority.

The raw-key-bearing wire surrogate is function-local to the private strict
decode and caller-bound derivation boundary. The raw `submit_key` string may
exist only during that decode/derive operation, and decoded key bytes are
consumed only to derive `SubmitKeyRef` under the authenticated caller namespace.
The validated private request representation must retain only sanitized request
facts plus safe private `CallerRef`, `SubmitKeyRef`, and `ClaimID` values, not
the raw `submit_key` string, decoded key bytes, or original raw-key-bearing wire
request. Full request objects remain unsafe as log payloads. This tranche makes
no secure-memory-erasure claim and does not claim arbitrary invalid Go
formatting operations, including invalid `%w` on non-error values, are
overrideable by domain formatting hooks. Submit-key validation errors remain
fixed bounded errors.

## 5. Reliable Keyed-Submit Invariant

Reliable keyed submit is explicitly opt-in.

One authenticated-caller namespace and submit idempotency key identifies one reliable-submit claim. If that claim becomes capable of execution-producing staging or Nomad registration, ES assigns exactly one immutable `run_id` before the first execution-producing effect and later returns or recovers that same handle for the same claim.

Exact retry cannot create another stage package, another execution package, or another Nomad job. Concurrent exact retries converge on the same submit correlation outcome.

For durable same-operation replay, the current private invariant is that an
exact redelivery of the latest already committed operation replays the committed
result without new mutation or external effect. Accepted replay returns the same
accepted record and receipt. Provably-not-accepted replay returns the same
terminal record. This private source repair is complete for latest-operation
replay and remains runtime-unwired; public reliable-submit runtime enablement is
still a later gate.

The selected durable replay repair is latest-operation-only. Exact replay is
guaranteed only when the incoming command matches the current latest committed
durable mutation descriptor: mutation reference, closed private operation kind,
and versioned safe operation-input binding. An older operation arriving after a
later committed mutation is stale or superseded, not exact replay, and the
current later record is not represented as the older operation's replay result.
No historical mutation-result log is selected; historical replay requires a
separate ADR and schema.

The operation-input binding includes expected predecessor revision and every
operation-specific safe opaque reference or immutable value that changes command
meaning. It excludes mutation reference itself, raw requests, submit keys,
caller URIs, environment values, credentials, filesystem paths, unrestricted
provider IDs, trace/request/session/report IDs, logs, and result bodies. Reuse
of one mutation reference with a different operation kind or input binding is a
mutation conflict. Same payload with a new mutation reference is not exact
replay and must proceed through ordinary revision, phase, and transition
validation without updating mutation identity merely to bless an already
completed effect.

The same caller and key used with a non-equivalent request is conflicting reuse. Conflicting reuse must be detected before another execution-producing side effect.

A different authenticated caller cannot probe, reuse, conflict with, or learn the existence of another caller's key.

A transport retry is not a new semantic execution. A new semantic execution requires a new caller key.

The final `run_id` generation algorithm remains open.

The pure internal model names the assigned ES reference `RunRef` to avoid
freezing the current execution-locator implementation. `RunRef` is opaque,
non-empty, immutable, equality-only, and has no JSON, database, scheduler, job,
allocation, trace, request, or session identity role. A later admission adapter
may map an already validated current or future ES locator into `RunRef`; that
adapter is outside this tranche.

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

The pure model encodes the first internal gate with distinct phase types rather
than one optional-field state bag. Claim phases are separate from views and
decisions: pending before assignment, ambiguous before assignment,
effect-capable assigned, pending after assignment, ambiguous after assignment,
accepted, and provably-not-accepted after assignment are claim phases;
recovered accepted and exact replay are views over valid existing state; conflict,
unauthorized, and expired/unavailable correlation are decisions that disclose no
existing claim run or receipt.

The model's effective-plan witness covers fourteen effect-time categories:
request schema or version, execution mode, effective timeout semantics,
effective CPU, effective memory, runtime profile or immutable profile
reference, artifact identity, derivation-spec identity, output identity,
effective command and argument vector, environment additions, mounts, network
posture, and authority-handoff applicability. CPU and memory are separate
categories. Empty argument additions, environment additions, and mounts are
resolved concrete values. Unresolved categories prevent witness construction.
Output identity can be explicitly inapplicable only through a future
execution-kind rule, and authority handoff can be explicitly inapplicable;
generic inapplicability for required categories fails closed.

The rejected self-validating plan binder remains absent. The implemented
`resolved-execution-plan-extraction-foundation` derives one private semantic
plan from actual current ES admission and runtime resolution. That plan is
authoritative only for admitted semantics; legacy Submit consumes it now, and
the unwired private v1 `PlanBinding` producer consumes its actual frozen tuple
rather than re-resolving the same categories. Separate owned material
contains all primary payload, runtime-support, compressed/parsed mount, Vault
CA, and combined trust-bundle bytes. The plan and material are package-private,
deep-copied at mutable boundaries, have private untagged fields, pass only
through narrow typed projections, and inherit one fixed zero-data formatter
that emits `<private execution value redacted>` for content-bearing formatting.

Current successful Submit always constructs `authority_handoff`. Its current
semantic plan therefore has no applicability flag: structural presence means
applicable. The optional Codex credential-location subcomponent retains its
real applicability flag. The unwired reliable witness/model and SQLite masks
are unchanged. The new producer resolves current authority category 14 as
applicable. The generic model's allowance for future execution-kind
inapplicability is not current Submit truth or runtime authority.

The semantic plan is admitted semantic truth only. Semantic-plan equality
across qualified host contexts proves admitted-semantic equality only.
Captured host context and run/provider projection add additional
execution-shaping facts, so plan equality is not provider-job, provider-effect,
dispatch, replay, restart, or safe-host-substitution identity. The private v1
binding selects admitted semantic facts and captured material identities; host
and run facts remain outside it as separately captured future prerequisites.

The earlier extraction foundation by itself selected no canonical binding or
witness. The separate private v1 producer now selects only an unwired encoding,
commitment and completeness assessment. It does not supply durable
material/replay-envelope custody, host-context replay treatment, or reliable
runtime orchestration. It does not synthesize `PrepareRequest` or `Manifest`
proof from the plan, create a parallel admission engine, tighten the current
empty-environment-allowlist contract, or infer authority-handoff
inapplicability contrary to current Submit. The producer uses source-normalized
semantic names without a second transformation before ordering and collision
checks.

Current environment validation remains unchanged: reserved runtime/control keys
are forbidden; when a manifest declares allowed environment keys, invocation
keys must stay within that set; when that list is empty, current source does not
enforce explicit allowlist membership. If a future project decision makes an
empty list mean no environment additions, that requires a separate owning
admission-contract change and compatibility review.

Current supported `Submit` constructs `authority_handoff`. The private v1
producer derives category 14 as resolved from that current source-owned
behavior and does not treat generic inapplicability masks as current runtime
truth. The earlier B1 extraction alone selected no reliable witness or mask
migration; this producer still changes no model mask or SQLite schema.

### Private admission binding v1: current unwired producer and exact format

Decision `ES-PRIVATE-ADMISSION-BINDING-V1-20261115-01` selects a bounded
ES-private source rule on the reopened canonical-binding/completeness seam.
`buildReliableSubmitAdmissionBinding` reads the actual `resolvedExecution`
returned by `Service.resolveExecutionForSubmit` and a validated private
reliable-family marker. It checks each source fact before the corresponding
model category can be resolved. The fourteen-category witness means checked
input completeness under those producer/source assumptions; it is not
independent proof that admission ran, that durable custody or current
authorization exists, or that execution is permitted. The package-private
assessment always reports not-effect-ready and lists missing later runtime
prerequisites. Only the named private synthetic same-delivery composer calls
the builder. No runtime function-value alias, handler, provider, store, or
config uses it. Current public strict decoding still refuses
a structural reliable-submit body.

For the current static-script kind, the named validation-to-category map is:

| Model category | Required producer check before `ResolvedCategory` |
| --- | --- |
| `RequestSchemaOrVersion` | Validated reliable family/contract and admitted request and invocation schema facts. |
| `ExecutionMode` | Actual admitted supported mode, consistent with the typed command. |
| `TimeoutSemantics` | Nonnegative effective timeout in seconds and the matching ordered supervisor timeout argument. |
| `CPU` | Concrete positive effective CPU. |
| `Memory` | Concrete positive effective memory in MiB. |
| `RuntimeProfile` | Selected nonempty profile and image reference, coherent with authority profile. Image reference is not immutable image-content identity. |
| `ArtifactIdentity` | Valid requested primary artifact and signed payload digests, signed-payload equality with captured primary bytes and its material descriptor. |
| `DerivationSpecIdentity` | Concrete admitted labeled SHA-256 derivation digest. |
| `OutputIdentity` | Concrete admitted output ID for current static-script execution; generic future inapplicability is not used. |
| `CommandAndArgv` | Typed executable and exact ordered arguments, including command/timeout consistency. Empty additions remain concrete. |
| `EnvironmentAdditions` | Exact effective environment key/value map after current precedence, including required platform/Vault keys coherent with plan and authority; empty caller additions are concrete. No trim/casefold of effective keys. |
| `Mounts` | Ordered one-to-one mount plan/material pairing, requested/verified signed artifact equality, signed payload digest versus captured compressed bytes, existing bounded parser revalidation and ordered parsed-entry equality. Empty list remains concrete. |
| `NetworkPosture` | Concrete admitted network-access flag. |
| `AuthorityHandoffApplicability` | Current unconditional authority plan and coherent profile, Vault reference, optional Codex credential location, and captured trust flags; category is always resolved. |

Runtime-support digest/bytes, runtime-identity tmpfs size, fixed job envelope,
and trust presence/bytes are mandatory additional effect-shaping checks; they
do not add model categories or change its masks. The builder applies the
existing aggregate captured-material budget first. It revalidates each
already captured compressed mount sequentially with the existing governed
mount parser and the same per-mount and aggregate body/stream limits, and
compares ordered parsed names, kinds, full normalized modes, content lengths
and bytes. It does not refetch, reread signed evidence, write staging, invent
a signed digest, run a third archive interpreter, or reinterpret a stored name
after the parser's single normalization. Raw `"./ name"` may legitimately
produce stored `" name"`; permitted directory repeats and implicit directories
remain governed by the parser. This adds bounded in-memory work and temporary
memory for the unwired producer; the legacy runtime peak bound is not a claim
for the new producer. The current legacy path still lacks an independent
requested-versus-returned signed mount artifact equality check. A signed
request-A/discovery-B/payload-P combination may therefore reach legacy staging
if other current checks pass; this is a residual current-path limitation, not
a live policy repair by this producer.

The v1 binding is a computational commitment under HMAC-SHA-256 and the
specified encoder, not mathematical injectivity, encryption, host eligibility,
storage custody, image content identity, provider-job identity, result
authenticity, exactly-once delivery, or effect authority. The private key is
exactly 32 bytes and explicitly supplied. No configured, default, global,
result-authentication, or raw-submit key is used. The key ID is 1 to 64 ASCII
bytes matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Let `header` be ASCII
`ESRS-PB` followed by `00`, `01`, a two-byte unsigned big-endian key-ID byte
length, and the key-ID bytes. Let `canonical-v1` be the exact binary message
below. `mac = HMAC-SHA256(K, ASCII("execution-substrate/reliable-effective-plan/v1") || 00 || header || canonical-v1)`.
`PlanBinding = header || mac`, with exactly 32 MAC bytes. The header and key ID
are authenticated. The first slice uses only synthetic test keys. A later
effect consumer must retain the original version/key and fail closed when
unknown or unavailable; fresh-key rebind is not equality with an old claim.

Every top-level field is present exactly once in ascending ID order. A field
is `uint16BE(id) | uint8(type-tag) | uint64BE(payload-byte-length) | payload`.
Nested records are concatenated fields with the same framing and specified
ascending local IDs. No Go layout, reflection, JSON, generic canonicalizer,
formatter, or decoder supplies bytes. Type tags are fixed: `1` UTF-8 string
(payload is its exact bytes), `2` signed 64-bit two's-complement big-endian
integer, `3` boolean (exactly `00` or `01`), `4` record (nested TLVs), `5`
sequence, `6` map, `7` raw 32-byte SHA-256 digest, and `8` one-byte state.
State bytes are `00` absent, `01` present, `02` inapplicable; required facts
cannot use absent or inapplicable. A sequence payload is `uint64BE(count)`
then, for every element in source order, `uint64BE(element-byte-length) |
element-bytes`. String elements are untagged UTF-8 bytes; record elements
are their nested TLV bytes. A map payload is `uint64BE(count)` then
`uint64BE(key-byte-length) | key-UTF8 | uint64BE(value-byte-length) |
value-UTF8` for each entry sorted by unsigned UTF-8 bytes of the exact
effective key. Map keys are unique after their source-owned normalization;
the current effective environment keys have no additional trim or casefold.
Nil and empty collections have the same zero-count concrete encoding; the
current resolver's effective environment is nonempty because it injects
required platform/Vault keys, even when caller additions are empty.
Sequence order, including command arguments, mounts, parsed entries, and
security options, is retained. Strings reject invalid UTF-8 without invented
Unicode normalization. Admitted digest strings use exact lowercase
`sha256:[0-9a-f]{64}`; their normalized source values are encoded as strings,
while material byte hashes use tag `7`.

A material descriptor is a tag-`4` record with local field `1` state (tag
`8`); if present it has field `2` byte length (tag `2`, nonnegative) and field
`3` SHA-256 of the captured bytes (tag `7`). Absent and inapplicable states
omit fields `2` and `3`. Primary, support, compressed mount and regular-file
content are present; a present empty regular file has length zero and
SHA-256(empty). Directory content is inapplicable. Missing optional trust
bytes are absent, while present trust bytes must agree with the captured
authority trust flags. There is no independent per-component digest output.

The eighteen top-level fields and complete nested record field IDs are:

| Top ID/type | Exact payload and ascending local IDs |
| --- | --- |
| `1` record | `1` reliable family schema `execution-substrate.reliable-submit-request/v1`; `2` reliable contract `execution-substrate.reliable-submit/v1`; `3` admitted request schema; `4` admitted invocation schema (all strings). |
| `2` string | Admitted execution mode. |
| `3` integer | Effective timeout in **seconds**; command timeout semantics are checked against field 10. |
| `4` integer | Exact `resolvedTaskResources.cpu` integer passed unchanged to Nomad task `Resources.CPU` (Nomad CPU resource units; no producer conversion). |
| `5` integer | Effective memory in **MiB**. |
| `6` record | `1` runtime profile name; `2` selected image reference string. |
| `7` record | `1` requested primary artifact digest; `2` signed primary payload digest; `3` captured primary material descriptor. |
| `8` string | Derivation-spec digest. |
| `9` string | Admitted output ID. |
| `10` record | `1` typed executable string; `2` ordered argument sequence of strings. |
| `11` map | Exact effective semantic environment key/value strings. |
| `12` sequence of mount records | Each mount: `1` requested artifact digest; `2` signature-verified returned artifact digest; `3` signed payload digest; `4` source-normalized target string; `5` read-only boolean; `6` compressed material descriptor; `7` ordered sequence of parsed-entry records. Each entry: `1` once-normalized name string; `2` kind string (`directory` or `regular`); `3` full normalized mode integer; `4` content material descriptor. |
| `13` boolean | Admitted network-access flag. |
| `14` authority record | `1` applicability state (present for current Submit); `2` runtime profile name; `3` Codex credential-location record; `4` workload Vault record; `5` workload-zone Vault config digest; `6` trust-flag record. Codex record: `1` state (present or inapplicable), and only when present `2` CLI path, `3` credential source, `4` Vault secret path, `5` Vault secret field (strings). Vault record: `1` mode, `2` address, `3` auth mount, `4` auth role, `5` JWT audience (strings). Trust-flag record: `1` Vault-CA present and `2` combined-TLS present (booleans). |
| `15` record | `1` captured runtime-support digest string; `2` captured support material descriptor. |
| `16` integer | Runtime-identity tmpfs size in **bytes**. |
| `17` job-envelope record | `1` job type, `2` group name, `3` group count, `4` task name, `5` driver, `6` user (strings except count integer); `7` privileged boolean; `8` ordered security-option sequence of strings; `9` restart record; `10` reschedule record. Restart record: `1` attempts integer, `2` mode string, `3` interval integer in **nanoseconds**, `4` delay integer in **nanoseconds**. Reschedule record: `1` attempts integer, `2` unlimited boolean, `3` delay integer in **nanoseconds**, `4` delay-function string, `5` max-delay integer in **nanoseconds**. |
| `18` trust record | `1` Vault-CA material descriptor; `2` combined system/workload TLS material descriptor. |

All scalar integer conversions must fit signed 64-bit range. The producer
checks length/count arithmetic before each sum or multiplication and refuses
any `canonical-v1` longer than 64 MiB. It first counts and validates the
entire schema, including source-normalized key uniqueness, before sorting a
map or allocating a large buffer; it then streams the same framing directly
to HMAC without retaining a second large canonical preimage. The limit is a
new producer-only input/work bound, not a legacy admission or retention cap;
it adds no filename or entry cap to the existing mount parser. Hashing and
parser revalidation use bounded additional temporary memory, and the private
assessment holds only detached descriptors and the opaque `BoundPlan`.
Content-bearing/key-bearing aggregates are unexported, untagged and use the
fixed private redaction formatter. Raw canonical bytes, keys, environment
values, private paths, per-component hashes and MAC bytes are never surfaced
through supported formatting, JSON/text marshaling, errors, public DTOs or
logs. No secure-erasure or concurrent caller mutation guarantee is made.

Binding equality under one retained key attests the encoded admitted
semantics and captured material identities only. The captured source tuple
also contains staging/results paths, owner UID/GID, SPIRE source directory
and datacenter as separate placement requirements; those are **captured**
facts, not a retained behavioral topology proof or qualified host-substitution
identity. No image-content pin is captured merely by a selected mutable image
reference. Missing image-content, placement, key-custody and replay-envelope
proof remain explicit runtime prerequisites, not reasons to fail all unwired
producer success cases. There is no new lifecycle phase algebra.

The selected codec-3 private synthetic exact-retry rule compares canonical
original intent and field presence separately from PlanBinding. An explicit
value becoming omitted conflicts even if effective bindings match; an unchanged
sparse retry reuses winner-original facts, not new defaults. Lookup by the
caller-scoped key precedes current resolution, material acquisition and active
key choice. A found legacy or unavailable claim is never absence. The public
request decoder and unkeyed Submit retain their current behavior.

### 6A. Private synthetic original custody and exact format

The private same-delivery classifier has one nil-by-default test-only barrier
immediately before claim establishment, used to make concurrent winning and
losing proposals deterministic in controlled synthetic fixtures. It carries
no production setting, effect permission or runtime caller.

The first scope is permanently synthetic_nonoperational_v1 (integer 1). The
admission-owned strict parser retains one typed, key-free original intent and
the same request delivered to the actual resolver. It rejects invalid raw
UTF-8, lone surrogate escapes, duplicate decoded object/map names, wrong-case
schema aliases, unknown members, null, trailing content and numeric overflow
before lossy JSON decoding. Private JSON depth is at most eight; raw request
and decoded intent are each at most 262,144 bytes. The raw 43-character
canonical base64url submit key is decoded transiently to 32 bytes and used
with the canonical synthetic caller URI to derive PB1 caller-scoped 32-byte
CallerRef and SubmitKeyRef. Neither raw key nor raw JSON is persisted.
The synthetic caller URI helper is syntax, not real peer authentication.

Payload is ASCII ESRSPAY1 (8 bytes) | format u16=1 | bodyLength u32 | one
fixed count-10 object. Its exact ordered IDs are: 1 identity (count-2:
CallerRef bytes32, SubmitKeyRef bytes32); 2 original intent (count-15);
3 original effective plan (count-14); 4 captured material (count-5);
5 PB1 assessment (count-4); 6 image (count-5); 7 placement (count-6);
8 provenance (count-6); 9 key/format (count-6); 10 scope u8=1.
Each field is ID:u16 | state:u8 | length:u32 | value, with exact ascending
IDs. State 0 means absent with zero length; state 1 means present; state 2
is invalid as a field state. Nested objects begin count:u16. Ordered sequences
begin count:u16 and repeat elementLength:u32 | element. Canonical maps begin
count:u16 and repeat keyLength:u16 | decoded UTF-8 key | valueLength:u32 |
decoded UTF-8 value, sorted by unsigned decoded-key bytes. Integers are
big-endian; durations are i64 nanoseconds. Unknown, duplicate, trailing or
length-mismatched data fails.

Original-intent IDs 1–15 respectively hold outer schema, reliable contract,
required invocation marker u8=1, optional invocation schema, artifact digest,
derivation digest, output ID, optional mode, optional timeout u32, optional
resources count-2 CPU/memory u32, optional argv sequence, optional env map,
optional mount sequence, optional annotations map and optional reserved
runtime-profile annotation value. Each original mount is count-3: source
count-1/artifact digest, normalized target and optional read-only bool.
Absent differs from present-empty, including maps/sequences and profile.
Mode is absent/empty/async only; sync is refused. The real resolver consumes
this same parsed delivery. PB1 binding encoding remains unchanged, and only
the private composer invokes its requested-versus-verified mount refusal.

Effective-plan IDs 1–7 are each count-2 nested objects: (1) request and
invocation schemas; (2) mode and timeout; (3) CPU and memory; (4) profile name
and image reference; (5) artifact and payload digests; (6) derivation digest
and output ID; (7) executable and ordered runtime arguments. ID8 is the
semantic-environment map; ID9 is ordered mounts, each count-5 with requested
artifact, verified artifact, signed payload digest, normalized target and
read-only bool. ID10 is network bool; ID11 authority count-14; ID12 support
digest; ID13 identity tmpfs u64; ID14 job envelope count-17. Authority
leaves, in order, are profile, Codex applicability, CLI path, credential
source, Vault secret path/field, Vault mode/address/auth mount/auth role/JWT
audience, zone-config digest and CA/TLS applicability. Job leaves, in order,
are job/group/count/task/driver/user/privileged/security-option sequence,
restart attempts/mode/interval/delay and reschedule attempts/unlimited/delay/
function/max-delay. Source-owned fixed policy and applicability checks still
govern hydration.

Captured material count-5 is exact payload bytes, support bytes, ordered
mount archives, optional Vault CA and optional TLS bytes. Each archive is
count-2 (compressed bytes, ordered parsed entries); each entry is count-4
(validated name, directory bool, full os.FileMode u32, contents). Directory
contents are state 0/nil; regular contents are state 1, including nonnil
empty. Entry names are not normalized again. Assessment count-4 is PlanBinding
(inner u16 length 1..256 plus raw bytes; outer TLV length 2+inner length),
resolved witness u16, inapplicable witness u16 and material identity count-5
(primary, support, ordered mount identities, CA, TLS). A material descriptor
is packed state:u8 | length:u64 | SHA-256:32 (41 bytes); absent/inapplicable
states have zero length/digest. Each mount identity is count-5 (requested,
verified, payload digests, compressed descriptor, entry sequence); each
entry identity is count-4 (name, directory, full mode, content descriptor).
PB1 remains the one semantic/digest authority.

Image count-5 stores selected reference, synthetic 32-byte content digest,
issuer, proof-kind u8=1 and topology requirement. Placement count-6 stores
original staging/results/SPIRE/datacenter strings and UID/GID u32; topology
must match original datacenter requirement. Provenance count-6 stores exact
synthetic marker, primary artifact/payload/support digests, ordered count-3
mount-source identities (IDs 1 requested, 2 verified, 3 payload), and
count-2 CA/TLS applicability. Key/format count-6 stores binding format
u16=1, binding key ID, envelope key ID, wrapper format u16=1, payload format
u16=1 and algorithm u16=1. IDs use 1..64 case-sensitive ASCII bytes, first
alphanumeric and remaining alphanumeric/period/underscore/hyphen.

Sealed file is a fixed 14-field header plus combined AEAD. Header is ASCII
ESRSENV1 | wrapper u16=1 | total headerLength u32 | count u16=14, then
ordered TLVs: algorithm, payload format, scope, binding format (u16/u16/u8/
u16), two key IDs, independent object ID bytes32, CallerRef bytes32,
SubmitKeyRef bytes32, raw PlanBinding bytes, intent commitment bytes32,
context commitment bytes32, plaintext length u32, combined length u32.
AAD is ASCII ESRSAAD1 followed by the complete raw header. AES-256-GCM
combined output is Go's random 12-byte nonce | ciphertext | 16-byte tag;
length is plaintext+28. Header/AAD are frozen before Seal. Intent HMAC domain
ESRSINT1 covers exact payload field 2 including TLV header; context HMAC
domain ESRSCTX1 covers exact payload fields 6–8. Neither is copied into
plaintext. Witness masks are in payload and claim row, not header. Private key
fingerprints are in registry/claim row, not payload/header. Complete-file
SHA-256 and actual length are computed only after Seal/publication and stored
in the immutable claim descriptor; no self-digest enters plaintext/AAD.
Commitment comparisons use a constant-time primitive.

Plaintext is at most 1 MiB, sealed file 2 MiB, header 4 KiB, captured
component 256 KiB, individual data string 64 KiB. Binary reader limits are
object depth five, combined container depth eight, 32,768 TLV nodes and
8,192 sequence elements. It checks lengths/arithmetic before allocation and
counts actually retained decoded leaves within the aggregate decoded budget,
without repeatedly charging enclosing TLV lengths. Source admission's
narrower field/count limits also apply. No unsupported version or implicit
default is accepted. Image/placement/provenance are synthetic typed facts,
not provider image pin or qualified host proof.

Exact new admission files are reliable_submit_replay_intent.go,
reliable_submit_replay_format.go, reliable_submit_replay_hydration.go and
reliable_submit_replay_private.go. The latter is the sole direct private
resolver and PB1 composer call site. Its one reload callback invokes
verifyPrivateReplayOriginal before returning any redacted verified-original
outcome. Only the finite internal-package facade in the persistence ADR
crosses the import edge; no public DTO/raw getter exists.

Original intent, delivery, key bundle/permit, authenticated metadata/payload,
hydrated plan/material, descriptor and verified-original aggregates use fixed
redacted formatting, no general JSON/text marshal, public DTO, raw getter,
payload export or value-bearing log. Bounded private binary custody encoding
is the selected exception. Resolver/Vault/artifact/SQL/filesystem/crypto errors
map at the new private boundary to finite fixed classes, not value-bearing
causes. No secure erasure, hostile-root, arbitrary same-UID isolation,
universal side-channel or secret-freedom claim is made.

Private envelope publication and fsync precede claim establishment; their
transaction boundaries remain separate, so an unclaimed object is inert.
Current authorization, genuine image/host proof, one-run assignment, durable
effect intent before staging, dispatch-attempt before provider registration
and uncertainty reconciliation remain future operational gates. No v3 claim
can be promoted to a run/effect/receipt. Reliable submit remains unavailable.

### 6B. Proposed private original replay and durable claim progress

This section governs the fixture-only source candidate. Section 6A describes
current codec 3, whose original remains permanently non-progressing. The
[persistence ADR section 15B](reliable_submit_persistence_and_concurrency.md#15b-proposed-private-original-replay-and-durable-claim-progress)
owns the row, reader, transition and migration rules. The sole new non-test
cross-package consumer is `es/admission/reliable_submit_replay_private.go`.
Its unexported fixture entry points require an injected synthetic caller,
image, key catalog and local fixture dependencies. The producer uses the same
strict parsed delivery for incoming intent and existing resolver/PB1 assessment
on a genuine miss. Dependencies may read fixture material only. A hit requires
no current resolver, defaults, material, image or active-key selection. An
occupied incompatible row refuses before resolution.

#### Dispatch and cryptographic domains

Dispatch on the complete tuple. SQL schema and per-row codec are separate
version axes. Schema 4 privately accepts both custody tuples.

| Row | Admitting schema | Codec / semantic scope / encoded scope | Intent / PB1 / wrapper / payload / algorithm | Payload / header / AAD | Intent / context / permit domains |
| --- | --- | --- | --- | --- | --- |
| Legacy | Historical per ADR, carried through 4 | 1 or 2 / none / NULL | All replay format columns NULL, legacy generic binding | None | Existing durable operation digest only |
| Immutable original | 3 or 4 | 3 / `synthetic_nonoperational_v1` / 1 | 1 / 1 / 1 / 1 / 1 | `ESRSPAY1` / `ESRSENV1` / `ESRSAAD1` | `ESRSINT1` / `ESRSCTX1` / `ESRSFRZ1` |
| Fixture progress | 4 | 4 / `synthetic_progress_nonoperational_v1` / 2 | 1 / 1 / 2 / 2 / 1 | `ESRSPAY2` / `ESRSENV2` / `ESRSAAD2` | `ESRSINT2` / `ESRSCTX2` / `ESRSFRZ2` |
| All other tuples or mixed components | Refuse | Refuse | Refuse | Refuse | No alternate decoder or key search |

Algorithm 1 is AES-256-GCM with random 12-byte nonce and 16-byte tag. PB1 v1,
key-purpose/fingerprint namespace `ESRSKEY1`, safe references and strict
original-intent grammar stay byte-identical. Binding and envelope keys
remain separate purposes. Cryptographic labels here are literal ASCII with
no terminator. Integers are big endian. Each TLV is `u16(ID) || u8(state) ||
u32(value length) || value`. Absent TLVs have state 0 and zero-length value.
Present TLVs have state 1. Reject other states, repeated, reordered, missing
required, unknown and trailing fields. Every nested ID, count, presence,
width, sequence/map order, normalization and semantic restriction in section
6A is normative with exactly the substitutions below.

| ESRSPAY2 top-level ID | Present value |
| --- | --- |
| 1 | Identity count 2, caller then submit-key reference, each 32 bytes |
| 2 | Original intent count 15 per 6A, including absent versus present-empty values, collections and mount flags |
| 3 | Original effective plan count 14 per 6A, including authority count 14 and job count 17 |
| 4 | Captured material count 5 per 6A, including ordered archives and entries |
| 5 | PB1 assessment count 4 per 6A, including binding length and two u16 witness masks, material identities and descriptors |
| 6 | Image count 5 per 6A, proof-kind 1 remains synthetic |
| 7 | Placement count 6 per 6A, with matching synthetic topology |
| 8 | Provenance count 6 per 6A, except leaf 1 is exactly `synthetic_progress_nonoperational_v1` (36 ASCII bytes). Codec 3 retains `synthetic_signed_dependencies_v1`. |
| 9 | Key/format count 6 per 6A. IDs 1 through 6 are u16=1, binding key ID, envelope key ID, u16=2, u16=2, u16=1. |
| 10 | Scope u8=2 |

Payload framing is `ESRSPAY2 || u16(2) || u32(body length) || body`.
Body is `u16(10)` followed by those TLVs. Header framing is
`ESRSENV2 || u16(2) || u32(complete header length) || u16(14)` and the
fourteen present TLVs below.

| ESRSENV2 header ID | Exact value |
| --- | --- |
| 1–4 | Algorithm u16=1, payload u16=2, scope u8=2, PB1 binding format u16=1 |
| 5–6 | Binding and envelope key IDs, separately 1–64 case-sensitive ASCII bytes, first alphanumeric, rest alphanumeric or period, underscore or hyphen |
| 7–9 | Random object ID, caller and submit-key references, each 32 bytes |
| 10 | Raw PB1 plan binding, 1–256 bytes, no inner length prefix |
| 11–12 | Intent and context commitments, each exactly 32 bytes |
| 13–14 | Plaintext and combined lengths, each u32, combined equals plaintext plus 28 |

Header length is 289 plus both key-ID lengths and raw PB1 binding length
(292–673). The file is that header, then nonce, ciphertext and tag. AAD is
`ESRSAAD2 || complete raw header`. Intent commitment is HMAC-SHA-256 under
the binding key over `ESRSINT2 || complete TLV 2`. Context commitment is
the same algorithm/key over `ESRSCTX2 || complete TLV 6 || complete TLV 7
|| complete TLV 8`. Permit binding is `SHA256(ESRSFRZ2 || bindingFP32 ||
envelopeFP32 || complete header || plaintext)`. Complete-file SHA-256 is
unprefixed and calculated after Seal. Share the nonce budget by actual
envelope key across scopes. Use existing constant-time comparisons for
commitments, fingerprints, digests and protected references.

Limits are 262,144 bytes each for raw JSON and decoded intent, eight JSON
levels, 1,048,576 plaintext bytes and aggregate retained binary leaf bytes
each, 2,097,152 sealed bytes, 4,096 header bytes, 262,144 bytes per captured
component, 65,536 bytes per data string, object depth 5, container depth 8,
32,768 TLV nodes, 8,192 sequence elements and the narrower 6A source domain
limits. Check lengths, arithmetic and allocation/count budgets before
allocation or descent. Reject mixed headers/payloads, substituted objects,
unknown fields/formats, wrong lengths/digests/keys/scopes, wrong PB1 or
provenance and noncanonical intent. Row, header and typed original must
agree. Creation identity is verified through the durable record. Revision,
phase, operation, assignment, facts and receipt remain SQLite progress.
None enters the original AEAD or requires resealing. AEAD authenticates
only the immutable original.

The explicit fixture opener uses the existing owner-only root,
`synthetic-replay-v1.marker` with exact `synthetic_nonoperational_v1\n`
bytes, and `objects/v1/` plus 64 lowercase hex digits matching the header's
32-byte object ID. The marker identifies the shared fixture root. The row,
header and payload select scope. Preserve the existing codec-3 root/caller
semantics and both selectors' no-follow, descriptor identity, mode, exclusive
create, fsync and no-adoption rules. The old opener cannot expose codec 4.
A marker, synthetic caller, fixture key or image never qualifies startup.
Both fixture publishers use the shared `allocateReplayObject`
boundary in persistence ADR §15B.5A. Scope 1 participates in serialized
count/exclusive-create. Codec-3 format, immutable rows, key/grant semantics,
and the function-owned `loadClaimFresh` callers and lifetime are preserved.
Confirmed allocation release precedes permit consumption and Seal. A failed
handoff preserves any created inert name and grants no usable publication.

#### Finite internal fixture interface

These symbols are exported only across Go's admission internal import
boundary. The private admission composer and named fixture tests are their
sole consumers. Opaque values are zero/foreign-issuer invalid, fixed-redacted
and nonserializable. Semantic aggregates also redact.

| Method and inputs | Output and required authority check |
| --- | --- |
| `OpenPrivateReplayProgressCustody(ctx, root)` | Opaque `PrivateReplayProgressCustody` using existing fixture root, file and schema checks. Closed or canceled custody refuses. |
| `LookupProgressOriginal(ctx, claimID)` | Opaque `ProgressLookup` of validated absent, compatible locator or occupied/refused. Issuer-bound locator permits only exact original key IDs to the injected catalog. Identity and strict parsed delivery precede lookup. No phase/ref/dependency disclosure. |
| `FreezeProgressOriginal(ctx, miss, initialPhase, boundPlan, keys, ProgressOriginalInput)` | Opaque `ProgressFrozen` after checking same issuer/claim, absent lookup, initial fixture phase 1 or 2, bounded typed fields, full witness and scope. The admission input comes from the resolver/assessment on the same parsed fixture delivery. |
| `ReserveProgressSealUse(ctx, frozen)` | Opaque `ProgressSealPermit` only after known durable reservation COMMIT for the exact active purpose/fingerprint pair and frozen digest. Uncertain COMMIT grants no permit. |
| `PublishProgressOriginal(ctx, frozen, permit)` | Opaque `ProgressPublication` for one exclusive, identity-checked and synced file. Verify issuer, frozen digest, object association and active eligibility, consume permit before Seal and retain any orphan. No refund. |
| `EstablishProgress(ctx, frozen, publication)` | Opaque `ProgressAttempt` and created, occupied or write-unknown disposition. Validate full issued binding, exact active registry pair in write transaction and existing caller/key occupation. Retain the expected full record and generated rowid inside the owning establishment invocation for its bounded recovery. |
| `WithAuthenticatedProgressOriginal(ctx, locator, retainedKeys, incomingIntent, purpose, verify, use)` | Repaired pooled read matches the locator's full immutable identity. Check both retained keys in one snapshot, then securely open exact file, verify descriptor/AEAD/commitments and decode fixed `ProgressOriginalView` (identity, typed intent with presence, plan, material, PB1 assessment, image, placement, provenance, formats). The sole admission verifier validates semantic domains, recanonicalizes and recomputes PB1. Custody compares its returned `ProgressOriginalMatch` (claim, recomputed bound plan/witness and reconstructed canonical typed intent) with authenticated data and compares incoming canonical intent in constant time. Mismatch refuses before `use`. Match grants a synchronous opaque `ProgressAccess` to the sole admission continuation. |
| `ReadFixtureProgress(ctx, access)` | `FixtureProgress` with revision, fixture phase and phase-appropriate fixture run/receipt. Check live issuer-bound borrow, keys and context, reread through repaired pooled reader, match complete immutable identity. Current projection leaves any earlier write disposition unchanged. |
| `ApplyFixtureProgress(ctx, access, expectedRevision, fixtureMutation, FixtureProgressCommand)` | Finite ADR outcome and eligible fixture projection. Same live access, key and identity checks and one existing durable-service conditional transition and CAS. The command union and historical reconciliation are defined in ADR §15B.3. A separately supplied command uses a new live one-use borrow and its exact revision and mutation input. The service rechecks the current-row fixture predicate for a new same-run marker in CAS and separately validates positive terminal fixture evidence. Kind 1 records a bounded fixture no-marker observation and supplies no operational permission. |
| `NewFixtureAcceptedEvidence(claim, run, marker, fact, receipt)` | Redacted bounded synthetic assertion of Accepted with exact receipt association. Invalid input refuses. |
| `NewFixtureNotAcceptedEvidence(claim, run, marker, fact)` | Redacted bounded synthetic assertion of NotAccepted with no receipt. Invalid input refuses. |
| `Close()` | Closes only the issuing custody. Outstanding borrows become invalid. |

The closed authentication purpose is current replay or establishment
confirmation with the issued `ProgressAttempt` within the owning
establishment invocation. The attempt expires when that invocation returns
or is canceled and supplies no restart input. Confirmation checks the
attempt issuer/claim before reading and compares the opaque expected full
initial record to the authenticated row. It returns only the comparison's
finite disposition, invoking `use` for progress only when the ADR permits
disclosure. Known created, definite occupied and write-unknown cases retain
their distinct dispositions. The known losing establishment still reports
Occupied if its subsequent winner lookup, key selection or authentication
cannot disclose progress. Proved changed incoming intent still reports Conflict.
Ordinary unauthenticated lookups do not gain this disposition. An uncertain attempt never discloses a
different winner. A known successful insert's committed snapshot is
eligible only after authenticating the same immutable original.

Each borrow allows one progress read or mutation, including its bounded
recovery. Its lifetime ends on return or cancellation. Capabilities never
authorize another row, scope or issuer. The boundary has no full plaintext
buffer, raw store, full-record getter or verified boolean. The typed view
carries only bounded admission input. The single invocation cannot export a
plaintext buffer, extend its lifetime or turn fixture evidence into a
provider or staging capability. Recheck exact active or retired
original keys on operation entry and recheck them in the write transaction
before CAS. Revoked, missing, changed fingerprint and wrong-purpose keys
refuse. Confirmation checks the original paired keys under the issuer lock
before projecting the committed snapshot. It checks the borrow after taking
the lock and again after qualification. Failure preserves known COMMIT or
unresolved unknown and withholds the projection. There is no instantaneous
cross-process revocation guarantee.

K1 limits an invocation's recovery to authenticating an exact full expected
record to confirm its own write. Failed recovery preserves unknown, withholds
its projection and starts no second write, new mutation or rebase. Failed
post-commit authentication preserves known commit and withholds projection.
A later explicit command or authenticated current-state read uses fresh
authentication and its own live borrow. It cannot change the earlier
disposition. A fixture marker is a current-state transition only. No
marker, read, exact latest replay or fixture outcome supplies operational
permission. The full operational Validated No-Dispatch Evidence requirement
in the persistence ADR §8 remains unchanged. Its cross-restart evidence
and authority are outside this fixture operating model.

Malformed delivery refuses before lookup. Incompatible, unsupported,
missing-after-occupancy, corrupted, wrong-key and unavailable outcomes are
fixed and disclose no stored state, bytes or causes. Changed intent, stale
and current fixture results follow the ADR. Write uncertainty has a separate
fixed result. Fixture references cannot convert to operational RunRefs or
public receipts. Public structural reliable-request refusal and unkeyed
Submit stay in force.

### 6C. Selected operational handoff and receipt-only recovery

PR #12's current-admission repair makes operational originals
`operational_local_v2` with exact retained signed evidence from one ordinary
resolution; `operational_local_v1` is removed and refused. Only an unmarked
claim presented by a process whose admission token equals the enabled durable
admission row, and whose trust was confirmed with EGS inside the deadline,
can progress toward its first effect. Replacing trust, verifier or policy
advances the admission generation in the same epoch: a retained claim is
judged again by the new content, and one it denies is refused as denied until
a later generation allows it. For every original, a committed accepted receipt is verified from the authenticated historical original and
exact current caller/eligible ACTIVE or RETIRED original key pair, independently
of current trust, verifier, policy, admission generation, withdrawal, resolver,
staging and provider. A marked
claim without a receipt may reconcile only verified positive registration and
record its immutable receipt; it cannot create another sender or POST. Wrong,
missing, revoked or mixed keys and unauthorized callers remain nondisclosing
refusals. A refused unmarked first-effect cut withholds run/receipt and
reports denied or unavailable while its
earlier acknowledged or uncertain write disposition remains accurate. A retry
that attempts no cut, such as recovery or a stamped-but-unmarked retry,
returns the stored run to its authenticated original caller and sends no
trust request.

The [Operational Handoff](reliable_submit_operational_handoff.md) defines the private candidate codec-5 original, exact
caller scoping, private result projections and two distinct authorization
paths. Current exact caller authorization precedes lookup. First effects
require current admission and an exact ACTIVE key pair. Accepted replay
verifies an equivalent qualified retained original and immutable receipt with
the exact ACTIVE or RETIRED pair. The receipt-only path consumes retained facts
and current caller authorization. Mutable execution admission, current
resolution, staging and provider access are excluded from that path.
§6B continues to govern the completed private fixture.
In the candidate, receipt recovery recomputes the retained marker projection
and receipt MAC. Concurrent qualified receipt observations return the same
verified winning receipt. This records provider registration only.
The private projection reflects the current qualified cut. A denied or
unverified pre-stage cut withholds the assigned run. A losing establishment
preserves conflict or the qualified current winner as specified in the
operational owner table. Write disposition survives a cleanup denial.
Claim-scoped public lifecycle authorization remains a later qualification.

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

The persistence and concurrency ADR now selects local embedded SQLite as the
storage family for the first implementation path, preserves the current
`CGO_ENABLED=0` build posture, selects `modernc.org/sqlite v1.54.0` with
`modernc.org/libc v1.74.1`, selects private same-package persistence hydration
in `es/admission/internal/reliablesubmit`, and freezes revision/CAS plus
provider-effect-intent ordering. It also selects the target latest-operation
replay contract and requires a SQLite v2 logical descriptor that pairs the
latest mutation reference with closed operation kind and versioned input-binding
digest. It does not select the state-path config key, TTL, public request or
receipt vocabulary, Nomad reconciliation mechanism, or runtime integration.

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

The target contract defines semantic submission outcome classes without
selecting exact public JSON field names, HTTP status codes, route shapes, or
error strings. The unavailable contract-adapter foundation adds an
admission-local, transport-neutral ES outcome projection for these classes. It
encodes outcome kind, phase-specific same-caller `RunRef` disclosure,
`ReceiptRef` presence, whether exact retry of the same request is safe, whether
a new key is required, and whether an accepted submission reference is
available. It does not encode HTTP status mapping, public error strings, CP or
Coordinator progression, provider IDs, or raw private store state.

- accepted: one execution was accepted; recover the stable `run_id` and bounded receipt.
- exact replay: return the same known outcome without another execution-producing effect.
- conflict: the same caller/key was used for a non-equivalent request; perform no new effect.
- pending: the keyed submission is still being processed or reconciled; perform no duplicate effect.
- provably not accepted: ES has positive evidence that no execution-producing provider effect was accepted.
- ambiguous: ES cannot yet prove accepted or not accepted; caller must not automatically issue a new semantic execution.
- expired or unavailable correlation: the prior correlation can no longer be recovered; this is not proof that no execution existed and does not silently permit reuse of the old semantic command.
- unauthorized: deny without disclosing whether the correlation exists.

Accepted and accepted exact replay require an accepted submission reference and
receipt reference. Pending before assignment and ambiguous before assignment
forbid `RunRef` disclosure. Pending after assignment, ambiguous after
assignment, and accepted outcomes require the same assigned `RunRef` for the
same authorized caller.
Provably not accepted after assignment retains the assigned `RunRef`
internally, but same-caller public disclosure remains
`open_for_later_transport_contract`; the private foundation records no receipt,
no accepted-reference availability, and no public-transport decision for that
outcome. Conflict and unauthorized outcomes disclose no existing claim run or
receipt. Exact public vocabulary and HTTP/public outcome mapping remain open.

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

The future declaration adds one explicitly named and versioned reliable-submit
producer sub-contract under the governed-execution declaration. The
sub-contract name is `reliable_submit`. Its reliable contract identifier is
`execution-substrate.reliable-submit/v1`, and its reliable request schema is
`execution-substrate.reliable-submit-request/v1`. That additive sub-contract is
narrow: it semantically declares only the reliable-submit contract
family/version supported, whether reliable submit is enabled for the
installation, a bounded safe unavailable or disabled reason, request and
response schema identifiers, the minimum safe request-contract discriminator
required by a reliable client, supported recovery modes, and non-authority
labels. It is not a generic `capabilities` map, feature registry, plugin
registry, or cross-service probing framework. The later declaration should use
`contract`, `enabled`, `disabled_reason` when disabled, request and response
schema identifiers, required discriminator, supported recovery modes, and
non-authority labels. It must not freeze a redundant enabled/status/reason
triple, and transient store health is not producer-contract truth.

A future reliable client must use two independent fail-closed gates:

1. authenticate and read the producer declaration, then require the exact reliable-submit sub-contract and enabled status;
2. send a structurally distinct reliable-submit request variant.

The producer declaration alone is not execution authorization, admission, run existence, lifecycle truth, submit readiness, or proof that a specific request will be accepted. The request discriminator alone does not replace producer compatibility negotiation.

The target reliable request uses the existing `POST /v1/executions:submit` route. This tranche does not select a new route. A separate route remains a possible later fallback only if future concrete security or compatibility evidence invalidates the same-route design. Recovery-by-key or query-route shape remains open.

The current unkeyed compatibility variant remains the current
`PrepareRequest`-compatible request body. The reliable variant uses a
submit-specific request family and must not remain merely an optional semantic
interpretation of `PrepareRequest`.

The reliable request schema identifier is
`execution-substrate.reliable-submit-request/v1`. The mandatory top-level
structural discriminator is `reliable_submit`. The nested reliable object
requires `contract = "execution-substrate.reliable-submit/v1"` and
`submit_key`. The private admission-local request shape contains
`schema_version`, `reliable_submit`, `invocation`, optional `mode`, optional
`timeout_seconds`, and optional `resources`; it reuses lower-level
`ArtifactInvocation`, `ExecutionMode`, and `ExecutionResources` values without
modifying `PrepareRequest`.

The reliable-specific validation owns only the exact reliable request schema,
required discriminator and contract, canonical submit-key syntax, reliable v1
async-only rule, non-negative timeout, resources-present completeness, and
rejection of malformed mixed reliable/legacy semantics. Omitted `mode` resolves
to `async`; explicit `async` is allowed; `sync` is rejected for reliable v1.
Omitted resources mean ES later resolves current defaults. If resources are
present, both CPU and memory must be positive, and an empty resources object is
invalid. Invocation must still satisfy current `PrepareRequest` and admission
semantics when later runtime wiring calls the existing ES admission path. The
foundation must not duplicate artifact, derivation, policy, runtime-profile,
resource/admission, manifest, or trust validation.

Because current body decoding is strict, a current server rejects a future
reliable body carrying `reliable_submit` before calling current `Submit`
behavior. A changed value in the existing `schema_version` field alone is not
the selected discriminator.

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

Current legacy `Service.Submit` already consumes the private source-grounded
resolved-execution-plan extraction foundation. That implemented foundation is
the freeze-point input to the current typed plan, material, run, authority, and
Nomad projections; it is not reliable-submit runtime wiring and does not by
itself supply canonical encoding, a final `PlanBinding`, a completeness witness,
durable custody, reliable dispatch, ambiguity reconciliation, public reliable-
submit DTOs, or a Coordinator adapter.

B1's finite package-local direct-call closure and exact producer, freeze,
validation, payload-projection, metadata, and source-distinct literal-golden
inventories are bounded assurance, not whole-program noninterference or a
general alias, taint, SSA, or semantic analyzer. Tranche B2 now completes the
bounded privacy and independent-assurance refinement: three governed retention
logs contain only `es result retention failed run_id=%s` and the validated run
ID; selected structured Nomad control JSON is bounded to 256 KiB and one
compatible document; job summaries remain explicitly unbounded but
one-document because caller-environment aggregates remain unbounded; and
successful authenticated public Logs remain unbounded opaque workload output.
Non-success Nomad bodies are not public or ordinary-log diagnostics. B2 does
not select a universal provider-response or workload-output limit.
`preparedAdmission` is fixed-redacted under ordinary formatting and remains
`{}` under ordinary JSON; that bounded defense does not cover reflection,
`unsafe`, malicious same-package code, arbitrary serialization, or secure
erasure. Its second source-distinct control-plane-profile golden is ES
profile-coverage evidence, not current CP request bytes or CP authority. Its
finite guard is source-bounded and not a general analyzer. Reliable
keyed-submit runtime remains unwired, and native Linux runtime validation of the
combined candidate remains pending.

This target contract makes these explicit non-claims:

- no reliable submit runtime integration implemented;
- no runtime behavior implemented;
- no producer declaration field implemented;
- no public request DTO implemented;
- no public/runtime reliable-submit handler or route decoder is wired; the private admission-local `parseValidatedReliableSubmitRequest` and `decodeStrictReliableSubmitJSON` helpers remain unwired;
- no route implementation;
- private canonical effective-plan encoding, `PlanBinding` construction from
  admitted facts, and a complete fourteen-category witness exist only in the
  unwired package-private producer and confer no effect permission;
- no public or operational durable replay-envelope custody; the private
  synthetic codec-3 custody in section 6A has no effect permission;
- no mutation-history store or history-wide replay;
- no public reliable-submit runtime wiring;
- no public replay DTO or recovery route;
- no public or runtime persistence integration;
- no global state-path configuration or service-startup database construction;
- no public or runtime schema, migration, backup, restore, or storage migration
  tooling exposed to operators;
- no exact HTTP code selected;
- no error string selected;
- no public persistent receipt-store implementation;
- no public reliable response field names;
- no final `run_id` generation strategy;
- no deterministic `run_id` decision;
- no recovery query selected;
- no supplemental header selected;
- no reliable prepare selected;
- no Nomad registration retry decision;
- no Nomad behavior implemented;
- no broad lifecycle store;
- no scheduler;
- no durable exactly-once assignment from the pure model alone;
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

Reliable keyed-submit runtime implementation requires these local gates:

- preserved public opt-in and versioning docs-contract coverage;
- pure internal reliable-submit model tests;
- reliable request foundation and producer sub-contract target tests;
- `reliable-submit-durable-same-operation-replay-repair`;
- independent audit and exact-byte commit of the documentation/docs-contract
  ADR tranche that selects latest-operation replay;
- source-grounded resolved-plan extraction (satisfied by the private current-Submit foundation);
- narrow persistence and concurrency ADR decision;
- ES-to-Nomad uncertain-outcome reconciliation decision;
- retention and expiry decision;
- security and privacy review;
- request, receipt, and error model tests;
- compatibility tests;
- implementation provenance and independent audit.

## 17. Open Seams

The following seams remain open:

- exact public producer response schema identifier and final declaration
  rollout behavior;
- recovery field names;
- replay-only versus query route;
- exact public outcome and error vocabulary;
- exact reliable-submit state-path config key;
- TTL, tombstone, and garbage collection;
- runtime consumption of the private v1 binding and witness, with original-key
  availability and unknown-version refusal;
- full original explicit-intent/presence capture and key-only exact-retry
  lookup, separately from effective binding equality;
- durable material custody and host-context replay treatment;
- plan snapshot versus immutable references;
- Nomad reconciliation mechanism;
- deterministic versus random assigned `run_id`;
- bootstrap exception;
- caller namespace refinement beyond authenticated identity;
- later Coordinator consumer mapping.
