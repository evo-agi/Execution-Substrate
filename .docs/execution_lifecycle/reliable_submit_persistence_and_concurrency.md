# Reliable Submit Persistence And Concurrency ADR

## 1. Status And Purpose

Status: accepted architecture decision and first private source implementation
for the ES-owned reliable-submit persistence and concurrency path.

This tranche adds private admission-local durable claim source and tests only:
one backend-neutral claim-store port, one backend-neutral durable semantic
service, one private durable-record codec, one SQLite implementation using
`modernc.org/sqlite v1.54.0`, and one shared backend conformance suite. It
implements no configuration source, no request or response DTO, no HTTP handler,
no staging behavior, no Nomad behavior, no producer-contract field, no runtime
startup wiring, and no public reliable-submit availability. Reliable submit
remains unimplemented end to end.

This ADR freezes the durable-state boundary and ordering rules that the later
source implementation must consume from the committed pure model in
`es/admission/internal/reliablesubmit`.

The documentation/docs-contract tranche for
`reliable-submit-durable-same-operation-replay-repair` now freezes the target
latest-operation replay contract in section 9A. That target requires a later
record/codec and SQLite v2 logical schema migration. It is not implemented by
the current private source.

A later unavailable contract-adapter foundation, implemented in private
admission-local package `admission` helpers, now selects the reliable request
schema `execution-substrate.reliable-submit-request/v1`, reliable contract
`execution-substrate.reliable-submit/v1`, discriminator `reliable_submit`,
submit-key syntax, caller/key derivation, composite `ClaimID` construction
through the committed pure-model constructor, and ES-neutral outcome projection.
It does not implement source-grounded resolved effective-plan extraction,
canonical effective-plan encoding, `PlanBinding` construction from admitted
facts, complete effective-plan witness construction, durable replay-envelope
custody, or runtime orchestration. Those helpers remain runtime-unwired and do
not alter this ADR's durable schema, migrations, store port, or SQLite startup
status.

## 2. Current Repository And Deployment Reality

The current reliable-submit source is admission-local and private under
`es/admission/internal/reliablesubmit`. The committed pure model in `model.go`
remains unwired, transport-neutral, persistence-neutral, effect-free, and unable
to enforce one winning durable claim or cross-process compare-and-swap by
itself. The persistence source in this tranche consumes that model through
private durable hydration and remains unwired from submit, HTTP, Nomad, and
runtime startup.

The current module now carries the selected SQLite dependency for the private
store source: `modernc.org/sqlite v1.54.0`, with the exact expected
`modernc.org/libc v1.74.1` transitive coupling. No PostgreSQL dependency is
introduced.

The current durable record and SQLite schema version 1 store the latest
`lastMutation` reference only. They do not store closed operation kind,
operation-input binding digest, or mutation history. The latest-operation replay
descriptor selected in section 9A is target design for a later source tranche.

The current Remote Alpha ES binary deployment path builds ES through
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64` for both the Python and shell payload
builders in `scripts/internal/remote_alpha_deploy_es_binaries.sh`. This build
posture is part of the current deployment reality and must be preserved by the
first reliable-submit store implementation path.

Current `ExecutionConfig` contains execution writable-state roots for staging
and retained results only: `execution.staging_root_dir` and
`execution.results_root_dir`, plus runtime-image and runtime-support fields.
Current service startup creates only the staging and results roots when submit
is configured.

The accepted long-lived service posture is `User=es`, `Group=es`, `UMask=0027`.
Stable ES-owned state is expected to be owned by `es:es`, without supplemental
groups or ACL-dependent shortcuts.

Existing ARS file/index patterns use in-process mutexes, temporary-file writes,
and atomic rename for a bounded artifact index. They are useful local file
publication evidence, but they are not a cross-process durable CAS substrate
for one authoritative reliable-submit claim.

## 3. Authority Boundary

The future reliable-submit store owns only narrow ES submit-correlation
authority:

- authenticated caller namespace binding;
- safe private submit-key representation;
- private effective-plan binding and completeness evidence;
- reliable-submit claim phase;
- immutable ES-assigned `RunRef` after assignment;
- bounded `ReceiptRef` after accepted submission;
- monotonic revision and mutation provenance needed for CAS;
- retention, expiry, tombstone, ambiguity, and corruption posture.

The store must not become:

- allocation history;
- runtime status timeline;
- log index;
- result-content store;
- cancellation-completion truth;
- runtime retry or reschedule policy;
- Coordinator work, attempt, dispatch, acceptance, or semantic state;
- Git, CI, validation, or publication truth;
- adapter, Bridge, or connector authority;
- Nomad lifecycle mirror.

Nomad remains submitted-execution lifecycle authority. Coordinator remains
durable coding-work state authority for its own domain. Git, CI, validators,
adapters, and Bridge retain only their own documented authority and evidence
roles. Provider metadata, Nomad allocation IDs, EvalID, trace IDs, request IDs,
adapter sessions, and Bridge records are not reliable-submit correlation
authority.

## 4. Storage-Family Decision

The selected embedded storage family for the first reliable-submit persistence
path is local SQLite.

SQLite is selected because reliable submit needs durable uniqueness,
immutable run assignment, phase constraints, revision CAS, tombstones, bounded
replay, migration discipline, and crash recovery in a local host deployment.
Those requirements map naturally to relational constraints and transactions
without requiring an external database service.

SQLite is local host storage only for this first path. Multi-host shared
database, HA, replication, and external database service operation are explicit
non-claims.

The selected Go SQLite driver is `modernc.org/sqlite v1.54.0`. It must remain
CGO-free under the current build contract, with `modernc.org/libc v1.74.1` as
the expected coupled transitive module. A CGO-only SQLite driver is excluded
while the supported ES build path preserves `CGO_ENABLED=0`.

This tranche selects WAL, `synchronous=FULL`, `foreign_keys=ON`,
`trusted_schema=OFF`, bounded `busy_timeout`, immediate write-lock acquisition,
user-versioned forward-only embedded migrations, and fail-closed corruption and
unsupported-version handling. Online backup/restore, managed backup, destructive
restore, host replacement, and operator repair remain later operations
contracts.

The current SQLite implementation claims a zero-version database only through a
narrow empty-bootstrap gate: before setting the ES application ID or creating any
reliable-submit table, trigger, or index, it inspects persistent `sqlite_schema`
and requires no pre-existing non-`sqlite_%` schema object. A non-empty database
with `application_id = 0` and `user_version = 0` is rejected as unsupported and is
not semantically claimed by this store. This gate does not claim to identify
every possible historical byte-level provenance of an otherwise empty SQLite
file.

Rejected first-path alternatives:

- bbolt or another embedded key/value store: not selected for the first path
  because the relational claim uniqueness, phase constraints, tombstones, and
  migration grammar would become store-specific application logic.
- handwritten JSON, append-only files, file directories, locks, and atomic
  replacement: not selected as the authoritative claim store because they would
  make ES implement a custom database for cross-process CAS, partial-write
  recovery, lock handling, compaction, and corruption classification.
- existing ES or ARS file/index patterns: not sufficient durable claim
  authority because they do not prove cross-process reliable-submit CAS.
- provider or Nomad metadata: rejected as correlation authority because it does
  not solve caller-to-ES ambiguity and is explicitly not caller recovery
  authority.
- external database service: rejected for the first path because it widens
  deployment, backup, ownership, and service dependencies beyond the narrow
  local ES store decision.

## 5. Package And Hydration Boundary

The concrete store, backend-neutral port, durable semantic service, and private
durable-record codec belong in the existing admission-local package
`es/admission/internal/reliablesubmit`, in separate files from `model.go`.
They are unexported implementation details, not a public storage API, generic
repository framework, ORM abstraction, database platform, generic SQL layer, or
lowest-common-denominator CRUD interface.

The pure model core remains I/O-free and database-free. `model.go` must not
import SQLite, `database/sql`, filesystem packages, time, locks, JSON codecs,
or storage helpers merely to support persistence.

Persistence hydration may use a narrow private same-package codec to access and
validate private opaque refs and phase state. No raw caller, submit-key,
plan-binding, run, or receipt accessor is exported merely for storage. No
`Bytes`, `Raw`, `MarshalJSON`, SQL `Value`, SQL `Scan`, DTO, or database helper
API is added to the public model surface for persistence.

The store must hydrate through the committed pure model invariants. It must not
define a second persistence phase enum or independent phase algebra that can
contradict the model's claim phases, replay views, or non-disclosing decisions.

The private port expresses reliable-submit durable semantics only:
establish-or-load by `ClaimID`, load by `ClaimID`, and compare-and-swap by
expected revision. It must not expose `*sql.DB`, `*sql.Tx`, pgx types, SQL
strings, SQLite result codes, SQLSTATE, database paths, DSNs, raw opaque
reference bytes outside the private codec, public DTOs, Coordinator identities,
or Bridge identities. Backup is not part of the common port.

### Pure-Model Phase Versus Provider-Effect Facts

The committed `reliablesubmit` phase remains the authoritative claim-shape
algebra.

Provider-effect intent is an orthogonal durable fact over an existing assigned
claim phase. It is not a pure-model phase. Staging or materialization evidence
is an orthogonal local-effect fact. Provider-dispatch-attempt evidence is an
orthogonal durable fact. Provider-response and reconciliation evidence are
orthogonal facts.

Those effect facts may constrain which pure-model transition is valid, but they
do not create a second model phase vocabulary. The persistence contract must not
introduce a provider-effect-intent phase, staging phase, provider-dispatch
phase, provider-response phase, or any other persistence-specific phase enum.

Persistence hydration must reconstruct or validate an existing pure-model phase
plus the orthogonal provider-effect evidence. Same-package private access does
not authorize bypassing constructors, normalization, or committed model
invariants.

Another subpackage, including a child SQLite store package, may be reconsidered
only through a later explicit encapsulation decision. It is not selected by
this ADR.

## 6. Minimum Durable Fact Model

Authoritative stored facts:

- store format version and schema/migration state;
- authenticated caller namespace safe representation;
- safe private submit-key representation scoped by caller namespace;
- claim identity as persisted or reconstructable from caller/key refs;
- private effective-plan binding and required witness/completeness facts;
- committed reliable-submit claim phase;
- immutable `RunRef` after assignment;
- bounded `ReceiptRef` after acceptance;
- monotonic revision;
- latest-operation descriptor for v2 rows: latest mutation reference, closed
  operation kind, and versioned safe operation-input binding digest;
- created, updated, expiry, tombstone, and corruption-unavailable posture;
- provider-effect intent and ambiguity facts needed to prevent duplicate
  provider effects after crash or restart.

Private security material:

- submit-key digest, HMAC, or equivalent safe representation;
- private effective-plan binding;
- private receipt binding;
- private operation-input binding digest for the latest committed mutation;
- redacted mutation provenance and integrity checks.

External references:

- ES-assigned `RunRef`;
- bounded `ReceiptRef`;
- later ES-owned reconciliation reference only if it is not provider lifecycle
  truth and not public recovery authority.

Derived projections:

- exact latest-operation replay view;
- conflict, unauthorized, expired-unavailable, and unavailable decisions;
- same-authorized-caller run disclosure eligibility;
- accepted-reference eligibility;
- public receipt projection when selected later.

Forbidden lifecycle duplication:

- allocation IDs, EvalID, scheduler job identity as recovery authority;
- runtime status timeline;
- logs;
- result contents;
- cancellation completion;
- runtime retry or reschedule policy;
- Coordinator semantic work or attempt state;
- Git, CI, validation, publication, adapter, Bridge, or connector state.

## 7. Revision And CAS Semantics

Each claim row has one monotonic revision. Every new mutation carries an
expected predecessor revision. Exact replay is latest-operation-only and must
prove the same caller/key, private binding, mutation reference, closed operation
kind, and versioned operation-input binding before stale-revision rejection.
Different mutation references remain subject to revision, phase, and transition
rules.

The caller namespace plus safe submit-key representation is unique. Concurrent
first deliveries converge on one durable claim. Same caller/key with the same
private binding loads or replays the existing claim. Same caller/key with a
different private binding is a conflict before any new effect and discloses no
existing `RunRef` or receipt.

`RunRef` assignment is immutable. A claim can move from pre-assignment to
assigned exactly once. A same-operation replay that observes the already
assigned same `RunRef` is idempotent. A stale mutation that tries to assign a
different `RunRef`, mutate the wrong revision, or skip the committed phase is
rejected fail-closed.

The store, not an in-process mutex, is mutation authority. In-process locks may
be used only as optimization or local serialization. They do not replace SQLite
uniqueness, transactional mutation, revision checks, or durable replay.

If a transaction COMMIT outcome is uncertain, the caller must retry by loading
the durable claim and comparing caller/key, binding, the full
latest-operation descriptor when present, phase, revision, run, receipt, and
effect facts through full expected-record equality. Uncertainty is not
permission to create a second claim, assign a second run, or repeat an external
provider effect.

## 8. Provider-Effect Intent And Ordering

The durable contract distinguishes committed pure-model claim phase from
orthogonal provider-effect facts. The ordering facts are:

- assigned but no provider effect may have started;
- durable provider-effect intent committed;
- staging or materialization evidence recorded when selected;
- provider-dispatch-attempt fact committed;
- provider request may have crossed the process boundary;
- pending provider result;
- ambiguous provider result;
- accepted;
- provably not accepted.

Effect intent must be committed durably before any external execution-producing
I/O that could stage or submit work for the provider path. External I/O occurs
outside the SQLite transaction.

Provider-effect intent alone is not evidence that a provider request was
dispatched. Staging or completed staging alone is not evidence that a provider
request was dispatched. The provider-dispatch-attempt fact must commit durably
before the provider request is sent.

Absence of the provider-dispatch-attempt fact becomes positive ES-owned
evidence that no provider request crossed the process boundary only through the
complete Validated No-Dispatch Evidence predicate below. After that predicate
passes and the current revision is validated, ES may repair or reuse staging for
the same claim and `RunRef`, commit the provider-dispatch-attempt fact through
expected-revision CAS, and perform the first same-`RunRef` provider dispatch
only after that marker commit is known successful. No new claim or `RunRef` is
created.

Once the provider-dispatch-attempt fact exists, the request may have crossed the
process boundary even if ES crashed before observing a response. Crash or
restart then requires loading the claim and running ES-owned reconciliation or
returning/recovering pending or ambiguous outcome. It must not automatically
send a second Nomad submission. Generic Nomad/job absence is not sufficient
proof of non-acceptance after dispatch may have occurred. Provider response,
provider transport failure, response loss, or provider-call uncertainty evidence
requires the committed provider-dispatch-attempt fact.

The conservative dispatch-attempt marker may create an ambiguous window even
when the provider request was not actually sent. That safety tradeoff is
resolved by later reconciliation; it is not hidden as exactly-once provider
execution.

Accepted and recovered-accepted require the durable `RunRef` and bounded
`ReceiptRef`. Provably-not-accepted after assignment requires positive ES-owned
evidence. Ambiguity remains ambiguity until stronger ES-owned evidence is
durably recorded.

## Validated No-Dispatch Evidence

Marker absence is positive ES-owned evidence that no provider request crossed
the process boundary only when every condition below holds:

1. The exact same active durable claim was successfully loaded using its
   authenticated caller namespace and submit-key scope.
2. The durable record exists.
3. The record is not missing, expired for active use, tombstoned as unavailable,
   corrupt, undecodable, or on an unsupported schema or migration state.
4. Private record decoding succeeded.
5. Hydration or validation against the committed pure-model invariants
   succeeded.
6. The loaded `ClaimID`, private effective-plan binding, and `RunRef` match the
   operation being recovered.
7. Provider-effect intent is durably committed.
8. The provider-dispatch-attempt fact is absent.
9. Every relevant durable transaction outcome is known, including the
   effect-intent transaction, any attempted dispatch-marker transaction, and any
   preceding revision/CAS mutation.
10. No unresolved commit-uncertainty condition could explain the apparent
    absence of the marker.
11. The implementation contract and stored record version both guarantee that
    every provider-I/O path commits the dispatch-attempt fact before provider
    I/O.
12. The current record revision has been loaded and validated for the next CAS
    mutation.

Only after all conditions hold may ES repair or reuse staging for the same claim
and `RunRef`, commit the dispatch-attempt fact through expected-revision CAS, and
perform the first provider dispatch for that same claim and `RunRef` after the
marker commit is known successful.

Missing state is not valid marker absence. Corrupt or undecodable state is not
valid marker absence. Unsupported migration or schema state is not valid marker
absence. Tombstone or expiry is not valid marker absence. Unresolved commit
uncertainty is not valid marker absence. Process-local memory, trace IDs,
request IDs, or generic provider absence are not valid no-dispatch evidence.
Failure of any condition makes reliable submit unavailable, ambiguous, or
fail-closed according to later implementation semantics. Failure does not
authorize dispatch or fallback to unkeyed submit.

Ordering implications:

- Provider-dispatch-attempt fact implies provider-effect intent.
- Provider-call response or call-uncertainty evidence implies a committed
  provider-dispatch-attempt fact.
- Provider response or uncertainty evidence must not exist in an ordinary valid
  no-marker state.
- `Accepted` requires the existing pure-model `RunRef` and `ReceiptRef`
  invariants.
- Contradictory effect-fact combinations fail closed and require invariant,
  corruption, or unavailable handling rather than silent normalization.
- The current SQLite schema adds check constraints and triggers for impossible
  row combinations, immutability, and monotonic physical facts. The service and
  pure model remain the transition authority and the SQL layer must not
  reproduce the full semantic transition graph.

## 9. Operation Contract

This table is the target durable-operation contract that reliable-submit runtime
integration must satisfy before enablement. It is not a blanket claim that every
same-operation replay path is fully implemented by the current private source.
The target invariant remains that an exact redelivery of the same durable
operation replays the already committed result: accepted replay returns the same
accepted record and receipt, provably-not-accepted replay returns the same
terminal record, and no new mutation or external effect occurs.

| Operation | Precondition | Expected revision | Idempotent replay | Conflict result | Resulting pure-model phase | Durable effect facts established or changed | Transaction boundary | External-I/O rule |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Establish or load claim | Authenticated and authorized caller namespace, valid safe key representation, valid private binding input | None for first insert; current revision for mutation | Same caller/key/binding loads existing phase and effect facts | Same caller/key/different binding returns conflict with no run or receipt disclosure | Pending before assignment, ambiguous before assignment where permitted by the current durable request/model source, or existing hydrated pure-model phase | No provider-effect fact established | One SQLite transaction for insert-or-load and uniqueness check | No external I/O |
| Compare binding | Existing claim loaded under caller namespace | Current observed revision | Same binding preserves existing phase and effect facts | Different binding conflicts before effect | Existing hydrated pure-model phase or conflict decision | No provider-effect fact established | Same read/write transaction when part of mutation; read transaction for replay | No external I/O |
| Assign run | Existing pre-assignment phase and valid `RunRef` | Current revision | Already assigned same `RunRef` is same-operation replay | Different `RunRef`, stale revision, or invalid phase fails closed | Existing assigned/effect-capable model phase | Immutable `RunRef` assignment only; no provider-effect intent | One SQLite transaction with CAS and immutable run constraint | No external I/O |
| Record provider-effect intent | Existing assigned/effect-capable claim, no prior provider-effect intent, and valid `RunRef` | Current revision | Existing same intent reloads existing assigned phase plus intent fact | Stale revision or incompatible phase fails closed | Remains the existing assigned/effect-capable model phase unless another committed model transition is independently justified | Provider-effect intent committed; no staging, provider dispatch, provider response, or provider acceptance is proved | One SQLite transaction before external I/O | External provider/staging I/O begins only after commit |
| Begin or complete staging/materialization | Existing assigned claim with provider-effect intent committed | Current revision if durable local-effect evidence changes | Existing same staging evidence reloads existing phase plus evidence | Stale revision, wrong run, or incompatible evidence fails closed | Existing assigned pure-model phase is unchanged unless another model transition is independently justified | Bounded local-effect evidence or references only; no provider dispatch is proved | One SQLite transaction for durable evidence when selected; external staging I/O remains outside SQLite transaction | Staging repair or reuse must retain the same claim and `RunRef` |
| Record provider-dispatch attempt | Existing assigned claim with committed provider-effect intent | Current revision | Existing same dispatch-attempt fact reloads existing phase plus fact | Stale revision, wrong run, or incompatible phase fails closed | Existing assigned pure-model phase is unchanged unless later evidence justifies another committed model transition | Provider-dispatch-attempt fact committed; no provider acceptance is proved | One SQLite transaction before provider I/O | Provider request may be sent only after commit; no external I/O inside transaction |
| Record provider call observation or uncertainty | Same active durable claim with matching `ClaimID`, private effective-plan binding, and `RunRef`; committed provider-effect intent; committed provider-dispatch-attempt fact; ES-owned provider pending, ambiguous, transport-failure, response-loss, or call-uncertainty evidence | Current revision | Exact same-operation observation or uncertainty reloads existing phase and evidence | Missing dispatch-attempt fact, stale revision, wrong claim, wrong binding, wrong run, incompatible evidence, provider absence alone, or attempt to record terminal accepted/provably-not-accepted through this observation path fails closed | Only an existing or newly justified committed model transition among `PendingAfterAssignment` or `AmbiguousAfterAssignment`; accepted and provably-not-accepted evidence use the dedicated terminal operations below | Provider-call observation or uncertainty evidence recorded; no lifecycle timeline or provider history store; no new `ClaimID` or `RunRef` | One SQLite transaction | No external I/O inside transaction; provider-call observation or uncertainty evidence cannot be recorded in a no-marker state |
| Record reconciliation evidence | Same active durable claim and `RunRef` plus expected revision/CAS; ES-owned reconciliation evidence over either Validated No-Dispatch Evidence or a committed provider-dispatch-attempt fact | Current revision | Exact same reconciliation observation reloads existing phase and evidence | Wrong claim, wrong run, stale revision, contradictory marker ordering, provider-response labeling in a no-marker state, or incompatible evidence fails closed as invariant, corruption, or unavailable posture | Existing pure-model phase, or an existing committed transition justified by explicit reconciliation evidence only | With validly absent dispatch-attempt fact: validated no-dispatch evidence, local staging/materialization recovery facts, or fail-closed inconsistency evidence only; no provider response or call uncertainty. With dispatch-attempt fact: accepted, positive provably-not-accepted, still-pending, or ambiguous evidence | One SQLite transaction | No external I/O inside transaction; reconciliation is separate from recording a provider-call response and introduces no second phase algebra |
| Accept with receipt | Positive accepted evidence for same assigned `RunRef` and valid bounded `ReceiptRef` | Current revision | Same accepted receipt reloads accepted/recovered-accepted | Different receipt, stale revision, or wrong run fails closed | Accepted | Accepted evidence and bounded `ReceiptRef` for the same `RunRef` | One SQLite transaction | No external I/O |
| Record provably not accepted | Positive ES-owned evidence that no provider effect was accepted for this assigned run | Current revision | Same not-accepted record reloads same phase | Absence-only evidence, accepted phase, stale revision, or wrong run fails closed | Provably not accepted after assignment | Positive not-accepted evidence for the same `RunRef` | One SQLite transaction | No external I/O |
| Exact replay or load | Authorized same caller/key lookup | None for read; current revision if it also refreshes safe metadata | Same binding returns exact replay over underlying phase and effect facts | Different binding conflicts; Unauthorized discloses nothing | Exact replay view over existing pure-model phase or non-disclosing decision | No new provider-effect fact unless an explicit safe metadata mutation is selected later | SQLite read transaction, or read/write only for explicit safe metadata mutation | No external I/O |
| Tombstone or expire | Retention rule selected and claim eligible under policy | Current revision | Existing tombstone returns expired-unavailable/unavailable posture | Attempt to delete assignment truth or permit key reuse fails closed | Expired unavailable decision or retained tombstone-backed phase | Tombstone, expiry, or unavailable posture without lifecycle history | One SQLite transaction | No external I/O |
| Corruption or unavailable | Store open/read/validation detects malformed durable state or unavailable database | Not applicable | Retry may load if later healthy | No conflict detail beyond safe unavailable/corrupt posture | Unavailable fail-closed decision; must not fall back to current unkeyed submit | No new provider-effect fact; no repair semantics unless later explicitly designed | No mutation unless later repair tool is explicitly designed | No external I/O and no provider effect |

### Current Same-Operation Replay Implementation Gap

The committed private durable service supports internal COMMIT-unknown reload
within one operation through `reloadAfterUnknown`: if the store commit outcome is
unknown, the service reloads the claim and can recognize the exact expected
post-commit record.

The general mutation path does not yet recognize a previously committed
`lastMutation` before expected-revision and operation-specific apply logic.
Terminal accepted and provably-not-accepted redelivery are known failing
examples: a duplicate `acceptWithReceipt` or `recordProvablyNotAccepted` call can
reload an already terminal phase and then enter operation-specific provider
candidate validation instead of replaying the committed terminal result. This
gap may affect other durable mutation redelivery cases and therefore requires a
complete mutation-operation inventory, not a repair scoped only to those two
terminal examples.

The private store remains runtime-unwired, so this current source limitation
does not affect current public execution behavior. It is nevertheless a hard
prerequisite before reliable-submit config or store lifecycle wiring, producer
enablement, or public runtime enablement. The dedicated future tranche is
`reliable-submit-durable-same-operation-replay-repair`.

## 9A. Durable Latest-Operation Replay Repair ADR

Status: target selected by documentation and docs-contract only. No durable
service, durable record, SQLite schema, migration, store, runtime, public API,
producer, configuration, staging, Nomad, or lifecycle source repair is
implemented by this ADR tranche.

The current private source facts remain:

- the durable service supports internal COMMIT-unknown reload and full expected
  post-commit record comparison inside one mutation call;
- the general mutation path does not yet recognize a previously committed
  `lastMutation` before stale-revision rejection and operation-specific apply
  logic;
- exact terminal and nonterminal redelivery is not generally implemented;
- the SQLite schema version is still v1;
- the durable record and SQLite row persist only the latest `lastMutation`
  reference and do not retain operation kind, operation-input binding, or
  mutation history.

### Replay Scope

Exact replay is guaranteed only for the current latest committed durable
mutation on the claim. No historical mutation-result log is introduced by this
repair. An older operation arriving after a later committed mutation is not
represented as exact replay and must be classified with the existing private
stale or superseded posture. The current later record must not be represented
as the earlier operation's replay result. Historical replay, if later required,
needs a separate ADR, record model, backend conformance expansion, and schema.

### Latest-Operation Descriptor

The repair selects one atomic persisted latest-operation descriptor. The
descriptor describes the durable mutation that produced the current record
revision and contains exactly these logical facts:

- latest mutation reference;
- closed private operation kind;
- versioned safe operation-input binding digest.

The three descriptor facts update atomically with every successful v2 mutation.
A matching mutation reference with a different operation kind or different input
binding is a mutation conflict, not stale revision and not exact replay.
Mutation reference alone is not sufficient proof of same semantic command.

Establish or load remains special. Caller/key uniqueness and private plan
binding own claim establishment: same caller/key and same binding loads the
existing claim, while same caller/key and different binding conflicts. Establish
redelivery does not rewrite the current latest-operation descriptor merely to
bless a new delivery identity. If the initial row stores an establish
descriptor, that descriptor is only the initial latest-operation descriptor; it
does not replace caller/key plus plan-binding claim idempotency.

### Closed Operation-Kind Vocabulary V1

The first version private operation-kind vocabulary is closed over the mutating
durable service commands:

- `assign_run`;
- `record_provider_effect_intent`;
- `record_staging_evidence`;
- `record_provider_dispatch_attempt`;
- `record_provider_call_observation`;
- `record_reconciliation_evidence`;
- `accept_with_receipt`;
- `record_provably_not_accepted`;
- `tombstone_or_expire`.

Establish/load is not part of ordinary mutation replay. A stored establish
descriptor, if present on the initial v2 row, remains subordinate to
caller/key plus plan-binding claim establishment.

### Operation-Input Binding

The operation-input binding is a versioned, domain-separated private digest:

`SHA256("es/reliable-submit/durable-operation-input/v1\0" || deterministic operation-specific safe encoding)`

The deterministic operation-specific safe encoding must be length-delimited or
otherwise unambiguous. It must include the expected predecessor revision,
operation-specific enum or kind facts, and every operation-specific safe opaque
reference or immutable value that changes command meaning. Semantic values must
be normalized before sorting or duplicate detection, every meaningful input must
affect the binding, and no raw-input projection or public accessor is allowed.
Future binding changes require a new version and schema migration.

For incoming mutation commands, the operation-input binding contains the
expected predecessor revision, the closed operation kind, and every current
request-carried safe receipt or evidence input that changes command meaning.
Claim identity and private plan binding are validated from the loaded claim. An
existing durable-state fact is not made into a request-carried input merely
because it participates in transition validation.

For terminal `accept_with_receipt` and `record_provably_not_accepted`, no
terminal operation row treats `RunRef` as a request-carried operation input. The
immutable `RunRef` is validated from the hydrated existing assigned phase and
durable record. Terminal apply cannot proceed without the valid assigned-run
context required by the committed pure model. COMMIT-unknown full
expected-record equality still includes the durable `RunRef` and the complete
latest-operation descriptor. This ADR selects no terminal request-shape
expansion.

The binding includes, where applicable:

- `RunRef`;
- provider-effect-intent reference;
- staging-evidence or materialization reference;
- provider-dispatch-attempt reference;
- provider-observation semantic kind and safe reference;
- reconciliation semantic kind and safe reference;
- `ReceiptRef`;
- terminal not-accepted evidence reference;
- retention reason and requested expiry or tombstone inputs.

The binding excludes:

- mutation reference itself;
- service-generated timestamps;
- raw requests;
- submit keys;
- caller URIs;
- environment values;
- credentials;
- filesystem paths;
- unrestricted provider IDs;
- trace, request, session, and report IDs;
- logs and result bodies.

The digest is private durable evidence. It must not be derived from provider
reports, traces, logs, scheduler IDs, request IDs, session IDs, public recovery
responses, or external observations that are not themselves the selected safe
operation input.

### Detection Ordering

The durable service repair must use this ordering:

1. Authorization and caller derivation occur before the durable service.
2. Load the current record.
3. Validate schema and codec, then hydrate the pure phase.
4. Validate claim identity and private plan binding.
5. Derive and validate the incoming operation descriptor.
6. Compare mutation reference before stale-revision rejection:
   same mutation plus same operation kind and input binding is exact
   latest-operation replay; same mutation plus different operation kind or input
   binding is mutation conflict.
7. For a different mutation, apply retention and inactive-state classification.
8. Validate expected revision.
9. Validate phase and effect preconditions.
10. Apply the semantic transition.
11. CAS.
12. On CAS loss, reload and repeat replay, conflict, stale, or superseded
    classification before returning stale.
13. COMMIT.
14. On COMMIT uncertainty, reload and retain the existing stricter full
    expected-record equality comparison, including the latest-operation
    descriptor.

Exact replay comparison must occur before inactive-state refusal so an exact
duplicate of the current latest tombstone operation can return the committed
inactive outcome. Corrupt, unsupported, or unhydratable state fails closed
before replay and must not mutate.

### Operation-Specific Replay Matrix

| Operation kind | Binding inputs | Valid source phases | Committed result | Exact latest-operation replay | Same mutation with different input | Different mutation with stale predecessor | Disclosure allowed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Establish or load | Caller/key claim identity and private plan binding are establishment identity; an optional establish descriptor may include initial predecessor and initial phase inputs | No prior row for first insert; existing valid row for load | New claim at initial phase, or existing claim loaded | Same caller/key/binding loads existing claim without descriptor rewrite | Same caller/key/different binding conflicts | Not an ordinary mutation replay case | No existing run or receipt for conflicts; existing claim disclosure follows phase rules |
| `assign_run` | Expected predecessor revision and `RunRef` | Pre-assignment pending or ambiguous claim eligible for assignment | Assigned/effect-capable record with immutable `RunRef` | Same assigned record and same `RunRef` | Mutation conflict | Stale or superseded; no replay | Same authorized caller may receive the assigned `RunRef` under phase rules |
| `record_provider_effect_intent` | Expected predecessor revision and provider-effect-intent reference | Assigned/effect-capable claim with no prior intent | Existing assigned phase plus committed intent fact | Same record and same intent fact | Mutation conflict | Stale or superseded | No receipt; run disclosure follows assigned phase rules |
| `record_staging_evidence` | Expected predecessor revision and staging or materialization evidence reference | Assigned claim with committed provider-effect intent | Existing phase plus staging/materialization fact | Same record and same staging fact | Mutation conflict | Stale or superseded | No raw paths or staging material; only safe private evidence fact |
| `record_provider_dispatch_attempt` | Expected predecessor revision and dispatch-attempt reference | Assigned claim with committed provider-effect intent | Existing phase plus dispatch-attempt fact | Same record and same dispatch fact | Mutation conflict | Stale or superseded | No provider acceptance; run disclosure follows phase rules |
| `record_provider_call_observation` | Expected predecessor revision, `RunRef`, provider-observation semantic kind, and safe observation reference | Same active claim with matching run, committed intent, and committed dispatch-attempt fact | Pending or ambiguous phase justified by observation or call-uncertainty evidence | Same semantic observation and same `RunRef` | Mutation conflict | Stale or superseded | Safe observation fact only; no unrestricted provider ID, trace, request, report, log, or body disclosure |
| `record_reconciliation_evidence` | Expected predecessor revision, `RunRef`, reconciliation semantic kind, and safe reconciliation reference | Same active claim with matching run and committed intent, over Validated No-Dispatch Evidence or committed dispatch-attempt fact | Existing phase or explicitly justified transition from reconciliation evidence | Same reconciliation fact and same `RunRef` | Mutation conflict | Stale or superseded | Safe reconciliation fact only; no provider or report workaround |
| `accept_with_receipt` | Expected predecessor revision, accepted evidence reference where represented, and `ReceiptRef` | Provider outcome candidate with assigned-run context validated from hydrated durable state | Accepted record with bounded receipt | Same accepted record and same `ReceiptRef` | Mutation conflict | Stale or superseded | Same authorized caller may receive accepted record and receipt reference |
| `record_provably_not_accepted` | Expected predecessor revision and terminal not-accepted evidence reference | Provider outcome candidate with assigned-run context validated from hydrated durable state | Terminal provably-not-accepted record | Same terminal record | Mutation conflict | Stale or superseded | No accepted receipt; any run disclosure remains private or future public-shape gated |
| `tombstone_or_expire` | Expected predecessor revision, retention action, unavailable reason, and requested expiry or tombstone inputs | Claim eligible under the selected retention policy | Inactive expired or tombstoned record | Same inactive record | Mutation conflict | Stale or superseded | Bounded inactive outcome only; no resurrection and no lifecycle detail |
| Corrupt, unsupported, unavailable | Not applicable | Store open, decode, migration, or hydration failure | Fail-closed unavailable, unsupported, or corrupt classification | Never replay | Never mutates | Never mutates | Fixed bounded private error posture only |

Same payload with a new mutation reference is not exact replay. It proceeds
through ordinary revision and phase validation. Operation-specific no-op
behavior must not update `lastMutation` merely to give a new identity to an
already completed effect, and must not bypass mutation identity, revision, or
phase checks.

Terminal exact replay preserves the prior disclosure boundary: accepted exact
replay returns the same accepted record and `ReceiptRef`,
provably-not-accepted exact replay returns the same terminal record, same
mutation with different receipt or evidence binding conflicts, and no public run
or receipt disclosure policy is widened.

### Concurrency And COMMIT Uncertainty

Concurrent exact duplicates may both load the same predecessor revision. One CAS
wins. The loser reloads and compares the current latest-operation descriptor:
same mutation, same operation kind, and same input binding returns exact replay;
same mutation with different binding returns mutation conflict; a different
mutation returns stale, superseded, or conflicting progression according to the
current revision and phase. No second durable semantic mutation or external
effect occurs.

COMMIT-unknown recovery remains stricter than ordinary latest-operation replay.
The existing reload-after-unknown posture compares the complete expected
post-mutation record. The v2 source repair must include the latest-operation
descriptor in that full-record equality comparison and must not use descriptor
match alone to declare an uncertain commit successful.

### SQLite V2 Logical Schema And Legacy Rows

A SQLite schema migration is required. The logical v2 additions are the latest
operation kind and latest operation input-binding digest, paired with the
existing latest mutation reference. Exact SQL column names are not frozen by
this ADR; the logical fields, constraints, migration posture, and acceptance
evidence are frozen.

The v2 schema must enforce:

- closed supported operation kinds;
- fixed-length input digest;
- operation kind and digest either both present or both absent for a migrated
  legacy row;
- every newly created v2 row has a complete descriptor;
- every successful v2 mutation updates mutation reference, operation kind, and
  fixed-length input digest together with revision `old+1`;
- no descriptor-only update;
- no revision update without the descriptor triple;
- no delete or retention resurrection;
- migration continuity and future-version rejection remain fail closed.

Existing v1 rows cannot be assigned invented operation semantics. The selected
legacy/unbound migration posture is:

- preserve the existing v1 row;
- retain the legacy mutation reference without treating it as a complete
  descriptor;
- mark operation kind and input digest unavailable/unbound;
- do not infer operation kind or input binding from phase, durable effect facts,
  provider evidence, reports, logs, traces, request IDs, provider IDs, retained
  result material, or external observations;
- do not claim exact same-operation replay for that unbound latest mutation;
- a same-mutation replay attempt against an unbound legacy descriptor fails
  closed with a private replay-unavailable or unsupported classification;
- a later valid distinct mutation may proceed through normal revision and phase
  rules and writes the first complete v2 descriptor;
- no background rewrite, state deletion, or fabricated replay result is
  authorized;
- unsupported future schema versions fail closed.

### Record, Codec, Store, And Source-Tranche Consequences

The later source repair must update the durable record and codec to represent
both the optional legacy/unbound descriptor and the complete v2 descriptor. The
durable service must derive and compare operation descriptors. SQLite row scan,
write, CAS, physical constraints, and migrations must persist them. Shared
backend conformance must cover the same semantics.

The private `claimStore` port remains establish/load/CAS. No PostgreSQL-specific
type, SQLSTATE, DSN, advisory-lock, TLS, credential, schema, or operational
behavior enters the private port. A future PostgreSQL backend may implement the
same private service contract and conformance suite without leaking backend
details into service semantics.

Implementation ordering is frozen:

1. this documentation and docs-contract ADR tranche;
2. independent audit and exact-byte commit of this documentation tranche;
3. record, codec, schema, service, store, and conformance implementation
   tranche;
4. independent transaction and security audit of the source repair;
5. no reliable-submit state-path configuration or store lifecycle, producer
   enablement, public DTO, handler, staging, Nomad, or runtime behavior until
   the source repair is accepted.

## 10. Crash-Window Matrix

| Crash window | Durable facts | Could provider dispatch have occurred? | Duplicate delivery or first-effect behavior | Required reconciliation | Forbidden inference |
| --- | --- | --- | --- | --- | --- |
| Before claim persistence | No claim, no run, no provider-effect intent, no dispatch-attempt fact | No ES-owned dispatch exists for this claim | A retry may become first delivery after normal auth/admission | None beyond normal auth/admission | Claim absence after no effect does not prove anything about unrelated callers |
| After claim before run assignment | Caller/key and binding survive restart; no run exists | No | Same binding sees pending before assignment; different binding conflicts | None | No provider effect may be inferred |
| After run assignment before provider-effect intent | Claim has exactly one immutable `RunRef`; no provider-effect intent or dispatch-attempt fact | No | Same binding reloads assigned run and continues only through CAS | None | No Nomad acceptance may be inferred |
| After effect intent before staging | Run and provider-effect intent survive; dispatch-attempt fact is absent | No only after the full Validated No-Dispatch Evidence predicate passes | Staging and the first same-run provider dispatch remain permitted only after the full predicate passes; the marker is then committed through expected-revision CAS, provider I/O occurs only after marker commit success, and no new claim or `RunRef` is created | Verify Validated No-Dispatch Evidence and current revision | Intent alone is not provider dispatch or acceptance proof |
| During staging or local effect preparation | Same run and effect intent survive; staging may be partial; dispatch-attempt fact is absent until committed | No only after the full Validated No-Dispatch Evidence predicate passes | Retry repairs or reuses same run-scoped material; first same-run provider dispatch remains permitted only after the full predicate passes; the marker is then committed through expected-revision CAS and provider I/O occurs only after marker commit success | Staging repair/reuse validation and Validated No-Dispatch Evidence, unless later evidence shows dispatch may have occurred | Partial staging is not a new semantic execution and not provider dispatch |
| After staging before dispatch-attempt commit | Same run, effect intent, and any selected staging evidence survive; dispatch-attempt fact is absent | No only after the full Validated No-Dispatch Evidence predicate passes | First same-run provider dispatch remains permitted only after the full predicate passes; the marker is then committed through expected-revision CAS and provider I/O occurs only after marker commit success | Verify staging evidence, Validated No-Dispatch Evidence, and current revision | Completed staging is not provider dispatch or acceptance proof |
| After dispatch-attempt commit before provider call | Same run, effect intent, and dispatch-attempt fact survive | Yes, conservatively, because crash cannot distinguish this window from one where the call crossed the boundary | No automatic provider call or resubmit on restart | ES-owned reconciliation is required | Dispatch-attempt is not acceptance, generic provider absence is not proof, call outcome or uncertainty evidence requires the marker, and the process cannot infer the call did not cross the boundary |
| Provider call may have occurred before conclusive response | Run, intent, and dispatch-attempt fact survive; pending or ambiguous must be retained or recoverable | Yes | Retry must not auto-register again | ES-owned reconciliation is required | Generic provider absence is not proof of no acceptance, and call outcome or uncertainty evidence requires the marker |
| Provider response uncertain or ambiguous result persisted | Pending or ambiguous after assignment survives with same run and dispatch-attempt fact plus call outcome or uncertainty evidence | Yes, unless reconciliation later proves otherwise | Retry returns or observes pending/ambiguity until stronger evidence exists; no automatic provider resubmission | ES-owned reconciliation is required | Ambiguity is not rejection, generic provider absence is not proof, and call outcome or uncertainty evidence requires the marker |
| After accepted receipt persistence before caller response | Accepted run and receipt survive | Yes, accepted | Exact retry returns accepted or recovered accepted | None | Lost caller response is not a new execution |
| During COMMIT uncertainty | Retried caller must reload and compare durable state | Depends on the operation; external effects must not be repeated from uncertainty | Existing committed row wins if present; otherwise fail closed per operation | Reload and compare caller/key, binding, latest-operation descriptor when present, phase, revision, run, receipt, and effect facts through full expected-record equality | Uncertain commit is not permission to repeat external effects |
| After expiry or tombstone | No-reuse fact or unavailable posture survives as required by retention policy | Unknown from absence alone | Retry returns expired/unavailable or a bounded tombstone-backed outcome | Retention/repair policy only when later selected | Expiry or deletion is not proof that no execution existed |

## 11. Retention And Tombstones

Expiry cannot become generic absence. Deletion cannot be represented as proof
that no prior execution existed. Automatic key reuse after expiry is not
allowed by inference.

The store must retain historical assignment truth, tombstone, or unavailable
correlation posture as required by the selected retention policy. Exact TTL,
garbage collection, archival behavior, compaction, and operator repair remain
open.

Tombstones remain bounded submit-correlation facts. They do not retain lifecycle
timelines, logs, result contents, cancellation completion, or provider history.

## 12. Security, Permissions, And Corruption

Raw submit keys, raw request bodies, raw effective-plan material, raw argv
values, environment values, credentials, trust material, local paths, scheduler
IDs, allocation IDs, EvalID, trace IDs, request IDs, and adapter session IDs
must not be stored or logged as public recovery authority.

The future store path must be a separate ES-owned state path. It must not reuse
`execution.staging_root_dir` or `execution.results_root_dir` as the database
path. The future state path requires an explicit configuration addition in a
later tranche.

Future directory and file posture must follow stable ES-owned state: `es:es`
directory ownership, owner-only or equivalently restrictive database and sidecar
file modes, and no symlink or hardlink trust shortcut. The exact mode and
readiness checks are a later implementation detail, but the store must not
require root, supplemental groups, or broader deployment privileges.

Public errors, logs, support output, audit records, and recovery responses must
not include raw database diagnostics, raw SQL, absolute database paths, driver
exception text, raw keys, raw bindings, raw request material, or secrets.

Corruption or malformed durable state fails reliable submit closed. It must not
fall back to current unkeyed submit, create a new claim, allocate a second run,
or repeat a provider effect. Backup and restore design remains a later gate.

## 13. Initial Deployment Topology

The first supported deployment may use one ES process on one host. Correctness
still derives from SQLite uniqueness, transaction isolation, and revision CAS,
not from that one-process shape.

This ADR does not import the Coordinator writer-session, writer-lease,
operation-epoch, proof, or advisory-lock model into ES. Coordinator patterns
are contrast only unless a later ES-specific decision adopts one explicitly.

Multi-host shared database, high availability, replication, remote database
service operation, and active/active ES writers are non-claims for the first
reliable-submit store path.

## 14. Required Dependency-Selection Gate

Before adding a SQLite driver or concrete store source, the dependency-selection
tranche must verify from primary sources:

- Go 1.26.5 compatibility;
- CGO-free builds under `CGO_ENABLED=0`;
- linux/amd64 and linux/arm64 support;
- `database/sql` behavior or a documented replacement API decision;
- license and redistribution posture;
- exact direct and transitive version constraints;
- static and cross-build behavior for the supported deployment path;
- busy, locking, transaction, and isolation behavior;
- backup and corruption APIs or documented absence;
- deterministic local/offline test and build posture;
- sidecar file, journal, WAL, fsync, and permissions behavior;
- maintenance and security update posture.

This gate must not select a CGO-only driver while preserving the current
`CGO_ENABLED=0` build contract.

Current source-grounded dependency license and notice posture for the selected
modules:

- `modernc.org/sqlite v1.54.0` carries a BSD-3-Clause-style module `LICENSE`
  requiring retention of the copyright notice, license conditions, and
  disclaimer in source redistributions, and reproduction of those notices in
  binary-distribution documentation or accompanying materials.
- The bundled SQLite engine provenance is distinct from the Go wrapper/module
  license: the local `SQLITE-LICENSE` states that SQLite deliverable code and
  documentation are public domain.
- `modernc.org/libc v1.74.1` carries a BSD-3-Clause-style module `LICENSE` with
  the same source and binary notice-retention posture, and its local
  `LICENSE-3RD-PARTY.md` records additional third-party notices that must
  accompany applicable source or binary redistribution.
- `golang.org/x/sys v0.46.0` carries the Go Authors BSD-3-Clause-style `LICENSE`
  notice posture plus the Go `PATENTS` additional patent grant terms.

This is dependency-governance evidence for the private SQLite store tranche, not
legal advice or final packaging clearance. A complete transitive notice inventory
and assembled distribution notice remain a later release/packaging gate.

## 15. First Concrete Source Tranche

The first concrete source tranche is:

- same-package private durable-record codec in
  `es/admission/internal/reliablesubmit`;
- one private backend-neutral claim-store port;
- one backend-neutral durable semantic service;
- one shared backend conformance suite;
- same-package SQLite store files, separate from `model.go`;
- `modernc.org/sqlite v1.54.0` as the selected CGO-free SQLite driver;
- `modernc.org/libc v1.74.1` as the exact expected transitive coupling;
- `go.mod` and `go.sum` updates for that driver and its transitive modules;
- one initial schema and migration path;
- unique caller namespace plus safe submit-key claim constraint;
- immutable run-assignment constraint;
- revision CAS for every mutation;
- provider-effect-intent persistence before external I/O;
- hydration through the committed pure model;
- crash, concurrency, corruption, permission, migration, and replay tests.

That tranche still does not wire current submit, HTTP, DTOs, producer contract,
staging, Nomad, lifecycle, result handling, Coordinator, Bridge, CP, IM, Git,
CI, validation, publication, global ES configuration, state-path startup wiring,
or public reliable-submit availability. Runtime integration and the explicit
ES-owned reliable-submit state-path configuration addition remain a later
tranche.

The next reliable-submit source repair tranche must implement the section 9A
latest-operation replay contract before any runtime enablement. It must update
the private durable record and codec, SQLite migration and physical constraints,
SQLite row scan/write/CAS, durable service descriptor derivation and comparison,
and shared backend conformance tests. It must preserve the private
establish/load/CAS `claimStore` port shape unless a separate ADR selects
historical mutation retention or another backend-neutral semantic requirement.
It must not edit public API/DTO source, producer declaration source, global
configuration, app startup, current submit/staging/Nomad source, Coordinator,
Bridge, CP, IM, or dependencies.

## 16. Explicit Non-Claims And Open Decisions

Explicit non-claims:

- no end-to-end reliable submit is implemented in this tranche;
- no global ES configuration source change is made in this tranche;
- no current submit, HTTP, DTO, producer-contract, staging, Nomad, lifecycle,
  result, Coordinator, Bridge, CP, IM, Git, CI, validation, or publication
  behavior changes;
- no backup API is added to the common port;
- no online backup/restore, managed backup, destructive restore, host
  replacement, or operator repair implementation is included;
- no PostgreSQL dependency, source, schema, DSN, TLS, credential, advisory-lock,
  HA, replication, or migration implementation is included;
- no live backend switching, dual write, automatic SQLite/PostgreSQL portability,
  export/import format, or existing-data migration guarantee is made;
- no broad ES lifecycle store;
- no provider metadata authority;
- no unkeyed fallback for reliable submit;
- no exported raw persistence accessors;
- no second phase algebra;
- no multi-host or HA claim.
- no latest-operation descriptor is persisted by current source;
- no SQLite v2 replay-descriptor schema or migration is implemented by current
  source;
- no durable same-operation replay source repair is implemented by this
  documentation/docs-contract ADR tranche.

Open decisions:

- exact reliable-submit state-path config key;
- exact TTL, tombstone, garbage-collection, archival, and repair policy;
- exact caller namespace source wiring at the authenticated request boundary;
- exact durable replay-envelope persistence, including safe reconstruction or
  custody of original argv and environment values and selection of any safe
  immutable references;
- exact Nomad reconciliation query and evidence rules;
- exact public receipt, recovery, HTTP status, and error vocabulary;
- exact runtime submit integration tranche.

A future PostgreSQL backend may implement the same private claim-store port and
shared conformance suite only after a separately accepted requirement justifies
managed database operation. That later backend must preserve active claims,
tombstones, immutable `RunRef` values, receipts, revisions, effect facts,
ambiguity, and no-reuse semantics through a separate contract and audit.
