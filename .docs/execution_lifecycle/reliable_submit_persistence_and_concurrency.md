# Reliable Submit Persistence And Concurrency ADR

## 1. Status And Purpose

Status: accepted architecture decision with bounded private codec-3 synthetic
replay custody on the reopened reliable-submit seam. Public/runtime reliable
submit remains unavailable.

The historical first tranche added private admission-local durable claim
source and tests: one backend-neutral claim-store port, one durable semantic
service, one private durable-record codec, one SQLite implementation using
`modernc.org/sqlite v1.54.0`, and a shared backend conformance suite. It
implements no configuration source, no request or response DTO, no HTTP handler,
no staging behavior, no Nomad behavior, no producer-contract field, no runtime
startup wiring, and no public reliable-submit availability. Reliable submit
remains unimplemented end to end.

This ADR freezes the durable-state boundary and ordering rules that the later
source implementation must consume from the committed pure model in
`es/admission/internal/reliablesubmit`.

The historical source tranche for `reliable-submit-durable-same-operation-replay-repair`
implemented the section 9A latest-operation contract. Codec-1/2 rows retain
their historical meaning and generic nonempty opaque references. The private
record/codec stores a complete v2 latest-operation descriptor for historical
new and later-mutated rows; valid v1 rows migrated as legacy/unbound codec-1
rows, and the durable
service performs exact latest-operation replay, mutation-conflict detection,
CAS-loser reload/replay classification, and COMMIT-unknown full-record equality
including the descriptor.

A later unavailable contract-adapter foundation, implemented in private
admission-local package `admission` helpers, now selects the reliable request
schema `execution-substrate.reliable-submit-request/v1`, reliable contract
`execution-substrate.reliable-submit/v1`, discriminator `reliable_submit`,
submit-key syntax, caller/key derivation, composite `ClaimID` construction
through the committed pure-model constructor, and ES-neutral outcome projection.
Those adapter helpers do not implement source-grounded plan extraction,
canonical effective-plan encoding, `PlanBinding` construction, a complete
witness, durable replay-envelope custody, or runtime orchestration. The
separate private `resolved-execution-plan-extraction-foundation` now extracts
the current legacy Submit plan from real admission/runtime resolution, but it
does not import or wire this reliable store, construct a binding, or alter this
ADR's schema, migrations, store port, or SQLite startup status.

The separate 2026-11-15 private admission binding v1 source selection
constructs a runtime-unwired `PlanBinding`, exact fourteen-category witness,
and `BoundPlan` from the actual frozen resolver tuple. It remains an
always-not-effect-ready assessment. At PB1 it had no production caller; the
codec-3 synthetic composer is its only selected new non-test caller. The pure
model's generic opaque/nonempty binding contract, fourteen masks, codec-1/2
rows, store port and latest-operation semantics remain unchanged.
Its signed mount provenance carry-through adds no live admission refusal.

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

SQLite schema version 3 adds only private synthetic codec-3 custody and a
same-database key-use ledger. Historical codec-2 rows still store the latest
`lastMutation` reference with closed operation kind and input binding; migrated
codec-1 rows retain their unbound legacy mutation reference. Both retain
their generic nonempty opaque CallerRef, SubmitKeyRef and PlanBinding domains,
including values shorter than 32 bytes and bindings longer than 256 bytes.
Only complete codec-3 rows require CallerRef/SubmitKeyRef of exactly 32 bytes
and PlanBinding of 1..256 bytes. No mutation history is stored.

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
first deliveries converge on one durable claim. Historical codec-1/2 loads
compare the same private binding and different binding conflicts without
disclosing a `RunRef` or receipt. The private codec-3 synthetic adapter
instead loads the verified winner by key before current resolution and compares
canonical winner-original intent and field presence. A changed intent
conflicts; no codec-3 result confers any effect permission.

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

**O2 historical codec-1/2 CAS cleanup — Bounded slice rule refinement.**
After a known successful `BEGIN IMMEDIATE`, every `compareAndSwapClaim`
pre-COMMIT exit, including cancellation, SQL/read failure, CAS miss, and
missing-row return, must confirm ROLLBACK with a context independent of the
request. Confirmed rollback preserves the ordinary result/error. Failed
rollback requires synchronous discard of that exact driver connection and a
fixed unavailable result with no `record`, `applied`, or `found` success claim;
cleanup failure overrides even a would-be nil-error return. Before dispatching
COMMIT or a test-only COMMIT fault seam, the operation records the attempted
boundary. No rollback follows an attempted COMMIT. Any non-nil COMMIT result
requires exact-connection disposal before returning COMMIT-unknown or allowing
a durable reload; unconfirmed disposal returns unavailable and forbids
classification. Known successful COMMIT retains the existing applied/winner
record and revision semantics. A canceled caller may remain unavailable:
request-independent cleanup does not detach semantic work from cancellation.
A high-level `sql.Conn.Close()` alone is not disposal proof, and no uncertain
transaction may return to the usable pool. This rule changes neither codec-3
claim/grant/key guards nor A1 original-key read cleanup, selected separately
below as a before-runtime concern.

**A1 original-key read cleanup — Bounded slice rule refinement.**
`checkOriginalReplayKeys` keeps its binding-key, envelope-key and optional
ACTIVE checks in one read transaction on one checked connection. Semantic
BEGIN, SELECT and COMMIT use the caller's context. The read never registers a
missing key. Purpose/fingerprint matching, ACTIVE requirements for new use,
RETIRED-original eligibility for existing-claim verification, and
REVOKED/missing/mismatched refusal remain unchanged. A transaction's paired-key
snapshot is not a promise of instantaneous cross-process revocation; the next
fresh-context transaction observes a later committed key-state transition.

Invalid keys retain unsupported precedence. An already-canceled request
returns fixed unavailable before read BEGIN. Cancellation observed at
acquisition, semantic failure or the final success check cannot become success
because cleanup succeeded. An A1-local release guard is installed before
dispatching read BEGIN or its test-only fault seam. It distinguishes
not-dispatched, known-begun, COMMIT-attempted and known-ended states. A nonnil
result after BEGIN dispatch is potentially post-execution: the exact driver
connection is discarded before ordinary pool return, and the read returns
unavailable without retry or durable-write outcome classification. Known
pre-dispatch cancellation need not discard a connection on which no
transaction was dispatched.

After known BEGIN and before read-COMMIT attempt, every exit confirms ROLLBACK
with a new private context independent of caller cancellation. The cleanup
context has a fixed unexported five-second budget, created when rollback
starts, and its cancel function is always released. This bounds the context,
not every driver or OS close call; no timeout worker is selected. Confirmed
rollback permits ordinary connection release and preserves the safe operation
result. A failed, expired or unconfirmed rollback instead discards that exact
connection and returns fixed unavailable, overriding any ordinary result.
Confirmation samples the cleanup context immediately after the rollback
response and before releasing its cancel function. Only a nil rollback response
with no observed cleanup-context error permits ordinary release; a nil response
after observed expiry is unconfirmed and follows the same exact-discard and
fixed-unavailable rule. This post-operation observation is not an atomic
wall-clock guarantee through the later connection close.
A possibly open read transaction never reaches ordinary `sql.Conn.Close()`.

The read marks COMMIT attempted before invoking COMMIT or its test-only seam.
A nonnil COMMIT result requires exact-connection discard, fixed unavailable,
and no post-attempt rollback or durable-claim reload: this read has no write
winner to classify. Known successful COMMIT ends the transaction and permits
ordinary release. Cancellation checked before an explicit success return
still refuses; cancellation after that observation/return boundary is not
promised detectable. Cleanup never moves semantic key queries to a background
context or authorizes success, retry, or a key/grant mutation.

The A1-local no-ordinary-release decision precedes discard. The existing
supported exact-connection primitive is unchanged. If its first disposal
response is unconfirmed, one direct synchronous rescue with the real primitive
is permitted; neither attempt restores success, and there are at most two
attempts. If both remain unconfirmed, withhold that connection from ordinary
`Conn.Close()` and return unavailable. This connection-local choice may
retain a transaction or lose pool capacity; it proves neither physical close
nor later store availability under simultaneous disposal failure. It adds no
store-wide poison flag, registry, retry loop, finalizer, background disposer,
or whole-store reopen. A high-level Close or pool count alone is not
physical-close proof.

The one-use Seal permit is consumed before this key check and stays burned on
failure; there is no refund or same-permit retry. Failure stops before Seal,
claim INSERT, and the authenticated callback at their respective callers.
Publication creates an owner-only candidate file before consuming the permit;
a failed check may leave an inert empty/unclaimed file. Existing no-delete,
no-adoption and no-object-ID-reuse rules remain, and a later valid publication
uses a new legitimate permit and object ID. A1 changes neither shared
`beginRead`/`rollbackIfOpen` callers nor O2, C1/D1, schema, migration,
codec, public configuration, or runtime wiring.

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

### Selected codec-5 interpretation of §8

Operational command operands bind the exact authenticated predecessor. Intent
and marker use the owner-specified preimages. Stamp and marker require a
fresh matching held-stage measurement. Receipt CAS accepts the authenticated
positive verifier witness and rechecks it against the current row. Cleanup
can withhold projection while preserving the invoked command's disposition.

The [Operational Handoff](reliable_submit_operational_handoff.md) selects a target scoped to codec 5. It retains
conditions 1–8 and 11, uses exact lock-held current revision and expected-revision
CAS for 12, and substitutes a checked current authenticated writer turn after
`BEGIN IMMEDIATE` on the same unchanged authority domain for conditions 9–10.
This selects present first-effect eligibility and preserves all earlier observed
write dispositions. The codec-5-only staging rule requires a newly acquired
exclusive live owner or its still-live continuation. This carve-out supersedes
the repair/reuse permission above and in §10 for codec 5 alone. The marker
transition, sole sender issuance, uncertainties and resume conditions are
defined in the target owner. §15B continues to govern the fixture scope.

In the local candidate the schema-5 migration preserves codecs 1–4 and adds
the codec-5 constraints and scoped unique RunRef index. A provisioned
operational custody handle opens only the checked current schema. Its writer
runs under the existing immediate-transaction discipline, with a single
directly acknowledged first-marker continuation. Later reads authenticate the
original and project durable facts. Operational opening qualifies the
pre-existing claim population on the checked schema snapshot. Exact expected
row equality after write uncertainty requires complete original and key
qualification for confirmation. Observed disposition and release qualification
are separate. The old fixture remains governed by §15B.

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

This table is the private durable-operation contract implemented by the current
durable source and still required before runtime enablement. An exact redelivery
of the current latest durable operation replays the already committed result:
accepted replay returns the same accepted record and receipt,
provably-not-accepted replay returns the same terminal record, and no new
mutation or external effect occurs. Older operations after later progression are
stale or superseded, not historical replay.

The following operation table describes historical codec-1/2 durable service
semantics. The codec-3 synthetic path has only immutable establishment and
checked load; it rejects every RunRef, effect, receipt and CAS mutation.

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

### Current Same-Operation Replay Implementation Status

The committed private durable service now recognizes a previously committed
latest-operation descriptor before stale-revision and inactive-state refusal.
Same mutation plus same closed operation kind and input binding returns the
operation's committed result without another CAS. Same mutation plus different
kind or input binding returns mutation conflict without widening run or receipt
disclosure. Same mutation against a migrated legacy/unbound descriptor fails
closed as unavailable rather than inventing operation semantics.

The private store remains runtime-unwired, so this source repair does not affect
current public execution behavior. It is nevertheless a completed prerequisite
for later reliable-submit config or store lifecycle wiring, producer enablement,
and public runtime enablement.

## 9A. Durable Latest-Operation Replay Repair ADR

Status: historical codec-1/2 private source implemented and runtime-unwired;
section 15A owns the later codec-3 synthetic extension. The durable service,
durable record, SQLite schema v2 migration, SQLite row scan/write/CAS, store
tests, and shared conformance tests implement this ADR inside
`es/admission/internal/reliablesubmit`. No runtime, public API, producer,
configuration, staging, Nomad, or lifecycle source is wired by this source
tranche.

The current private source facts remain:

- the durable service supports internal COMMIT-unknown reload and full expected
  post-commit record comparison inside one mutation call;
- the general mutation path derives a complete latest-operation descriptor,
  compares it before stale-revision rejection and inactive-state refusal, and
  classifies exact replay, mutation conflict, or legacy/unbound replay
  unavailable;
- exact latest-operation redelivery is implemented for terminal and nonterminal
  durable mutations;
- the SQLite schema version is v2;
- the durable record and SQLite row persist the latest `lastMutation`, closed
  private operation kind, and operation-input binding digest for codec-2 rows;
- migrated codec-1 rows retain only `lastMutation`, carry no invented operation
  semantics, and fail closed for same-mutation replay;
- no mutation history is retained.

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

For historical codec-1/2, establish or load remains special. Caller/key
uniqueness and private plan binding own claim establishment: same caller/key
and same binding loads the existing claim, while different binding conflicts.
Codec-3 synthetic establishment is governed separately by section 15A.
Establish
redelivery does not rewrite the current latest-operation descriptor merely to
bless a new delivery identity. If the initial row stores an establish
descriptor, that descriptor is only the initial latest-operation descriptor; it
does not replace caller/key plus plan-binding claim idempotency.

### Closed Operation-Kind Vocabulary V1

The first version private operation-kind vocabulary is closed over the
new-row establishment descriptor and mutating durable service commands:

- `establish_claim`;
- `assign_run`;
- `record_provider_effect_intent`;
- `record_staging_evidence`;
- `record_provider_dispatch_attempt`;
- `record_provider_call_observation`;
- `record_reconciliation_evidence`;
- `accept_with_receipt`;
- `record_provably_not_accepted`;
- `tombstone_or_expire`.

Establish/load is not part of ordinary mutation replay. The stored establish
descriptor on an initial v2 row remains subordinate to caller/key plus
plan-binding claim establishment.

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

This operation-kind table likewise describes the historical codec-1/2 durable
service. Codec-3 synthetic rows do not enter these mutation operations.

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
post-mutation record. The current v2 source includes the latest-operation
descriptor in that full-record equality comparison and does not use descriptor
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

The current source repair updates the durable record and codec to represent both
the legacy/unbound codec-1 descriptor and the complete codec-2 descriptor. The
durable service derives and compares operation descriptors. SQLite row scan,
write, CAS, physical constraints, and migrations persist them. Shared backend
conformance covers the same semantics.

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

The [Operational Handoff](reliable_submit_operational_handoff.md) history matrix selects the codec-5-only crash
behavior, including the exclusive-stage rule and preservation of residue after
marker rollback. The table below supplies the earlier general design context.

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

The historical first concrete source tranche was:

- same-package private durable-record codec in
  `es/admission/internal/reliablesubmit`;
- one private backend-neutral claim-store port;
- one backend-neutral durable semantic service;
- one shared backend conformance suite;
- same-package SQLite store files, separate from `model.go`;
- `modernc.org/sqlite v1.54.0` as the selected CGO-free SQLite driver;
- `modernc.org/libc v1.74.1` as the exact expected transitive coupling;
- `go.mod` and `go.sum` updates for that driver and its transitive modules;
- schema v2 with v1-to-v2 migration preserving existing rows as legacy/unbound;
- unique caller namespace plus safe submit-key claim constraint;
- immutable run-assignment constraint;
- revision CAS for every mutation;
- provider-effect-intent persistence before external I/O;
- hydration through the committed pure model;
- crash, concurrency, corruption, permission, migration, and replay tests;
- current latest-operation replay descriptor source and docs-contract alignment.

That tranche still does not wire current submit, HTTP, DTOs, producer contract,
staging, Nomad, lifecycle, result handling, Coordinator, Bridge, CP, IM, Git,
CI, validation, publication, global ES configuration, state-path startup wiring,
or public reliable-submit availability. Runtime integration and the explicit
ES-owned reliable-submit state-path configuration addition remain a later
tranche.

The completed latest-operation source repair preserves the private
establish/load/CAS `claimStore` port shape. Later reliable-submit gates remain
runtime consumption and original-key availability for the now-unwired private
v1 binding, durable material custody, state/store lifecycle and configuration,
Nomad reconciliation, and public runtime enablement. Those later
gates must not reinterpret the source repair as mutation-history support,
public replay DTOs, PostgreSQL implementation, or end-to-end reliable-submit
availability.

## 15A. Private codec-3 synthetic custody, SQLite and recovery

This is a Bounded slice rule on the reopened reliable-submit seam, not a
runtime or effect path. The only codec-3 scope is synthetic_nonoperational_v1.
The private adapter loads by caller/key before current resolver/default/key
selection, authenticates the winner's original envelope, compares canonical
original intent/presence and returns either verified winner-original replay,
fixed conflict, exact own-commit confirmation or unavailable/unknown. A
different valid equal-intent winner is not proof this attempt committed. Legacy
codec-1/2 same-binding durable semantics in sections 7–9A remain intact.

SQLite schema version 3 and per-row codec 3 are separate versions. Append
migration 3; migration-1/2 SQL literals and ledger hashes remain byte-identical
(9613ba74cd6573626277b1f04a20b9c3ec5f9edf8b6b7408e94cbb45edc32dcd
and 9280a62450488dfa54907d268d693f3f7d4f0b78b9a3553a1b659206d2c970e9).
The existing 32 claim columns and claim_rowid are copied exactly, with
bidirectional in-transaction rowid/old-column comparison before dropping the
old table. Migration-3 is one SQL literal: a transient same-transaction
ordinary CHECK(ok=1) assertion table inserts 1 only if counts and both
32-column-plus-rowid EXCEPT directions match; a mismatch aborts the migration.
The final migration-3 literal is 21,829 bytes with SHA-256
`4dafddbf477fd7f64ad88cf2b1e2b2becb378827e81cd6cc694456798c9a00be`;
the complete supported schema-3 shape digest is
`15ab48bde4d53bb252dc954a2aa3b1db12de7295111f23bb0264f74f153dba92`.
That table is dropped before COMMIT and is not another database or durable
schema object. Fourteen nullable physical columns are added: replay_scope,
intent_format, intent_commitment, context_commitment,
envelope_wrapper_format, envelope_payload_format, envelope_algorithm,
envelope_ref, envelope_size, envelope_sha256, binding_key_id,
binding_key_fingerprint, envelope_key_id and envelope_key_fingerprint.
The inherited 32-column projection, in order, is caller_ref, submit_key_ref,
plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag,
run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns,
assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref,
staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns,
provider_observation_kind, provider_observation_ref,
provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref,
reconciliation_at_unix_ns, expires_at_unix_ns, retention_state,
unavailable_at_unix_ns, unavailable_reason, last_mutation_ref,
latest_operation_kind, latest_operation_input_digest and codec_version.
claim_rowid remains the INTEGER PRIMARY KEY. The inherited witness, phase,
effect, retention and latest-operation CHECKs remain exact except the codec
domain widens to 1/2/3 and both 2 and 3 require latest-operation fields.
For codec 1/2 all fourteen must be NULL, and all inherited generic nonempty
opaque caller/key/binding, phase, latest-operation, CAS and history semantics
survive. Only codec 3 requires caller_ref and submit_key_ref BLOB exactly 32,
plan_binding BLOB 1..256, all fourteen fields complete, scope=1, formats and
algorithm=1, commitments/fingerprints/file SHA BLOB exactly 32, envelope size
29..2,097,152, and exact relative-ref/key-ID byte grammar. Codec-3 INSERT is
initial revision/establish operation, phase PendingBeforeAssignment, retention
active, no expiry, RunRef, receipt, effect, staging, dispatch, provider or
reconciliation fact. Every codec-3 UPDATE/DELETE is forbidden. Historical
codec-1/2 updates still permit only 1→2 or 2→2 with new fields NULL.

On schema 3, codec 3 is the only permitted new claim. Codec-1/2 rows remain
only as authenticated historical state inherited through supported migration.
For a legacy establish request, the store may load a same-key valid migrated
historical row within its existing transaction and return it to the durable
service for caller/key and plan-binding classification. An absent legacy key
must be refused without inserting or partially mutating a codec-1/2 row. A
current codec-3 winner must not be treated as historical state; malformed,
corrupt, or semantically invalid existing rows fail closed. This narrow
historical-load rule remains private, admission-local, runtime-unwired, and
non-effect-capable. It does not enable operational custody or reliable submit.

The envelope_ref TEXT predicate is non-NULL TEXT, instr(x,char(0)) IS 0,
length(CAST(x AS BLOB))=75, exact BINARY prefix objects/v1/, exactly 64
remaining bytes and a suffix with no byte outside lowercase [0-9a-f].
The key-ID predicate for both registry and codec-3 claim fields is non-NULL
TEXT, no embedded NUL, byte length 1..64, first byte [A-Za-z0-9], remainder
only [A-Za-z0-9._-]. These predicates are two-valued CASE/ELSE-0 checks and
are mirrored by the Go reader; SQLite TEXT length alone is not enough.

Two additional STRICT tables live in this SAME SQLite DB:
reliable_submit_key_registry(key_id TEXT PRIMARY KEY, purpose 1 binding or 2
envelope, material_fingerprint BLOB exactly 32 UNIQUE across purposes,
state 1 active/2 retired/3 revoked) and
reliable_submit_seal_use(envelope_key_id TEXT PRIMARY KEY REFERENCES
reliable_submit_key_registry(key_id), granted_count INTEGER NOT NULL between
0 and 4294967296). Claim binding_key_id and envelope_key_id also reference
the actual reliable_submit_key_registry table. A registry INSERT must be
new ID/new fingerprint, valid ID/purpose/32-byte fingerprint and ACTIVE.
Its UPDATE preserves ID/purpose/fingerprint using IS NOT and permits only
1→2, 1→3 or 2→3. Counter INSERT must be new ID, valid envelope-purpose
ACTIVE registry row and count zero. Counter UPDATE preserves key ID with
IS NOT and permits exactly OLD.granted_count+1 at or below the bound while
registry remains ACTIVE. All three tables have unconditional BEFORE DELETE
abort triggers; claim codec-3 has unconditional BEFORE UPDATE abort. Registry
and counter have explicit BEFORE INSERT EXISTS same-ID/fingerprint guards,
and UPDATE guards are independent of no-delete. Claim INSERT checks both
ACTIVE registry purpose/fingerprint matches. Normal claim establishment is
one targeted ON CONFLICT(caller_ref,submit_key_ref) DO NOTHING, followed by
winner load; other conflicts fail. No generic IGNORE or REPLACE is used.
The named objects are reliable_submit_claims_no_delete,
reliable_submit_claims_guard_insert_v3,
reliable_submit_claims_guard_update and the unique
reliable_submit_claims_envelope_ref_unique index; each key table has its
respective _no_delete, _guard_insert and _guard_update trigger. Registry
INSERT aborts on EXISTS same BINARY key_id OR same fingerprint; counter
INSERT aborts on EXISTS same BINARY envelope_key_id or NOT EXISTS an ACTIVE
purpose-2 registry row. Counter UPDATE aborts if NEW.envelope_key_id IS NOT
OLD.envelope_key_id, NEW.granted_count IS NOT OLD.granted_count+1, count exceeds
4294967296 or the ACTIVE purpose-2 registry row is absent. Registry UPDATE
aborts if ID, purpose or fingerprint IS NOT the old value, state is NULL, or
transition is outside 1→2/3 and 2→3. Claim INSERT requires NOT EXISTS checks
to be false for both registry rows matching ID/purpose/fingerprint/ACTIVE,
while deliberately **not** checking caller/key existence before the targeted
DO NOTHING. All checks have explicit NULL branches; no SQL UNKNOWN authorizes
a value or transition. The complete final DDL literal and this object manifest
are compared on open, not accepted merely because a ledger row exists.

Every managed connection, including open/migration, key, claim and reload,
sets and verifies recursive_triggers=ON before relevant prepare/read/write.
DSN initialization also requests it; WAL/FULL, foreign_keys=ON and
trusted_schema=OFF remain required. Unknown/unreadable/zero recursive result
refuses. REPLACE implicitly deletes a conflicting row and its DELETE
triggers fire only under recursive triggers, so this is necessary for
no-replacement. No claim is made against an administrator disabling protections,
dropping triggers or replacing DB/files.

The key-use owner registers/compares actual 32-byte key material under a
private fingerprint SHA-256(ASCII ESRSKEY1 | bytes), with a purpose-independent
domain so aliases and cross-purpose reuse fail. It reserves before every Seal
under BEGIN IMMEDIATE, checks both keys ACTIVE, checks the actual envelope
key count <2^32 and checks the sum of committed grants across ALL envelope
counter rows <32 in the first fixture domain. The counter increments once and
a known successful COMMIT alone yields one process-local one-use permit.
Unknown COMMIT yields no permit or Seal; failed Seal, collision, publication
failure, orphan, loser or claim failure burns capacity without refund.
For these private claim, grant and key-state write transactions, a COMMIT error
or pre-COMMIT-close uncertainty discards that specific SQLite driver connection
before the high-level connection is closed or any claim outcome is reloaded.
BEGIN dispatch is itself an uncertainty boundary: the pinned driver may execute
`BEGIN IMMEDIATE` and then return an error. Every non-nil BEGIN result is
treated as potentially post-execution unless a mechanically verified driver
contract proves otherwise. From dispatch onward, the exact connection must
either enter the known-successful transaction cleanup path or be safely rolled
back or synchronously discarded before ordinary pool return. Cleanup does not
depend on the request context that produced the BEGIN error. A failed or
unconfirmed disposal returns a fixed unavailable result and cannot authorize
claim classification, mutation retry, a Seal grant, or a permit. Grant BEGIN
uncertainty returns no permit even if later observation sees durable state.
Claim, grant, and key-state writes share this entry rule; no mutation is retried
after an ambiguous BEGIN result. The post-COMMIT handling below is unchanged.
The discard uses the supported `database/sql.Conn.Raw` callback returning
`driver.ErrBadConn`. Confirmed disposal removes that driver connection from
circulation under the pinned pool implementation and takes its close path.
The local disposal evidence does not independently prove physical close
success or a universal close deadline. A failed discard cannot authorize
success or a Seal permit. No rollback follows an attempted COMMIT.
If an earlier ROLLBACK itself fails, the same discard is required; an
unconfirmed discard makes the operation unavailable and forbids classification.
These are the existing codec-3 claim/grant/key rules. The proposed codec-4
caller preserves its prior write uncertainty when classification cannot run.
Codec-3 claim uncertainty is classified only after confirmed discard,
through a separate freshly opened SQLite connection with current schema and
connection protections verified without migration. That read compares durable
state; it never repeats the claim mutation. A genuinely pre-COMMIT failure
leaves its published-but-unclaimed file inert, while a completed COMMIT whose
response was lost may be recognized only from the fresh verified durable row.
Retirement/revocation blocks new grants; if observed before consuming an
outstanding permit it burns that permit. It cannot instantly cancel an
already granted use in another process; the claim transaction still requires
both keys ACTIVE. A retired original may verify/decrypt an existing claim;
revoked/missing/mismatched originals refuse. The near-2^32 test has a separate
reservation-only limit profile. No production key loader or global rollback
protection is selected.

For the distinct historical codec-1/2 CAS path, O2 requires a real pinned
SQLite fault matrix over authentic migrated schema-1/2 rows. It must prove
pre-COMMIT rollback or exact driver disposal, independent writer-lock release,
no reuse after discard, complete durable row/revision/latest-operation facts,
no false success under cancellation or unconfirmed cleanup, and later healthy
operation on the same store. A real COMMIT followed by a lost response must
advance at most once, dispose the uncertain connection before classification,
and use the durable service's full expected-record equality. A pre-dispatch
COMMIT error must not be turned into a rollback shortcut after the attempted
boundary. Legacy codec-1/2 compatibility and migration literals remain;
codec-3 CAS stays refused. This evidence does not qualify runtime wiring,
public Submit, native installed-source behavior, or A1's read path.

The publisher uses an independent random 32-byte object ID as
objects/v1/<64 lowercase hex>, never as AEAD nonce. The qualified test root
and fixed parent are validated at opening/setup. Under held root/parent
identity it exclusively creates a regular owner-only one-link no-follow file,
consumes one permit, Seals frozen payload/header/AAD with separate AES-256-GCM
key and Go NewGCMWithRandomNonce, writes exact bounded bytes, readback-checks
the held file, fsyncs file and parent, checks close, then reopens the visible
candidate read-only, nonblocking, no-follow and close-on-exec under the held
parent and compares visible/held identity and full bytes.
Only a complete verified publication descriptor may enter claim INSERT.
Unclaimed partial or complete files remain inert; no rewrite/delete/adoption.
The later reader loads expected associations only from the real claim row,
checks ref, held/visible file identity, exact complete size/SHA, wrapper/AAD,
registry/actual original keys, Open, strict payload, layer copies, then invokes
the admission-owned PB1 verifier as its last internal callback. The preclaim
writer validates against frozen prospective associations and never fabricates
an authoritative claim for its own check. SQL cannot authenticate external
file bytes.

Every read-only open of the synthetic marker or a replay-object candidate,
including held and visible reader opens, uses
`O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` before descriptor `Fstat` and
regular-file qualification. `O_NONBLOCK` is a liveness control only: a FIFO,
Unix-domain socket, directory, or other nonregular pathname replacement must
return promptly through open failure or post-open type refusal rather than
block before qualification. Such replacements fail closed before claim creation
or any authenticated callback. Only an owner-only regular one-link descriptor
with the required mode, bounded size, held/visible identity, complete bytes,
SHA and AEAD checks may proceed. Qualified regular-file reads retain their
complete existing behavior; `O_NONBLOCK` relaxes no read, identity, integrity
or authority check. Directory opens retain their directory-qualified semantics,
and the publication creator retains exclusive `O_CREAT|O_EXCL|O_RDWR` creation.
No pathname-only precheck, polling, retry, goroutine, background thread,
adoption, repair or new path-based authority is selected. This source-level
rule does not qualify live-host or native VFS behavior.

Migration 0→3 applies 1+2+3 in one transaction; 1→3 applies 2+3 together;
2→3 applies 3. A pre-COMMIT failure with confirmed rollback retains the
authenticated opening version. A known COMMIT yields complete schema 3,
subject to postcommit shape check. Unconfirmed COMMIT may leave complete old
or complete new state; close the uncertain handle and use a fresh NONMIGRATING
verifier of application_id, user_version, ordered ledger/source hashes,
tables/columns/STRICT/indexes/FKs/CHECKs/triggers, quick/foreign-key checks
and legacy row shape/preservation evidence. Classify recovered-old or
recovered-new, not a known direct COMMIT response. A complete old state may
undergo a separately initiated ordinary upgrade. Mixed or unverifiable
state is unavailable, without blind retry, writable_schema or backfill.
Reservation and claim COMMIT unknown have their distinct rules above and in
the submit contract; migration recovery never mints a Seal permit or claim.

The exact new internal-package files are replay_custody_format.go,
replay_custody_structure.go, replay_custody_file.go, replay_key_use_sqlite.go,
sqlite_replay_claim.go, sqlite_replay_schema.go and sqlite_replay_shape.go.
The only new source testdata files are public synthetic whole-byte literals
testdata/replay_payload_v1.hex, testdata/replay_header_v1.hex and
testdata/replay_aad_v1.hex, independently calculated from the selected field
tables rather than derived from the Go encoder under test.
The finite exported-in-internal-package facade is PrivateReplayCustody,
PrivateReplayKeys, PrivateReplayFrozen, PrivateReplaySealPermit,
PrivateReplayPublication, PrivateReplayAttempt, PrivateReplayClaimLookup,
PrivateReplayClaimCommitFault and AuthenticatedClaimMeta. The selected
constructors and operations are
OpenPrivateReplayCustody, NewPrivateReplayKeys, NewPrivateReplayFrozen,
EncodePrivateReplayIdentity, EncodePrivateReplayAssessment,
LoadSyntheticClaim, Found, OriginalKeyIDs, ReserveSealUse,
PublishSealedSynthetic, EstablishSyntheticClaim, WithAuthenticatedClaim,
MatchesAttempt, MatchesClaimAndPlan, Close and the fixed error classifier
ErrPrivateReplayClaimCommitUnknown. A finite InjectClaimCommitFaultForTesting
hook can lose the actual claim COMMIT response after applying the transaction,
or close its connection before COMMIT, only in the explicitly synthetic test
fixture; it has no runtime caller or configurable production path. Only an
opaque, one-use permit crosses
the admission import edge; its authority never does. The lower package owns
SQL, complete bounded byte framing before the authenticated callback,
key-use and file custody; admission owns typed original semantics, the only
direct real resolver/PB1 composition and PB1 recomputation. There is no
general plaintext/key getter, exported raw store, arbitrary verified flag,
second database, queue or shared kernel.

Private aggregates and boundary errors use fixed redacted formatting.
Binary custody encoding is the selected bounded private exception; no raw
submit key/JSON, generic JSON/text marshaler, private value-bearing errors or
logs are selected. A known synthetic claim is never effect-ready. Native
file/VFS qualification, real caller authorization, genuine image pin, host
qualification, production keys/restore/GC/epoch/TTL, run/effect protocol,
public recovery and deployment remain separate governed gates.

## 15B. Proposed private original replay and durable claim progress

This **Bounded slice rule extension** on the reopened reliable-submit seam
is implemented in the source candidate. Schema 4 carries historical codecs
1/2 and the initial-only codec 3 described in section 15A. Section 6B of the
[submit contract](submit_idempotency_correlation_and_recovery.md#6b-proposed-private-original-replay-and-durable-claim-progress)
owns the codec-4 wire grammar and finite admission/custody boundary.
A schema version authenticates the store shape. A codec version selects a
record grammar. Use one ES SQLite domain and one occupied
`(caller_ref,submit_key_ref)` across all codecs. One row holds one original
and one attempt. There is no promotion, reset, second run, claim/key reuse,
replay-object discovery or change to Nomad's lifecycle authority.

Architectural review selected the K1-corrected contract for bounded
implementation. The phase map below records the dependency order and freezes
the scope of source validation and independent acceptance.

### 15B.1 Pooled loadClaim prerequisite and exit precedence

The pinned diagnostic showed pooled `loadClaim` returning a connection with
an open transaction after cancellation following real BEGIN, cancellation
after successful SELECT and a modeled error after real BEGIN. Subsequent
same-store reads/CAS failed and a direct nested-BEGIN probe saw the retained
transaction. No stale successful read or unsafe durable mutation was
observed. Diagnostic exit zero meant the observation assertions held.
`loadClaimFresh` closed its zero-idle function-owned pool in the tested cases,
ran zero failed authentication callbacks and allowed later codec-3 discovery
and verification. Universal physical-close and latency properties remain
unproved. Before phase 1 both readers used a write-shaped COMMIT error that
supplies no evidence of a write. The function-owned reader's error shape
remains unchanged.

Phase 1 implements the pooled `loadClaim` cleanup below. The source-bound
targeted regression passed on the repaired reader after correcting the
test's trigger restoration. Its seam-only pinned reader counterfactual
retained the old operation ordering and failed later same-store reads and
CAS. This evidence is local engineering validation. The change uses local
test boundaries and the existing exact-discard primitive. Set release ownership before BEGIN
dispatch. BEGIN, SELECT and read COMMIT keep the caller context. Disposition
of a previously attempted write is handled by that write's owner.

| Pooled read exit, in precedence order | Disposition |
| --- | --- |
| Invalid lookup/input | Zero record, existing invalid classification. No connection acquired. |
| Valid input, canceled before acquire or before dispatch | Zero record, fixed read unavailable. Normally release an acquired connection with no dispatched transaction. |
| Acquisition fails with a live request | Zero record, safe existing acquisition classification. If cancellation is observed, read unavailable. |
| BEGIN dispatched, response fails or is unconfirmed | Zero record, read unavailable. Disable ordinary release first and dispose the exact connection. No semantic retry or rollback. |
| Known BEGIN, no COMMIT attempted | Roll back on the same connection using a private request-independent context with a five-second deadline. Read both rollback response and `cleanupCtx.Err()` immediately after the response, before self-cancel. Always release the cancel function. |
| Rollback error, observed expiry even with nil response, or unconfirmed rollback | Overrides SELECT result, not-found and corruption with zero record/read unavailable. Disable ordinary release and dispose the exact connection. |
| Confirmed rollback with request cancellation observed before returning | Zero record/read unavailable. Normal wrapper close is permitted. |
| Confirmed rollback and live request | Preserve safe original classifications, including not-found and corrupt. Always return a zero record on error. |
| COMMIT attempted, nonnil or unconfirmed response | Zero record/read unavailable. Dispose on that exact connection before any ordinary return. No post-attempt rollback or semantic read retry. |
| Successful read COMMIT | Transaction end known and wrapper may close. Return the validated record only if the final caller-context observation is live, otherwise zero record/read unavailable. |

Do not dispatch COMMIT after observed cancellation. On uncertain transaction
end, use the existing exact disposal primitive with one bounded A1-equivalent
rescue on uncertain disposal response, using the same connection. If neither
attempt confirms quarantine, withhold the wrapper from ordinary close/pool
return. Discard confirmation carries the existing bounded database/sql
quarantine meaning. Physical close failure, universal unblock time and
cancellation after the last observation remain outside that proof. No poison
registry, background disposer, semantic retry or whole-store restart.
`loadClaimFresh`, its callers/lifetime, shared rollback/COMMIT/error
mapping and A1/O2/C1/D1 remain outside this correction. Fresh-reader
normalization and operational qualification are separate decisions. Scope2
has no fresh-reader consumer. When the schema head advances, the fresh
reader's existing generic exact-schema check recognizes the new store head.

### 15B.2 Complete logical row and original fields

This table inventories all 47 physical fields. INTEGER means SQLite signed
64-bit INTEGER and strict storage type; timestamp means positive normalized
UTC Unix nanoseconds in that representation. B32 is BLOB exactly 32 bytes,
with SQL NULL only where marked. Go verifies exact pre-narrowed enum ranges,
storage class and NULL versus empty, byte widths, cloned safe typed refs,
and existing time/phase/fact validators. The physical rowid is separately
projected privately for scope2, including from the insert transaction before
COMMIT, and never disclosed. The table is specific to codec 4. The earlier
branches retain their narrower or broader historical field rules as defined
in section 15A. Here “fixed” means immutable at every successor.

| Logical field and physical column | SQL type, initial and mutation | Evidence owner and Go validation |
| --- | --- | --- |
| Creation row identity `claim_rowid` | INTEGER PRIMARY KEY, SQLite-generated, fixed | SQLite, exact physical row identity on reads/CAS/recovery |
| Safe caller `caller_ref`, safe submitted key `submit_key_ref` | B32 each, initialized from authenticated synthetic caller and canonical key, fixed, pair UNIQUE | Admission, typed ClaimID and header/payload equality |
| Original binding `plan_binding` | BLOB 1–256, complete raw PB1 binding, fixed | Admission, recompute and constant-time compare |
| Complete witness `witness_resolved_mask`, `witness_inapplicable_mask` | INTEGER each 0–16383, initialized from PB1, fixed, disjoint, union 16383, latter disjoint from 7935 | Admission, complete ordered fourteen-category witness, exact equality to payload |
| Creation time `created_at_unix_ns` | Timestamp set by durable service once, fixed | Durable service clock and normalized round-trip |
| Codec `codec_version` and scope `replay_scope` | INTEGER 4 and 2, fixed | Custody/codec strict joint dispatch |
| Intent grammar `intent_format` | INTEGER 1, fixed | Admission strict typed intent parser |
| Original intent/context commitments `intent_commitment`, `context_commitment` | B32 each, fixed | Custody recomputes exact domain and compares row/header |
| Formats `envelope_wrapper_format`, `envelope_payload_format`, `envelope_algorithm` | INTEGER values 2,2,1, fixed | Custody exact tuple including header/payload |
| Object locator `envelope_ref` | TEXT, 75 bytes per section 15A path predicate, initialized by exclusive publication, fixed, UNIQUE when non-NULL | Custody validates syntax, decoded object ID, held descriptor and same file |
| Sealed size/digest `envelope_size`, `envelope_sha256` | INTEGER 29–2,097,152 and B32, fixed after publication | Custody checks actual full file length, exact header/combined relationship and SHA-256 |
| Original keys `binding_key_id`, `envelope_key_id` | TEXT 1–64 each per section 15A byte grammar, distinct, each FK to registry, fixed | Custody checks exact original IDs, purpose, registry state and header/payload |
| Key identities `binding_key_fingerprint`, `envelope_key_fingerprint` | Distinct B32, fixed, exact registry match | Custody recomputes under shared fingerprint namespace and compares |
| Phase `phase_tag` | INTEGER 1–7, initialized to 1 or 2 by typed fixture input, legal transition below only | Durable service hydrates existing phase algebra, tagged fixture projection |
| Run `run_ref` and assignment time `assigned_at_unix_ns` | B32 and timestamp, initially NULL, both required in phases 3–7, fixed once assigned | Durable service binds one typed fixture run, validates presence and assignment |
| Receipt `receipt_ref` | B32 or NULL, initially NULL, present only at phase 6 and then fixed | Durable service accepts exact typed fixture receipt in op8 |
| Revision `revision` and update time `updated_at_unix_ns` | INTEGER initial 1, increments one without overflow, timestamp initially equal to creation, nondecreasing | Durable service uses expected revision and existing clock validation |
| Latest mutation `last_mutation_ref`, `latest_operation_kind`, `latest_operation_input_digest` | B32, INTEGER 1–9, B32, initialized to random mutation/op1/derived digest. Replace together on committed successor, with a different mutation ref. | Durable service compares full latest descriptor, predecessor supplied to digest |
| Intent `effect_intent_ref`, `effect_intent_at_unix_ns` | B32 and timestamp or both NULL initially, set once in op3 after assignment | Durable service validates assigned attempt and fixture fact type |
| Staging `staging_ref`, `staging_at_unix_ns` | B32 and timestamp or both NULL initially, set once in op4 after intent | Durable service validates fixture evidence only |
| Dispatch `dispatch_ref`, `dispatch_at_unix_ns` | B32 and timestamp or both NULL initially, set once in op5 after current-row validation of an explicit command | Durable service validates same-run fixture marker, no provider call |
| Provider observation `provider_observation_kind`, `provider_observation_ref`, `provider_observation_at_unix_ns` | INTEGER 0–5 and B32/timestamp pair. Initial 0/NULL/NULL. Set by op6, op8 or op9 after dispatch. Only terminal ops 8/9 may replace an existing nonterminal observation. | Durable service validates exact assigned run where carried, enum/fact pair and resulting phase |
| Reconciliation `reconciliation_kind`, `reconciliation_ref`, `reconciliation_at_unix_ns` | INTEGER 0–6 and B32/timestamp pair. Initial 0/NULL/NULL. Set once by op7. Kinds 1/2/3/6 remain earlier observations after advancement. | Durable service validates run, when-recorded facts and current row compatibility |
| Retention `expires_at_unix_ns`, `retention_state`, `unavailable_at_unix_ns`, `unavailable_reason` | NULL, INTEGER 1, NULL, TEXT empty respectively, fixed | Durable service rejects expiry/tombstone operation 10 for scope2, no automatic/manual claim expiry or GC |

Within the sealed original, payload ID 2 owns intent/presence, 3 owns the
resolved original plan, 4 captured material, 5 the PB1 assessment including
material identities, 6 synthetic image, 7 original placement, 8 provenance,
9 format/key IDs and 10 scope. Their exact typed sizes, nullable leaves and
initial sources are the closed section 6B grammar and its 6A references.
Every sealed field is fixed at establishment. Admission verifies semantic
source facts and PB1. Custody verifies structure, commitments and header
associations. SQL stores only the fields listed above, including assessment's
binding/witness projections, and enforces their widths, association and
immutability. There is no new plaintext table or copy of intent, plan values
or material. Payload ID 1 duplicates the safe row identity; header reference
and key/format overlaps must match. Creation identity is governed by SQLite
and full-record equality; current mutable facts never enter the sealed
original. Legacy TTL/retention and existing registry key retirement/revocation
continue under their own rules. The fixture claims themselves stay occupied.

### 15B.3 Existing transition model and exact operation identity

The phase number denotes an existing model variant within the fixture. Tags 1 and 2
are pending/ambiguous before assignment, 3 assigned, 4 and 5 pending/
ambiguous after assignment, 6 accepted and 7 provably not accepted after
assignment. `FixtureProgressCommand` is a closed union with the following
eight cases. All refs are distinct typed fixture roles backed by 32 bytes,
bound to the authorized claim and assigned run where required. There is
no provider, stage or runtime method on these values.

| Op and ordered request part IDs | Predecessor, recorded change and postcondition |
| --- | --- |
| 1 Establish, part 10 | Under occupied-key check, true miss only. Revision 1, phase 1 or 2, no assignment, receipt or effect fact, active retention. |
| 2 Assign, part 3 (run) | Phase 1 or 2 to 3. Assign one run and timestamp. Same-run equivalence is a no-op after exact/stale checks. Different run refuses. |
| 3 Intent, part 4 (intent) | Assigned run required. Set intent tuple once, phase unchanged. |
| 4 Staging evidence, part 4 (staging) | Intent required. Set fixture staging tuple once, phase unchanged. |
| 5 Dispatch marker, parts 3 (run), 4 (dispatch) | Explicit command with the current-row predicate below. Set first fixture marker at phase 3, preserving reconciliation. Staging fact optional. No subsequent marker. |
| 6 Provider observation, parts 3, 5 (kind), 4 (fact) | Assigned candidate 3/4/5, exact run, intent and dispatch. Set previously absent provider tuple. Kind 1 to phase 4, kinds 2/5 to phase 5. Terminals are separate operations. |
| 7 Reconciliation, parts 3, 6 (kind), 4 (fact) | Record once per the kind table below, or validate an exact replay/no-op. Kind 1 is a fixture no-marker observation. No tuple replacement. |
| 8 Accept with receipt, parts 7 (receipt), 4 (fact) | Candidate 3/4/5, marker and independently validated positive same-run acceptance evidence. Atomically set phase 6, provider kind 3 and receipt. Preserve reconciliation. |
| 9 Provably not accepted, part 4 (fact) | Candidate 3/4/5, marker and independently validated positive same-run negative evidence. Atomically set phase 7 and provider kind 4. Preserve reconciliation. Receipt stays NULL. |

Reuse `SHA256("es/reliable-submit/durable-operation-input/v1\0" ||
u16(kind) || i64(expected predecessor) || parts)`, where each ordered part
is `u16(tag) || u32(length) || bytes`, big endian. Observation kinds in
parts 5/6 are u16. Each ref part is exactly 32 bytes. The separate mutation
ref participates in replay equality and is not hashed into the digest.
For op1 the predecessor is 0. Part 10 begins with ASCII `ESRSEST2`, then
caller-ref32, key-ref32, u32 binding length and binding bytes, resolved
and inapplicable mask u16 each, initial phase u8, creation time i64,
codec u16=4, scope u8=2, intent format u16=1, intent/context MAC32 each,
wrapper/payload/algorithm u16 each, 75 ASCII object-ref bytes, sealed size
u32, file SHA32, u16 binding key-ID length and bytes and its FP32, u16
envelope key-ID length and bytes and its FP32. No delimiter other than
the specified lengths. Generated rowid is compared in full expected
record equality, outside the digest. Later digests concern only the
specified request inputs and predecessor. The codec-4 marker binds the
assigned fixture run before its marker reference. Service-generated successor
times and assigned context on terminal operations are checked through
record equality, outside the later operation digest. Do not change the
legacy digest or codec-3 establishment encoding.

The successor path clones the complete original, preserves codec 4 and
scope 2, and uses the existing durable transition authority. It never emits
the legacy codec-2/no-replay constructor shape. CAS uses a dedicated
mutable-only SQL argument list, conditioned on codec 4, row identity,
expected revision and active row, after full-original comparison and
registry recheck in the same checked `BEGIN IMMEDIATE` transaction.
Compare raw persisted enum domains before narrowing to Go widths, including
raw codec (e.g. 65540) and u8 enum aliases (e.g. 257). Generic legacy
service loads/establish/CAS deny scope2 and cannot enter the fixture branch.
Codec 3 continues using its own facade and initial-only behavior.

#### Codec-4 reconciliation records an observation of this attempt

The inherited contract and source differ in two places. Section 8 permits
a first same-run dispatch after complete Validated No-Dispatch Evidence,
fresh CAS and known marker COMMIT. The pinned `durable_record.go:351–430`
and migration 1–3 CHECKs require reconciliation NoDispatch to coexist only
with phase 3 and no marker/provider. The pinned `durable_service.go:377–417`
sets reconciliation once, and ops 8/9 at lines 422–499 clone that tuple.
Pending, Ambiguous and Inconsistent then fail the inherited current-phase
check on a terminal successor. The baseline tests exercise recording and
these shape constraints. This is a static owner/source mismatch on the
reopened seam. Codec 4 gets a bounded extension. Codec-1/2 checks and
transitions, codec-3 initial-only rows, and migrations 1–3 keep their
existing meanings.

Use the existing single kind/ref/time tuple as the first reconciliation
observation of one attempt. No new fields, supersession or history table.
Kinds 1/2/3/6 describe the state when recorded. Current phase, marker,
provider and receipt give the current decision. Ops 5, 6, 8 and 9 preserve
every byte of the prior reconciliation tuple including kind and timestamp.
Op 7 can fill an empty tuple only. An identical fact at current revision
may return a validated no-op only if the kind's current evidence predicates
still hold, with no new evidence of COMMIT. The current predicate applies
to all kinds after latest-replay and stale classification. After a marker,
kind 1 cannot return that no-op. A differing tuple is refused. Replaying an older reconciliation command never refreshes
the observation or claims history-wide write proof.

| Reconciliation kind | Op 7 conditions and phase when recorded | Legal phase and relation on later reads |
| --- | --- | --- |
| 0 Absent | Initial tuple is `0/NULL/NULL`. Op 7 never writes kind 0. | May stay absent in any phase. Terminal phase still needs its positive decision fact. |
| 1 NoDispatch (fixture no-marker observation) | Authenticated active phase-3 row, exact run and predecessor, committed intent and no marker/provider. Stays at 3. | Without marker, phase 3 and provider absent. With marker, phase 3 or 4–7. The observation time is no later than marker time. The old absence supplies no operational authority or evidence of a past write disposition. |
| 2 Pending | Candidate 3/4/5, marker present. Provider absent or kind 1. Record at resulting phase 4. | Phases 4–7 with marker. Retain the original tuple, including on transition to stronger evidence. |
| 3 Ambiguous | Candidate 3/4/5, marker present. Provider absent or kind 2/5. Record at resulting phase 5. | Phases 4–7 with marker, same tuple. |
| 4 Accepted | Add to existing phase 6 with marker, provider kind 3 and receipt. No new terminal decision. | Phase 6 only, same marker, provider and receipt. |
| 5 NotAccepted | With marker and positive same-attempt negative evidence, move candidate 3/4/5 with absent provider to 7, or corroborate existing 7 with provider kind 4. No receipt. | Phase 7 only, same marker, provider absent or kind 4. |
| 6 Inconsistent | Candidate 3/4/5, marker present. Provider absent or kind 2/5. Record at resulting phase 5. | Phases 4–7 with marker, same tuple. |

Every nonzero tuple needs assigned run and committed intent, with
reconciliation time no earlier than intent time. Kinds 2–6 also require
the observation time to be no earlier than the marker time. Provider
kind 1 requires phase 4, kinds 2/5 require phase 5, kind 3 requires
phase 6 and kind 4 requires phase 7. Nonzero provider needs the immutable
marker and fact time at or after that marker. Op 6 only fills an empty
provider tuple. With no provider yet, op 6 can advance either nonterminal
reconciled phase to the newly observed phase. If a provider is present,
an identical observation is a valid no-op at current revision and a
different nonterminal provider tuple refuses. Only ops 8/9 may replace a
nonterminal provider tuple with a terminal tuple. Phase 6 always requires
provider kind 3 and a receipt. Phase 7 requires provider kind 4 or
kind-5 reconciliation. A present provider in phase 7 must be kind 4.
Terminal phases and receipts remain immutable.

#### First fixture marker and terminal evidence

A new explicit op 5 is a storage-model transition. Require a supported
checked schema/codec, the same authenticated immutable original, an active
retained row with the matching claim, plan and assigned RunRef, hydrated
phase 3, committed intent, absent marker/provider and the exact expected
revision. Recheck this predicate against the current row in the CAS writer
transaction. The predicate uses the current row and command. It applies
whether or not a kind-1 observation is present. Kind 1 keeps its existing
tag and records a bounded fixture no-marker observation at that snapshot.
It supplies no operational permission or proof about earlier responses.

A stored marker is immutable. Exact latest-operation replay can describe
the committed marker. A fresh marker command refuses when one is present,
even with the same marker ref. Every fixture outcome is effect-ineligible.
The complete operational [Validated No-Dispatch Evidence](#validated-no-dispatch-evidence)
requirement in §8 remains unchanged. See §15B.4 for the three distinct
invocation, later fixture and operational guarantees.

Ops 8/9 and negative reconciliation require a bounded synthetic terminal
assertion checked independently of command selection by the durable service.
`FixtureTerminalEvidence` is redacted and has private claim, run, marker, fact,
outcome and receipt fields. The two explicit outcomes are Accepted and
NotAccepted. Only Accepted associates a receipt.

`NewFixtureAcceptedEvidence(claim ClaimID, run FixtureRunRef, marker FixtureFactRef,
fact FixtureFactRef, receipt FixtureReceiptRef) (FixtureTerminalEvidence, error)`
and `NewFixtureNotAcceptedEvidence(claim ClaimID, run FixtureRunRef, marker
FixtureFactRef, fact FixtureFactRef) (FixtureTerminalEvidence, error)` are the
only added constructors. Invalid inputs and zero assertions refuse. These
constructors describe fixture assertions, with no external event or provider
authority. For an authenticated original, the durable service checks claim,
run, marker, valid fact and explicit outcome. Accept also compares the
command receipt to the separately constructed evidence receipt. Reject and
negative reconciliation require no receipt and exact fact association. The
check precedes reliance on the assertion for replay or no-op. Candidate
phase checks still follow latest replay classification. Corroborative
kind 4 checks the existing accepted row and adds only the observation.
The operation digest, schema and original encoding remain unchanged.
Earlier Pending, Ambiguous or Inconsistent observations remain visible
as historical facts and cannot prove the terminal decision. An opposite
terminal decision, wrong evidence, different run or missing marker refuses.
A candidate with occupied nonterminal reconciliation can resolve through
op 8 or op 9 without replacing its reconciliation. A separately supplied mutation
leaves any prior unknown disposition unchanged.

#### Complete example states and refusals

| History | Before restart | Retained state after restart | Same later explicit fixture command |
| --- | --- | --- | --- |
| A | Intent and reconciliation are known committed at revision 4. No marker invocation occurred. | The active phase-3 predecessor at revision 4, with intent and kind 1 and no marker/provider. | With fresh authentication, a new live one-use borrow and the same explicit marker command at revision 4, the first synthetic marker may commit. |
| B | The same predecessor. An earlier marker transaction did not commit, but its response was classified unknown, recovery was unavailable and cleanup of the uncertain connection was confirmed. | The same complete predecessor as A. The returned unknown response is not a stored row fact. | The same eligibility and possible first synthetic marker. The earlier invocation remains historically unknown. |

Nothing in the 47-field row or synchronous borrow distinguishes A from B
after restart. A diagnostic driver can label the histories for testing, but
its memory supplies no command input or authority. The later fixture command
is counted separately. In both histories the selected result is a storage
transition and supplies zero provider-I/O permission. If a prior marker
actually committed, the current stored marker blocks a new marker command.

Each row below shares the same complete immutable original descriptor,
codec 4 and scope 2, caller/key and physical rowid within its example.
Creation time is 10. Retention is always active with expiry and unavailable
time NULL and reason empty. A dash in an optional field is SQL NULL.
Other tuple values are symbolic typed refs with times in nanoseconds.
`op/predecessor/ref` denotes the complete latest descriptor with that
operation's exact digest over the listed typed input. All immutable
columns and the sealed file stay byte-identical through each sequence.

| Example state | Phase / revision / update time | Latest op/predecessor/ref and digest inputs | Assigned run/time | Intent | Staging | Marker | Provider (kind/ref/time) | Reconciliation (kind/ref/time) | Receipt |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A/B before reconciliation | 3 / 3 / 13 | 3/2/m3 `[I]` | R/12 | I/13 | — | — | 0/—/— | 0/—/— | — |
| A/B retained predecessor after restart | 3 / 4 / 14 | 7/3/m4 `[R,1,N]` | R/12 | I/13 | — | — | 0/—/— | 1/N/14 | — |
| A/B after later explicit first marker | 3 / 5 / 15 | 5/4/m5 `[R,D]` | R/12 | I/13 | — | D/15 | 0/—/— | 1/N/14 | — |
| C pending provider, before reconciliation | 4 / 5 / 15 | 6/4/m5 `[R,1,P]` | R/12 | I/13 | — | D/14 | 1/P/15 | 0/—/— | — |
| C after Pending, then restart | 4 / 6 / 16 | 7/5/m6 `[R,2,Q]` | R/12 | I/13 | — | D/14 | 1/P/15 | 2/Q/16 | — |
| C accepted on one branch | 6 / 7 / 17 | 8/6/m7a `[C,A]` | R/12 | I/13 | — | D/14 | 3/A/17 | 2/Q/16 | C |
| C positively not accepted on an independent branch | 7 / 7 / 17 | 9/6/m7n `[X]` | R/12 | I/13 | — | D/14 | 4/X/17 | 2/Q/16 | — |

The C alternatives use independent copies of the fixture, never successive
terminal choices on one row. Ambiguous and Inconsistent work the same way
from phase 5 with their original kind 3 or 6 tuple and provider absent
or kind 2/5. All example states remain effect-ineligible.

| Negative or replay case | Required result |
| --- | --- |
| A marker COMMIT is unknown and bounded readback is missing, failed or advanced | Keep write unknown and withhold projection in that invocation. No replacement mutation, second write or rebase. A separately supplied later fixture command uses its own current-row check and leaves the old result unknown. |
| Stale predecessor after an intervening revision, with no exact latest match | Stale. No rebase or write. |
| Existing marker and a fresh marker command | Refuse, even if the marker ref is equal. An exact latest read replay only reflects the recorded result. An earlier uncertain call is not confirmed by exact latest read replay. |
| Changed original | Fixed original conflict before any progress disclosure or write. |
| Wrong RunRef or marker association | Refuse before state change. |
| Opposite terminal evidence or alternate receipt after a terminal decision | Refuse without changing the terminal row or creating another attempt. |
| Old reconciliation mutation replayed after an A/B marker or C terminal decision | Old predecessor is stale. The retained tuple is not proof of that old operation. While op 7 is still latest, exact input replays and changed input under the same mutation conflicts. |

### 15B.4 Replay, contention and uncertainty decisions

A validated original access binds issuer, caller/key, physical rowid,
codec/scope, raw PB1 binding, witness, creation time and all 14 original
descriptor fields. Reload before any projection or mutation and match all
of that identity again. It can observe a later revision of that same
original. A mutation uses the caller's exact expected revision, never an
automatically rebased one. Reject an invalid capability, malformed command
or canceled invocation before useful work. Authenticate the original and
match incoming intent before comparing/disclosing current progress. After
authentication, compare latest mutation, kind, predecessor-derived input
digest before stale-revision and transition checks. Repeat classification
on a known CAS loss. Never loop into a replacement claim or operation.

| Case | Selected result and disclosure |
| --- | --- |
| Current replay with authenticated same original, including after restart or advancement during authentication | Current validated fixture projection, with same assigned run and receipt only at phase 6. No dependency resolution or new Seal. |
| Valid observed row with changed incoming original | Fixed original conflict, no prior run/receipt or progress. |
| Latest mutation, kind and predecessor-bound input all match | Exact latest replay, even if caller's expected predecessor now appears stale. Only authenticated current projection. |
| Latest mutation ref matches, kind or input differs | Fixed mutation conflict, no prior progress or refs. |
| Expected revision differs and no latest match | Stale, with no run/receipt. No rebase or write. |
| Definite occupied-key loser or known CAS loss | Reread through repaired pooled reader. Established same-intent winner may return winner-original projection. A definite establishment loser retains Occupied with zero projection if the winner cannot be authenticated. CAS winner with exact latest op returns exact replay, not own-commit proof. Advanced unrelated mutation returns stale. Proved changed intent or mutation input conflicts as above. |
| Missing, unsupported, wrong scope, corrupt, invalid immutable/key match | Only validated absence at initial lookup permits first proposal. All others fixed refused, zero prior state and no replacement or adoption. |
| Evidenced not-applied or refused | Preserve the observed disposition, such as refusal before dispatch or a known CAS loss. A failed recovery read after write uncertainty cannot establish this disposition. |
| Read unavailable before a write | Fixed unavailable, zero record and no write. |
| Known successful write COMMIT | Known committed disposition from the write. Before projecting success, prove authorized same original and return the committed snapshot. If post-commit authentication or its read fails or is canceled, retain known commit and withhold projection. |
| Actual write attempted and COMMIT unconfirmed | Preserve write unknown after exact write-connection quarantine under existing bounded policy. Use one independent checked connection from the existing pool with repaired reader and reauthenticate the recovered original. Only exact full expected record confirms own commit. No second write, replacement mutation, rebase or automatic retry within the invocation. |
| Equivalent but different original/winner, advanced row or changed result during unknown recovery | No own-commit confirmation. Preserve write unknown, with no projection. This includes lost evidence of an earlier applied mutation after another revision. |
| Recovery read unavailable, canceled, missing, wrong-scope, corrupt or authentication refused | The earlier write remains unknown. A read-COMMIT error reports read unavailability only. Withhold projection in the invocation and issue no further semantic write. |

Exact own-commit confirmation compares every persisted field, the
physical rowid, codec/scope, immutable descriptor, revision, full latest
descriptor and all progress timestamps and facts. It follows successful
authentication and constant-time comparisons where required. Recovery starts
only after the uncertain transaction cannot reenter the pool, using existing
bounded write disposal. If no safe read is possible, preserve unknown.
Exact latest-operation replay is a separate query about the current
descriptor. Full own-COMMIT proof belongs to the invocation and its
bounded recovery. No history-wide write proof is selected.

#### K1 invocation scopes and operational gate

| Scope | Guarantee |
| --- | --- |
| One write invocation and its recovery | Preserve known commit, evidenced not-applied/refused, or unknown. Only an authenticated full expected record can confirm its own COMMIT during recovery. Unknown recovery performs no second semantic write, automatic fresh mutation, rebase or retry loop. A failed recovery withholds projection. Failed post-commit authentication withholds projection and preserves known commit. |
| Later explicit fixture command | A separately supplied command requires fresh original authentication, a new live one-use borrow and the caller's exact current expected revision and mutation input. Evaluate a new marker against the current persisted row. An absent marker does not resolve a prior unknown write. The fixture predicate does not establish the complete operational no-dispatch predicate. |
| Later authenticated fixture read | Current replay may project authenticated current fixture state. It does not resolve a prior unknown write or rewrite a known disposition. Exact latest replay describes the current descriptor, without confirming ownership of an earlier uncertain transaction. |
| Operational dispatch or restart recovery | A later explicit fixture command grants no operational permission. The selected codec-5 interpretation of §8 delegates present-state eligibility and sender proof to Operational Handoff. Fixture eligibility and write-disposition guarantees above remain unchanged. |

The fixture facade has no retained response history, extra knowledge
ledger or second attempt. Neither local memory, traces, reports, tests,
chat history nor a caller verified flag supplies operational authority.
No staged execution or provider-I/O path consumes a fixture result.

### 15B.5 Migration 4, physical constraints and compatibility

Append one literal named `private original replay and fixture claim progress`
in `sqlite_replay_progress_schema.go`. Migration source SHA-256 is
`879b24ac563d37ccdd1bdb5ec13c923b93213f2caea69a1110281796e20e667e`.
The pinned driver's exact schema-4 shape SHA-256 is
`2ae4721c8526ed9b8de35fd3acdfa31448eae9b547ba8662a22ed130035f7c15`.
Preserve literal bytes and ledger hashes 1–3, exact
shape hashes 1–3, the application ID 1163088467, and the existing checked
connection requirements: WAL, synchronous FULL, foreign keys and recursive
triggers ON, and trusted schema OFF. No disabled checking, writable
schema, ALTER in place for constraints, or new durable table.

| Schema 4 object | Exact compatibility or selected change |
| --- | --- |
| `reliable_submit_migrations` | Unchanged STRICT table, INTEGER version PK, unique non-NULL name, positive applied time, 64-character source SHA. Add ledger row 4 only after full copy proof. |
| `reliable_submit_claims` plus automatic pair index | Rebuild STRICT table under its exact name, all 47 existing columns in projection order, INTEGER PK rowid and global UNIQUE caller/key. Keep existing witness, phase/run/receipt, paired fact, retention and latest-operation constraints. Preserve the inherited reconciliation phase predicate for codecs 1–3, with a separate codec-4 historical tuple compatibility rule from §15B.3. Extend the joint codec/descriptor CHECK and active-only rule for codec 4. Keep codecs 1/2 all descriptor NULL, 3 exact initial shape. Both registry FKs retained. |
| `reliable_submit_claims_envelope_ref_unique` | Same nonpartial unique index on envelope_ref. Legacy NULLs coexist, any non-NULL ref is unique across scopes. |
| `reliable_submit_claims_no_delete` | Unconditional BEFORE DELETE abort, including managed INSERT/UPDATE OR REPLACE implicit deletes with recursive triggers. |
| `reliable_submit_claims_guard_insert_v4` | Replace v3 insert trigger. Only 3 and 4, each exact initial shape, and active distinct correct-purpose original key IDs and fingerprints in registry. Codec4 revision 1, initial phase 1/2, matching initial timestamps, all progress facts absent, op1. Preserve targeted caller/key DO NOTHING and validate the occupied winner. |
| `reliable_submit_claims_guard_update` | Keep legacy 1→2 and 2→2 branch and current protections; always reject codec3. Codec4 allows only 4→4. NULL-safe `IS NOT` immutable comparison including rowid and every original field. Check one revision increment, changed mutation ref, nondecreasing update, matching allowed operation footprint and all row checks. Require exact registry identities with active/retired state. No caller/key, terminal or receipt rewrite, owner reset or cross-codec update. |
| `reliable_submit_key_registry` | Unchanged STRICT table. ID PK with exact byte grammar, purpose 1/2, unique B32 fingerprint across purposes, state 1/2/3; preserve automatic indexes and all rows. |
| `reliable_submit_key_registry_no_delete`, `reliable_submit_key_registry_guard_insert`, `reliable_submit_key_registry_guard_update` | Exact existing definitions. No deletion, no duplicate ID/material or nonactive registration, immutable identity/purpose/fingerprint, retirement/revocation only along 1→2, 1→3, 2→3. |
| `reliable_submit_seal_use` | Unchanged STRICT table. Envelope key ID PK/FK to registry, count INTEGER 0–4,294,967,296. Preserve all rows/indexes. |
| `reliable_submit_seal_use_no_delete`, `reliable_submit_seal_use_guard_insert`, `reliable_submit_seal_use_guard_update` | Exact existing definitions. No deletion or refund, register counter at zero with active purpose-2 key, increment one only while active. |

| Authority | Checks for the codec-4 transition |
| --- | --- |
| Admission/custody | Match authenticated original/PB1 and cryptographic envelope, registry/key identity and issuer-bound access. These checks supply no progress or effect authority. |
| Go durable service | Sole semantic transition writer. Validates typed command, exact operation digest, the current fixture row for kind 1 and the first synthetic marker, same original/run and terminal evidence provenance, when-recorded observation and current full row coherence. Classifies only the invocation and its own recovery, using its own write evidence. Applies the existing phase model. |
| SQLite | Guard row/PK/descriptor immutability, revision CAS, terminal phase and receipt locks, typed storage and current row-shape relations. Protect the reconciliation tuple once present and the marker once present. Allow the codec-4 historical kind/phase/time combinations in §15B.3 while retaining the old branch for codecs 1–3. No SQL digest validation, evidence authentication, prior-response history or independent transition authority. |

Storage delta rules allow revision, update time and latest descriptor plus
only these columns per op: assignment and phase (2), intent pair (3),
staging pair (4), absent-to-present marker pair with phase unchanged (5),
provider tuple and phase (6), first reconciliation tuple and phase (7),
provider tuple/phase/receipt (8), provider tuple and phase (9). One-time
facts go only from absent to present. SQL checks row shape, nondecreasing
time and non-null fact times within creation/update, and bounded presence
and kind/phase relations. Use null-safe predicates so NULL cannot bypass a
guard. Go owns the semantic sequencing and when-recorded evidence checks.
Managed REPLACE and UPSERT cannot replace an original or bypass these
constraints. Occupied incompatible rows stay occupied at capacity.

Pristine bootstrap and ordered schema digest omit only the literal internal
seven-character `sqlite_` prefix with the pinned engine's ASCII case
comparison. Other schema objects participate in pristine and exact shape
checks. Existing digest encoding and authentic hashes remain unchanged.

Under the existing checked `BEGIN IMMEDIATE`, authenticate the actual
opening application ID, version, complete schema and ledger, or the literal
pristine state, before changing data. Preflight can refuse early. It grants
no migration authority. The validated lock-held version supplies the
recovery baseline and selects the remaining route if a competing opener
has advanced the file. An authenticated current head reached after preflight
ends the lock-only transaction with known cleanup and zero migration writes.
After known BEGIN, a pre-COMMIT exit uses a request-independent bounded
ROLLBACK. Observe the cleanup context immediately after the response and before
self-cancel. A timely successful rollback preserves the ordinary refusal. After
migration writes have begun against an authenticated lock-held baseline, an
unconfirmed rollback can reach the unpublished opener's recovery boundary if
the exact connection was discarded or ROLLBACK reports that its wrapper is
already closed. The closed-wrapper response establishes only where cleanup
ownership passes. The migration function finishes its connection ownership and
the opener checks the close result of the original unpublished pool before one
fresh checked nonmigrating observation on the caller context. That observation
alone classifies the old or current state. Withhold recovery when the borrowed
connection may still own the transaction and safe transfer is unconfirmed.
This pre-COMMIT route records zero COMMIT attempts. The same observation
boundary handles a lost response after COMMIT dispatch. A pristine empty schema
0 takes 1→2→3→4. Authentic 1 takes 2→3→4, 2 takes 3→4, 3 takes 4.
These are single atomic transactions through the selected head, including
ledger/version updates. Preserve the literal migrations' earlier
proofs. Before step 4, snapshot registry `rowid,key_id,purpose,
material_fingerprint,state`, seal-use `rowid,envelope_key_id,granted_count`
and ledger `version,name,applied_at_unix_ns,source_sha256` of rows 1–3
in transaction-local temporary tables. Drop only the three claims triggers.
Rename the old claims table to `reliable_submit_claims_v3` as in migration
3. Neither registry nor seal-use depends on claims, and no retained trigger
reads that table. Create the target under the canonical name. Copy explicit
`claim_rowid` and all 46 named columns in the 15A projection order, with
the 14 descriptor columns following the inherited 32. Prove counts and
both full-row EXCEPT directions for claims, using binary collation on text
and exact storage types. Prove the same for all captured registry, counter
and ledger rows, including actual row identities and per-key/aggregate
counts. An in-transaction CHECK assertion with 0/1 and ABORT makes any
mismatch fatal. Do not reapply active-key eligibility to carried rows or
touch sealed files. Drop old table and assertion objects, recreate the
claims index and three triggers, record ledger 4 and user_version 4.
Before COMMIT verify exact shape digest, ledger and application ID, zero
foreign_key_check rows and no scratch object. No intermediate shape is
published. Preserve private file/database authority and size checks.

| Migration/open case | Result |
| --- | --- |
| Authentic pristine 0 or authentic 1/2/3 | Selected atomic path above, prove full old state carried except required new schema/ledger rows. Authentic 4 opens without migration. |
| Unsupported app/version/shape/ledger, downgrade, nonempty version 0, or corrupt/foreign state | Refuse before writes. No automatic repair/adoption. |
| Pre-COMMIT failure and confirmed rollback | Preserve exact opening schema/data, no handle or authority. |
| Known COMMIT | Accept exact new head after all checks. |
| Lost COMMIT response or unconfirmed pre-COMMIT rollback eligible for pool disposition | Check closure of the original unpublished pool, then classify one fresh checked nonmigrating open. Exact authenticated current shape/ledger/app/FKs with quick check accepts the observed current head. Exact authenticated recorded old shape (or pristine empty 0) returns recovered-old refusal and closes the observation pool. Intermediate, unreadable, malformed, canceled, close failure, or any other version returns unavailable. Recovery issues no migration retry. |

Older binaries' refusals remain distinct. The historical PB1/schema-2
`TestSQLiteV3OldBinaryRefusesWithoutMutation` keeps its purpose and uses
an authentic schema-3 target fixed independently of the current opener.
The repo contains its invocation. Preserve the retained authenticated
historical PB1 binary, its bound harness/source provenance and authentic
schema-3 fixture. This slice does not rebuild or relabel either artifact.
Phase 4 adds a distinct schema-3 binary probe built from official
`f1aa8b934cc26c16a966a110c7b408abdaeadce7` and full tree
`8dd27f9acba98ed70d93736bdef8300ef1aba53f` plus an enumerated one-test
harness. Build only from the complete pinned external `SCHEMA3_SOURCE`
export and a one-entry overlay, as specified in §15B.7. Qualify the fully
populated schema-4 target before invoking the old opener. Compare full
logical before/after plus version, ledger, shape, key/grant data and object
files via nonmigrating reads. Fixture upgrade requires prior-version
handles to be closed. Mixed old/new binary operation on one root is outside this selection.
A schema-2 binary result cannot qualify this schema-3 binary. Physical
file byte equality and physical-close behavior are distinct from logical
row preservation. No binary is built in the contract turn.

### 15B.5A Shared fixture object allocator and budget boundaries

At the pinned base `PublishSealedSynthetic` checks object count and then
does its exclusive create outside a SQLite transaction
(`replay_custody_file.go:399–435`). The count/create protocol below is a
new cross-scope custody boundary. Both `PublishSealedSynthetic` (scope 1)
and `PublishProgressOriginal` (scope 2) call the same unexported
`allocateReplayObject` in `replay_custody_file.go` on the same qualified
fixture root, its fixed object namespace and its checked SQLite domain.
A custody handle owns the filesystem checks and allocated descriptor.
The existing checked store connection supplies the writer lock. No raw
transaction or descriptor crosses the facade. The prior-version handle
exclusion applies. The protocol qualifies cooperating handles and
processes on the same unchanged database/root. It does not extend to
mixed old binaries, unmanaged filesystem writers or undetected
out-of-band database replacement.

| Allocation boundary | Required action and disposition |
| --- | --- |
| Publisher entry | Check custody/permit/frozen identity and request before allocation. Scope 1 first qualifies custody/parents, the frozen value and permit presence. Then arrange irreversible burn before checking permit ownership or allocation. Scope 2 retains its wrapper burn rules. The allocator itself neither consumes a permit nor changes a grant. |
| Acquire and establish release ownership | Acquire one exact connection via `c.store.checkedConn(ctx)`. Install an allocator-local release guard before BEGIN dispatch. If canceled before dispatch, normally release any unused connection and refuse. An acquisition or qualification error also refuses. |
| BEGIN dispatched | On the caller context issue exactly one raw `BEGIN IMMEDIATE` on that connection. A nil response enters the known-open critical section. An uncertain response forbids ordinary release and goes to exact discard, with no ROLLBACK or second BEGIN. |
| Count and exclusive create | In the known transaction, validate the held and visible root/objects/v1 identity chain. Count every name other than dot entries on a fresh no-follow descriptor for that same directory, reading at most 33 names. Inert and orphan names count. At 32 or more, refuse. Below that bound, use only the preselected validated basename and one descriptor-relative `Openat(O_CREAT\|O_EXCL\|O_RDWR\|O_NOFOLLOW\|O_CLOEXEC, 0600)`. Collision, I/O failure, suspected drift or observed cancellation refuses, without retry or adopting the name. |
| Record descriptor ownership | Own any created FD immediately, before checks or cancellation branches. Normalize mode only on that freshly owned FD. Require a regular empty owner/group-matching file with mode 0600 and link count 1. Compare held FD and no-follow visible name by device/inode, owner/group, type, mode and link count. Verify the directory identity chain. Close the count descriptor on every path. |
| End known-open transaction | The allocator performs no DML and never issues COMMIT. On every known-BEGIN exit, use a request-independent private five-second `ROLLBACK` on that connection. Observe the return and `cleanupCtx.Err()` immediately before self-cancel. Nil response with no observed expiry/cancellation proves transaction end. Confirm ordinary wrapper return. A canceled request or failed wrapper return still refuses publication. |
| Uncertain BEGIN or end | Disable ordinary release. Use the existing exact-connection discard primitive. Permit one real synchronous rescue on that same connection if first response unconfirmed. If both unconfirmed, withhold ordinary `Conn.Close`. Read/transaction disposition for allocation is fixed unavailable, including nil rollback response after observed expiry. Confirmed quarantine does not rescue this allocation. |
| Refusal after create | Close every owned FD once, clearing ownership before close. Do not remove the name. An entry left by exclusive create is an inert counted orphan even if SQLite rolled back or its end was unconfirmed. No descriptor handoff, usable publication, Seal, claim, adoption, reuse or refund. A close error refuses and supplies no physical-close proof. |
| Successful handoff | Only after confirmed rollback and ordinary wrapper return, recheck live request and same held/visible file and directory identities. Transfer the sole unpublished FD to the existing publisher, which owns every remaining close. Then run the existing permit consumption, active key check and Seal/write/fsync/checked close/reopen/verify path outside the lock. |

Only count, exclusive create and their local identity checks are inside the
critical section. No external callbacks, material acquisition, encryption,
file write/fsync, grant transaction, claim establishment or CAS runs there.
The cleanup deadline bounds the context observation. It does not guarantee
OS close or a universal unblock time. No new lock file, retry loop, disposer
or registry is selected. The scope-1 implementation is limited to this
shared allocation and its call-site lifecycle. Keep codec-3 format, immutable
rows, key/grant rules and `loadClaimFresh` callers and lifetime. Keep A1/O2/C1/D1
and shared SQLite helpers. Failing behavior or missing required resource
qualification refuses at the boundary without OS-label fallback.

| Shared bound | Enforcement and exact claim |
| --- | --- |
| Four custody-bearing claim slots | The existing establish writer transaction classifies caller/key occupation first, counts all codec-3/4 rows, and inserts a new unique claim only below four. All progress phases count. At capacity, existing keys still receive their usual occupied/same-intent/conflict handling. |
| 32 object names | `allocateReplayObject` serializes count plus exclusive create across compliant same-domain publishers. The bound counts all existing directory names including orphans during a qualified operation. It is not proof of orphan persistence through an unsynced crash or of a cap under unmanaged insertion or replacement. |
| 32 aggregate durable reservations | Existing `reserveReplaySealUse` checked writer transaction applies the aggregate limit across both selectors using the fixture profile. Only known COMMIT issues a permit. Migration or failed allocation never refunds or resets an issued reservation. |
| 2^32 reservations per envelope key | Same reservation transaction and shared registry identity/fingerprint and counter constraints. No fresh namespace or reset on scope change, retirement or failure. |
| 16 MiB database/sidecar budget | Existing `checkReplayDBFiles` checks the sum of the DB, -wal, -shm and -journal at fixture validation boundaries and refuses on unsafe metadata or observed overrun. This is a detection check, not a hard real-time ceiling. A later budget refusal cannot rewrite the known or unknown status of an earlier write. |

### 15B.6 Prospective source and test map

Phase 0 reviews this contract. Phase 1 repairs the local pooled reader and
binds its regression. Phase 2 implements codec/scope, format and schema.
Phase 3 implements durable successors and the private composition. Phase 4
validates restart, concurrency, unknown outcomes and no-effect boundaries.
Phase 5 is one fresh independent acceptance audit of the integrated exact
source. These phases select one source acceptance target. Prefix `I/`
denotes `es/admission/internal/reliablesubmit/`,
and `A/` denotes `es/admission/`. New paths are explicit.

| Phase and path (owner) | Edit class, constraint and validation |
| --- | --- |
| 1, 2, 3 `I/sqlite_store.go` (SQLite) | Scope cleanup to pooled `loadClaim` first, add local fault points and keep current `loadClaimFresh`, O2 and shared helper behavior. Later add exact codec4 scan/rowid, head gates, targeted insert/claim budget and dedicated protected CAS. Tests P, M, T, U below. |
| 2/3 `I/durable_record.go`, `I/durable_operation.go` (durable model) | Strict v4 codec/descriptor and clone/equality, codec-specific historical reconciliation compatibility, v4 establishment/marker input binding and same-authority successor path. Keep codec1/2 and codec3 encodings, exact legacy predicates and golden digests. T, F. |
| 2 `I/sqlite_replay_claim.go` (SQLite record) | Add explicit tuple/initial op and exact descriptor validation. Keep old constructor, object/key syntax and codec3 establishment digest. M, T, F. |
| 2 `I/sqlite_migrations.go`, new `I/sqlite_replay_progress_schema.go`, `I/sqlite_replay_shape.go` (SQLite) | Append literal, exact shape 4 and codec-4-only SQL storage/tuple compatibility. Preserve `I/sqlite_replay_schema.go`, inherited branch and literal/shape hashes 1–3. M, T. |
| 2/3 `I/replay_custody_format.go`, `I/replay_custody_structure.go` (custody format) | Closed version dispatch and bounded typed structural projection. Preserve codec3 wire data and strict sizes. F. |
| 2/3 `I/replay_custody_file.go` (custody) | Add finite fixture facade, scope selection and shared `allocateReplayObject` called by both publishers, with allocator-local transaction and FD ownership. Preserve verification, lifetime and fresh-reader use outside this allocation change. F, R, U, N, L. |
| 3 `I/durable_service.go` (durable progress) | Add original-bound codec4 path, current-row fixture marker and terminal checks, historical observation preservation and exact per-invocation write recovery. Preserve legacy caller policies and codec3 refusal. T, U. |
| 2/3 `A/reliable_submit_replay_format.go`, `A/reliable_submit_replay_hydration.go`, `A/reliable_submit_replay_private.go` (admission) | Produce/interpret scope2 typed original and exact PB1 from same delivery, add one private composition path. Preserve codec3 and leave `A/reliable_submit_replay_intent.go`, PB1 binding sources and `I/model.go` / `I/store.go` byte-identical. R, F, N. |
| 1 new `I/sqlite_pooled_claim_read_cleanup_test.go` (SQLite tests) | Bind real transactions and old/new same-regression instrument, assert safe same-store follow-ups. P. |
| 2/3/4 new `I/replay_progress_test.go` (custody/storage tests) | Independent vectors, all v4 transitions/facts and corruption matrix, restart, unknown write and original preservation. F, T, U. |
| 3/4 `I/replay_custody_file_test.go` (custody and SQLite boundary) | Add shared allocator tests and a local child helper for independent process contention. Preserve existing fault, identity and normal publisher regression tests. L. |
| 2 `I/sqlite_store_test.go`, `I/sqlite_physical_test.go` (storage tests) | Codec3+1 at store lines 545, 620, 649 and physical line 128 currently means unknown codec 4. Select literal unsupported 5 there and add malformed 4 separately. Update intentional current insert-trigger drops at store lines 651 and 756 and physical line 130 to v4 name. Keep v2 invalid NULL/empty and schema 99 cases, old CAS test and targeted conflicts. M, T. |
| 2 `I/sqlite_replay_migration_test.go` (migration tests) | Target head-dependent bootstrap/from-1/from-2/precommit/known-response-loss cases at explicit 4, add opening 3 and 47-field/full key/counter/ledger witnesses. Preserve existing legacy fixture projection width 33 for authentic seeds and old-or-new rollback assertions. M. |
| 2/4 `I/sqlite_replay_shape_test.go` (shape/probe tests) | Split explicit 1–3 from fourth exact shape digest, no three-entry array indexed by migration4. Retain historical PB1 test identity and fix its target/readback to exact schema3 using historical literal fixtures. Add independent schema3 probe invocation and schema4 logical witness. M. |
| 3/4 `I/guardrails_test.go`, `A/reliable_submit_guardrails_test.go` (private reachability) | Extend finite exports, typed semantic caller/source graph inventories and rejection mutants. Keep sensitive payload, no-runtime, no-config and no-public guards. N. |
| 3/4 conditional `A/workstream_c_guardrails_test.go` (existing exact inventories) | Preserve resolver, semantic plan/material hydration and aggregate caller counts. Update the synchronized-field inventory for the per-custody close lock and invocation-local view, attempt and access lifetime flags. Bind exact references to the shared publisher and the two permit wrappers. Keep package-state, namespace registry and runtime exclusion unchanged. N. |
| 3/4 `A/reliable_submit_replay_private_test.go` (composition tests) | Exercise genuine same parsed delivery and replay/refusal on real storage; preserve the old scope tests. R, N. |
| 2–4 `PLANS.md`, the three owning lifecycle docs of this contract and `docs_contract_test.go` (owner/status) | Report verified source phase and retain owner tables. Update the root test's current schema-3 source literal expectation at line 4043 to head 4 only when implementation lands. Preserve current codec3 and public refusal assertions and historical ledger/shape checks. |

Appendix A's suggested `I/replay_key_use_sqlite.go` change is unnecessary.
Reuse its exact existing permit issuer/consumption, key lifecycle/checks and
grant counters with the new frozen digest and distinct opaque wrappers.
Its A1 read body remains unchanged. Appendix A omits the legacy corruption,
migration/shape/old-probe, admission typed guard and root doc test impact
listed above. `I/store_conformance_test.go`'s codec2+1 is still deliberately
malformed codec3, never an unsupported-4 fixture. `I/sqlite_replay_schema_test.go`
continues proving the codec3 shape and replacement guards against head 4;
new v4 cases live in the named progress test. Keep the existing
`I/durable_record_test.go`, `I/durable_operation_test.go`,
`I/durable_service_test.go`, `I/sqlite_replay_claim_test.go`,
`I/replay_key_use_sqlite_test.go` and `I/replay_custody_format_test.go`
as regression evidence. Preserve existing tests in
`I/replay_custody_file_test.go` alongside the named new cases. Existing v1 golden
testdata and historical production-source probes are preserved.

#### Consolidated repair path map

| Path | Selected refinement |
| --- | --- |
| `I/sqlite_store.go`, `I/sqlite_replay_shape.go` | One lock-held migration decision and literal internal namespace. Preserve all migration literals, digests and shared reader/disposal helpers. |
| `I/replay_custody_file.go` | Revalidate confirmation keys and borrow lifetime at projection. Restore scope-1 preflight before burn while preserving both allocator call sites. |
| `I/durable_service.go` | Check current predicates for fresh reconciliation, and bound explicit terminal assertions in the existing semantic service. |
| `A/reliable_submit_replay_private.go` | Map failed winner disclosure to the already known occupied outcome in the definite-loser branch. |
| `I/sqlite_replay_migration_test.go`, `I/sqlite_replay_shape_test.go`, `I/replay_custody_file_test.go`, `I/replay_progress_test.go`, `A/reliable_submit_replay_private_test.go` | Maintained regression parents for lock-held opening, literal namespace, scope-1 preflight, confirmation, reconciliation, terminal evidence, and occupied disposition. |
| `I/guardrails_test.go`, `A/reliable_submit_guardrails_test.go`, `A/workstream_c_guardrails_test.go` (conditional inventory only) | Bind the two terminal evidence constructors, their finite aggregate and caller sites, and exact permit reference changes at the publication preflight. Preserve existing negative mutants and package-state, routing and effect exclusions. |

The admission lost-response witness adds two test-only sources in a private
external view of the authenticated candidate. Its internal bridge attaches
and restores the exact fixture store's existing COMMIT-response seam. It
executes real COMMIT, reports the modeled response failure and can cancel
recovery. It adds no product interface or production bytes. The admission
parent `TestPrivateReplayProgressAdmissionUnknownNoEffects` observes
establishment and mutation, unavailable and exact authenticated readback,
and a later current read. It requires one write per faulted invocation and
zero effect contacts under the admission counters. The ordinary suite
uses the checkout without the bridge.

### 15B.7 Acceptance by test identity

Tests below use isolated owner-only fixture roots, real SQLite and sealed
files where indicated. Faults are private test controls, nil by default.
Exclude production config, dependencies that contact live services and
process-wide FD-count assertions.

| ID and exact new test parent | Fixtures and required assertions |
| --- | --- |
| P `TestSQLitePooledClaimReadCleanup` | Real single pooled connection with `CancelAfterRealBegin`, `CancelAfterRealSelect`, `AmbiguousRealBegin`, `AmbiguousReadCommit`, `RollbackError`, `ExpiredRollbackNilResponse`, `TimelyRollback`, `DoubleDiscardWithholds`, `PreDispatchCancellation`, `OrdinaryNotFound`, `OrdinaryCorrupt`. Drive actual deadlines including nil-response-after-expiry, first discard failure/rescue and double-uncertain bounded scope. Confirm zero record on cleanup uncertainty, fixed tables and no post-COMMIT rollback or retry. Disconnect injections then prove fresh-context same-store read and CAS before teardown whenever quarantine was confirmed or no transaction dispatched. In the withholding case prove no ordinary close, with no same-store availability assumption. Preserve complete row equality around reads. Run identical test and instrumentation bytes on pinned old reader and repaired reader in separate fixtures, retaining old observation/failure and new pass. |
| F `TestPrivateReplayProgressFormatVectors` | Independently construct fixed bytes for both payload/header/AAD shapes, HMACs, permit/establishment digests and deterministic external AEAD ciphertext for validation only. Reject format/codecs/scope mix, ref swap, key/fingerprint mix, invalid marker, widths/presence/order/depth/node/allocation/corruption and trailing bytes. Compare exact domains and parser limits, preserve codec3 golden inputs and PB1. |
| R `TestPrivateReplayProgressAdmissionReplay` | Real SQLite/files. Same original after restart with deliberately changed defaults, material and active key plus retained original keys. Zero resolver/material/current-key/new-seal calls on hit. Changed intent discloses no refs. Cross-scope occupation refuses, deterministic initial winner under barrier, genuine negative and occupied/cap cases. |
| T `TestPrivateReplayProgressTransitions` | Independent fixtures for all allowed initial phases, transition and enum branches, incompatible joint facts, `FixtureNoMarkerThenFirstMarkerAfterRestart`, `NonterminalReconciliationThenPositiveAcceptedAfterRestart`, `NonterminalReconciliationThenPositiveNotAcceptedAfterRestart`, `HistoricalReconciliationProviderProgress` and `TerminalReconciliationAndContradictions`, terminal receipt stability, one RunRef, no op10. Compare physical rowid/all immutable fields and envelope bytes after each success and failure. Validate malformed4, unknown5, raw alias, wrong scope/format, NULL/empty, copied/foreign/closed bearer and attempted legacy use. Shared cap and no slot reuse. |
| U `TestPrivateReplayProgressConcurrencyAndCommitOutcome` | Advance between authentication and progress read/CAS with two handles. Exercise exact latest replay, same mutation changed kind/input, stale/advanced, distinct authenticated equivalent winner, full own COMMIT confirmation and restart. Inject precommit failure, actual commit with lost reply and unavailable/corrupt/canceled/missing/wrong-scope recovery reads. Compare full durable record and operation count. Include `UnknownMarkerCommitDoesNotRetryWithinInvocation`, `IndistinguishableRestartHistoriesHaveSameFixtureEligibility`, `ExplicitLaterFixtureCommandDoesNotConfirmPriorUnknown`, `CurrentReplayDoesNotConfirmPriorUnknown`, `StaleMarkerAndLateReconciliationReplay`, `ExistingMarkerExactReplayOnly` and `WrongOriginalOrRunCannotAdvance`. Count an explicitly supplied later fixture command separately. Assert equal A/B retained rows and eligibility, preserved prior dispositions and zero effects. The unresolved invocation issues no second write or projection, including on an advanced winner. |
| L `TestPrivateReplaySharedObjectAllocation` | `CrossSelectorFinalSlotTwoHandles` and `CrossSelectorFinalSlotHelperProcess` seed 31 inert names, reserve two real permits and contend through both selectors for the last slot. Exactly one verified object, no 33rd name. `CancelAfterExclusiveCreate`, `AmbiguousBegin`, `AmbiguousRollbackAfterExclusiveCreate`, `ExpiredRollbackNilResponse`, `DiscardRescue` and `DoubleDiscardWithholds` assert exact connection/FD disposition, inert counted orphan where created, burned permit, unchanged already-issued counts, no Seal/claim/refund on refusal and subsequent work after confirmed release/quarantine. `NormalPublishersVerify` checks existing verified custody behavior with both normal publishers. The sole child control is `TestPrivateReplayObjectAllocatorHelperProcess`, selected only by the parent test across an independent process. Keep `TestReplayPublicationFaultAndIdentity`. |
| M `TestSQLiteV4MigrationPreservesFullState` | Authentic 0/1/2/3 seeds, historical 1/2 and codec3 rows, populated active/retired/revoked keys and usage counts. Compare complete typed physical/logical row sets and ledger hashes before/after. Inject rollback, failure after actual COMMIT, bad/intermediate/recovery failures. Assert forbidden downgrade, replace/UPSERT/deletion/reinsert/immutable rewrites, legitimate historical CAS, codec3 construction/initial-only and grant continuity. |
| M `TestSQLiteV4PreviousSchema3BinaryRefusesWithoutMutation` | Build exact schema3 tree plus external test-only overlay `previous_schema3_probe_test.go` with sole `TestPreviousSchema3OpenerProbe`. It invokes actual old opener on `ES_REPLAY_SCHEMA3_TARGET`, asserts unsupported and prints `SCHEMA3_REFUSED_SCHEMA4`. Bind binary via `ES_REPLAY_SCHEMA3_PROBE`. Compare complete nonmigrating logical witnesses pre/post with populated rows of each codec and original objects. Separately run original PB1 historical probe on schema3 target. |
| N `TestPrivateReplayProgressHasNoEffectPaths` | Existing guard files and finite allowlists plus negative mutants for direct/transitive runtime/provider/staging/startup/public projection. In fixture behavior use counter-backed fail-on-contact provider/runtime/staging/live credential boundaries. Immutable fixture status cannot provide a nominal or structural operational handle. Include matched, mismatched, accepted, unknown, cancellation and incompatible cases. Run authentic baseline App/API refusal and existing unkeyed compatibility tests. |

Prospective validation uses pinned Go and readonly cached modules. After
phase 1, run the pooled test alone, retain targeted old/new source and
instrumentation hashes. At integration, the exact focused commands (with
private fixture paths for authenticated probes) are:

```sh
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=180s -run '^TestSQLitePooledClaimReadCleanup$' ./es/admission/internal/reliablesubmit
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=180s -run '^(TestPrivateReplaySharedObjectAllocation|TestReplayPublicationFaultAndIdentity|TestPrivateReplayProgressFormatVectors|TestPrivateReplayProgressTransitions|TestPrivateReplayProgressConcurrencyAndCommitOutcome|TestSQLiteV4MigrationPreservesFullState|TestSQLiteV4PreviousSchema3BinaryRefusesWithoutMutation|TestSQLiteV3OldBinaryRefusesWithoutMutation|TestSQLiteLegacyCASConnectionCleanup|TestReplayOriginalKeyReadCleanup|TestReplayGrantC1PreCommitConnectionQuarantine|TestReplayGrantD1BeginResponseLossQuarantine|TestReplayKeyStateD1BeginResponseLossQuarantine)$' ./es/admission/internal/reliablesubmit
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=180s -run '^(TestPrivateReplayProgressAdmissionReplay|TestPrivateReplayProgressHasNoEffectPaths|TestReliableSubmitFoundationHasNoRuntimeWiring|TestReliableSubmitBindingProducerHasNoProductionCaller|TestPrepareRequestShapeRemainsLegacyAndUnkeyed|TestResolvedSubmitLegacyEquivalenceOneNomadRegistrationAndAuthorityRecovery)$' ./es/admission
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=180s -run '^(TestWorkstreamCContractPrepareAndSubmitRemainSeparatedAtAPIBoundary|TestSubmitPublicRouteRejectsStructuralReliableBody)$' ./es/api ./es/app
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=600s ./es/admission/internal/reliablesubmit ./es/admission ./es/api ./es/app
"$GO" test -mod=readonly -count=1 -p=1 -json -timeout=600s ./...
```

The previous-schema-3 build uses `SCHEMA3_SOURCE`, a complete external
source export of the pinned PR #10 commit and tree. Verify all 427 leaves
by committed path, mode, blob, byte count and SHA-256. Use one external
Go overlay JSON whose sole Replace entry maps the absent
`es/admission/internal/reliablesubmit/previous_schema3_probe_test.go`
under that export to the absolute external harness source. Bind that JSON
and harness, toolchain, argv, workspace-off cached module graph and every
actual compiled source, module metadata and embed input by path and bytes.
Include compiler and resolved paths/environment in the evidence. Path
or environment differences affect binary reproducibility separately from
source identity. No product inputs come from the schema-4 candidate.

```sh
(
  cd "$SCHEMA3_SOURCE" || exit
  "$GO" test -mod=readonly -overlay "$SCHEMA3_OVERLAY" -c -o "$SCHEMA3_PROBE" ./es/admission/internal/reliablesubmit
)
ES_REPLAY_SCHEMA3_TARGET="$SCHEMA4_TARGET" "$SCHEMA3_PROBE" '-test.run=^TestPreviousSchema3OpenerProbe$' -test.v
```

`SCHEMA3_SOURCE`, `SCHEMA3_OVERLAY`, `SCHEMA3_PROBE` and `SCHEMA4_TARGET`
are absolute independent paths. Bind the binary before use. The separately
constructed schema4 target exists and has its full nonmigrating witness
recorded before the old opener runs. The schema4 test verifies afterward
with a nonmigrating reader. Bind both witness records.
Retain the historical PB1 binary/harness provenance and selection
`-test.run=^TestOldPB1OpenerProbe$ -test.v` separately. Run all selected
go test parents and required subtests, record JSON outcomes/skips by
identity, require no skip for the new bounded paths, and explain all changed
skips against baseline. Package and full-tree runs protect neighboring
contracts; historical native/host evidence has its original authority and
does not qualify this source's runtime. Use capability-based validation at
the established file/open boundaries. No OS-label fallback. Command results
belong to a separately bound source generation and evidence record.

Operational ingress, authenticated SPIFFE choice, state-path and key loader,
production image/host and first-effect authorization, creation-only provider
registration, correlated recovery, public responses, backup/restore and
deployment remain later decisions. Neither compatible fixture keys nor a
fixture accepted/receipt result qualifies any of them.

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
- no multi-host or HA claim;
- no history-wide replay or mutation-history store;
- no public replay DTO or public reliable-submit endpoint;
- no PostgreSQL backend implementation.

Open decisions:

- exact reliable-submit state-path config key;
- exact TTL, tombstone, garbage-collection, archival, and repair policy;
- exact caller namespace source wiring at the authenticated request boundary;
- operational replay-envelope/key custody, including production key epoch,
  restore/rollback, TTL/GC and residence choices; the bounded codec-3
  synthetic custody in section 15A does not answer those deployment gates;
- exact Nomad reconciliation query and evidence rules;
- exact public receipt, recovery, HTTP status, and error vocabulary;
- exact runtime submit integration tranche.

A future PostgreSQL backend may implement the same private claim-store port and
shared conformance suite only after a separately accepted requirement justifies
managed database operation. That later backend must preserve active claims,
tombstones, immutable `RunRef` values, receipts, revisions, effect facts,
ambiguity, and no-reuse semantics through a separate contract and audit.
