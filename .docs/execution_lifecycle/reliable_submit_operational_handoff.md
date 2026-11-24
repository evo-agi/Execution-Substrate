# Reliable Submit Operational Handoff Owner Contract

## 1. Status and precedence

| Class | Scope |
| --- | --- |
| Current invariant | Codecs 1/2, immutable codec 3, fixture-only codec 4, structural public keyed-request refusal and ordinary unkeyed Submit retain their meanings. ES owns its durable facts, Nomad its scheduling and execution observations, and Coordinator semantic acceptance. |
| Selected target | Re-derivation of the reliable-submit Reopened redesign seam. A single private handoff across durable CAS, exclusive staging, one-use dispatch and positive receipt recovery. PR #12 published the private schema-5 source at `8058561` as an open pull request; schema 5 is unmerged, stays on the reopened seam and is not a Current invariant. Independent source acceptance and native qualification are separate later gates. |
| Re-derivation in this repair | Repair PR #12's retained-current-admission omission with a v2 signed-evidence original, one durable admission row compared under the SQLite writer lock at every first-effect cut, a commissioned Service-owned view of that row, and a confirmation deadline. `operational_local_v1` is removed. The repair is a committed draft-PR candidate awaiting fresh independent audit and red-team review. |
| Proof only | Real local SQLite and actual descriptor-relative fixture staging with two independent handles/processes, provisioned test keys and a counting loopback provider through the same private composition. Four operational claim slots, 32 object names, and 32 aggregate nonrefundable reservations. |
| Native prerequisite | Governed Ubuntu 24.04 Linux arm64 supported-local, one ES installation and exact authorized SPIFFE workload identity, default-off startup, private precommissioned state, qualified transport/provider and mounts, finite retained storage, and caller-scoped lifecycle authorization. |

[Persistence ADR](reliable_submit_persistence_and_concurrency.md) owns SQLite,
CAS and migration governance, including its scoped §8 exception. [Submit and
recovery](submit_idempotency_correlation_and_recovery.md) owns caller and
disclosure policy and prior binary grammars. [Admission
model](es_execution_admission_model.md) owns composition and current source
inventories. This document owns the codec-5 specializations, transient sender
and provider proof. Apply these specializations after the referenced general
rules. §15B and §6B continue to govern codec 4.

The future execution shape is asynchronous static-script/default, one immutable
qualified image, no extra workload mounts or workload network access, and one
single-region nonperiodic, nonparameterized batch job with one group and one
task. ES still consumes the source-owned resolved plan, material and PB1
binding. Initial resolution verifies the signed material, a qualified image
digest and immutable placement. New effects from a retained original assess
its frozen inputs against current admission and installation policy with exact
agreement. Receipt replay processes only retained facts and caller authority.
The contract introduces zero CP, Coordinator or other run-truth writers.

## 2. Installation, scope and physical state

Commission one unchanged SQLite database, original custody and staging domain
with one independent random nonzero 32-byte installation ID and uint64 epoch
greater than zero, stored in the administrator-owned qualified installation
policy. The proof supplies these values as immutable injected fixture facts.
Bind the ID and epoch to the exact verified caller identity, anchored DB and
journal/sidecar directory, custody and staging parent, key registry, installed
provider identity and paths/mount mappings in §3. Retain qualified parent
descriptors. Compare visible and held directory/file identities, owner/mode,
device/mount and required capabilities at open and at each operation boundary.
A pathname, copied identity value, stale handle or empty replacement cannot
establish continuity. Qualify SQLite's local lock and durability semantics,
including journal/sidecar fidelity, and kernel descriptor-relative semantics by
behavior. Cooperating instances run one qualified release on that same local
domain and present the same admission token. The epoch names the deployment
identity of §3. Replacing trust, the provenance verifier or the built-in
policy configuration does not change the epoch; it advances the admission
generation of the admission row below. An epoch change is not implemented:
the stored installation and epoch are immutable, and a procedure for one is
the prerequisite `CP-EPOCH` of §8. Any such procedure requires withdrawing
all old effect-enabled processes and requalification before enabling new
effects.
Existing accepted receipts require a retained-original qualification for the
original epoch. Keep read qualification of earlier epochs tied to the same
unreplaced domain and retained manifests. Older epochs cannot obtain new
first-effect permission.

Replaced/rolled-back/restored/cloned data, detached or relinked roots, sidecar
loss, mixed writers, key reuse, unapproved policy changes, namespace writes
outside this contract, HA/failover and process-image cloning of a live sender
violate the proof premises. Detected violations close the affected operation.
The contract does not derive safe restoration from logical row equality.
Independent immutable policy and qualified custody are required to detect
administrative violations. Public enablement requires separate commissioning.
The current rootful supported-local profile leaves the `es:es` private-store
ownership prerequisite unsatisfied. The loopback proof establishes no installed
ownership, provider, host, mount or durability claim.

| Schema | Row codec | Scope | Operational read / write / dispatch |
| --- | --- | --- | --- |
| Historical 1–4, readable unchanged in 5 | 1/2 | SQL NULL | Occupancy only / refuse / refuse |
| 3–5 | 3 | `synthetic_nonoperational_v1` / 1 | Occupancy only / refuse / refuse |
| 4–5 | 4 | `synthetic_progress_nonoperational_v1` / 2 | Occupancy only / refuse / refuse |
| 5 | 5 | `operational_local_v2` / 3 | Exact verified original / current-admission-governed first effect / live sender only |
| Wrong, partial or unknown tuple, including the removed `operational_local_v1` literal | Any | Any | Fail closed / refuse / refuse |

Legacy and fixture APIs retain their current scopes and refuse codec 5
projections, authority and effects. Global caller/key occupation spans the
table. Occupied foreign scope projects unavailable without a run. Existing
objects, keys, permits, markers, rows and receipts cannot be promoted, relabeled
or republished as operational originals. Preserve original migration 1–4
literals, digests and application. Append migration 5, under the existing
checked opening transaction, to rebuild claims with the same 47 columns and
constraints for codecs 1–4, add codec 5 admissibility, add one partial unique BINARY BLOB-key index on `run_ref WHERE codec_version=5 AND run_ref IS NOT NULL`,
and create the one-row admission table below with its triggers.
Set and check the exact schema-5 ledger, shape, trigger/index definitions and
version under lock. Copy every field including physical rowid. Compare both
row sets with explicit BINARY text comparison and exact NULL/bytes handling
before dropping old claims. Preserve other tables, counters, global uniqueness,
and existing guarded same-scope mutations unchanged. Codec-5 triggers prevent
delete, rowid or immutable change, any nonselected transition, regression and
marker/receipt replacement. Enforce complete codec-5 invariants on hydration
and under writer CAS even where SQL constraints enforce shape. Reject partial,
unsupported, or mixed schema/ledger states without migration guessing, creation
of replacement state or fallback. Use existing opener disposal and checked
readback for unknown migration COMMIT. A fresh opener must qualify the exact
result before any operation.

Only assignment generates a RunRef. Retain its exact ASCII as a SQLite BLOB.
Target RunRef generation uses independent
32 random bytes, string form `esoh-` plus 64 lowercase hexadecimal digits,
excluding all-zero. Zero/empty run uses SQL NULL. A codec-5 RunRef collision
with any codec-5 row, including a distinct caller, refuses assignment without
another draw or reassignment. The installation reserves the `esoh-` prefix
from other writers for stage names and `esoh-job-` for provider job IDs. The
stage component is precisely the selected RunRef, and the provider job component
is `esoh-job-` plus the 64 digits. Match full component bytes. The public
run grammar and representation remain the existing contract.

### Retained columns and transitions

Use the ADR's existing field encodings and SQL representations including all
reference widths and nonempty requirements, with the following exact groups
covering 47 columns. Timestamp columns are signed positive Unix nanoseconds,
nondecreasing across a transition. Ref/time pairs change together. SQL NULL
denotes absent optional values including run and receipt.

For exactly codec 5, validate optional BLOB presence before constructing
phase or effect facts. A non-NULL RunRef has the existing 69-byte width and
operational grammar. A non-NULL receipt or fact reference has the existing
32-byte width, followed by the existing phase, kind, time and nonzero
validation. A reconciliation reference remains forbidden. Empty BLOB and
SQL NULL are distinct decoder inputs. The shared scanner and legacy codec
rules do not change.

| Group | Exact columns | Codec-5 rule |
| --- | --- | --- |
| Claim and PB1 | claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, created_at_unix_ns, codec_version | Positive rowid and valid disjoint PB1 masks. Immutable from establishment. Codec = 5. |
| Original | replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref, envelope_size, envelope_sha256, binding_key_id, binding_key_fingerprint, envelope_key_id, envelope_key_fingerprint | Immutable non-NULL exact descriptor of §3. Envelope ref is the existing random object-name grammar. Match descriptor, header and qualified physical original. |
| Phase and run | phase_tag, run_ref, assigned_at_unix_ns | 1 pending, 3 effect-capable assigned, 6 accepted. Establish 1 with run/assigned NULL, assign once to 3 with run/time. Intent, stamp and marker preserve 3. Accepted preserves run/time and changes 3 to 6. |
| Progress | effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns | Each pair begins NULL, is set once in this order while phase 3 and stays immutable. Marker is permanent. A later stage ref or marker cannot exist without every preceding pair. |
| Positive terminal | receipt_ref, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns | Kind=0 with NULL receipt/ref/time until phase 6. One atomic acceptance writes receipt and kind=3 positive ref/time. All four then immutable. |
| No negative history | reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns | Kind=0 and ref/time NULL. On marker without receipt disclose ambiguity. No durable ambiguous/no-acceptance observation, negative terminal or stage-repair mutation. |
| Retention | expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason | NULL, 1, NULL, empty text respectively. Always charged and occupied. |
| Latest operation | revision, updated_at_unix_ns, last_mutation_ref, latest_operation_kind, latest_operation_input_digest | Revision 1 on establish and +1 on each separate applied transition. Exact latest-operation replay preserves the row. Kind codes 1, 2, 3, 4, 5 and 8 across the selected transitions. Reuse existing durable-operation encoding and protected comparisons. |

For kind 1 use existing establish with immutable descriptor, kind 2 binds run,
kind 3 binds intent ref, kind 4 stage ref, kind 5 marker ref and kind 8 binds
receipt then positive observation ref. The existing operation digest uses each
existing kind-specific input plus predecessor revision under the durable service
contract. Every write compares identity, scope, current revision and exact
expected immutable and predecessor facts, before constructing the expected
post-write row and committing. Permit one durable write attempt per command.
An authenticated winner may supply its current projection, with the attempted
write disposition kept separately. Unknown outcome recovery compares the full
expected record, including latest operation and physical rowid. Exact readback
may classify the command as OwnCommitConfirmed. Advanced or mismatched state
cannot classify it. No operations 6, 7, 9 or 10 on codec 5. No alternate row
writer. Migration can rewrite physical table storage only under the existing
authority. Existing key registry/counter writers and installation commissioning
own those facts, outside claim progress. Staging custody owns files. No provider
or receipt-history mirror or new stored claim column is selected. The one
authority table is the admission row.

### Admission row

Migration 5 creates `reliable_submit_operational_admission`, a STRICT table
that can hold exactly one row. It is the durable fact behind "current
admission" for this domain.

| Column | Rule |
| --- | --- |
| `singleton` | Primary key, equal to 1. |
| `installation` | 32 bytes, not all zero. Immutable. |
| `epoch` | Integer greater than zero. Immutable. |
| `generation` | Integer greater than zero. |
| `admission_digest` | 32 bytes. |
| `state` | 1 enabled, 2 withdrawn. |
| `updated_at_unix_ns` | Positive, nondecreasing. |

Epoch and generation are stored as positive SQLite integers; a value above
2^63-1 is refused before any write. Its triggers allow no delete; an insert
only into an empty table with generation 1 and state 1; and an update only as
a withdrawal (same generation and digest, state 1 to 2) or an advance
(generation plus one, a different digest, new state 1), with installation and
epoch unchanged. A withdrawn row cannot return to enabled at the same
generation.

Two existing claim triggers gain one clause each. A codec-5 insert aborts
unless an enabled admission row exists. A codec-5 update whose latest
operation kind is not 8 aborts unless an enabled admission row exists; the
codec-5 table constraint already limits such an update to kinds 2, 3, 4 and 5.
Kind 8, accept with receipt, is not affected, and codecs 1–4 are not affected.
Migration 5 copies the earlier rows before it creates any trigger.

Because migration 5 was amended before it merged, a database that carries the
schema-5 shape published at `8058561` is refused on open, without change, by
the pinned shape digest and by the migration ledger hash. No production opener
exists, so no such database is expected outside test directories.

## 3. Original, key cuts and encodings

| Axis | Selected value |
| --- | --- |
| SQL / per-row codec / scope | 5 / 5 / 3 |
| Original intent / PB1 | 1 / 1 |
| Wrapper / payload / cipher | 3 / 3 / 1 |
| Deployment / stage / projection / evidence | Each 1 with independent literal domain labels below |

SUB §6A and §6B define the prior strict nested grammar and parser. Reuse their
exact TLV envelope field meanings, state convention, byte order and raw intent
grammar. Operational plaintext is `ESRSPAY3 || u16(3) || u32(body bytes)`
followed by `u16(11)` and ordered TLVs. IDs 1–10 are §6B top-level IDs with
these replacements: TLV 6 leaf 2 is the 32-byte qualified OCI content digest
and leaf 4 is proof kind u8=2 (installed qualification for native, explicit
fixture authority for proof), leaf 1 equals the digest-pinned resolved image,
and issuer and topology equal qualified frozen facts. TLV 7 has exact qualified
staging/results/SPIRE/datacenter strings and UID/GID. TLV 8 leaf 1 is the
ASCII literal `operational_local_v2`. TLV 9 wrapper and payload leaves are
u16=3. TLV 10 is u8=3. Each original and resolved plan contains zero additional
mount items, network false and the exact selected mode/profile/job shape.

TLV 11 uses a count of 15 followed by present ordered TLVs: (1) deployment
format u16=1, (2) installation B32, (3) epoch u64, (4) provider installation
B32, (5) endpoint TLS leaf SPKI SHA-256 B32, (6) endpoint HTTPS DNS name,
(7) port u16 1..65535, (8) region, (9) datacenter, (10) namespace,
(11) staging parent, (12) results root, (13) SPIRE socket path,
(14) provider build B32, (15) expanded Job template digest B32. B32 means
32 raw bytes, zero refused for identity/key/proof fields. Provider installation
is a separately provisioned nonzero random identity for one qualified Raft
domain. Build is SHA-256 of the commissioned installed executable. The
fixture uses independently provisioned test build and endpoint identities.
Region, datacenter and namespace match lower-case ASCII
`[a-z0-9][a-z0-9-]{0,62}` with final byte alphanumeric. DNS hostname uses
one to 253 lower-case ASCII DNS bytes with those labels, no trailing dot.
Paths in 11–13 are absolute ASCII 2..512 bytes, with each component 1..128
of `[A-Za-z0-9_.-]` other than dot/dotdot, no trailing slash, empty
component or backslash, equal to placement leaves 1–3. Placement datacenter
equals leaf 9. Fix namespace to `es-operational-v1` and require its
exclusive-writer qualification. Leaf 15 identifies one immutable versioned
template per epoch and build as specified in §6. Credential, CA private
material and secret keys are absent from TLV 11. Provision and validate the
exact peer name/pin, approved trust chain and credential separately under the
qualified policy. Frozen originals bind the SPIFFE identity through the
existing caller ref and policy's exact identity check.

Header starts with `ESRSENV3 || u16(3) || u32(header bytes) || u16(14)` and
then the same 14 present TLVs as §6B with payload=3 and scope=3. Header length is
289 plus lengths of the two key IDs and raw PB1 (292..673). AAD is
`ESRSAAD3 || raw header`. File appends AES-256-GCM's random 12-byte nonce,
plaintext ciphertext and 16-byte tag. Intent HMAC under the original
binding key is `ESRSINT3 || complete TLV 2`. Context HMAC under the same
key is `ESRSCTX3 || complete TLVs 6,7,8,11` in that order. Permit binding is
`SHA256(ESRSFRZ3 || bindingFP32 || envelopeFP32 || raw header || plaintext)`.
Envelope SHA-256 is unprefixed over the complete file. Preserve separate
key purposes and purpose-aware fingerprints (`ESRSKEY1`), strict dispatch
on all axes and constant-time protected comparisons. Accept no alternate
decoder, key search, downgrade or mixed tuple.

Require raw and decoded intent each ≤262144 bytes, JSON depth ≤8, plaintext
and aggregate retained binary leaves each ≤1048576, sealed file ≤2097152,
header ≤4096, captured component ≤262144, data string ≤65536, object depth
≤5, container depth ≤8, TLV count ≤32768, each sequence ≤8192, and existing
narrower §6A limits. Check overflow, counts, exact lengths and states before
allocation. Refuse malformed, noncanonical order, missing, duplicate, unknown,
trailing or mismatched leaves. Redact all private values as in §6B. Use only
the captured material in proof verification and stage rendering.

Authenticate same original bytes/file descriptor and row descriptor, caller,
PB1, two exact purpose-key identities/fingerprints, AEAD, commitments and
policy binding. Keep the held original and exact immutable row plus scope as
an optimistic certificate until the writer turn compares them with the
fresh row and performs bounded physical revalidation. Revalidate the exact
pair from the same SQLite registry at grant issuance, claim establishment,
pre-stage authorization and marker admission, using the selected same-row
cuts. Both must be precommissioned ACTIVE and designated as the exact permitted
operational pair by the immutable installation policy. Designation cannot
be inferred from an existing fixture registry entry. Refuse missing,
revoked, wrong-purpose or replacement keys. A failed registry check means
unavailable. Use shared
permit/counters keyed by actual key, with no fixture missing-key registration
for operational scope. Consume once, charge reservation before object
publication and retain charge or residue through failure. Publish and sync
the immutable original before claim insert, under existing custody ownership.
Two independently charged publications may yield a single claim winner. Only
the winner's descriptor may be used. A losing or uncertain invocation cannot
adopt its own object as the winner.

First-effect authorization also requires the current caller, original epoch
and current execution admission at each stage and marker boundary. Observe
key/policy cuts in the corresponding checked writers immediately before
allowing a stage attempt and applying marker. A key change after stage cut
may leave inert residue and blocks a later marker cut. Admission precedes
revocation at a serialized cut. Revocation cannot retract authority already
validly admitted or I/O already in flight. Observed cancellation, policy
withdrawal or key denial before entry burns the continuation. Receipt-only
verification and positive-receipt CAS may use the exact ACTIVE or RETIRED
pair with currently authorized caller and qualified retained original, and
confer solely read/reconciliation authority. No mixing of keys from other
objects or substitution of present resolver output for retained input.

### PR #12 v2 retained evidence and current admission

The repaired candidate keeps codec 5, scope 3, eleven outer `ESRSPAY3` fields,
and every wrapper, AAD, commitment, receipt and claim-column literal
unchanged. It amends the unmerged migration 5 to add the admission row of §2;
migrations 1–4 and their literal hashes are untouched. TLV 8 provenance leaf 1
is the authenticated ASCII literal `operational_local_v2`, and no other
literal names an operational original. Leaf 5 is the complete
signed `evidencev1.ArtifactEvidence` (Claims **and** Seal) encoded by compact
`encoding/json.Marshal` without a newline. The field is nonempty valid UTF-8
and at most 256 KiB within the existing 1 MiB original; one exported store
constant carries that cap for custody and admission. Strict typed decoding
refuses unknown members, multiple values, duplicate or noncanonical spellings,
order and whitespace by requiring exact full-record re-encoding. The evidence
contract's `CanonicalBytes` signs claims only and is not this full-record wire.
Durable custody validates the v2 leaf only as bounded opaque bytes and keeps
scope 1/2 grammar intact; for scope 3 it accepts only the v2 literal with that
opaque evidence scalar. Admission validates the evidence structure, signed
claims, signature and frozen-plan associations. The common original reader
must authenticate, decode, bind PB1 and re-encode the original without
requiring current Service trust or policy.

`operational_local_v1` is removed and is not a compatibility edge. PR #12 as
published at `8058561` could seal that literal with an empty provenance
sequence, but no production caller could create one, and a database carrying
the published schema-5 shape is refused on open. Scope-3 custody refuses the
v1 literal, the reader refuses it in its fail-closed default, the encoder
refuses an empty evidence record instead of choosing a literal, and no
production source contains the v1 literal. Unknown variants fail closed.
Maintained inert vectors independently build the full scope-3 TLV and PB1
preimage/MAC from the published `8058561` field layout for the complete
signed-v2 Claims+Seal bytes, and build the published empty-sequence v1 bytes
as a negative vector that custody and the reader must each refuse. The
expected v2 wire is compared in full with the production encoder; the common
reader and retained qualifier consume that expectation. Validly re-signed
claims mutations must first pass the configured synthetic verifier before an
association refusal is attributed to binding. Claims-syntax refusals remain
separate. A direct currently revoked signer still has a valid signature but
cannot gain a first effect.
The private full-record carriers on `preparedArtifact` and `resolvedExecution`
use owned immutable strings and redacted formatting; they do not expose the
signed record through ordinary result or provider projection formatting.

One ordinary successful `resolveExecutionForSubmit` supplies the v2 evidence.
`preparedArtifact` owns a redacted immutable full-evidence copy after its
existing discovery/evidence/request/trust checks. `resolvedExecution` carries
that copy separately from plan, material, host and PB1. The builder seals it
before claim insert, with no second resolution, ARS read, lazy fetch or
Service-wide last-evidence cache. The private 256 KiB cap does not narrow
ordinary unkeyed Submit. Bind evidence artifact/payload digests, derivation,
output, signed artifact type, target and network claims, runtime capabilities,
argv, selected default profile and full retained payload bytes to the original
intent and plan. Keep publication `IntentDigest` distinct from the reliable
request-intent commitment. `imageIssuer` is not the artifact signer. Reject
oversize or contradictory evidence before publication. An empty or missing
record refuses and never selects another literal. The carrier adds one compact
marshal of the already validated evidence to ordinary resolution. It cannot
fail an ordinary request: if the record cannot be represented the carrier
stays empty, ordinary Prepare and Submit proceed unchanged, and only the
private builder refuses.

#### Admission content, digest, token and view

"Current admission" on this path means exactly: the enabled admission row of
§2, a process whose installed view carries a token equal to that row, and a
confirmation of that view's trust with EGS inside the deadline below.

- **Admission content** is the normalized trust model, the provenance
  verifier (algorithm, key ID, public key) and the built-in policy set a
  process would use to admit.
- **Admission digest** is SHA-256 over the label `ESOHADM1` followed by
  length-framed fields: the trust model's canonical bytes, the verifier
  algorithm, key ID and public key, the number of built-in policies, and for
  each policy its identifier and, for the configured literal-deny policy,
  every configured entry in order.
- **Admission generation** is the store counter that starts at 1 and
  increases by exactly one each time the domain's admission content is
  replaced.
- **Admission token** is (installation, epoch, generation, admission digest).
  Only the store mints a nonzero token.
- **Fence**: a first-effect cut proceeds only if the presented token equals
  the enabled admission row read under the SQLite writer lock.

The digest covers trust, verifier and policy configuration. It does not cover
the compiled behaviour of the built-in policies: two different ES builds with
the same configuration present the same digest. One qualified release per
domain therefore remains a premise, named `CP-RELEASE` in §8.

Three private store operations are the only writers of the admission row.
Each is one `BEGIN IMMEDIATE` transaction and is idempotent by content, so an
unknown COMMIT outcome returns an error, the caller stays closed and calls
again.

| Operation | Rule |
| --- | --- |
| Commission | Empty table: insert generation 1 with this digest. Enabled row with the same installation, epoch and digest: adopt its generation. Anything else refuses. |
| Advance (expected generation g) | Row at generation g with a different digest, enabled or withdrawn: write generation g+1 with this digest, enabled. Row already at g+1 with this digest, enabled: success. Anything else refuses. |
| Withdraw | Enabled row with the token's installation and epoch: write withdrawn. Already withdrawn: success. The token's generation need not match, so a fenced process can still stop the domain. |

The view of a Service is installed at most once, after startup
has loaded and verified trust, by Commission or Advance for the domain's
nonzero installation and epoch. It holds the returned token and deep copies of
the normalized trust lists, provenance verifier key bytes and validated
built-in policy entries; the digest is taken over exactly those retained
lists, so what is hashed is what is enforced. The view, the latches and the
confirmation time are held by the admission state package below, not by
fields of `Service`. The verified trust publication
is bound to the original Service instance; a copied precommission Service
cannot borrow it. The retained trust JSON representation must fit the existing
256 KiB dependency response bound. Nil ordinary evaluator means its
validated configured default. A nonnil evaluator must be an exact supported
`admissionPolicySet` whose concrete members are inspected before any call;
unknown, nested or arbitrary interface implementations cannot run under a
writer. One Service cannot commission or advance twice, change realm or
reenable after its local latch. `Service.Initialize` cannot replace trust once
a view is installed, including a fetch racing commission. A process whose view
no longer equals the row is finished for first effects until it is restarted
and commissioned or advanced again; it does not adopt new content while
running. No production caller commissions, advances or withdraws.

Withdrawal sets the local latch first and then writes the durable row. It
reports success only when the durable withdrawal is confirmed; a failed or
unknown write still leaves this process closed. Withdrawal is durable and
domain-wide, and enabling again requires an advance to new content. Replacing
trust, verifier or policy advances the generation in the same epoch and does
not invalidate any original: a claim the new content allows completes, and a
claim it denies is refused as denied. None of the three operations may run
inside a writer turn, and none holds `Service.mu` or the lock of the
admission state across its store call; the view or latch changes only
outside the transaction.

Each of the three operations runs its one transaction under the custody
handle's lock in read mode (`OperationalCustody.mu`), so `Close` waits for it.
That lock is not reentrant. A call made from a callback of a borrow on the
same handle takes the read lock a second time on one goroutine, and that
deadlocks when a `Close` is waiting between the two. The three operations
must therefore be called outside every borrow of the same handle. No
production code calls them at all (§8). The proof hooks of the tests do call
them inside a borrow, and run no concurrent `Close`.

#### Where the token is checked

| Cut | Check | Serialized with the claim write |
| --- | --- | --- |
| Before establish | Local view sampled before and after composing the original, and one pooled read of the row before any reservation or publication. Hints, not the authority. | No |
| Establish turn | The presented token equals the enabled row read through the turn's connection. | Yes |
| Before run assignment, and before intent and pre-stage | Pre-check: one pooled read of the row, then the same qualification callback. It refuses before a writer turn is requested and grants nothing. | No |
| Run assignment, intent, pre-stage, stamp and first-marker turns | The store reads the row through the turn's connection and passes it to the qualification callback; the returned match must carry a token equal to that row. Then the bounded local evaluation of the retained evidence. | Yes |
| Post-COMMIT release | The row is read again on a pooled connection beside the key re-read, with the same callback and comparison. | No |
| Final sender entry | Local view only: identity, latches and confirmation deadline. | No |
| Accept with receipt, receipt reads, marked reconciliation | None. | n/a |

An advance or a withdrawal is itself a writer transaction, so it is strictly
ordered against every claim write: a claim write either committed before it
or sees it. The callback receives the stored token and compares it first, so that a
fenced process evaluates no evidence and
reports `OperationalUnavailable`; the store's own comparison stays the
authority, and a match that carries no token can never pass a first-effect
cut. The establish pooled read protects the domain's 32 nonrefundable
reservations from a process that does not know it is fenced; a change between
that read and the turn can still cost one reservation per race. The final
sender entry deliberately does not read the row: a sender minted from a marker
that committed before the advance was validly admitted. A returned withdrawal
therefore means that no later first-effect write commits on the domain; one
sender already past its release re-read may still POST.

The claim triggers of §2 make "no codec-5 first-effect progress on an
uncommissioned or withdrawn domain" a property of the store even if a caller
omits the Go comparison. They do not identify the writer; the token
comparison does.

#### Freshness

The process records the time of its last successful confirmation.
Commissioning and advancing record none, so the first use must confirm.
Confirmation runs outside every writer turn and every transaction, and holds
neither `Service.mu` nor the owner mutex while it fetches. The lock of the
admission state is held only for the read before the request and for the
write after it. At the two
pre-checks it runs inside the borrow of the original, so the custody handle's
read lock is held across the request and `OperationalCustody.Close` waits for
a request in flight, bounded by the EGS client timeout. The confirmation of a
fresh delivery holds no lock. It performs the
same fetch and signature verification as `Service.Initialize`, computes the
admission digest with the fetched trust, and compares it with the view.
Equal: the confirmation time becomes the instant sampled before the request
was sent. Different: a permanent local superseded latch is set and this
process admits nothing further, even if EGS later serves the old trust again.
A fetch or verification failure changes nothing. Confirmation is attempted at
most once per invocation and only at three points: before the first authority
sample of a fresh delivery, and before each of the two pre-checks that precede
run assignment and intent. Recovery, accepted replay, stamped retries,
receipt reads and marked reconciliation never confirm and send no trust
request.

Every use of the view requires: installed for this Service, installation and
epoch equal to the domain's, not withdrawn, not superseded, a confirmation
exists, and less than 30 seconds elapsed since it on both the monotonic and
the wall clock, with neither reading negative. The limit is a compiled
constant. Because the qualification callback samples the view at its start
and end inside the writer turn, the deadline is enforced inside the writer
without I/O. The test clock seam can only add a non-negative skew to the
elapsed time; a negative value refuses, so it cannot lengthen the deadline.
The process does not adopt new trust while running. It stops, and a restarted
process advances the generation.

Not solved here: if EGS serves an older validly signed payload, ES cannot
tell (`CP-ROLLBACK` in §8). Within one domain the generation counter still
prevents a stale process from joining or silently replacing newer content.
Ordinary unkeyed Submit is unchanged and still reads trust only at startup.

#### Admission state package

The installed view, the withdrawal and supersession latches and the time of
the last confirmation are fields of one unexported struct in the package
`es/admission/internal/admissionstate`, under that package's own read-write
lock. `Service.mu` does not cover them. The package is one production file.
It imports neither `reflect`, `unsafe` nor `C` and performs no I/O, and
while it holds its lock it calls no function that a caller supplied.

Two handle types leave the package: the state of one Service and one
installed view. Each is a struct whose only field is an unexported pointer
to an unexported struct. `NewService` makes the state once, for that
Service, and keeps the handle in the unexported field `Service.operational`.
A Service built any other way holds the zero handle, which is closed: it
answers no to every question and installs nothing. Every method of the
state takes the owner and serves only the Service the state was made for,
so a copy of a Service borrows nothing; the one exception is the question
whether the state was ever commissioned, which a copy is answered like the
original. The package owns every rule of this section that needs no I/O:
at most one view, a token that names the installation, the epoch and the
digest of exactly the content installed, two latches that nothing clears, a
confirmation time that only moves forward, and the deadline arithmetic. The
admission digest is computed there, over the content the view holds.

Admission content crosses the package boundary as plain data: the
normalized trust lists, the verifier's algorithm, key ID and public key, and
each selected built-in policy by its identifier with its configured entries
in order. It is copied on the way in and on every way out, so no caller
holds memory that a view enforces. `es/admission` maps its built-in policy
set to that form and back, and builds the set from the view for every
evaluation, so what is evaluated is what the digest names. A policy the
mapping does not know refuses in both directions.

Outside the package the following do not compile. A test holds that by
type-checking each form against the real packages for all three build
targets, beside controls that pass. It uses the type checker of the standard
library (`go/types`), which follows the same language rules as the compiler;
it does not run the compiler itself. The forms:

- a selection of a field of the state, of a view or of either handle;
- the name of either struct type, in a declaration, a literal, a conversion
  or a constraint;
- a handle literal that sets its pointer;
- a conversion of a handle, or of a pointer to one, to a struct type of the
  same shape written elsewhere, because an unexported field name of another
  package is a different name;
- a copy, an overwrite or a restore of the state's value, because no
  expression outside the package has that type.

For these two struct types the whole-value, mirror and type-parameter rules
of the guard below are therefore implied by the compiler outside the
package. They stay in force for every other owning type, and inside the
package.

Two things remain possible outside the package, and the guard below holds
both by exact inventories. The first is a call of an exported function or
method of the package, which Go's `internal` rule limits to `es/admission`
and the packages below it. A call cannot clear a latch, move the
confirmation time back or install a second view. A wrong call can still
install, withdraw or record a confirmation at a place no review put it, for
example a confirmation that asked nobody. The second is an assignment of the
whole handle `Service.operational`, which only `es/admission` can write. A
handle saved earlier names the same state and restores nothing. A new handle
from the constructor, or the zero handle, is a state without a view: like a
restarted process it has forgotten the local latches, it admits nothing
until a view is installed in it with a token of the store for its content,
and its first use must confirm with EGS.

The package boundary does not hold against reflection or `unsafe`. A
`reflect` value reached from a handle can be made settable without an
`unsafe` import, and the red-team tests rewrite a view that way. Those
roads stay with the import inventory below.

Neither the package boundary nor any inventory below holds against code that
writes the memory of its own process without going through the language. The
compiler and the inventories read Go source, and such code needs none of the
forms they look for. The fifth audit showed it on linux/amd64 with one
production function that opens `/proc/self/mem` and writes at the address of
the state: the withdrawal latch of a withdrawn Service was cleared, and its
check of current admission answered true again. The function imports neither
`reflect`, `unsafe` nor `C`, names no protected field, and in its form with
`syscall` changes the result of no test. No source inventory can hold that
road in general, because the path can be put together at run time and the
operating system offers other ways to the same memory. By reasoning, not by
measurement, the same is true of a data race that breaks Go's memory safety
and of code loaded at run time. Every production file of the module and
every dependency is therefore inside the trust boundary of the admission
state. The boundary is one of the language, not of the process: nothing may
rely on it against code of lower trust in the same process. A control
against such code would have to come from the operating system, and none is
claimed here.

The other ways to that memory are system calls. A raw system call through
`syscall` or `golang.org/x/sys/unix`, a write to `/proc/self/mem` through
`os`, `ptrace`, `process_vm_writev`, a mapping or a shared memory segment
placed over memory in use, and a process started for the purpose all reach
the memory of the process through the kernel, and all belong to this limit.
The fifth audit measured the write to `/proc/self/mem`; the others are named
by reasoning. The import inventory below does not list the files that import
`syscall` or `golang.org/x/sys/unix`: on Linux `os` alone reaches the same
memory, so such a list would hold less than this limit already says.

Two kinds of road do go through the language without a `reflect`, `unsafe`
or `C` import, and the guard holds both. First, a value whose type has the
underlying type `unsafe.Pointer` converts to a pointer of any type in every
file; the import of `unsafe` is needed only to spell the type. The standard
library hands out such values, for example `reflect.Value.UnsafePointer`
through the exported `reflect.Type` field of the error type
`json.UnmarshalTypeError`, and so does the dependency function
`golang.org/x/sys/unix.MmapPtr`. From one such value an index into a large
array type reaches any address above it. After the red-team, both were
measured on linux/amd64 to clear the two latches of a struct on the heap
from a file that imports neither `reflect`, `unsafe` nor `C`, with `go vet`
silent. So a raw pointer value may appear only in a file that imports
`unsafe`, which the import inventory holds by its hash. Second, some
dependencies export raw memory access as ordinary Go functions that take an
address as an integer: `modernc.org/libc`, which the SQLite driver uses,
exports the C library's `memset` and `memcpy`, and the red-team reopened a
withdrawn Service with them. So an import of a dependency package outside a
reviewed list puts its file into the import inventory as well.

#### Typed inventories and guard limits

Maintained typed production inventories enforce zero non-test references to
`Service.commissionOperationalAdmission`,
`Service.advanceOperationalAdmission` and
`Service.withdrawOperationalEffects`, to the two private handoff entries, the
domain and provider constructors and the store's release proof hook, each with
a positive control. Each of the three store operations
`OperationalCustody.CommissionOperationalAdmission`,
`OperationalCustody.AdvanceOperationalAdmission` and
`OperationalCustody.WithdrawOperationalAdmission` has exactly one reference,
from the Service method of the same purpose, so none is reachable from
production code either. The inventories also enforce zero non-test
configuration of
`Service.operationalProof` or its hook callbacks, the clock seam included;
exactly one reference to `Service.confirmOperationalAdmission`, whose
once-per-invocation closure is invoked at exactly three sites; exactly two
callers of `Service.fetchVerifiedTrustModel`; exactly one construction of the
admission state, in its constructor, which `NewService` alone calls; and
exactly one view construction, in the install method of the state, which
only the one function that installs the view calls, which only the
commissioning and advance methods call.
Exactly three store functions contain a statement that
writes the admission table, and no production statement updates its
installation or epoch column. The same gate carries the prerequisite
identifiers of §8 and prints them when a production reference appears.
A method inventory also counts dynamic dispatch. A method of the same name
that an interface or constraint of the two packages declares
(`interface-method`), and a selection of that name on an interface or
type-parameter value (`interface-selection`), are references to the method.
Neither is a direct call, so each is refused as an indirect reference even
where its site is listed: a gated entry cannot be reached through an
interface, a constraint or an embedded interface of these packages.
Exact protected-field reads, assignments and keyed initializers cover verified
trust ownership, the handle `Service.operational`, and inside the admission
state package the installed view/withdrawal/supersession/confirmation and
the view identity/token/content, then the handoff owner links and proof
hooks; mutex
reference counts do not replace
these access inventories. Which fields must have one is read from the types:
every field of the two structs of the admission state package, and every
field of a production struct whose type holds one of its two handle types,
fails the guard until it has an inventory, and a package variable that holds
a handle is refused. An occurrence inside a function literal is an access
kind of its own and passes only where an inventory lists it: the two token
reads of the qualification callback. Transparent parentheses enclosing a resolved field
selector do not change its access kind: parenthesized reads, including right-hand
side and receiver/base evaluation, remain reads; parenthesized whole-field `=`
targets remain assignments; parenthesized compound-assignment and
increment/decrement whole-field targets remain read-writes; keyed literal field
keys remain initializers. Range-clause `=` key and value whole-field targets
are assignments. Taking a field's address is an `address` access, whether
explicit with `&` or implicit through slicing an addressable array or calling a
pointer-receiver method on an addressable field value. An assignment,
increment/decrement, range target, address-of, `clear`, `close`, `delete` or
`copy` destination applied through a selector, index, slice, type assertion,
conversion or dereference chain rooted at the field is a `write-through` access.
A conversion is a transparent step in that chain. A channel send on the field,
and an `append` whose first argument is rooted at the field, are write-through
as well. None of
these is a read; an unresolved selection in such a chain is unclassified and
fails the inventory.

A protected field can also be written without being spelled. For every
protected field the inventory therefore also lists each whole-value
occurrence of its owning struct type as its own access kind: a positional
literal element (`initializer`), a keyed literal that omits the field
(`zero-initializer`), an assignment or range `=` target that is or contains the
owning type by value (`whole-assign`), a conversion in either direction
between the owning type, or a pointer to or container of it, and any other
type (`whole-convert`), a declared variable, parameter, result, receiver or field
that is or contains it by value, a type-switch clause for it, a `new` or
`make` of it (`whole-declare`), a `copy`, `clear`
or `append` over a container of it (`whole-copy`), and any other use of such a
value, which copies the field (`whole-read`). A defined type over the owning
struct counts as the owning type. A conversion away from a pointer to the
owning type is the one Go allows between pointers to structs of the same
shape. It gives the same storage a second type, through which the field can
be written without any occurrence of the owning type, so it is listed like a
conversion to the owning type. One conversion away is exempt: to an interface
type that is not a type parameter. Of a value it is a copy, which
`whole-read` lists; of a pointer it is an alias, the first limit below. An
instantiation of a generic function or type whose type argument is, contains
or points to the owning type is listed as well (`whole-instantiate`), written
or inferred, because the generic body can convert, copy or overwrite the
value where no inventory reads it. Every type argument is read. The
construction inventory
counts the same forms, so a zero-value declaration and a same-shape
conversion of an authority type are refused like a second literal. The older
site-count inventories of lock and lock-protected fields list the whole-value
occurrences of their owning struct in the same way, beside their identifier
counts.

Two more kinds are listed where a type is written, not where a value is
used, so that a form of use the inventories do not know fails by default.
Each escape found in review (a whole-value conversion, a pointer conversion,
a generic body) reached a protected field through a second struct type of the
owner's shape. Between pointer types, Go converts a pointer to the owning
type only to a pointer to a struct type with the same fields, and an
unexported field name can be written only in the owner's package. Where no such type is written, no
conversion gives the owner's storage a second set of field names. The
inventory therefore lists every written struct type whose field names, in
the same order and embedded where the owner's are, equal the owning type's
(`whole-mirror`): named, anonymous, local or generic, in a declaration, an
alias, a constraint, a field or a parameter, whatever its field types and
tags. No such type exists today. A type parameter defers the choice of a
type to an instantiation, which can be in a package that declares no owning
type. The inventory therefore lists, at its declaration, every type parameter
whose constraint has a type term that is the owning type or reaches it
through pointers, slices, arrays, channels, maps or struct fields: directly,
in a union, or through a named or embedded constraint (`whole-constrain`).
No such type parameter exists today. Beside both, an exact inventory holds
every type parameter declared in a package that declares an owning type,
today the one of `replayPresence`, so a new generic function or type there
fails a test until it is listed.

Each owning type is read in every production package of the module, not only
in the package that declares it. A production package is chosen by the
directory the go command compiles it from, not by a pattern or by its import
path: every package in the dependency closure of the module's packages whose
directory lies inside the repository is read. A wildcard pattern such as
`./...` does not match a package in a `testdata` directory or in a directory
whose name begins with a dot or an underscore, and the go command still
compiles such a package when another one imports it, so it is read like every
other. A closure package compiled from a directory that is neither in the
repository, in the Go root nor in the module cache fails the loader, because
no inventory would read it. Another package knows the owning type by its
shape. Every protected field is unexported, which a test holds, so another
package cannot spell one: it can only declare, copy, convert, overwrite or
instantiate with a whole value, and each of those is listed there under the
kinds above. Today the only such occurrences are the seal permits that
`es/admission` receives from the store by value. A whole-value write is
listed and not named as a limit because it is not fail closed in every form:
a zeroed Service holds the closed zero handle and a copy of a commissioned
Service holds a handle bound to the original, so both admit nothing, and a
copied or zeroed store handle fails its self-pointer check, but a saved
whole value written back to the same owner restores the fields it held.
The admission state is no longer among those fields: a `Service` value
written back restores the handle, which names the same state with its
latches and its confirmation time as they are now.

The admission state package has inventories of its own. Every exported
function and method of the package has an exact list of the functions that
reference it, with a count for each: the constructor in `NewService`; the
question whether the state was commissioned, twice in `Service.Initialize`;
the question whether a view can be installed and the install itself, in the
one function that installs the view; withdraw, the two steps of a
confirmation and the question for the current view, each in the Service
method of the same purpose; the digest where the Service computes its
content, and inside the package at the install and at the confirmation; the
token read at establishment and at the comparison and the match of the
qualification callback; the content reads in the judgment of a retained
original; the proof value in the one function that returns the proof hooks;
and the inspection method and the question whether a handle names a view,
which exist for tests, nowhere. The exported
surface of the package is a closed list, so a new exported function, method,
type, constant or handle field fails a test until it is listed and has a
call-site inventory. The field and lock inventories above read the state
and view structs like every owning type. The one production file of the
package is pinned by the SHA-256 hash of its bytes, and a second non-test
file, a file of another kind or a directory below it fails the same test,
so every change of the package is a reviewed change. With that pin the
field and lock inventories inside the package repeat what the reviewed
bytes already fix. They stay, so that an update of the pin shows which
access changed.

Limits that remain, by name: values reached through an alias or pointer that
was itself obtained at an inventoried site; the bodies of called functions
and methods beyond Go's implicit address-of, which is a limit of dataflow
and no longer one of generics, because a generic is listed at its
declaration or at its instantiation by the rules above;
reflection; `unsafe`; cgo; code loaded at run time; and dependencies that
export raw memory access. For these an exact import inventory
covers every non-test source file of the module, so a new `reflect`,
`unsafe`, `C` or `plugin` import in any production package fails a test,
and so does an import of a dependency package outside the reviewed list.
It reads every non-test Go file in every directory of the repository
except `.git`, whatever the directory is called. The inventory
holds each file that has such an import by the SHA-256 of its content, so
every change to such a file fails a test until the inventory is updated.
The reviewed list names every dependency package that a production file
imports, with the module and version whose exported API was reviewed for
raw access to memory. A test compares the list in both directions with the
imports of the production files, and with what the go command reports for
all three build targets, so a new dependency import, a further package of a
listed module, a new version and a replacement each fail until the list is
updated. The raw pointer rule reads every expression and every declared or
used name of every production package for the same three targets, and a
value whose type has the underlying type `unsafe.Pointer` in a file that
does not import `unsafe` fails it. It judges the file that holds each such
value by the value's real position, not by the file and line that a
`//line` or `/*line` directive names. Every guard reads positions that
way, and a test refuses the calls that read an adjusted position in the
test files of the module; another test refuses such a directive in every
non-test Go file of the repository, so no production position is adjusted
at all. The rule reads the static types of the source: a type parameter
that inference sets to `unsafe.Pointer` holds such a value with no raw
pointer type in the file, and it cannot become a typed pointer there
without a constraint that spells the type, which the rule sees. With that
rule the import names the
files that can write storage past the typed inventories by every road
through the language known here, a data race aside; a source inventory
cannot show that no other road exists. The hash shows that such a file is
the one that was reviewed; neither reads what the file does. A
`//go:linkname` directive, which reaches an unexported function of another
package without naming it in Go syntax, is accepted by the compiler only in
a file that imports `unsafe`, so it is held by the same inventory.
Other `//go:` directives need no import: `//go:cgo_import_dynamic _ _
"name"` makes a `CGO_ENABLED=0` build a dynamic executable that loads the
named shared library, whose initialisers run native code in the process
before `main`. So every non-test Go file of the repository may hold only
the `//go:` directives of an exact reviewed list, today `//go:build`
alone, and a test fails on any other verb and on a listed verb that no
file holds.
Reflection inside a called library function, on a pointer or container
passed to it as an interface value, is such a called body: it cannot set an
unexported field by itself, and it can move or overwrite a whole value. The
typed inventories
read the Go files that three build targets (darwin/arm64, linux/amd64 and
linux/arm64) compile with default build tags. A file-set check fails when a
non-test Go file of the module is compiled for none of them, as behind
a custom build tag or for another operating system or architecture, and when
a production directory holds an assembly, C or object file, so no production
file of the module is outside the inventories. The check lists every
directory of the repository except `.git`, so a Go file that no compiled
package holds fails it in a `testdata`, dot, underscore or `vendor` directory
as anywhere else. Three forms make the go command compile a module from a
place the inventories do not read, and each fails a test: a directive of
`go.mod` outside the exact list `go`, `module` and `require`, which refuses a
`replace` line; a `go.work` file anywhere in the repository or above it, and
a workspace named by `GOWORK`; and a `go.mod` below the repository root. What
a test of the repository cannot see is a build made with other inputs than
the repository: the flags `-modfile` and `-overlay`, which `GOFLAGS` can
carry as well, and a toolchain or a module cache whose content is not the
published one. Code
outside the module, the
standard library and third-party dependencies, is not read. The table-writer inventory
reads SQL statement literals; a statement assembled at run time is not seen
by it, and the triggers of §2, not that inventory, are the barrier.
One limit has no inventory at all: a write to the memory of the process that
does not go through the language, which the section on the admission state
package describes. It needs no `reflect`, `unsafe` or `C` import, so the
import inventory does not see it, and no inventory reads what such code does.
Raw system calls through `syscall` and `golang.org/x/sys/unix` are part of
that limit, and the files that import those two packages are not listed.
The maintained guarantee is exact syntactic
occurrence, function site and access kind, not a general proof of aliases or
runtime safety. `Service.mu` owns the mutable Service state and the lock of
the admission state owns the latches and the confirmation time, while
the installed view is immutable and bound to its original Service.
The per-instance proof hooks are nil in production and non-authoritative.

#### Writers, locks and outcomes

For an unmarked original, each run/intent writer, pre-stage checked writer,
stamp writer and first-marker writer authenticates the exact current row,
original, keys, revision and retained material, compares the admission token
with the row, then checks complete current admission on that
same original. This is only bounded local Service admission over retained
bytes. Inside a SQLite writer the lock order is writer then a brief
read of the admission state under its lock, without `Service.mu`. Take the
handle of the immutable view while the latch and confirmation state allow
it, release that lock, run bounded local evidence verification,
trust and built-in `RequiredInputClasses`/`Evaluate`, then sample the view,
latches, deadline and identity again before positive return. No resolver,
ARS/EGS read, arbitrary evaluator, filesystem materialization or provider I/O
runs in this callback. Commission, advance and withdrawal take the custody
handle's lock in read mode and then the SQLite writer, without `Service.mu`
and without a stage or owner lock; the confirmation holds neither
`Service.mu` nor the owner mutex while it fetches, and at the two pre-checks
it runs under the custody read lock of the borrow. Installing a view takes
`Service.mu` and then the lock of the admission state, so that a trust load
cannot run between the comparison of the trust model and the install;
nothing takes the two in the other order, and no lock is taken while the
lock of the admission state is held. The final sender lock order is
owner mutex then a brief read of the admission state; no reverse path is allowed.
Post-COMMIT release rechecks the
same admission before it can release a sender. Final owner-protected entry
checks context, authority/Service/installation/epoch identity, withdrawal,
supersession, the confirmation deadline, original/marker/stage/request and
existing key eligibility before direct transport. No Service lock and no
lock of the admission state spans transport.

The first four rows are the judgment of a retained original, at a pre-check
or a first-effect cut.

| Cause | Reason | Run disclosed |
| --- | --- | --- |
| Retained original: signer not allowed or revoked, artifact revoked, built-in policy denies | `OperationalDenied` | No |
| Retained evidence does not verify under the current verifier | `OperationalDenied`. The original is already authenticated, so this means the verifier was replaced. | No |
| No view, token not equal to the row, withdrawn, superseded, deadline passed, unsupported required input or missing bounded payload | `OperationalUnavailable` | No |
| Malformed or contradictory authenticated evidence; an existing original whose realm is not the domain's | `OperationalIntegrity` | No |
| First delivery that ordinary resolution refuses, whatever the cause: the rules, an unsupported request or an unavailable dependency | `OperationalUnavailable`. Nothing is stored. | No |
| The context of the call has ended and the admission returned no refusal of its own in this call | `OperationalCanceled`. `OperationalTimeout` where the deadline of the call passes while the provider is asked about the job (below) | No, except while a durable marker is reconciled, where the stored run is returned (below) |

The first five rows are value-free and withhold run and receipt at the
refused cut. The last row is value-free except at the points named below.
`OperationalDenied` is the answer of the re-judgment only. A first delivery is
judged by ordinary resolution, whose typed error is not carried into this
result. What a first delivery tells its caller belongs to the public mapping.
That mapping is not selected and the handoff has no production caller. The
commissioning gate of §8 names it as the prerequisite `CP-PUBLIC-MAPPING`, so
the test that fails on the first production caller names that decision.

A cancelled call answers `OperationalCanceled` unless the admission returned
a refusal of its own in the same call. The store refuses every read, binding
and writer turn of a call whose context has ended, so a step that fails under
an ended context reports the cancellation and not `OperationalUnavailable` or
`OperationalIntegrity`: the pre-check's read of the row, the binding of the
intent, of the staged tree and of the marker, the verification of an accepted
receipt and the binding of a completed observation. Every writer turn checks
the context immediately before its COMMIT and the sender entry checks it
before its request, so a call found ended there commits no claim write and
sends no request. The fence, the view and a
completed judgment come first. A pre-check or cut that has read the row
reports a missing view or a differing token as `OperationalUnavailable`, and
a denial that its evaluation returned as `OperationalDenied`, also when the
context has ended meanwhile. A cancellation that arrives during an evaluation
that allows is reported as the cancellation, and from a pre-check no writer
turn is then requested.
When one call is both cancelled and refused by the authority, the authority
refusal is reported, at reconciliation and at the final sender entry alike,
because it withholds the run and a cancellation alone does not.
A cancelled call returns the stored run only while it reconciles a durable
marker: at the reconciliation entry, at the final sender entry, whose answer
arrives at that entry, during the observation of the job and at the binding
of a completed observation. The result there is the ambiguous one, with the
run and `OperationalCanceled`. One of the four points tells a passed deadline
from a cancellation. When the deadline of the call passes while the provider
is asked about the job, the exchange reports `OperationalTimeout`, as it does
when its own bound on that exchange passes, and the result is the same
ambiguous one with the run. At the other three points, and before the marker,
a passed deadline answers `OperationalCanceled` like a cancellation. A cancelled answer from a pre-check, a cut or
a binding before the marker is value-free. So is the one from the
verification of an accepted receipt, although run and receipt are durable
there: the retry under a live context returns both.
The durable write is never erased: denial after an acknowledged intent, stamp
or marker leaves it committed, and an unknown response is not upgraded. The
result carries one operation and write slot and reports the last writer
attempted in that call, as §4 states; an earlier applied writer of the same
call is visible in the row, not in that slot. A refused first-effect cut
returns a value-free result. An entry that attempts no cut (recovery, a
stamped-but-unmarked retry, a marked retry) returns the stored run to the
authenticated original caller under any authority and sends no trust request;
withholding at a refused cut is a result-shape rule, not a confidentiality
boundary against the claim's own caller.
A pre-stage denial creates no new stage; denial
after legitimate staging may leave inert charged residue; a marker after
withdrawal may remain but grants no sender. The complete
`OperationalNoChange` **and** `OperationalReasonNone` pre-stage gate, exact
revision CAS, permanent marker, direct-only one-use sender and no stage
reattachment remain in force. A withdrawal or advance observed before a cut
stops its next action; a previous committed write or already-entered I/O
cannot be retracted. A retry after a changed configured literal policy, artifact revocation or
signer revocation is refused at its first remaining cut, after a committed
run assignment or intent, without advancing or disclosing the claim. A later
generation that allows the claim lets a retry complete with exactly one POST,
so before staging a denial does not poison the claim. After staging the claim
keeps its charged residue and cannot stage again; it needs a new submit key.
That holds whatever stopped the call between staging and the stamp: a denial,
a fence, a confirmation deadline that passed while the tree was staged, or a
cancelled call. No confirmation is attempted between the pre-check and the
stamp, and a confirmation counts from the instant before its request was
sent, so a slow EGS answer followed by slow staging can use up the 30
seconds.

Receipt-only verification is outside current admission. Accepted receipt
verification needs exact caller, authenticated historical realm/original and
eligible exact ACTIVE/RETIRED key pair, but no view, token, confirmation,
stage, resolver or provider. A marked claim may record only verified
positive provider registration and immutable receipt, never dispatch again.
Missing/revoked/mixed keys and unauthorized callers still refuse without
disclosure. Canonical public caller selection and
installed lifecycle authorization remain outside this private injected proof.

The maintained proof uses an independently constructed complete signed-v2
outer wire derived from the published layout, rather than a producer/reader
round trip as its expected value. Otherwise-valid signed contradictions
isolate evidence-to-plan/material
association from signature refusal. An eligible retained cut observes actual
argv, artifact, profile, payload count and bounded text supplied to the
selected built-in policy. Two and three Services on one domain, and two
processes on one database, prove the fence, the denial and the later
completion; a fake signed EGS proves the freshness rules. These are local
proof obligations, not new authorities or installed consensus claims.

The existing per-instance `operationalAdmissionProofHooks` may carry one
nil-default `contextObserved` callback for inert test observation. It receives
only a detached `AdmissionPolicyContext` value with independently cloned argv,
after retained inputs are complete and immediately before the existing built-in
`Evaluate` call. It returns no decision and grants no permission, replacement
evaluator, storage fact or output channel. The nil-default `skew` callback is
the clock seam above. The store's nil-default release proof hook runs after a
directly acknowledged COMMIT and before the release re-read; it receives only
the operation and returns nothing. Non-test source configures no proof
hook. The exact call/read and configuration sites are maintained by typed
inventories; ordinary admission and the private writer's policy algorithm
remain unchanged.

## 4. Writer turn, sender and results

The §8 current-state substitution applies only to codec 5. Keep conditions
1–8 and 11. For 12 compare exact current revision after a successful
`BEGIN IMMEDIATE`, and enforce it in the same transaction's CAS. For 9–10,
the successful writer turn on the unchanged domain serializes ahead of any
later writer and after disposition of any earlier writer. It freshly reads,
decodes and hydrates the current authenticated row. Compare exact same
caller/key, claim rowid, PlanBinding, RunRef, scope, immutable descriptor and
physical original with the held authenticated certificate. Check active
retention, effect intent, and marker SQL NULL. Pre-stage turn also requires
stamp NULL. Marker turn requires the exact still-live stage owner's stamp
and revalidated snapshot. Qualification inside the turn is bounded read-only
descriptor and byte verification on retained original/stage and exact key
and policy reads. All creation, stage writes, sync, and provider I/O run
outside SQLite. Unsettled older writer either excludes this turn or settles
before the read. An unqualified store, busy/failed turn, changed certificate,
unlocked absence, or a cached snapshot cannot pass.

A complete successful pre-stage cut (`OperationalNoChange` with
`OperationalReasonNone`) allows only one immediately following exclusive
creation attempt with the checked revision and original. No other disposition
or reason grants that attempt. A failed cleanup, release or observed cancellation
after semantic qualification stops effect continuation and withholds run and
receipt, while preserving the earlier invocation's actual operation and write
disposition. A read-only cut neither invents a write nor erases one. A contender whose cut becomes
stale can at most leave inert stage residue after exclusive creation. Stamp
and marker CAS recheck exact revision and current admission. If a contender
already owns the stage, another exclusive create fails and produces no
authority. A marker can be applied only while the same original owner holds
verified stage descriptors through CAS and transport entry.

Private API signatures below specify roles and closed variants. Every argument
type is an opaque redacted value with validating private constructors. MutationRef is fresh nonzero random B32 for every new write. Closed
commands are nominal application inputs. No general-purpose setter, exported
boolean, raw token or method on a zero value can choose an authority variant.

| Owner entry | Typed input | Typed result |
| --- | --- | --- |
| Admission `handoff(ctx, AuthorizedDelivery, QualifiedDomain)` | Exact caller + immutable parsed delivery, qualified composition dependencies | `HandoffResult` below |
| Admission `recover(ctx, AuthorizedDelivery, QualifiedDomain)` | Same scope, accepted receipt read or bounded positive lookup for a marker | `HandoffResult`, zero senders |
| Durable service `apply(ctx, OriginalAccess, Revision, MutationRef, ProgressCommand)` | Live invocation-bound access, exact predecessor revision (zero on establish), fresh mutation identity. Closed command variants Establish, Assign, Intent, Stamp, Accept | `WriteOutcome` plus separate eligible projection |
| Durable service `applyFirstMarker(ctx, OriginalAccess, Revision, MutationRef, MarkerCandidate, OnApplied)` | Exact current live stage/request owner and synchronous private consumer callback | `MarkerOutcome` (WriteOutcome plus optional callback ExchangeResult only for AppliedFirstMarkerDirect). Calls OnApplied once only after directly acknowledged applied COMMIT and revalidation. OnApplied synchronously returns a tagged ExchangeResult or Closed. No sender escapes as a result. |
| Callback `consume(ctx, *liveSender, *handoffOwner)` | Exact issued pointer and currently active owner, bound stage and request | `ExchangeResult` or closed/refused, consumption before transport |
| Provider `postOnce(ctx, PreparedRegistration)` | Immutable exact fully formed request, admitted by private consume | `PostObserved(ImmediateAck)` or `PostInconclusive(ExchangeReason)` |
| Provider `observe(ctx, InitialJobLocator)` | Qualified realm, job locator, at most one Job and Evaluations read each | `ObservationPair` typed bounded snapshots or `Inconclusive(ExchangeReason)`. Only verifier can create PositiveProof. |

`WriteOutcome` is a closed tagged union with private storage. Transient
transport or scope failures are finite reasons (unavailable, canceled, stale,
wrong-scope, conflict, occupied, closed, integrity, capacity, unsupported,
inconclusive) and project no raw cause. Transport reasons additionally identify
timeout, I/O, HTTP status refusal, malformed/oversize, or continuity failure.
Execution and database observers receive value-free classes. Exact direct
acknowledgement means SQLite returns success for the very COMMIT following
the reported applied transition, after required checked disposal/authentication
for release. A successful commit of a read, no-op or latest replay cannot
construct this variant. Direct COMMIT with failed release still has known
write disposition and cannot issue a sender. A direct marker success never
requires inferring what a different call saw.

| Decision | Evidence | Sender count | Permission | Projection |
| --- | --- | --- | --- | --- |
| AppliedFirstMarkerDirect | Applied NULL-to-marker CAS and own direct COMMIT ACK | 1 | ConsumeOnce | Known marker, same run, ambiguous until positive acceptance |
| AppliedFirstMarkerReleaseFailed | Applied and direct ACK, failed post-COMMIT qualification or disposal | 0 | Stop | Known applied, withhold projection when release cannot authenticate |
| AppliedOtherDirect | Applied establish, assign, intent, stamp or accept and own direct COMMIT ACK | 0 | AdvanceOnlySelectedNextStep | Committed phase with authorized projection |
| DefinitelyNotApplied | Proven rollback/refusal before successful COMMIT | 0 | Stop | Preserve refusal and eligible current projection |
| OwnCommitConfirmed | Full authenticated own-commit readback after indeterminate command | 0 | Stop | Own applied confirmed, eligible read-only projection |
| UnknownCommit | Indeterminate and own readback unavailable or fails full equality | 0 | Stop | Unknown, withhold projection in this invocation |
| ExactLatestReplay | Exact mutation, operation, predecessor and input match latest | 0 | ReadOnly | Authenticated current projection |
| NoChange | Successful current read or read-only/no-change transaction | 0 | ReadOnly | Authenticated current projection |
| StaleCAS | Stale revision, failed CAS or advanced record | 0 | Stop | Stale, eligible authenticated winner or withhold |
| ConflictOrOccupied | Different intent, foreign scope or unique-key loser | 0 | Stop | Conflict or eligible authenticated same-scope winner |
| Refused | Validation, permission, capacity, context or integrity refusal | 0 | Stop | Fixed refusal class, withhold unqualified facts |

An invocation reports the selected operation and its own disposition when one was
attempted, a finite current reason, and separately qualified projection. The
absence of an attempted write is distinct from Refused. Results carry no
continuation authority. Earlier acknowledged writes are facts and never
substitute for a later command result or checked denial. Cleanup may withhold
projection and report a closed reason while preserving the selected write
disposition. A direct COMMIT stays known when release fails. Establishment
confirmation requires exact owned row equality plus a live authorized context
and the exact ACTIVE effective key pair, authenticated descriptor and file,
and original/PB1 association. Failure of that qualification preserves Unknown.
Later commands confirm against the same original and current operation's key
and owner eligibility. Receipt recovery reads may use the exact RETIRED pair.

| Composition exit | Projection and disposition |
| --- | --- |
| Initial lookup | Unauthorized before lookup. Conflict, scope, integrity and unavailable denial withhold. A current authenticated original may project. Initial absence has no write. |
| Occupied winner lookup | Conflict is returned with Occupied and no projection. Equivalent eligible winner may project with Occupied. Failed winner qualification withholds with Occupied. |
| Post-establishment authentication | Own confirmed permits only eligible read-only projection. Unknown withholds. Failed release of direct COMMIT preserves known establishment, with no projection or further operation. |
| Assign or intent | The invoked command reports its own disposition. Refused and unknown withhold. A confirmed/no-op/stale result may project only authenticated current facts and stops effects. |
| Pre-stage turn | Only a complete NoChange plus ReasonNone result allows one following exclusive attempt. Failed cleanup, release, observed cancellation, denied or stale cuts stop effects and withhold run and receipt while retaining the earlier operation/write result. |
| Stage creation, materialization or stamp | Qualified retained collision may return Pending. Integrity failure withholds. Stamp reports its own disposition and only direct applied advances. |
| Marker | Only direct applied first marker with successful release calls the synchronous consumer. Refusal or unknown withholds. An authenticated applied marker without a send remains ambiguous. |
| Observation | Qualified evidence is required for receipt CAS. An inconclusive exchange leaves eligible marker ambiguity with the bounded reason. |
| Receipt CAS | Expose the same verified immutable receipt from the authenticated allowed outcomes. Refusal or unknown withholds. |
| Callback completion or cleanup | Burn the local right, dispose after synchronous use, and withhold on failed cleanup without changing the selected operation or write disposition. |

Read-only cuts may withhold a projection while preserving a command observed
earlier in the invocation. A later attempted command takes precedence in the
reported write slot. After a definite rollback, any projected row is freshly
authenticated at the same revision with the operation's current qualification.
The nil-default per-domain proof hooks in the private composition order the
establishment, pre-stage, stamp, marker and entry cuts in maintained tests. The
instance-scoped custody pre-stage proof observes semantic success and real
rollback/release before it may model a failed cleanup response or order caller
cancellation. The stage-close witness observes real cleanup and may model its
reported error. These hooks create no write, projection or sender authority.
A rollback-response model runs after the real rollback and leaves connection
release to the existing deferred cleanup. The maintained admission proof counts
stage creation and materialization attempts at their direct call sites, after
the complete pre-stage gate. Its direct exchange observer sees only the HTTP
method just before the unchanged concrete `RoundTrip` call; it cannot substitute
transport, supply a response or claim receiver delivery.
A maintained real-SQLite regression compares the same pre-stage schedules under
the disposition-only and complete-result admission gates; it records stage,
materialization, durable rows/charges, sealed original, and provider effects.
The internal result and admission composition remain separate observations.

The finite reason tags distinguish cancellation, stale, wrong scope, conflict,
occupied, closed, integrity, capacity, unsupported, and inconclusive. Exchange
failures additionally distinguish timeout, I/O, HTTP refusal, malformed or
oversized evidence, and continuity failure. Generic unavailable covers
unclassified unavailability. These private tags carry no raw cause.

Admission owns typed validation of the frozen plan, job, held stage and provider
observation. The internal durable service owns scoped capsules bound to the
active access and exact projection, and derives the durable intent and marker
using the selected fixed preimages. Stage revalidation supplies the exact
qualified stage evidence rather than a Boolean assertion. The provider verifier
issues distinct positive observation evidence only after validating the pair.
The admission association adapter checks the verifier's issuer, pointer and
exact projection and supplies the existing W MAC and complete witness preimage
to the owning access. The access independently checks the preimage and MAC
against its live authenticated projection and derives the existing receipt.
The stage adapter supplies the full bounded stage preimage from its held
descriptors. The access validates its scope, layout and metadata, pins the
exact bytes and requires a fresh matching measurement at use. First-effect
qualification supplies a match of the live original after checking current
admission and the commissioned domain. An immediate ACK carries no acceptance
authority. The exact reference inventories constrain these adapters and the
constructors and consumers across the Go package boundary.

For a matching active claim, the fresh explicit invocation can load its
current phase and choose a new authorized next command. A replay/no-op itself
has no effect permission. If one invocation receives an uncertain response
to any command (claim, assignment, intent, stamp, marker or receipt), end the
entire effect-producing sequence. Safe readback may classify but cannot
continue it. A definite marker failure also ends the invocation. Readback
after failed disposal withholds authority. A later explicit invocation
uses identical retained facts and identical fresh inputs identically.
Pre-assignment outcomes have no run. Authenticated assigned nonterminal
outcomes include the same run (Pending before marker, Ambiguous after marker).
Accepted includes same run and immutable receipt. Current authorization before
lookup, different-intent conflict, foreign scope, unavailable integrity or
key state, and unauthenticated failures withhold the run and receipt. Preserve
known occupied vs unknown own-write disposition internally. Recovery never
synthesizes an extra mutation to classify an earlier result.

HandoffResult is a private sum of Unauthorized, Conflict, Unavailable(reason),
PendingBeforeAssignment, PendingAfterAssignment(RunRef), Ambiguous(RunRef),
and Accepted(RunRef, ReceiptRef). A command with indeterminate disposition
and no authenticated projection maps to Unavailable(unknown-write) for that
invocation. Authenticated readback may supply the applicable class without
resuming effects. Equivalent retained original means the same currently
authorized caller/key namespace and exact original-intent TLV bytes under
the stored scope, bound by the intent HMAC, with the qualified exact frozen
file and PB1. Omitted and defaulted values retain their original representation.

The admission invocation owns an unexported pointer `handoffOwner`. Its
private one-use `liveSender` stores original self pointer, exact issuer and
owner pointers, held stage identity/handles, O, RunRef, S, D, P and prepared
request bytes/locator. State is invocation-local Open → Consumed or Closed,
with a single owner mutex serializing consumption, owner close and the actual
synchronous transport-entry decision.
The issuer registers no global state. Verify self pointer equals receiver,
issuer/owner and original match, owner active, keys/policy view and held
stage checks pass, and context live. Copy, zero, foreign pointer, wrong
binding, closed custody or escaped callback refuses. Consume state before
single synchronous transport entry. Prepare the request and transport before
the final gate. Under the owner mutex, revalidate the qualified binding and
sample context cancellation immediately before the synchronous transport call.
Owner closure ordered before that cut and cancellation observed at that sample
refuse entry. Independent context cancellation does not acquire the mutex.
Cancellation after the entry-admission cut is possibly delivered, including
before any OS send. Close may wait for synchronous use to complete. No physical
wire atomicity, instantaneous cancellation, or universal close latency is
selected. Burning on mismatch or denial prevents any
later retry by that owner. Callback return closes access and burns any unused
sender, with disposal by the invocation owner after transport exits. No
goroutine or later callback receives a usable owner. Close/failed validation
and disposal forbid additional operations. The cut relies on actual callback
ownership and the live Go process. Process-image fork/clone of a live
capability is outside the proof. The existing per-custody lifetime controls
remain in use. No A3 topology, global registry, lease, root-pair registry,
new flock or poison subsystem.

## 5. Exclusive staging and exact bindings

Only after known durable run assignment and intent with the new checked cut,
try one exclusive descriptor-relative mkdir of the exact run component under
qualified parent at mode 0750. Existing partial or complete directory (even
with no stamp), any retained stamp without its live owner, path alias, missing
directory with retained stamp, collision and unresolved cleanup all withhold
authority. Preserve every residue and capacity charge. No delete/recreate,
adopt, reopen for dispatch, new run, refund or repair/reuse. A still-live
successful owner can finish its nonfailed sequence. Evidence inspection may
observe old files without taking stage ownership. No cross-invocation stamp
authority. Before stamp, marker and consume compare actual ordered entries,
contents and held and visible identities under that owner. On failure burn,
close and withhold.

The allowed tree has root and exact entries `payload`,
`payload/artifact.tar.gz`, `run`, `run/platform`,
`run/platform/es-runtime-support`, and `run/result`. When original CA/TLS
applicability is true include both `run/platform/workload-vault-ca.pem` and
`run/platform/workload-ca-bundle.pem`, otherwise neither. Directories and
support executable mode 0750, payload archive 0600, trust files 0640, exact
commissioned uid/gid.
Result directory is empty before dispatch. Artifact, support and optional
trust file bytes are the corresponding exact retained leaves. Each file at
most 262144 bytes, aggregate at most 1048576, at most eight child entries,
and no extra names. Relative path ≤128 ASCII bytes, depth ≤3, exact list
only. Refuse symlinks, file links other than nlink=1, cross-device paths,
devices, special/type or mode changes, unknown entries, mismatched lengths,
unstable before/after stats or visible/held mismatch and content changes.
Directories must have their exact observed link counts, with no topology
change across checks. Stage filesystem sync and qualification of held
descriptors precede stamping. Native must prove all worker-visible bind
sources and mount modes match the frozen projection, staged inputs stay
stable through provider use, and runtime/result writes cannot alter them.
A pre-entry check cannot prevent post-check hostile filesystem actions.

An operational stage parent is requalified from the held and no-follow visible
identities at each effect boundary, including the reopen, stamp, marker and
final entry. Compare the commissioned owner and anchored permitted mode.
The held parent, its visible entry and a second held sample must agree on
identity and metadata within each qualification. The independently opened
parent for exclusive creation is checked against the domain's original anchor.
Revalidation refuses drift before reading it as stamp evidence. Parent link
count is stable within each bounded check but may change across operations as
authorized sibling stages appear. Revalidation uses the original stamp's
historical parent count in the exact preimage after checking fresh safety and
per-check stability. Receipt-only recovery needs no live staging anchor.

A missing-stage prerequisite is a descriptor-relative no-follow lookup of
the exact child returning ENOENT under the held qualified parent. Confirm it
outside SQLite after the checked cut, then rely on exclusive mkdir for the race.
Treat every other error as refusal. Validate file descriptors before and after
hashing, plus child resolution from the held root. Stage writes end at completed
materialization.

### Preimages

`F(x)` is u32 byte length then bytes. Integers below are unsigned
big-endian of named width. B32 fields have no inner framing. Concatenate in
written order with no delimiters. Labels are exact ASCII without terminator.
Use SHA-256 unless HMAC is named.

| Value | Exact preimage |
| --- | --- |
| O original identity | `ESOHORIG1`, u64 physical positive rowid, caller B32, key ref B32, F(PB1), u16 resolved mask, u16 inapplicable mask, u64 creation ns, F(exact raw original header), F(canonical envelope ref), u64 envelope size, file digest B32, binding FP B32, envelope FP B32 |
| L locator | `ESOHLOC1`, installation B32, u64 epoch, provider installation B32, SPKI B32, F(DNS name), u16 port, F(region), F(datacenter), F(namespace), F(job ID), build B32, template digest B32 |
| I durable intent ref | `ESOHINT1`, O, F(run), L |
| P prepared projection | `ESOHJOB1`, L, F(canonical Job0 JSON) |
| S durable stage ref | `ESOHSTG1`, O, F(run), I, P, parent identity, root identity, u16 child-entry count, then for each sorted child F(relative path), identity, u64 size, and content digest B32 |
| D durable marker ref | `ESOHMRK1`, O, F(run), I, S, P, L, raw 32-byte mutation ref, u64 predecessor revision |
| C job correlation carrier | HMAC-SHA-256 binding key over `ESOHCOR1`, O, F(run), S, D, P, L. Encode 64 lowercase hex in exactly `Job.Meta["es_operational_correlation_v1"]`. |
| W durable positive observation ref | HMAC-SHA-256 binding key over `ESOHEVD1`, O, F(run), S, D, P, L, u64 initial index, raw 16-byte evaluation UUID |
| R durable receipt ref | HMAC-SHA-256 binding key over `ESOHREC1`, O, F(run), S, D, P, L, W |

L is the SHA-256 of its preimage. Stage identity encoding is type u8 (1
directory, 2 regular), u64 device, u64 inode, u32 uid, u32 gid, u32 POSIX mode
bits 07777, u64 link count. Compare against both held and visible descriptor
identities. Child order is ascending unsigned pathname bytes. Directory
size/digest in the preimage are zero, file size and unprefixed SHA-256 over
bytes are exact. Qualified parent identity and mount constraints are
validated separately from per-entry mode restrictions. Job0 has no carrier,
stage digest or filesystem inode. The wire Job adds only C to Job0.
§6 verifies C separately and removes it before comparison. This makes S,
D, C acyclic and lets recovery recompute P without adopting stage files.
The durable store protects the retained immutable D and S. Reconciliation
uses them directly after row authentication and structural validation.

## 6. Provider exchange and receipt

### Deterministic projection and permitted normalization

Job0 is the closed object rendered by the current `buildNomadJobSpec` rule
from the qualified captured projection with the target job ID, explicit
`Region` and `Namespace` added and initial priority set to integer 50.
Effect-bearing fields rendered by ES are the following, with no omitted or
additional submitted keys:

| Location | Fields and selected values |
| --- | --- |
| Job | ID and Name both target job ID, Region and Namespace from L, Type batch, Datacenters singleton frozen DC, Priority 50, Meta, TaskGroups singleton |
| Job.Meta | run_id is exact RunRef, execution_substrate.authority_handoff.schema is the literal v1, execution_substrate.authority_handoff.runtime_profile is frozen selected profile, execution_substrate.authority_handoff.workload_zone_vault_config_digest is exact captured zone digest. Only final wire adds es_operational_correlation_v1. |
| TaskGroups[0] | Name and Count from PB1-frozen job envelope (count 1), RestartPolicy Attempts/Mode/Interval/Delay and ReschedulePolicy Attempts/Unlimited/Delay/DelayFunction/MaxDelay from that envelope, Tasks singleton |
| Tasks[0] | Name/Driver/User from envelope, driver docker, Env exact existing rendered runtime map including frozen authority handoff, Resources CPU/MemoryMB from retained plan, Meta exactly run_id/artifact_digest/derivation_spec_digest/output_id from run and retained plan, Config |
| Config | image is qualified digest-pinned runtime image, command/args exact resolved supervisor command, privileged/security_opt exact qualified envelope, mounts exact built-in layout mapping for payload/run/SPIRE, network_mode is none. No added workload mount, alternate credential/image or network mode. |

The four Config.mounts entries, in order, are dictionaries with exactly
these fields. First, type=bind, source=<staging parent>/<RunRef>/payload,
target=/execution/staged, readonly=true. Second, type=bind,
source=<staging parent>/<RunRef>/run, target=/execution/run, readonly=false.
Third, type=tmpfs, target=/run/es-runtime-identity/<RunRef>, readonly=false,
and tmpfs_options with sole size key equal to retained identity tmpfs uint64.
Fourth, type=bind, source=directory of the frozen SPIRE socket, target=
/run/es-runtime-identity/<RunRef>/internal/source, readonly=true.
Check the existing qualified ownership contract for these layers. Require
native qualification to prove mutable writes isolated from retained inputs.
No runtime script, alternate Job builder or native adapter is created in
this turn.

The canonical JSON model is UTF-8, unique decoded object keys sorted by
unsigned UTF-8 bytes, arrays preserved, no insignificant whitespace,
double-quoted strings using shortest valid escapes for quote, backslash
and controls (named JSON control escapes where available, otherwise
lowercase four-digit u escape), raw UTF-8 for other scalar values, booleans
and null in lowercase, and decimal integer tokens normalized to their
mathematical value. Numeric domain is signed 64 to unsigned 64 inclusive
(`-2^63..2^64-1`), no negative zero, fractions or exponents. Refuse invalid
UTF-8/unpaired surrogates, duplicate decoded keys, trailing tokens, any
unsupported number, >16 levels, >8192 nodes or >65536 bytes decoded string.
No coercion, absent/empty equivalence or array reordering. Job0 ≤65536
bytes as Go's `encoding/json` writes it, with each `<`, `>`, `&` and control
byte as a six-byte escape. That form is at least as long as the one Nomad's
API writes when GET Job returns the job (Nomad v2.1.1 writes HTML characters
as they are), so the expanded Job stays within the GET bound below.
Canonical complete POST body ≤131072 bytes. Before the claim is stored, ES
projects Job0 and the POST body with a stage, a job name and a correlation
value of the lengths every run has, and refuses a request that does not fit
either bound as `OperationalMalformed`, with no claim, no reservation and no
publication. The projection after the run assignment therefore cannot fail
for size. HTTP JSON objects are strictly parsed even for removed or
immaterial fields.

GET Job returns Nomad's expanded Job object. Verify and then remove exactly
top-level CreateIndex, JobModifyIndex, ModifyIndex, Version, Status,
StatusDescription, Stable and SubmitTime. Version must be integer 0. Initial
indexes must agree as below. Status is one of pending, running or dead.
StatusDescription is string ≤4096 bytes, Stable boolean, SubmitTime positive
signed-64 ns. Verify C at its exact Job.Meta key and remove that key only.
The remaining whole object must equal the exact expanded template rendered
with the Job0 field values above. Every effect-bearing field is either a
named submitted value in the table, or an exact literal in the commissioned
expanded template. No other provider field may be ignored or wild-carded,
including the commissioned token accessor when serialized, Periodic,
ParameterizedJob, Multiregion, ParentID, Stop, AllAtOnce,
NodePool, Datacenters, constraints/affinities/spreads, dispatch, identity,
services/connect, networks/ports, scaling, volumes, actions, templates,
secrets, lifecycle hooks and policy/default values at every nesting level.

The template is a private canonical JSON object ≤65536 bytes with the actual
expanded inert/default literals and only these substitutions. At each
Job0 scalar or complete submitted variable collection in the table use an
object consisting of the sole key `"$job0"` with exact RFC 6901 pointer to
that same location in Job0. Placeholders for entire Meta, Env, Datacenters,
Config.mounts, Config.args and Config.security_opt are permitted as leaves.
Use individual named scalar placeholders for all remaining submitted
fields. All named submitted paths must be covered, each exactly once,
same pointer and destination. Object ancestors in Job0 retain structure
and arrays retain the one-group and one-task cardinalities. No placeholder
in any other position or added template key containing dollar sign. Dynamic
provider values beyond the explicit normalization removals cause refusal.
Use `SHA256(ESOHJTPL1 || F(canonical template))` as TLV 11 leaf 15.
Before provisioning require an authoritative checked template for this
exact build/admission/mount epoch and prove every fixed value is within the
selected execution shape. The proof fixture has its own frozen exact
template. No template inference from GET, caller input or immediate response.
Template/load mismatch is inconclusive. Native template qualification is a
later gate that must verify the installed defaults, including serialization
and normalization compatibility.

### Exchange limits and positive witness

| Exchange condition | Selected behavior | Extra POST deliveries |
| --- | --- | --- |
| FirstMarkerSender | One synchronous direct bounded POST, consumed before entry | 0 |
| RedirectOrReplay | Refuse redirect, retry and transport replay, including fallback | 0 |
| MissingOrRejected | Preserve ambiguity on 404, collision, timeout or other inconclusive response | 0 |
| PositiveAcceptance | Require qualified Job plus unique matching initial registration evaluation before receipt CAS | 0 |

Direct `POST /v1/jobs?region=<region>&namespace=<namespace>` with
`Content-Type: application/json`, exact host/realm/paths from L. Request
body contains exactly Job with C, EnforceIndex=true and JobModifyIndex=0.
Use explicit identity encoding, one fixed Content-Length, no Expect
continue, no redirects, proxies, middleware retries, replayable GetBody,
idempotency header, POST fallback, alternate endpoint or provider.
One fresh nonpooled HTTP/1.1 authenticated connection per exchange, no
HTTP/2, no reusable idle connection, no TLS early data. Trust only
commissioned direct endpoint and identity with probe-qualified no replay
behavior. Synchronous attempt uses total 5 s maximum (including connects,
TLS, headers/read), 1 s dial and 2 s TLS within it, ≤16384 response header
bytes, and immediate response ≤16384 body bytes. Consume the sender before
the only transport entry, regardless of whether bytes reach the receiver.
Count logical POST deliveries separately from TCP retransmissions. Count
entry, target receiver ingress and redirect receiver ingress separately.

Every request of the provider, the POST and both GETs, carries ES's Nomad
ACL client token in one `X-Nomad-Token` header and never in the URL. The
token comes from the same startup custody as the current submit client's
(`nomad.token_file`), and the provider cannot be built without a token in
Nomad's canonical SecretID form. No redirect is followed, so the token
reaches only the commissioned endpoint. PR #31's token guard holds the
provider's requests to its one request builder, and a runtime test checks
the token on each of the three requests.

A usable immediate response is HTTP 200, uncompressed JSON, object with
EvalID (canonical lower-case nonzero UUID in 8-4-4-4-12 form),
EvalCreateIndex, JobModifyIndex and Index (all same positive u64). The pinned
handler serializes embedded QueryMeta. Require LastContact integer 0,
KnownLeader false, NextToken empty string and Warnings empty string. Require
X-Nomad-Index equal to body Index. Refuse missing, unknown, duplicate or
wrongly typed members in this closed shape. Check a single application/json
content type with optional UTF-8 charset and absent or identity
Content-Encoding on every accepted response. An unparseable/nonselected response may leave the outcome ambiguous
and never authorizes a POST. A positive proof requires GETs even after an
immediate acknowledgement. Compare its UUID and index if authenticated
immediate ACK is available in the same invocation. No write for storing
that ACK alone.

Read each once, ordered Job then Evaluations, with same region/namespace and
peer, `GET /v1/job/<job>` and `GET /v1/job/<job>/evaluations`, using the same
query as POST. Omit stale, blocking/wait/index, filter and pagination.
Pinned direct qualified leader/consistent read path for both requests. Verify
HTTP 200, single-valued `X-Nomad-KnownLeader: true`,
`X-Nomad-LastContact: 0` and canonical positive decimal `X-Nomad-Index` at
least initial registration index on each response. The Job index header equals
Job.ModifyIndex. The Evaluations index header is at least every returned
evaluation's ModifyIndex. Those headers supplement commissioned read provenance. They cannot
supply it by themselves. Header size/connection rules as above, each response
≤262144 bytes and 5 s, 10 s pair maximum. Evaluations is a complete array
of 1..64 objects. Refuse pagination indications, duplicate IDs or mixed
job/namespace/type. Each evaluation requires canonical UUID, Namespace, JobID,
Type=batch, TriggeredBy, Priority, CreateIndex, ModifyIndex and JobModifyIndex.
Require positive create and job-modify indexes, ModifyIndex ≥ CreateIndex,
nonnegative integer Priority ≤100, ASCII trigger 1..64 bytes. Other eval
fields are structurally parsed and bounded but never interpreted as proof:
scheduler status/times/metrics/links convey no registration polarity.
Exactly one evaluation has TriggeredBy=`job-register`. Its Priority is
50 and its JobModifyIndex=CreateIndex=Job.CreateIndex=Job.JobModifyIndex>0.
Job.ModifyIndex ≥ Job.JobModifyIndex. Require the unmodified version zero
specification and exact C, Job projection and full locator. A foreign job,
registration collision, missing/expired evaluation, second registration eval,
initial-index mismatch, compare mismatch with authenticated ACK, oversize,
404, timeout, stale or other unqualified observation is inconclusive. A
404 carries no negative terminal inference. Preserve ambiguity and zero
new POSTs. No requirement that both reads be one atomic Job+Eval snapshot.

Primary source reference is Nomad v2.0.3,
`a2a5fee9c42d6481adcb9be865bcbccf8fd4d725`. The
[register endpoint](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/nomad/job_endpoint.go#L290-L375)
constructs the registration evaluation and indexes the success response
with the Raft index. [State store job
upsert](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/nomad/state/state_store.go#L1785-L1870)
checks EnforceIndex inside the write transaction and assigns initial Job
indexes. [FSM job registration](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/nomad/fsm.go#L695-L806)
uses separate job and eval writes, stamping the evaluation's JobModifyIndex
with that Raft index. The
[HTTP handler](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/command/agent/job_endpoint.go#L555-L617)
returns the [register response with embedded
QueryMeta](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/nomad/structs/structs.go#L1447-L1456).
The GET endpoints derive their indexes from the returned Job and eval table
respectively. [State evaluation
upsert](https://github.com/hashicorp/nomad/blob/a2a5fee9c42d6481adcb9be865bcbccf8fd4d725/nomad/state/state_store.go#L3435-L3490)
assigns a new evaluation's CreateIndex and updates ModifyIndex.
[Nomad registration API](https://developer.hashicorp.com/nomad/api-docs/jobs#register-job)
and [consistency modes](https://developer.hashicorp.com/nomad/api-docs#consistency-modes)
supply the exchange context. Installed source, build/patches/defaults, ACL,
namespace exclusivity, read provenance and actual transport still require
qualification. The current ES installer leaves Nomad unpinned.

Only the typed verifier constructs PositiveProof bound to O, same RunRef,
I, S, D, P, L and exact positive UUID/index witness. Compute W and R using
§5 (I is bound by D and validated predecessor). The admission caller passes
opaque proof to durable service, which rebinds it and exact authorized
pair/projection to the fresh checked row and expected revision before the
single kind-8 CAS. Independently qualified concurrent winners return only
the authenticated accepted row's receipt. No replacement even with a later
observation. A known mutation or successful exact own-commit confirmation
can project the same receipt. Failure to confirm leaves that invocation
unknown. A later accepted read recomputes O, P, L and receipt MAC over the
stored W and exact permanent stored marker and stage. W is the trusted
stored positive witness commitment, never a request-supplied value.
There is no need to rerender mutable resolver inputs, verify provider status
again, or read staging. Current caller authorization, original qualification,
equivalence, paired ACTIVE/RETIRED keys and checksum/MAC match are required.
A receipt concerns registration acceptance only. Nomad lifecycle and
Coordinator acceptance remain independent.

## 7. Authority and history matrix

This table is normative. New independent invocation authorization always
requires the current §4 gate. Prior observed dispositions convey zero authority.

| Scenario | Evidence | Sender count | Permission | Projection |
| --- | --- | --- | --- | --- |
| FreshPrestage | Fresh qualified writer turn, absent stamp and physical stage, exclusive-create only | 0 | CreateOneStage | Same run, pending until first marker |
| UnlockedAbsence | Snapshot, cache, preflight or unlocked marker absence | 0 | Stop | No effect eligibility |
| StageOwnerLost | Stage residue or retained stamp without original live owner | 0 | Stop | Same run pending or ambiguous, residue charged |
| PrestageUnknownSettled | Prior invocation stopped, fresh checked turn and no stamp or physical stage | 0 | CreateOneStage | Earlier response preserved, independent same-run eligibility |
| MarkerRollbackAfterStage | Real marker rollback or failed marker with completed stage residue | 0 | StopBothInvocations | Fresh absent marker cannot confer stage ownership |
| MarkerCommitReplyLost | Real marker COMMIT, response lost, even with exact readback | 0 | NeverPost | Same-run ambiguity until positive proof |
| MarkerDirectOwnerConsumed | Directly acknowledged first marker and one valid consumed live owner | 1 | AtMostOneReceiverDelivery | Receiver-count positive witness has exactly one ingress total |
| MarkerDirectOwnerLost | Known marker with canceled, failed or crashed owner before entry | 0 | NeverPost | Possibly indefinite ambiguity |
| MarkerCASLoser | Two marker commands, only the applied and directly acknowledged command eligible | 0 | NeverPost | Current projection only |
| Provider404 | Qualified GET absence or any inconclusive evidence | 0 | PositiveObservationOnly | Ambiguous, no negative terminal |
| AcceptedReplay | Current caller and qualified equivalent retained original with an eligible ACTIVE or RETIRED key pair | 0 | ReceiptOnly | Same immutable run and receipt without mutable admission, resolution, staging or provider |
| SyntheticAuthority | Synthetic row, object, permit, borrow, marker or receipt | 0 | OccupancyOnly | Unavailable across scope |
| PublicOrRouteOnly | Public route/startup or route-level permission alone | 0 | Refuse | Public keyed refusal and claim-scoped later gate |

K1 indistinguishable histories: A loses a pre-stage write response after
a settled applied intent. B directly observes that same write with the same
retained state and physical absence. With equal qualified current inputs,
both later explicit invocations may acquire the single new stage and then
seek the first marker. A's historical observed response stays unknown.
C loses a real first-marker COMMIT response. D directly observes the same
COMMIT then crashes before entering transport. Equal marker/stamp/row bytes
and equal current inputs afford zero senders to either later invocation,
regardless of distinguishable old in-process events. E rolls back a marker
after valid staging. Equal retained absence before/after a checked writer
turn is compatible with that rollback, but the prior physical stage and stamp
prevent distinct owner acquisition. No later invocation can recover zero POST
as proof of negative acceptance. A positive test follows the applied direct
marker, consumes once and counts exactly one ingress. The contract bounds
logical deliveries by one, and allows zero from a known marker.

For the safety argument, every eligible POST originates in the unique
applied NULL-to-marker transition on the qualified domain. The permanent
marker and serialization/current-revision CAS exclude a second transition.
Direct acknowledgement of that applied write is the only mint event. Recovery,
replay, no-op, losing CAS and restart allocate zero. A matching live, held
stage and frozen request can consume the sender once. Direct transport
introduces no second logical POST. Together these premises give conditional
at-most-once ES registration dispatch, with indefinite ambiguity, inert
residue and zero delivery possible. The model offers no exactly-once
execution, guaranteed send, registration acceptance, execution completion,
or universal prevention of workload side effects.

## 8. Capacity, disposal and later gates

The proof caps codec-5 claims at four via the checked writer count, including
all operational phases forever. Preserve global caller/key occupation across
legacy and synthetic records, count pre-existing operational records when
opening, and apply any tighter existing aggregate legacy/synthetic path bound
to that path without converting its quota into operational capacity.
Classify an existing key normally before new-work capacity refusal. Across
scopes share the custody object's exact 32-name limit (published and orphan
names, plus active exclusively allocated names), and a 32 aggregate reservation
cap over persistent charged counters across all purposes admitted to the
envelope publisher, including prior reservations and orphan sites. Each new
envelope grant consumes one durable aggregate reservation under the shared
writer plus the existing actual-key budget. Count an object once by its
qualified name. Completed or unconfirmed cleanup does not refund a charge.
For operational allocation the held-directory scan qualifies every existing leaf by canonical name, regular-file mode, ownership, device, link count and bounded size before creating a new name. Unknown accounting, unexpected names or exceeded bounds refuse new work.
No expiry, refund, reuse, automatic GC or routine human approval.

Allow at most one stage attempt/residue per assigned operational run, hence
four proof-stage roots and ≤4 MiB payload bytes total plus bounded metadata.
Limit custody payload to 32 × 2 MiB plus bounded metadata. Proof preconditions
include isolated finite test filesystem and reserved storage. SQLite and
sidecar allocation and runtime results require independent native byte and
capacity bounds. No operational limits are extrapolated from proof sizing.
Keep hard-close latency, physical/device close, actual double withholding
and hostile-native filesystem behavior as qualification/availability limits.
If disposal cannot be confirmed, release no further authority. Native evidence
must address SQLite sidecar/file-byte preservation and prohibit restoration
as an effect-enablement shortcut. These residuals do not select an unrelated
helper campaign.

Before native use require exact caller authorization (one verified canonical
SPIFFE workload identity, no route-level substitution), default-off startup,
es:es owner-only state/store/custody keys, domain/epoch commissioning, exact
provider build/pin and writer exclusivity, direct transport and read provenance,
native stage/mount identity and integrity, finite retained storage, and
caller-scoped lifecycle access with claim ownership. Current unkeyed Submit
and its builder, public structural keyed refusal, handlers, startup and
fixture composition have zero callers of the target entry. No new public
HTTP status, DTO field, producer declaration or configuration spelling is
selected. Current finite inventories enumerate the private typed references in the local candidate.

Commissioning gate. Commission, advance and withdrawal have zero production
callers, and so have the two private handoff entries and the domain and
provider constructors. A maintained gate fails on the first non-test
reference to any of
them and prints the prerequisites below, which must each be answered before
such a reference is added. The gate's identifiers are pinned against this
list, so the gate and this document cannot drift apart.

| Identifier | Prerequisite |
| --- | --- |
| `CP-ROLLBACK` | The trust publication carries a signed monotonic sequence, or an equivalent the owner accepts, so that an older validly signed payload cannot be confirmed as current. |
| `CP-EPOCH` | An epoch-change procedure exists, with drain or terminal rules for unmarked claims and receipt reads under a historical realm. Until then the stored installation and epoch cannot change. |
| `CP-POLICY-CUSTODY` | Who may commission, advance and withdraw, and where the installation policy is stored. |
| `CP-NATIVE` | The native prerequisites of the paragraph above. |
| `CP-RELEASE` | One qualified release per domain is enforced, or the admission digest covers the release. The digest covers configuration, not the compiled behaviour of the built-in policies. |
| `CP-NOMAD-ACL` | The provider's Nomad access under access control is settled: ES's token holds `submit-job` and `read-job` in the operational namespace and no other policy may write there, set up and checked by the Nomad ACL tool; registration runs the current submit path's access-control check over the provider's own pinned transport before `POST /v1/jobs`; what a 401 or 403 on registration means for the claim is selected; and the provider's endpoint and pin come from the same ES configuration as the current submit client's Nomad identity. |
| `CP-PUBLIC-MAPPING` | The public mapping of the handoff's results and reasons is selected: what each private reason tells a caller of the public keyed path. It includes what a first delivery that ordinary resolution refuses tells its caller. The private result answers `OperationalUnavailable` there, whatever the cause, while ordinary Submit names a refusal by the rules (`signer_revoked`, `artifact_revoked`). |

## 9. Future integrated proof and bounded path map

The consolidated repair adds one conditional companion to the original
repair map. `I/sqlite_store.go` may change only in `sqliteClaimRow.record`
for the exact codec-5 raw optional-BLOB check above. The rest of that file,
the shared scanner, codecs 1–4, migration literals and all stored formats
stay outside this correction. The repair allowance is 19 primary and eight
conditional paths with the same 37-file aggregate HEAD ceiling.

The following is the local candidate path allowance and proof map.
`I/` means `es/admission/internal/reliablesubmit/` and `A/` means
`es/admission/`. Any further file requires separate owner reconciliation at
that gate. Follow existing CAS, original custody, sidecar disposal and
reachable-caller inventories.

| Exact prospective paths | Governing scope and planned witnesses |
| --- | --- |
| I/sqlite_migrations.go, I/sqlite_store.go, I/sqlite_replay_shape.go, I/sqlite_replay_progress_schema.go, I/sqlite_replay_claim.go, I/sqlite_operational_handoff_schema.go (new) | §2 compatibility, atomic migration 5, exact shape/row and scope enforcement. Append a new literal and preserve migration 1–4 payloads |
| I/durable_record.go, I/durable_operation.go, I/durable_service.go, I/replay_custody_file.go, I/replay_custody_format.go, I/replay_key_use_sqlite.go, I/operational_handoff.go (new) | §§2–5 exact row/CAS, receipt admission, same original/key checks and sender callback boundary. Reuse the existing physical custody publisher |
| A/reliable_submit_operational_handoff.go, A/reliable_submit_operational_format.go, A/reliable_submit_operational_provider.go (new) | §§3–7 exact original/projection and one private composition with a finite private loopback-provider seam |
| A/staging_custody.go, A/executionpackage.go | §§4–5 already-held custody and layout projection for stage proof, preserving the ordinary path |
| I/operational_handoff_test.go (new), I/sqlite_replay_migration_test.go, I/sqlite_replay_shape_test.go | `TestOperationalHandoffMigrationCompatibility`, `TestOperationalHandoffWriterDisposition`, `TestOperationalHandoffFirstMarkerCAS`, `TestOperationalHandoffKeyCutsAndCapacity` |
| A/reliable_submit_operational_handoff_test.go, A/reliable_submit_operational_provider_test.go (new) | `TestOperationalHandoffPrestageRecovery`, `TestOperationalHandoffMarkerDispositionAndStageResidue`, `TestOperationalHandoffSenderLifetime`, `TestOperationalHandoffProviderExchange`, `TestOperationalHandoffReceiptRecovery` |
| I/guardrails_test.go, A/reliable_submit_guardrails_test.go, A/workstream_c_guardrails_test.go | `TestOperationalHandoffNoPublicStartupOrdinaryOrFixtureCaller` plus exact current-to-target inventory delta if new transient state is implemented |
| PLANS.md, .docs/execution_lifecycle/reliable_submit_operational_handoff.md, .docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md, .docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md, .docs/execution_lifecycle/es_execution_admission_model.md, docs_contract_test.go | Owner precedence and source status, replace schema-head assertion only when source changes |
| I/sqlite_physical_test.go, I/sqlite_store_test.go | Conditional schema tests move the unsupported codec above codec 5. Keep malformed supported-encoding cases separate and preserve the genuine schema-2 fixture. |
| I/replay_custody_file_test.go | Conditional exact scope-aware opener inventory, preserving the inherited nonblocking FIFO controls. |
| I/replay_custody_structure.go | Conditional shared reader bounds and exact operational TLV 11 validation. Synthetic document sizes, proofs and scope dispatch continue to use their own cases. |
| A/reliable_submit_replay_private_test.go | Scope amendment to the finite typed PB1 producer caller inventory in TestPrivateReplayFiniteCallerAndNoRuntimeWiring, preserving both fixture sites and the direct-call, count, escape and no-runtime checks. |

The PR #12 retained-current-admission v2 repair is a separate owner
reconciliation at this gate. It adds exactly five paths outside the table:
A/reliable_submit_operational_admission.go (new),
A/reliable_submit_operational_admission_test.go (new), A/service.go,
A/resolved_execution_plan.go and .docs/system_overview/boundaries.md. With
them the aggregate HEAD count for PR #12 plus that repair was 42 files.

The durable admission generation repair is a further owner reconciliation at
this gate. It adds exactly four more paths: I/operational_admission.go (new),
I/operational_admission_test.go (new),
A/reliable_submit_operational_admission_redteam_test.go (new) and
.docs/execution_lifecycle/implementation.md. With them the aggregate HEAD
ceiling for PR #12 plus both repairs was 46 files.

The admission state package is a further owner reconciliation at this gate.
It adds exactly two more paths: A/internal/admissionstate/state.go (new) and
A/internal/admissionstate/state_test.go (new). With them the aggregate HEAD
ceiling for PR #12 plus its repairs was 48 files.

The tests adopted from the red-team of the combined PR #12 are a further
owner reconciliation at this gate. They add exactly four more paths, all test
files: A/reliable_submit_operational_admission_redteam2_test.go (new),
A/reliable_submit_operational_admission_redteam2_crash_test.go (new),
A/reliable_submit_operational_admission_redteam2_guard_test.go (new) and
A/reliable_submit_operational_admission_limits_test.go (new). With them the
aggregate HEAD ceiling for PR #12 plus its repairs was 52 files.

The correction after the sixth audit is a further owner reconciliation at
this gate. It adds exactly one more path, a test file:
A/workstream_a_guardrails_test.go, whose source-term guard now reads the
real line of each occurrence, as every guard does. With it the aggregate
HEAD ceiling for PR #12 plus its repairs was 53 files.

Taking up `trunk_dev` after its PRs #23 and #22 is a further owner
reconciliation at this gate. Since PR #23, every test package of `trunk_dev`
runs its tests under a temporary directory whose path holds no symbolic
link, and a test fails for a package without the file that arranges it; the
admission state package is a new test package. PR #22 added a root test file
with two reads of an adjusted position, which the position-read test of this
document refuses. The CI's list of environment-only tests must name the
tests of this handoff that fail or skip themselves on the runner by design,
and its check refuses a line for a test that `trunk_dev` alone does not
define. It adds exactly three more paths, two test files and the CI's list:
A/internal/admissionstate/testtmpdir_main_test.go (new), which holds only
the package's `TestMain`,
remote_alpha_es_service_tls_status_local_boundary_test.go, whose two
position reads now ignore line directives, and
.github/ci/environment-only-tests.txt, which gains two lines: one for a test
that fails on the runner without its probe binary, and one for a test that
skips itself there. With them the aggregate
HEAD ceiling for PR #12 plus its repairs was 56 files.

The repairs after the third red-team of PR #12 and after its guard coverage
review, with taking up `trunk_dev` after its PRs #27 and #29, are a further
owner reconciliation at this gate. Taking up `trunk_dev` adds no path.
Nomad's client evaluates `${...}` and `%{...}` in the strings of a task as a
template, so the shared invocation validation and the mount target rule
refuse them in every string ES places in a job. The sizes of Job0 and the
POST body are checked before the claim, by one more reviewed caller of the
run projection with names of the lengths every run has, and every non-test
Go file may hold only reviewed `//go:` directives. The inventories and the
test of those lengths are in A/workstream_c_guardrails_test.go and
I/operational_handoff_test.go, which are already counted.
It adds exactly ten more paths, one production file, two
documents and seven test files:
A/mounts.go, whose mount target rule refuses those strings,
.docs/execution_lifecycle/contracts.md and
.docs/system_overview/contracts.md, which state the refusal,
A/nomad_request_strings_test.go (new),
A/reliable_submit_operational_job_bound_test.go (new) and the red-team's
five test files A/reliable_submit_operational_admission_redteam3_test.go (new),
A/reliable_submit_operational_admission_redteam3_codec_test.go (new),
A/reliable_submit_operational_admission_redteam3_finding_test.go (new),
A/reliable_submit_operational_admission_redteam3_fuzz_test.go (new) and
A/reliable_submit_operational_admission_redteam3_process_test.go (new). With
them the aggregate HEAD ceiling for PR #12 plus its repairs was 66 files.

The repairs after the red-team re-check of those repairs, with taking up
`trunk_dev` after its PRs #33, #41, #37 and #39, are a further owner
reconciliation at this gate.
Nomad's client parses each string of a task's driver configuration with
HCL, which drops a byte order mark at the start of the string and holds it
in Unicode Normalization Form C. So the shared invocation validation and the
mount target rule refuse, in each argument and each mount target, a leading
byte order mark, a string that is not in that form and a code point that is
not assigned in the Unicode version of ES's normalization tables, which
every later version of those tables then leaves unchanged. Nomad registers
no task with less than 10 MB of memory, so the shared request validation
refuses less. The reviewed list of dependency packages gains the two
packages of `golang.org/x/text` that the rule imports, in
A/workstream_c_guardrails_test.go, which is already counted.
PR #39 moved the tests of the scripts from the repository root to
scripts/, among them the counted
remote_alpha_es_service_tls_status_local_boundary_test.go, which keeps its
count there. It added internal/testutil/testutil_test.go, whose three
problem reports read a position that PR #12's position-read test refuses.
It adds exactly three more paths, the module file and two test files:
go.mod, which makes `golang.org/x/text` a direct requirement at the version
already selected, A/nomad_request_strings_redteam31_finding_test.go
(new), the re-check's tests, and internal/testutil/testutil_test.go, whose
three position reads now ignore line directives. With them the
aggregate HEAD ceiling for PR #12 plus its repairs was 69 files.

The repairs after PR #31 locked Nomad, with taking up `trunk_dev` after its
PRs #43, #42, #34 and #31, are a further owner reconciliation at this gate.
The operational provider now sends ES's Nomad token on its three requests,
prepares the registration with its own builder, and the commissioning gate
gains the prerequisite `CP-NOMAD-ACL`. A driver string must also be valid
UTF-8. Those changes are in A/reliable_submit_operational_provider.go,
A/reliable_submit_operational_handoff.go, A/service.go and their tests,
which are already counted. It adds exactly one more path, a test file:
A/nomad_request_guard_test.go, PR #31's token guard, which now covers the
provider and reads unadjusted positions. With it the aggregate
HEAD ceiling for PR #12 plus its repairs is 70 files.
Any further file again requires separate owner reconciliation.

The seal-permit guard follows the shared reservation writer
`reserveReplaySealUseWithScope`, the sole constructor after confirmed COMMIT.
The existing fixture wrapper selects the same fixture path, including its
registration and burn behavior. The operational path selects an already
registered key pair and checks global occupancy under the same reservation lock.

The operational PB1 sites are `A/reliable_submit_operational_handoff.go:
Service.composeOperationalOriginal` once for a newly resolved original, and
`A/reliable_submit_operational_format.go:verifyOperationalOriginal` once for
rehydration from captured inputs. Each calls the existing PB1 producer
directly. They join both existing fixture sites in the exact private
reference inventory. Only the original-production path may resolve.

Migration witness opens exact 1/2/3/4/5, preserves every legacy/progress byte
and physical rowid across migration, rejects malformed tuple/index/NULL cases,
proves scoped RunRef uniqueness, cross-scope collision and no conversion.
Use a separately source-bound schema-4 opener from the exact PR #11 squash
and offline inputs. Permit read-only version and schema qualification.
Require refusal with zero operational claim or payload hydration and
disclosure, migration or semantic writes, and relabeling. Historical
schema-2 and schema-3 probes cannot establish this check. Bind old compiled
opener and baseline/support source exactly. The local populated schema-5
refusal witness compares complete logical state and all retained sealed files.
At a separate quiescent cut close current pools, capture the exact main
database, WAL, SHM and journal identities/modes/bytes and explicit absences,
then invoke the immutable opener. Capture again before any logical read or
lifecycle observer. Native durability and hostile filesystem qualification
remain independent.
Precommit rollback and real COMMIT-response loss continue to require exact
checked disposition.

Use independent real SQLite handles and two processes on the same files, plus
explicit held-writer and release barriers, to distinguish excluded/stale turns
and real applied writes from recovered or ambiguous outcomes. Inject a real
rollback before marker COMMIT and a real COMMIT with lost response separately.
Check exact row, revisions, immutable descriptor and stage bytes/modes, retained
charges and transport counts at each boundary. Compete two marker attempts,
verify single CAS and sender, and deny old, stale or canceled owners. Verify
uncertainty stop for claim, assignment, intent, stage and receipt. Exercise
positive pre-stage restart independently from both marker-failure histories.
Exercise retired/revoked/missing/mixed-purpose keys at paired cuts and changed
epoch/installation. Refuse path mutation, replaced file identity, partial and
complete residue and missing physical staged directory. Test zero, copied,
foreign, escaped and expired sender and closure/cancel racing actual entry.

Actual counting loopback exchanges must witness single logical POST and zero
duplicate/redirect target ingress, including ambiguous/lost transport response.
The maintained proof separately counts direct exchange-method entry immediately
before the unchanged concrete RoundTrip call, standard HTTP GetConn callbacks,
and receiver ingress. The first is a synchronous call attempt, not proof of an
OS send or provider receipt. GetConn may be zero after method entry when the
request is canceled. The instance-scoped nil-default entry observer returns no
transport result and carries no effect authority. It also closes the first custody handle after losing the
response to a POST that reached the receiver. Reopening recovers the same
run through read-only provider observation.
Return lost provider reply, 404, timeout, stale/unqualified provenance, missing
eval, wrong/create/modify index or polarity, duplicate JSON and oversized
body, foreign Job or eval, changed defaults/metadata, wrong carrier and
valid exact evidence. Accept only the last valid positive evidence case with
receipt CAS. Verify concurrent winner and exact receipt after lost COMMIT
response, and same receipt after mutable resolver/admission changes with
eligible keys. Count zero resolver/stage/provider interactions for accepted
replay, and assert unauthorized before lookup and no foreign-run projection.
Use actual fixture staging/SQLite with the same private orchestration entry,
never a test-only reimplementation of the handoff decision. Verify current
ordinary Submit and fixture paths remain disjoint. Documentation tests
establish these selected obligations statically. Local proof results are recorded in the evidence for this candidate. Native
qualification and independent source acceptance are later gates.
