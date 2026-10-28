# R6J-R9.28/Stage-A outside-observer structural contract

## Status, sources, and authority ceiling

This is a **target-only, non-enabling** contract slice under the reopened
authority-issuance and worker/runtime-handoff seams in `PLANS.md`. The exact
accepted owner is the R9.28 delivery envelope of 168,307,308 bytes, SHA-256
`5b637a7247af865c888590863b021db9e5aa7fc15dd91aed50ad552a2cbad33c`;
its embedded owner is 167,125,065 bytes, SHA-256
`b9c1f5933155d39cf5f656f9ca6a69d27fa86c7ccac4bdfd32aee57b829bb647`.
The separate accepted review is 75,355 bytes, SHA-256
`fc0a604e8fd294840f69c623aeba94754c1bad4088d3f3e0f54bb0b9d837a9f6`.
Its acceptance covers bounded artifact design, not ES implementation, runtime,
physical durability, production wiring, or repository adoption. The owner
remains unchanged. The review's navigation erratum maps F01–F05 to
R9.28.2–R9.28.6; it does not call for an R9.29 owner repair.

Selected target sources are `target/architecture/WIRE_SCHEMA_REGISTRY.json`,
`JOURNAL_AND_RECOVERY_CONTRACT.json`, `AUTHORITY_AND_PERMIT_CONTRACT.json`,
`AUTHORITY_AND_WRITER_MATRIX.json`, `STAGE_BOUNDARY_CONTRACT.json`, the frozen
`CANONICAL_JSON_V2.json`, `PRIVATE_PROTOCOL_V2.json`,
`DURABLE_JOURNAL_PROTOCOL_V2.json`, `R9_28_RELATION_CONTRACT.json`, and the
R9.28 appendix inside that owner. The model source is inspected reference,
not an installed ES implementation. A prior planning report incorrectly called
the complete `EvidenceFrameV1` a 16-field message. The selected registry and
model require **17 fields**; only its record-hash preimage omits `record_hash`
and has 16 fields.

`es/internal/outsideobserverprotocol` may parse only well-formed **untrusted**
data and compute deterministic local hashes. A successful return conveys no
authenticated SPIFFE peer, verified `RunEntryV4`, approved permit, consumed
receipt, durable journal, process observation, or execution permission. Its
types and functions are private to ES and have no production importer. Stage A
adds no API/config/job/supervisor call path, endpoint, runtime store, mutable
authority, fixture issuer, or production evidence intake.

## Current ownership and distinct target surfaces

Current ES admission composes its documented upstream inputs, applies the
configured caller SPIFFE allowlist, submits one Nomad job, and projects Nomad
lifecycle without creating a parallel lifecycle store. The current
`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is workload-visible discovery of the
supervisor/helper JWT endpoint; SPIRE issues JWT-SVIDs and Vault owns subsequent
workload token/secret/lease issuance. The proposed observer/receiver endpoint
is separate and absent. `control-plane-normal-shell/v1` and its selection
annotation remain a **Temporary compatibility edge** with the reason, scope,
and removal condition in the existing lifecycle contracts. No Stage A file
changes that behavior.

The target receiver journal is proposed evidence custody. `SOURCE_JOURNAL.log`
would be the source of committed observation evidence; `SOURCE_STATE.json`
would be a recovery-derived cache only, never accepted caller state or a new
execution-lifecycle authority. Stage A represents a possible derived state in
Go but does not parse, serialize, persist, publish, or accept a cache. The
`SOURCE_STATE/v2` literal appears in accepted model source but is not an
explicit selected frozen architecture literal; serialization requires a later
contract decision.

## Canonical bytes and local scalar rules

All selected messages use `r6j-canonical-json/v2`. Before typed decoding, a
parser limits raw bytes to 4,194,304 and nested depth to 128; requires strict
shortest-form UTF-8; refuses BOM, whitespace outside strings, trailing data,
duplicate decoded keys, and keys out of ascending decoded UTF-8 byte order;
and requires exact canonical re-encoding equality. Strings use literal Unicode
scalars, `\"` and `\\`, the short escapes for backspace/tab/newline/formfeed/
carriage return, and lowercase `\u00xx` for other controls. Escaped solidus,
printable/non-ASCII Unicode escapes, and surrogates refuse. Integer tokens use
ASCII `-?(0|[1-9][0-9]*)` only, with no negative zero, fraction, exponent,
plus sign, nonfinite value, float conversion, rounding, or boolean-as-integer.
Field-specific range checks follow token recognition. The selected generic
unsigned ceiling is **2^63−1**, not the Go `uint64` maximum. `hex32`/`hex64`
mean exactly 32/64 lowercase hexadecimal characters; `ascii_id_1_128` means
`^[a-z0-9][a-z0-9._-]{0,127}$`. Unpadded base64url must decode and re-encode
identically; an encoded-character bound limits allocation before decoding, and
the decoded size is checked after decoding.

Each parser refuses missing/unknown fields, wrong JSON kinds, null in required
scalar positions, wrong literals, bounds, and local hash or in-object binding
errors. Hash equality is only self-consistency of supplied untrusted values.
Errors do not echo raw inputs. A typed `true` inside an evidence payload remains
an untrusted claim that the asserted process event happened.

## Selected Stage A shapes and limits

The lists below are **exact field sets**, not ordered wire serialization lists;
canonical encoding supplies sorted key order. The static implementation must
check the stated local rules and must not infer the deferred relations.

| Shape | Exact fields and local checks | Deferred relation |
| --- | --- | --- |
| `EvidenceFrameV1` | **17:** `schema,version,run_id,entry_digest,permit_digest,source_instance_id,epoch,sequence,producer_role,qualified_clock_ref,observed_time,previous_record_hash,payload_type,payload_length,payload_sha256,payload,record_hash`. Literal schema/version 1 and producer `es/outsideobserver`; IDs, hex64 values, signed int64 observed time, epoch 1..2^63−1, sequence 1..16384. At most 2,162,688 canonical bytes; decoded payload at most 2,097,152. Decode canonical base64url; match length, selected payload schema, `SHA256("R6J-OBS-PAYLOAD/v1" || NUL || decoded bytes)`, and `SHA256("R6J-OBS-RECORD/v1" || NUL || canonical 16-field core without record_hash)`. Sequence 1 requires a zero `previous_record_hash`. For `SourceCompleteV1`, its `last_nonfinal_record_hash` equals this frame's `previous_record_hash`. | Authenticated session fields, previous committed record, sequence progression, and actual process observation. |
| `AckV1` | **11:** `schema,version,run_id,source_instance_id,epoch,sequence,record_hash,journal_segment_id,durable_offset,source_state,commit_id`. Literal schema/version 1; IDs and hex64; epoch/durable offset 1..2^63−1, sequence 1..16384, source state `OPEN/COMPLETE/ABORTED`; at most 16,384 canonical bytes. | Full binding to one recovered final commit and state before accepting chronology `ack_sha256` (Stage B). |
| `JournalHeaderV2` | **16:** `endpoint_nonce,entry_digest,epoch,journal_identity_sha256,journal_nonce,observer_session_nonce,observer_spiffe_id,permit_consumption_receipt_sha256,permit_digest,receiver_session_nonce,receiver_spiffe_id,run_id,schema,session_binding_sha256,source_instance_id,version`. Literal schema/version 2; exact observer/receiver SPIFFE strings, IDs, hex32 nonces, hex64 digests, epoch 1..2^63−1. Recompute the session-binding domain from the 11 supplied session-core fields and journal-identity domain from `{journal_nonce,session_binding_sha256}`. | Verification of entry/receipt, peer TLS, endpoint manifest, or journal provenance. |
| `JournalFrameV2` | **12:** `evidence_record_hash,exact_frame_bytes_b64url,frame_length,frame_sha256,journal_identity_sha256,payload_type,schema,session_binding_sha256,source_sequence,transaction_kind,transaction_sequence,version`. Literal schema/version 2; hex64; sequences 1..16384; frame length 1..2,162,688; canonical wrapper at most 2,884,158 bytes and embedded base64url at most 2,883,584 characters. Decode exact embedded frame bytes, enforce its 17-field parser, length, frame domain hash, record hash, payload type, same-object sequence and kind (`SourceCompleteV1` with `evidence_failure=true` -> ABORT; with false -> COMPLETE regardless of result kind; otherwise EVIDENCE). | Header lineage, actual framed bytes/CRC, append offset, previous transaction and committed chain. |
| `JournalCommitV2` | **15:** `commit_hash,commit_id,durable_offset_after_commit,evidence_record_hash,frame_record_sha256,journal_identity_sha256,next_source_state,previous_commit_hash,schema,session_binding_sha256,source_sequence,transaction_kind,transaction_payload_sha256,transaction_sequence,version`. Literal schema/version 2; hex64; offset 1..2^63−1; sequences 1..16384 and equal within this object; `EVIDENCE/COMPLETE/ABORT` maps locally to `OPEN/COMPLETE/ABORTED`. Recompute commit hash over its 13-field core and commit ID over raw 32-byte commit-hash bytes. | Framed-record hashes, real offset, prior chain membership, and recovery-derived state. |
| `ObserverHelloV1` | **13:** `schema,version,run_id,entry_digest,permit_digest,permit_nonce,source_instance_id,epoch,observer_session_nonce,endpoint_nonce,observer_spiffe_id,expected_receiver_spiffe_id,requested_limits`. Literal schema/version 1; selected IDs/hashes/nonces/SPIFFE strings; exact seven-value limits object; at most 65,536 bytes. | Authenticated peer, verified entry/permit, endpoint manifest, handshake/session establishment. |
| `ReceiverHelloV1` | **9:** `schema,version,run_id,entry_digest,receiver_session_nonce,endpoint_nonce,receiver_spiffe_id,expected_observer_spiffe_id,accepted_limits`. Literal schema/version 1; selected IDs/hashes/nonces/SPIFFE strings; the same exact limits object; at most 65,536 bytes. | Live peer, manifest, Hello-to-Hello and permit/receipt binding. |

The exact limits object contains `evidence_frame_max_bytes=2162688`,
`evidence_payload_max_bytes=2097152`, `max_frames_per_session=65536`,
`max_frames_per_source=16384`, `max_sources=64`,
`per_source_aggregate_max_bytes=16777216`, and
`session_aggregate_max_bytes=67108864`. All seven are exact JSON integers, not
booleans. A syntactically correct SPIFFE literal is not an authenticated peer.

The five decoded payload schemas are closed:

| Payload | Exact fields and local rule |
| --- | --- |
| `SupervisorStartedV1` | `schema,parent_pid,pid,process_group_id,proc_start_token,pid_namespace_device,pid_namespace_inode,mount_namespace_device,mount_namespace_inode,executable_sha256,pidfd_bound,execution_authority_digest`; parent PID 1, PID 2..u32 max, group equals PID, ASCII start token 1..256, namespace values 0..2^63−1, hex64 hashes, literal `pidfd_bound=true`. |
| `SupervisorExitObservedV1` | `schema,pid,proc_start_token,wait_code_kind,exit_code,signal,core_dumped,observed_by_pid,identity_match`; PID 2..u32 max, printable ASCII token (0x20..0x7e) 1..256, `exited` requires exit code 0..255, null signal and false core dump; `signaled` requires null exit code, signal 1..64 and boolean core dump; observed-by PID 1 and identity-match true. |
| `SupervisorReapedV1` | `schema,pid,proc_start_token,pidfd_bound,reap_count,wait_owner_pid,terminal_status_sha256`; PID 2..u32 max, printable ASCII token (0x20..0x7e) 1..256, true pidfd bound, reap count 1, wait owner PID 1, hex64 status hash. |
| `NamespaceDrainedV1` | `schema,supervisor_pid,term_signal_count,kill_signal_count,reaped_descendant_count,remaining_pids,waitid_all_result`; PID 2..u32 max, counts 0..2^63−1, exact empty array, literal `ECHILD`. |
| `SourceCompleteV1` | `schema,result_kind,supervisor_terminal_status_sha256,supervisor_reaped_once,namespace_drained,last_nonfinal_record_hash,evidence_failure,terminal_reason`; result is `success/supervisor_failure/observer_failure`; hex64 hashes, true reaped/drained claims, boolean failure, printable ASCII reason (0x20..0x7e) 1..256; success requires failure false. A non-success result with `evidence_failure=false` still maps to COMPLETE locally. |

## Segment domain and later relations

`ComputeJournalSegmentID` checks four untrusted inputs and computes exactly
`SHA256(ASCII "R6J-OBS-JOURNAL-SEGMENT/v1" || one NUL || canonical
{run_id,source_instance_id,epoch,endpoint_nonce})`. The canonical object has
keys `endpoint_nonce,epoch,run_id,source_instance_id`. `journal_nonce`,
`receiver_session_nonce`, session binding, and wider journal identity are **not**
inputs. The wider `journal_identity_sha256` instead uses
`R6J-JOURNAL-IDENTITY/v2` over canonical
`{journal_nonce,session_binding_sha256}`. Neither digest grants entitlement.

Stage A closes only F01's selected static segment formula and F02's Ack syntax.
Stage B must bind Ack to the internally recovered committed evidence/state
before `ack_sha256`; recover chronology from an actual raw journal image and
its final committed transaction; and compare restart images using
`post[:E] == pre[:E]`, complete same-index transactions, derived states, and
each image's own tail policy. The six chronology events remain
`append-frame, append-commit, fdatasync, reread-validation,
state-publication, ack` in that order. No Stage A test simulates an actual
`fdatasync`, physical crash, Wait/reap, or authenticated receipt.

Stage B must retain the four accepted counterexamples: segment-as-journal
identity, malformed Ack accepted by chronology, synthetic chronology absent
from an image, and divergent same-header restart history. Partial frame,
partial commit, or uncommitted frame tails may retain the preceding committed
open prefix and truncate to durable end; a complete invalid open tail retains
the prefix but refuses continuation. A complete valid post-terminal transaction
refuses; partial/invalid/uncommitted terminal residue may truncate to the
terminal durable end. Image consistency alone is not physical durability.
The accepted 354 retained plus 151 added controls and 700 reviewer probes are
artifact evidence, not copied repository tests or this tranche's validation.

## Deferred authority decision and stage gates

The owner assumes an existing signed `RunEntryV4` issuer, verification suite,
and atomic OutsideObservationPermit ledger. They are **not established as
current ES contracts**. Its target split excludes ES admission, observer,
receiver, app, and runtimehelper from permit-consumption authority. Stage A
implements no `RunEntryV4`, `OutsideObservationPermitV1`, consume request,
`PermitConsumptionReceiptV1`, key lookup, signature verification, permit
client, receipt verifier, or authority-bearing state machine. The prospective
permit has 15 fields, consume request 11, and receipt 16 under the owner
contract; documenting them here does not make them executable ES types.

A concrete deferred design-governance conflict remains: the permit contract
allows `issuer_id` and `key_id` as ASCII length 1..128, while the receipt wire
registry uses the narrower lowercase `ascii_id_1_128` grammar. No intersection,
coercion, case folding, or implicit issuer assignment is selected here. Before
the **first** dependent executable work (including a Stage B permit client or
pure signature/receipt verifier), owning docs and review must settle complete
`RunEntryV4` bytes/digest, issuer/delegation, key suite/trust roots, atomic
ledger and receipt/failure semantics, and this identifier treatment. Pure
Stage B raw-image reasoning may proceed only over untrusted bytes.

Stage C isolated Linux process/endpoint/TLS work needs behavior-based capability
and security qualification, with no production job or registration. Stage D
disabled ES integration requires explicit doc-first migration, no active
public route/intake, and rollback tests. Stage E alone can consider live issuer
consumption, SPIRE registrations, receiver durability, Nomad job wiring, and
production evidence intake after independent review and deployment/rollback
evidence. None is activated by Stage A.
