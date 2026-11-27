# Execution Admission And Custody Standing Rules

These are the standing Workstream C rules for ES admission, material capture,
staging and result custody, proof artifacts and startup probes, together with
the outside-observer Stage A slice and the reliable-submit tranche status they
began with. They moved here unreworded from the `PLANS.md` section
"Cross-Repo Hybrid Integration ADR Pointer" at `trunk_dev` commit
`8129b82d79b5700049621b6d4e95b6bf37ada7ac`, so that `PLANS.md` holds intent and
order.

The detailed lifecycle contract for these rules is
`.docs/execution_lifecycle/contracts.md`.

Edit a rule here in place when it changes. Do not add dated status entries:
say what a change did in its pull request description. Some paragraphs below
still carry the review names and dates they had in `PLANS.md`; they stay
unreworded. Cite this file by section heading, never by line number.

### R6J-R9.28/Stage-A — inert outside-observer structural contract

The independently accepted R9.28 owner is bounded artifact-design evidence,
not repository adoption or runtime qualification. This namespaced Stage A slice
may add only the ES-private `es/internal/outsideobserverprotocol` untrusted
canonical/data parsers, local hash-domain checks, governing docs, and contract
tests described in `.docs/execution_lifecycle/outside_observer_protocol.md`.
It adds no active import, public route, configuration, job, process, endpoint,
issuer, ledger, receipt consumption, or production evidence intake.

The owner's assumed existing signed `RunEntryV4` issuer, verification suite,
trust root, and atomic OutsideObservationPermit ledger are not established as
current ES contracts. Authority issuance/delegation and worker/runtime handoff
remain reopened seams. Before the first executable permit client, signature or
receipt verification, or authority-bearing state machine, those contracts and
the documented permit/receipt identifier-grammar mismatch require an explicit
owning design decision and review. Pure future image-relation work may reason
only about untrusted bytes. This pointer changes no ES Workstream C priority,
current admission/Nomad lifecycle authority, caller SPIFFE allowlist, workload
JWT endpoint, or `control-plane-normal-shell/v1` compatibility edge.

Active bounded contract tranche: submit idempotency, submit correlation, and
recovery are now selected as the ES-owned documentation seam for the
Correlation And Recovery inventory item. The detailed target contract lives in
`.docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md`.
The first source-bearing reliable-submit tranche initially added the
admission-local pure Go model and tests in
`es/admission/internal/reliablesubmit`. The current source-bearing persistence
tranche extends that same private package with a backend-neutral claim-store
port, durable semantic service, private durable-record codec, shared backend
conformance tests, and a same-package SQLite implementation. The package remains
transport-neutral, unwired from submit, and unavailable through public runtime
surfaces. It models opaque caller/key, effective-plan binding, phase, replay,
disclosure, durable uniqueness, revision/CAS, and provider-effect ordering
without changing the current unkeyed submit request or response. Reliable submit
is not implemented end to end. The docs-contract ADR
`.docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md`
now freezes the persistence/concurrency direction: a narrow ES-owned
submit-correlation store, local embedded SQLite as the first concrete backend,
the current `CGO_ENABLED=0` build posture, `modernc.org/sqlite v1.54.0` with
the exact `modernc.org/libc v1.74.1` coupling, a private same-package
durable-record codec in `es/admission/internal/reliablesubmit`, revision/CAS
semantics, and durable provider-effect intent before external I/O. It adds
private store source, schema, migration, dependency, and tests only; it does not
add global ES configuration, production runtime wiring, public DTOs, HTTP
handler behavior, staging, Nomad, lifecycle, Coordinator, Bridge, CP, IM, Git,
CI, validation, or publication behavior.
The current Go build baseline is exact Go 1.26.5 as documented in
`.docs/system_overview/go_toolchain_baseline.md`; supported build/proof scripts
use `GOTOOLCHAIN=local` and do not add a database dependency or storage-family
implementation.
This planning tranche does not displace unrelated ES product priorities
globally. The private port exists only to permit a later PostgreSQL backend to
run the same conformance suite if a separately accepted product requirement
needs managed database operation. It does not promise live backend switching,
dual write, automatic SQLite/PostgreSQL data portability, export/import format,
existing-data migration, HA, replication, or multi-host storage. It freezes only
the public opt-in/versioning posture for a future
reliable keyed-submit implementation: keep the current outer producer-contract
v1 identity and current governed-execution contract identity, add one narrow
versioned reliable-submit producer sub-contract under the governed-execution
declaration, keep `POST /v1/executions:submit` as the route for both legacy and
future reliable variants, require a submit-specific reliable request family
distinct from `PrepareRequest`, require an in-band structural reliable-submit
discriminator that current strict decoding rejects, require producer-declaration
preflight plus in-band request discrimination as independent fail-closed gates,
reject header-only opt-in, and forbid silent downgrade to current unkeyed
submit. The current unavailable contract-adapter foundation tranche selects the
private reliable request-family vocabulary for later runtime use:
`schema_version = "execution-substrate.reliable-submit-request/v1"`, mandatory
top-level discriminator `reliable_submit`, nested
`contract = "execution-substrate.reliable-submit/v1"`, and nested `submit_key`.
It adds admission-local private validation for that reliable request shape,
cryptographic submit-key syntax, caller/key safe-reference derivation,
composite `ClaimID` construction through the committed pure-model constructor,
and an ES-neutral submission-outcome projection. The raw submit key exists only
transiently inside the private strict-decode and caller-bound derivation
boundary; the returned validated representation retains sanitized request facts
and safe private references only, not the raw key, decoded key bytes, or raw
wire request. This is a bounded lifetime/projection guarantee, not a secure
memory-erasure claim or a claim that arbitrary invalid Go formatting operations
are overrideable. Full request objects remain unsuitable as log payloads. These
helpers are not public DTOs and are not called by current runtime code. The
contract-adapter tranche alone does not select source-grounded resolved-plan
extraction. The selected source tranche is now
`resolved-execution-plan-extraction-foundation`, a bounded Workstream C
refinement and re-derivation of the reopened internal prepare/submit resolution
seam. It extracts one private `resolvedExecutionPlan` from the actual current
admission and submit-resolution path and makes current legacy `Submit` consume
only typed projections of that plan after a pre-effect freeze point. It does
not wire the private reliable-submit runtime or construct a `PlanBinding`.

The `resolved-execution-plan-extraction-foundation` seam is now authorized for
construction and local validation as one isolated candidate. This is a bounded
Workstream C refinement of the reopened internal admission/submit resolution
seam, combined with the minimum existing material-capture, resource-limit,
execution-root, staging-custody and retained-result-coherence source needed for
one coherent implementation. This sequencing permits construction before the
reported A2/custody acceptance work; it does not accept that work or authorize a
combined merge, commit or rollout. This records the original construction
authorization; the 2026-11-13 development-source disposition below records
current evidence status without retroactive Git or rollout authority. Current
legacy `Submit` is the immediate consumer of one real-admission-derived private
resolved plan. A future reliable
`PlanBinding` must consume the same admitted semantic facts, but no binding,
canonical encoding, replay custody, keyed dispatch, producer enablement or
recovery path is selected here. Reliable submit remains unavailable and runtime
unwired. The plan must not synthesize `PrepareRequest` or `Manifest` proof, create
a parallel admission engine, change environment or mount admission (which the
shared admission path owns, `.docs/execution_lifecycle/contracts.md`, section
5), or infer authority-handoff inapplicability contrary to current `Submit`.

**Current invariant:** real artifact, capability, target, runtime-profile,
policy and trust admission remain authoritative; successful legacy receipt,
Nomad job and authority handoff retain their public semantics. The strict
legacy decoder rejects a structural `reliable_submit` body, even when a schema
string alone is supplied. Blank schema/version still defaults to v1, explicit
nonblank legacy versions remain compatible, mode defaults to async, timeout to
zero, and omitted CPU/memory to 10/128. Request maps, slices and resources are
owned after the admission copy. Caller, profile and platform environment
precedence, empty allowlist behavior, policy-fetched payload reuse and both
implicit default and explicit `control-plane-normal-shell/v1` profile behavior
remain in force.

**Bounded slice rule:** `prepareAdmission` first owns a copy of the request and
performs its established artifact, trust, Vault/auth and policy reads and gates.
After successful admission, Submit takes one owned execution/placement
configuration snapshot for subsequent profile, placement and materialization
facts, including both roots. It is not an atomic snapshot of earlier admission
or all service-configuration reads. Artifact, capability, target and profile
gates run before placement validation; runtime-unavailable still precedes mode
rejection and sync rejection precedes dependency admission. The effectful
resolver captures policy-approved payload, runtime support, governed mount
bytes and trust material before run assignment. The private semantic plan owns
admitted execution meaning and a single typed command. Private captured
material owns bytes; private host context owns qualified host facts; a separate
private custody-placement value owns both normalized staging and results roots
from the same snapshot. The results root is outside the semantic plan, runtime
host context, provider job and future `PlanBinding` input. After successful
resolution, Submit assigns one locator, claims an exclusive descriptor-held run
root, materializes captured bytes, validates the complete expected tree before
the one Nomad registration, and returns the existing receipt. This capture is
not a guarantee against unsynchronized concurrent mutation of caller or config.

**Bounded static-script payload interpretation refinement:** admission inspects
exactly one effective regular top-level `entrypoint` in the signed compressed
payload. ES trims surrounding pathname whitespace and cleans slash-separated
tar paths; a lone normalized alias remains supported. All members share one
canonical destination namespace. Duplicate regular destinations, even with
identical bodies, file/directory conflicts (including implicit parents),
traversal, links and special entries reject. The policy scanner completes the
archive before allowing, retaining the 256 KiB compressed-input, 64 KiB text
and 64-entry bounds and adding a 16 MiB whole-decoded-stream bound including
headers, skipped bodies and trailing bytes. Nonzero decoded tar trailing bytes
and additional compressed gzip members/bytes reject. Runtime extraction applies
the same namespace and stream-tail rules and refuses existing destination
replacement before launch; it does not require a top-level entrypoint for
generic extraction. This narrows duplicate/ambiguous archive compatibility;
failure may leave earlier extracted temporary files, which cannot launch after
preparation fails. No payload rewriting, nested archive inspection, rollback,
public grammar, or policy-language change is selected. This source repair does
not constitute independent audit or native runtime qualification.

**Bounded static-script sparse and destination correction:** GNU sparse file
representations are unsupported: the old GNU sparse type and any effective
header carrying a `GNU.sparse.*` PAX record reject in the shared ES archive
layer before logical file-body reading or runtime destination creation. This
includes recognized 0.0/0.1/1.0, all-hole, and unknown sparse metadata; it
does not reject ordinary PAX/GNU long names. The 16 MiB policy decoded-stream
budget counts gzip-emitted tar bytes, so sparse-generated logical hole bytes
must never reach the policy body discard. Go's tar `Next` can parse bounded
sparse metadata before ES sees the header; this rule does not claim to prevent
all internal header-parsing work. Runtime does not acquire a generic 16 MiB
archive cap. For every supported effective tar name, ES trims the raw name once,
then cleans slash-separated components once. The resulting canonical name is
used unchanged for both namespace registration and runtime destination
resolution; component whitespace exposed by cleaning is significant. Thus
`./ entrypoint` resolves to ` entrypoint`, distinct from `entrypoint`, while
true aliases and duplicate destinations still reject. This narrows sparse
input compatibility and repairs the runtime-only second normalization without
changing signed payload bytes, policy scope, Submit order, or the post-admission
execution/placement snapshot boundary. Native final-source qualification was
pending at this source-correction stage; the 2026-11-13 disposition below
records the later selected-native evidence.

**Review-19 A2/composition source disposition:** the fresh independent
Review-19 audit accepted the bounded archive interpretation, material capture,
and focused composition source interaction with disposition
`A2_AND_COMPOSITION_SOURCE_ACCEPTED_RUNTIME_GATES_OPEN`. This is source scope
only. The accepted production bytes do not inherit historical native proof,
qualify installed mounts, or close the distinct deployment, key, capacity,
retention, final-acceptance, or reliable-submit gates.

**Review-20 bounded qualification-fixture refinement:** a native-only sibling
subsumes the existing governed mount/lifecycle fixture's assertions while
preserving that fixture's portable capability coverage. The sibling adds a
test-owned single-host installed-source identity witness. It holds the
selected staged directory and synthetic regular
file before the unchanged Nomad registration is forwarded, then correlates the
one run, job, task, allocation and Docker container while a bounded synthetic
workload barrier keeps that container alive. The witness must establish a common
host/container backing-filesystem identity domain before comparing held and
container-visible directory and file coordinates, exact visible source binding,
type/owner/mode, read-only destination, and synthetic content. Equal paths or
bytes alone are insufficient. Modeled offline regressions do not claim an
installed mount. Failure teardown attempts bounded barrier release or container
stop and exact test-owned Nomad job cancellation when registration was captured.
The native fixture remains unexecuted in Review-20; its later
live result is evidence, not ES execution, lifecycle, policy, or acceptance
authority. The separate running-deployment observation and all other gates
remain open. No production behavior or provider contract changes are selected.

**Review-21 bounded qualification-fixture correction:** Review-20 source review
identified three test-only control-flow gaps, not live reproductions. The
synthetic workload now acknowledges readiness only after supervisor preparation
has finished, and a bounded observer reads that fixed acknowledgement inside
the admitted governed container before observing the mount or writing release.
Docker selection is only a candidate: exact immutable ID, running state,
allocation label and task label must match before adoption or any container
exec, release or stop effect. The witness uses bounded selected-field Nomad job
and exact-allocation terminal reads with fixed safe failures; it never falls
back to raw Nomad logs, response bodies, task messages or full allocation
formatting. Failure cleanup may stop only an admitted container, may release
only after readiness, and may cancel the exact captured test-owned job. A
successful control request does not prove task or container absence. Anchor,
ready, installed-object observation, release and terminal times remain distinct.
The test-only evidence projection uses `test-mounted-source-identity/v2` to
record those distinct times and the readiness-qualified hold interval.
The repair is test-only and leaves the native fixture unexecuted; focused
artifact review and independent assessment remain prerequisites to live use.

**Review-22 test-owned task-label prerequisite correction:** the supplied
Review-21 bounded native report records separate linux/amd64 N1 A2, N2
syscall/custody/result, and N3 authenticated-HTTP passes, then one N4 refusal
at Docker candidate admission. It reports no native v2 installed-identity
record; N5 and linux/arm64 did not run. Its post-run selected-field observation
found a new allocation-labeled container without
`com.hashicorp.nomad.task_name`, but the fixture did not preserve the selected
candidate ID, so exact historical ps-to-inspect attribution remains open. The
native package and failed-run state remain unchanged, and these statements are
supplied report claims pending independent package inspection. Review-22
refines only the fresh N4 test-owned Nomad agent: its Docker plugin explicitly
requests `extra_labels = ["task_name"]` while retaining enabled volumes and
disabled image cleanup in one unambiguous witness profile. Default harness and
capability-probe agents retain their existing configuration. The label must be
derived by the task driver from its task identity; ES registration and job
construction do not supply it. The observer still requires the actual immutable
container ID, running state, allocation label, and task label before adoption
or any container effect. Offline config and modeled tests cannot prove that a
native agent emits the label or that the installed mount has the held backing
objects. Focused artifact review and independent assessment precede a separately
authorized native retry; running-deployment, key, retention, architecture, and
final acceptance gates remain open.

**2026-11-13 Review-22 development-source disposition:**
`DEVELOPMENT_SOURCE_FOUNDATION_ACCEPTED` applies to the exact Review-22
implementation in the 1,480,369-byte source archive with SHA-256
`3e89fa9e0b7cc788e2b6c829ea25af00ea6a37b57f249e84d2b98c918511ad65`
and canonical source manifest SHA-256
`d108e59ed5a9708bfd38c08f0d9202263fb5207e1d6522772181421ddd4b718d`.
Review-19 A2/material-capture and focused composition source acceptance is
preserved by the unchanged production implementation. Review-21/22 fixture
and task-label source acceptance belongs to the fresh test agent, not a
production Nomad label guarantee. This documentation-only successor retains
those implementation bytes; its new all-file manifest was not executed in the
historical native runs. The lifecycle contract below owns the meaning and
limits of this development evidence disposition.

The selected native programme is complete on linux/amd64 and linux/arm64
under its original source and command identities: N1 recorded 13 top-level
passes/227 subtests/4 package passes per environment; N2 12/13/1; N3 2/0/1;
N4 1/0/1 plus a validated native-live v2 installed-source witness; and N5
1/0/1 plus retained-result observations. These are ten selected environment
selections, not the full app/root suite or general platform support. amd64
N1-N3 retain their original Review-21 records without invented command IDs;
amd64 N4 retains its original Review-22 Go pass and external validator exit 1
alongside accepted exact-record reconciliation, not a rerun; amd64 N5 retains
its original accepted Review-22 result. arm64 N1-N4 retain their accepted
launch-accounting session. arm64 N5 is accepted as
`REVIEW22_ARM64_N5_EVIDENCE_ACCEPTED_SELECTED_NATIVE_PROGRAM_COMPLETE` for
command `r22-20261113-arm64-n5-71ce04a8` and the 860,160-byte safe package
SHA-256 `81538e93a2f8ba6017c73edd356ca82f137c6eb6bf1a95463b7d8dda62ad9f9b`.
Its selected records remain bounded supplied-record evidence; post-N5
recursive allocation was intentionally unmeasured. Older NOT_RUN selections,
validator failures, resource/baseline refusals and the unknown first entry in
the old resource refusal remain historical facts. Process status remains
PARTIAL, including earlier privilege/Docker and Git procedure exceptions,
inherited source assumptions, nonblocking observations, the non-green root
diagnostic and its limited selected-assertion comparison, and missing Review-08
runtime records. No all-green suite or universal absence of provider effects
is claimed.

Review-17's accepted 23-phase supported-local compatibility proof applies
only to its original source and inputs. It is not a Review-22 canonical run,
real upstream Codex proof, running-deployment or actual key-isolation
observation. Later source and native evidence has its own scope; neither proof
inheritance nor a repeat follows automatically without a concrete unaccepted
interaction for a selected operational claim.

**Bounded material and custody rules:** dependency JSON and admission-policy
payloads are each limited to 256 KiB; primary Submit payload to 32 MiB;
per-mount compressed transport and extracted regular-file bodies to 8 MiB,
with 32 MiB aggregate limits for each; complete decompressed tar streams to
16 MiB per mount and 64 MiB aggregate, including headers and trailing bytes;
runtime support to one stable no-follow regular file of at most 32 MiB;
normalized Vault and selected system CA inputs to 256 KiB each, with a combined
bundle limit of 524,289 bytes. These are per-submission limits, not a global
capacity or concurrency guarantee. Configured staging and results roots require
component-wise no-symlink qualification, distinct non-overlapping backing
objects, and startup behavioral capability checks when Submit is configured.
A genuinely Submit-disabled service does not acquire run or staging effects.
`BRINGUP_PROFILE=prepare-only` skips submit readiness and run effects, but the
canonical generated service remains Submit-configured and still performs key
loading and root capability qualification before listening.
Root claim refuses every pre-existing object and never chowns, chmods, adopts,
recurses through or deletes it. Two missing roots under the same deepest
existing lookup context reject before provisioning; roots with provably
disjoint existing parents may be created one component at a time with the pair
requalified after each creation. Cleanup may remove only an exact object whose
operation ownership is provable at the deletion effect; pathname reuse is
insufficient. Incomplete staging leaves, unpublished result temporaries and
normalization temporaries are retained when that proof is unavailable.
Current capability-probe names lack an atomic exact-object unlink proof, so
their small exclusive fixtures also remain under the configured roots after
startup validation; capacity impact is still an acceptance issue. No cleanup
scans or recurses. Materialization preserves each validated archive
component name, including whitespace inside a component. Complete-tree handoff
validation keeps its live descriptor count independent of sibling breadth.
Result access reopens staging read-only, and existing result directories and
evidence are validated without metadata repair.

**Review-06 MOUNT-READ-01 bounded slice refinement:** governed runtime mounts
have a distinct workload-visibility policy. Their complete mount subtree uses
normalized `0755` directories, `0644` non-executable regular files, and `0755`
executable regular files, while ownership remains with the selected execution-
platform state owner. Only executable intent survives archive-mode
normalization; setuid, setgid, sticky and arbitrary archive bits do not.
The claimed run root remains `0750`, so its host ancestry still prevents
unrelated users from traversing the mount subtree. Payload, runtime-support,
platform, trust, result-auth and other non-mount staging retain their private
modes. The Nomad/Docker governed bind remains read-only. Exact custody identity
registration and complete-tree pre-dispatch validation still apply to the
workload-readable mount modes. This source repair does not qualify actual
Docker/Nomad mount topology or close the pending native runtime gates.

**Review-07 CUSTODY-MODE-01 bounded custody refinement:** the independent
Review-06 source/evidence audit returned `BLOCK` because complete-tree
pre-dispatch validation compared only ordinary `0777` permissions against the
recorded mode. A stable post-registration setuid, setgid, or sticky-bit change
could therefore pass that comparison. The selected correction compares the
recorded and observed Unix file type, ordinary permissions, and all three
special mode bits exactly at expected-tree and claimed-root validation. It
does not change mount materialization modes, private staging modes, object
identity rules, ownership, provider submission, or cleanup authority. This
candidate requires a fresh independent Review-07 re-audit; native runtime,
mounted-topology, and deployment gates remain open.

**Review-08 REGISTRATION-MODE-01 bounded custody refinement:** the independent
Review-07 audit returned `BLOCK` on a registration-time gap. Newly created
staging child directories and files were checked only for ordinary `0777`
permissions after controlled ownership and mode operations, so a concurrent
special-bit change could become the recorded expected mode and later pass the
Review-07 exact-mode handoff check. Before each new child enters the expected
tree, the post-creation descriptor stat must match the intended Unix file type
and all `07777` mode bits exactly. A mismatch retains the claimed root and
unregistered child without repair or deletion and prevents provider submission.
Object-identity binding, governed mount and private creation modes, the
Review-07 post-registration check, and cleanup authority do not change. This
candidate requires a fresh independent Review-08 audit; native runtime,
mounted-topology, and deployment gates remain open.

**Review-09 PROOF-EVIDENCE-01 bounded proof-artifact refinement:** the accepted
Review-08 source and native linux/amd64 fixtures do not qualify the remaining
live supported-local proof. The existing proof wrapper copied the whole guest
proof workspace into host `.out`, including `managed-secrets.conf`, private
keys, SPIRE/Vault state, and workdirs. The runtime-identity example also emits
the proof secret value in its raw logs, so raw execution logs are not safe
evidence. The selected repair collects only explicitly classified top-level
proof evidence, records a deterministic relative-path and SHA-256 manifest,
uses a private `0700` host proof directory, and uses the same fail-closed
collector on normal progress and failure finalization. Missing safe outputs may
be omitted; selected unsafe types or excessive sizes fail collection without
recursive fallback. The proof collector is evidence projection, not ES,
Nomad, Vault, SPIRE, result-auth, or cleanup authority. The externally
provisioned retained-result key remains outside proof-owned cleanup. The live
supported-local compatibility proof and independent Review-09 audit remain
open; this repair does not enable reliable submit or deployment.

**Review-10 PROOF-RAW-OBS-01 / PROOF-RESULT-01 / PROOF-HOST-SCRATCH-01 /
PROOF-GENERATION-01 bounded proof-artifact repair:** artifact review of the
authenticated Review-09 candidate found that filename admission still copied
raw Nomad/Docker/systemd observations and opaque result bytes, while a
recursive host source snapshot and direct transcripts remained under host
`.out`. The host proof directory is evidence-only. A separate task-owned
private bootstrap scratch holds transport inputs and is removed only after
identity-bound exact cleanup; failure to prove that cleanup retains scratch
and reports the condition without widening deletion. The source snapshot uses
guarded Git's tracked and non-ignored untracked source selection, including
tracked `.out/Dockerfile`, with deterministic manifest and archive metadata;
ignored or sensitive local files never enter it. Guest evidence is fixed-schema
projection only: raw Nomad/Docker/systemd configuration, logs, response bodies,
and retained result bundles are not host evidence. The controlled normal-shell
bundle is checked against an exact bounded proof-only schema and represented
only by hashes, sizes, and fixed assertions. Each guest collection publishes
an exclusive setup, final, or failure generation; a complete final host
manifest covers every other retained evidence file and explicitly excludes
its own root record. This is a bounded slice rule
refinement of proof artifacts, not ES/CP/Nomad authority. Live supported-local
proof, independent Review-10 audit, deployment, and reliable-submit enablement
remain open.

**Review-11 PROOF-EXEC-STATUS-01 / PROOF-NODE-DETAILS-01 /
PROOF-HOST-MANIFEST-01 / PROOF-RUN-LINEAGE-01 bounded proof repair:**
source review of the authenticated Review-10 candidate found a deterministic
second-capture collision on the base status projection, an aggregate-unbounded
node-detail fetch with prefix-only URL admission, a host-manifest self-coverage
overclaim, and missing retained run lineage. A labeled capture writes only its
labeled summary, status, and execution projections, avoiding mixed base
lineage after a partial second capture. It retains a validated public run ID, its derived
Nomad job ID, and a bounded allocation ID with its labeled summary and fixed
execution projection. An unlabeled capture alone may write the base status
projection. Node details are fetched only from a precisely parsed loopback
authority, with per-response and aggregate bounds and incremental fixed-count
projection. The final host manifest is the root evidence record: its explicit
self-exclusion field states that rows cover every other retained evidence file,
and its bytes and digest are verified after writing. This is a proof-only
bounded slice rule refinement with no ES source, runtime, result-authentication,
public API, or reliable-submit authority change. Live supported-local proof,
fresh independent Review-11 audit, deployment, and reliable-submit enablement
remain open.

**Review-12 PROOF-RUN-LINEAGE-01 exact-one allocation repair:** the independent
Review-11 source audit blocked allocation lineage because the proof wrapper
retained the first entry from `nomad job allocs -json` without a repository-backed
ordering guarantee. Each unique supported-local proof job must have exactly one
Nomad allocation before the wrapper observes that allocation and retains its
bounded ID. Zero or multiple entries, a malformed entry, or an invalid ID fail
closed without a Nomad execution projection, result validation, or proof
success. Previously captured safe evidence remains eligible only for the
exclusive failure generation, with the primary failure status preserved. This
is a proof-only bounded slice rule, not a general Nomad retry, reschedule, or
multi-allocation policy; it does not alter ES's internal allocation-selection
policy. If multiple meaningful allocations become normal, the
proof contract must be redesigned explicitly. Live supported-local proof,
fresh independent Review-12 audit, deployment, and reliable-submit enablement
remain open.

**Review-13 PROOF-RUN-LINEAGE-01 strict-JSON allocation refinement:** the
independent Review-12 source audit blocked the proof allocation parser because
Python's default JSON decoder accepts nonstandard `NaN`, `Infinity`, and
`-Infinity` constants in otherwise selectable allocation responses. The
proof-only bounded slice rule requires strict JSON for the complete allocation
list, including unknown and nested fields. Any nonstandard constant fails with
the fixed safe allocation-list error before entry or ID selection, allocation
observation, lineage publication, staging check, result validation, or proof
success. Exact-one record count, order independence, duplicate refusal, and
the fixed lineage projection remain unchanged. This refinement does not alter
ES's internal allocation-selection policy, public contracts, runtime, or
reliable-submit wiring. Live supported-local proof, fresh independent
Review-13 audit, deployment, and reliable-submit enablement remain open.

**Review-17 PROOF-RESULT-HANDOFF-01 bounded proof-consumer repair:** the
Review-16 live supported-local proof passed both executions and captures but
stopped at result-validation because the producer's private workdir result
was never copied to the proof-root input expected by the consumer. The
selected correction binds validation to the already captured normal-shell
summary, its exact selected workdir and result path, and the matching fixed
Nomad lineage. It requires successful terminal exit-zero result availability,
positive bounded byte count, an unchanged original summary, and a stable
regular single-link result reached through held no-follow directories. It
then applies the unchanged exact proof bundle schema to those bytes and
publishes only the existing fixed safe result projection. Missing or rejected
input fails the existing result-validation phase and failure finalizer; no
legacy alias or another workdir is selected. The synthetic producer-shaped
regression no longer pre-creates the old alias. This proof-only bounded slice
rule does not widen result authentication, execution, collection, cleanup,
or cross-service authority. The historical live bundle was not inspected for
schema acceptance; independent source review and a separately authorized
live proof remain open.

**Targeted source-review repair status:** R2 through R5 are bounded local
corrections to the isolated candidate. R1 is selected for a candidate-only
refinement of the reopened retained-result publication/read seam. ES must
derive a compressed-byte commitment from its archive writer, retain the
candidate descriptor through no-replace installation, verify the installed
winner, and publish a private authenticated completion record. Every public
result read must authenticate that record and the exact buffered response
bytes before success. A pre-existing unmarked final, including a legacy or
crash-interrupted final, remains unavailable and is never adopted by a later
publisher. This is an explicit compatibility change, not a migration policy.
The record is result-byte eligibility only; it has no lifecycle, Coordinator,
caller-authorization or reliable-submit authority. The selected protocol and
synthetic validation do not accept deployment key isolation, native Linux or
mounted topology, power-loss durability, operational recovery, consumer
acceptance, independent audit, commit, merge or rollout. R1 closure remains
subject to implementation and validation of this selected rule.
An already authenticated result/record pair satisfies later terminal
observations before staging traversal or candidate creation, even when staging
has changed or disappeared. A partial or invalid pair remains unavailable;
only a genuinely absent pair permits publication. Publishers that have already
prepared different candidates still follow the no-overwrite conflict rule.
Configured Submit startup also qualifies natural `0750` result run-directory
creation under its process mask, retaining its exclusive synthetic probe;
failure refuses startup rather than repairing directory metadata.
`NESTED-STAGING-OWNER-PROBE-01` (bounded slice rule): configured Submit startup
also creates a `nested` directory inside its staging probe directory after
setting that directory to the stable `0750` stage mode, gives it the roots'
owner and that mode, and verifies both, as staging does inside each claimed run
staging root. The stage mode carries no setgid bit, so the new directory gets
ES's effective GID; a process that cannot change it to the roots' GID, for
example because the roots inherited a group it is not a member of from a setgid
parent directory, refuses startup with `nested staging directory ownership is
unavailable` instead of reporting ready while every submission fails to stage.
The nested directory is retained with its probe fixture.
`STARTUP-PROBE-USE-AGREEMENT-01` (bounded slice rule): the configured-Submit
startup probe and use must agree. Inside the nested directory, startup stages
one directory for each directory mode staging uses beyond the stable `0750`
stage mode, and one regular file for each file mode staging uses, and holds
each to staging's checks: a regular file with one link, on the staging root's
device, with the roots' owner and the exact mode. The modes come from one list
in staging custody (`stagedFileModes`, `stagedDirectoryModes`), and staging
refuses any mode outside it, so a new staging mode cannot skip the probe.
Inside the natural result directory probe, startup creates one file for each
mode retention gives its files, holds each to retention's checks, and renames
the bundle-mode file with the no-replace rename twice: onto a name that exists,
which must be refused as existing, and onto a free name, which must succeed and
keep the file. Linux refuses a no-replace rename onto an existing name before
it asks the file system, so only the second rename proves the primitive.
Startup therefore refuses an overlay whose layers are on different file
systems, a file system that does not keep a mode staging or retention can need,
and a results file system whose rename accepts no flags, instead of reporting
ready while submissions or retentions fail. The staged modes include the `0755`
directories and the `0644` and `0755` files that only submissions with governed
mounts use, so ES also refuses to start on a staging file system that cannot
keep those modes although submissions without governed mounts would work
there. That is deliberate: ES starts only where every submission it accepts can
be staged, rather than reporting ready and failing the submissions that have
governed mounts. ES also never changes
the owning user of a directory it opened by name: the startup probe, the claim
of a run staging root and `stagingCustody.ensureDirectory` refuse a directory
whose owning user is not already the roots' owning user, before any owner or
mode change. Nothing ties such an open to the creation an instant before, so a
user who may rename entries of the parent could otherwise have a root ES give
them somebody else's directory. Entries ES creates must therefore already
belong to the roots' owning user, as retained result directories always
required, so a root ES whose staging file system gives new entries to another
user, for example a bindfs mount with `--create-for-user`, is refused although
it started before this rule; a root ES on roots owned by another user is refused at startup with
`staging probe directory does not belong to the execution roots' owning user`.
The probe retains 13 entries per start, 9 under the staging root and 4 under
the results root, under the same no-uncertain-unlink rule.
The isolated candidate's AUTH-01 exact-path correction also applies to
transitive ancestry re-observation: a qualified key parent and descriptor
presentation are reopened component for component, including whitespace in an
ancestor. Configured execution-root normalization remains unchanged. This
source correction does not close deployment key isolation or other acceptance
gates.

**Independent Review-03 audit status:** the completed audit returned BLOCK on
supported-local configured-consumer compatibility (F1), contradictory current
staging-retention wording (F2), and the syntactically accepted root-parent key
path that the loader cannot open (F3). Review-04 selects a bounded repair:
trusted operator setup inputs carry stable non-secret store/key identifiers and
an external key-file reference to the generated ES config; no setup helper
reads or provisions the key. The supported key-file path has a non-root parent,
and key placement is lexically outside staging, results, and replaceable proof
workspaces. Current unkeyed Submit retains every successfully claimed run root
for all later outcomes. These changes refine configured-consumer compatibility
and key-placement validation, not the result publication protocol. This repair
requires new independent assessment and does not clear the audit BLOCK or the
remaining acceptance gates.

**Review-04 follow-up status:** source review found two remaining F1
configured-consumer defects. The setup script's sourceability guard does not
dispatch the wrapper's canonical `bash -s -- setup` stdin invocation, and the
supported-local key-placement fence fails to reject a filesystem-root owned
proof scope before the wrapper's later collection path. Review-05 selects only
the entrypoint and lexical owned-scope repair: direct-file and canonical stdin
setup dispatch exactly once, sourcing remains inert, and every declared
proof/bootstrap/repository/collection scope must be a clean single-leading-slash
non-root path before wrapper mutation or finalizer registration. Root and
ancestor/descendant overlap must fail closed without key-path diagnostics.
The Review-04 F2 retention and F3 key-parent fixes remain in force. Synthetic
entrypoint evidence does not qualify a live guest, physical alias isolation,
independent assessment, or any remaining acceptance gate.

**Temporary compatibility edge:** every successfully claimed run root is
retained, including partial materialization, failed or ambiguous registration,
terminal success and failed result publication. This conservative interim rule
avoids unsafe deletion but increases disk use and sensitive-material residence.
No reclamation authority, garbage collector, TTL or cleanup command is selected.
The operational capacity and reclamation gap must be resolved or explicitly
bounded before rollout. The held descriptor and pre-dispatch validation do not
by themselves prove the later Nomad/Docker host mount, and captured in-memory
bytes are not durable replay custody. Image tags do not prove immutable image
content. One Nomad registration per unkeyed Submit does not deduplicate retries.

**Acceptance boundaries selected on 2026-11-13:** the development-qualified
source foundation above is an evidence disposition for the exact authenticated
implementation and selected observations. It is not final product acceptance,
workload or feature/producer enablement, reliable-submit availability, general
platform support, or approval of an unspecified environment. It grants no
staging, cleanup, Git, integration, publication or deployment effect. Accepted
source/native evidence retains its original identities and limits.

A local source-preservation commit is a separate, explicitly authorized effect.
It may be considered only after this governing amendment and focused document
validation are reviewed and the exact candidate, index and intended commit
contents are reauthenticated. This disposition does not authorize that commit.
Integration into another checkout or branch, merge, remote publication and
rollout require separate authority and applicable checks. A local
`origin/trunk_dev` tracking ref is not current remote truth; PUB-GOV-01 remains
unresolved. A production environment need not be selected merely to consider
the later local preservation gate.

Environment-bound operational/rollout acceptance remains open. Before expanded
or unattended workload operation it requires a named environment and
architecture; actual service/operator/workload trust and permission
relationships; running mount/source paths and backing-object observations;
actual key exposure and isolation, including aliases and relevant same-UID
contexts; selected and enforced accumulated-root/result/probe capacity and
sensitive-material residence bounds; and an explicit reclamation owner,
authority and implementation or enforceable bounded operating disposition.
When supported-local consumer operation is claimed, its current-source and
environment interaction must be qualified. The temporary qualification
scratch limits are not an ES product retention policy. Existing retained
material stays protected and resident pending its own disposition. A separately
scoped development/qualification task is not blanket operational permission,
and none is granted here. Cross-compilation, Mac fixtures and a test-owned
installed-mount witness do not observe a running deployment. A demonstrated
missing prerequisite stops the affected scope; accepted evidence is not rerun
by default without a concrete unaccepted interaction. The current runtime,
startup, result-verification and reliable-submit-unavailable guards remain in
force.
Tranche B1, `ES-B1-SEMANTIC-OWNERSHIP-COMMAND`, refines that extraction
foundation without beginning the later privacy/assurance tranche. The shared
admission helper borrows the caller request, immediately deep-copies every
mutable member, and applies a private Prepare-versus-Submit admission intent.
That one admission-owned working copy is the only mutable authority for mode
handling, schema defaulting, validation, and normalization. Successful
admission returns one frozen authoritative request snapshot; immutable
defensive transfer copies remain permitted and are not competing authorities.
The caller retains ownership until that initial copy completes and must keep
the request and every reachable mutable member race-free during the copy.
Concurrent unsynchronized mutation during copying is a caller data race, not
an ES synchronization guarantee. After the owned copy completes, later caller
mutation cannot change admitted or submitted state, and downstream defensive
copies do not create a second mutable authority.
The helper also retains the exact workload-zone Vault config reference used
for the successful blob fetch and auth-plan resolution. Submit then captures
one immutable package-local configuration snapshot before resolving the
artifact/runtime-profile gates, effective resources, primary payload,
runtime-support bytes and identity, governed mount bytes and their single
gzip/tar semantic parse, workload trust bytes, and finally the qualified
platform-state owner. Successful return from that effectful read resolver is
the freeze point. No run ID, staging directory, file write, ownership mutation,
or Nomad call is allowed before it.

The private `resolvedExecutionPlan` is admitted semantic truth. It owns request
and invocation schemas, effective mode and timeout, CPU and memory, runtime
profile identity and selected image, semantic profile and caller environment
inputs, one typed runtime command, distinct artifact/payload/derivation/output
identities, ordered governed mounts, network permission, current authority
inputs, runtime-support digest, runtime-identity tmpfs size, and the fixed
semantic job envelope. The payload digest comes only from the discovery/evidence
relationship already cross-checked by admission; raw payload bytes remain
owned material. ES does not rely on ARS for their integrity: every ARS blob
read by digest is hashed by ES and used only when it equals the requested
digest (`.docs/execution_lifecycle/contracts.md` section 5A). Current authority
handoff is unconditionally applicable for every admitted Submit; no plan-level
applicability degree of freedom remains, while the Codex credential-location
subcomponent remains genuinely optional.

Separate private material owns payload, runtime-support, compressed/parsed
mount, normalized Vault CA, and combined trust-bundle bytes. Captured host
context contains only normalized qualified values: the cleaned absolute
staging root, qualified numeric owner, cleaned absolute SPIRE source directory,
and trimmed non-empty Nomad datacenter. The results root is trimmed, cleaned,
and required absolute for current ES service/custody qualification, but remains
outside the semantic plan, captured host context, provider-job projection, and
B1 binding. The semantic plan owns none of those placement facts and owns no
run/job identity, owner-derived environment, endpoint URI, staged path,
workspace path, or other derived host/run path. After freeze, current Submit assigns one locator and derives one
run projection from the semantic plan plus captured host context. That
projection adds run/job identity, owner/run/endpoint environment, host and
staged mount sources, datacenter, endpoint, and derived paths. It then claims
the run-scoped staging root exclusively as its first filesystem mutation,
materializes only captured bytes, builds the authority handoff and provider job
from typed projections, calls Nomad once, and returns the unchanged receipt.
The executable and complete supervisor arguments are represented by one
private `resolvedRuntimeCommand` constructed exactly once before freeze; the
execution-package layout does not implement a second command grammar.

The semantic plan is admitted semantic truth only. Semantic-plan equality
across qualified host contexts proves admitted-semantic equality only. It does
not prove provider-job, dispatch, replay, restart, safe-host-substitution, or
provider-effect identity because captured host context and run/provider
projection add additional execution-shaping facts. Future `PlanBinding`
work must explicitly select whether and how those facts are bound. B1 selects
no canonical encoding, witness, replay, restart, or host-context binding
treatment. B1 protects successful behavior with an unmodified actual job tree,
one source-distinct complete literal default-profile expected Nomad job, a
direct pointer-owned token/template ledger expanded only in the expected tree,
and a separate literal authority-handoff expected object through real
`Service.Submit`. A finite package-local direct-call closure plus exact
source/type producer, mutation, validation, payload-projection, and metadata
inventories protect this B1 shape. Those guards are not whole-program
noninterference or general alias, taint, SSA, or interprocedural analysis.
Tranche B2, `ES-B2-PRIVACY-INDEPENDENT-ASSURANCE`, now completes the bounded
privacy and independent-assurance refinement without reopening B1 semantic
ownership. Public error serialization retains the existing route, HTTP status,
error code, DTO shape, field names, precedence, and successful behavior while
the five selected operational-cause families use only these fixed messages:
`workload-zone vault configuration is invalid`,
`derive execution host context failed`,
`stage workload vault trust material failed`,
`derive execution platform state owner failed`, and
`execution submission failed`. Nomad non-success bodies and underlying causes
are not public or ordinary-log diagnostics. The three governed result-retention
calls emit only `es result retention failed run_id=%s` with the validated public
run ID.

Submit registration, projected-allocation list, and allocation-detail JSON use
the existing 256 KiB transport boundary and one compatible JSON document;
unknown provider fields remain accepted. `fetchJob` remains explicitly
unbounded but one-document because current admitted caller-environment
aggregates are unbounded and Nomad job summaries echo `Task.Env`. Successful
authenticated public Logs remain unbounded opaque workload-output bytes and are
not structured provider JSON. B2 therefore selects neither a universal
provider-response limit nor a public Logs byte/oversize policy.

`preparedAdmission` carries the private formatter marker as its first anonymous
field, redacts ordinary formatting and formatted standard-library logging to
`<private execution value redacted>`, and remains `{}` under ordinary
`encoding/json`. This is bounded defense in depth, not reflection, `unsafe`,
malicious same-package, arbitrary-serializer, secure-erasure, or authorization-
to-log protection. A second complete source-distinct direct literal job and
authority-handoff golden covers `control-plane-normal-shell/v1` through real
`Service.Submit`; it is ES profile-coverage evidence, not a snapshot of the
current Control Plane request or a transfer of CP authority. The rejected
2.9 MB position-indexed B2 guard is not accepted assurance and is replaced,
not repaired or rolled back. Permanent B2 assurance is behavior-first; the
structural part is local, directly authored, and position-independent; and
non-purging cancellation is enforced by a private construction that has no
purge option. Its compact inventory freezes the current public execution JSON
fields and the Nomad response fields production consumes without rejecting
unknown incoming provider fields. The `preparedAdmission` checks cover only
ordinary formatting, formatted standard-library logging, ordinary JSON,
marker placement, and field visibility. The `fetchJob` and authenticated
public Logs exceptions remain exactly as selected above.

Open-world source-flow and test-honesty questions remain fresh-audit
obligations. Provenance proves byte identity only. No positional records,
replacement-output workflow, package source graph, source fingerprint,
generated inventory, or general analyzer is selected. Permanent tests do not
claim arbitrary alias/helper-flow detection, coverage of custom logging sinks,
arbitrary same-package aggregate conversion, whole-program noninterference, or
whole-runtime reliable-submit nonwiring. The accepted B1 guard remains intact.
Reliable keyed-submit runtime remains unwired; the private foundation remains
present, current public Submit remains unkeyed, and native Linux runtime
validation of the combined candidate remains pending.

The opened parent and root identities remain
held through complete expected-tree revalidation immediately before that one
handoff. For every registered directory, that revalidation opens a fresh
independent directory description at position zero, revalidates its identity,
and reads entries incrementally one at a time from that fresh description.
Invocation-local expected ownership is a hierarchy: the root owns its
direct-child map and every expected directory owns only its direct children.
Each parent-to-child edge owns its segment bytes and identity once; no node or
secondary index retains cumulative ancestor paths. Construction is linear in
traversed path-segment occurrences, retained variable data is linear in unique
edge-segment bytes plus expected nodes, and validation uses the expected tree
plus one fixed read batch. Each observation is processed immediately and
validation stops after at most the expected-child count plus one observed
entry, so it never materializes or sorts the complete untrusted directory
inventory. These are structural bounds, not exact Go heap, allocator, stack,
descriptor, RSS, or secure-erasure claims. Each expected object's no-follow
identity and policy is revalidated.
Missing, replaced, malformed, duplicate, or unexpected descendants fail before
Nomad without disclosing an unexpected child name.
Regular expected children require link count exactly one; expected directories
require a positive link count because their link count may grow as their
expected child directories are materialized.
This is completeness validation for the current operation, not residue
discovery, adoption, cleanup, quarantine, or reclamation. Every post-claim
return closes descriptors and retains the visible run root; this custody rule
is not reliable-submit runtime wiring.

The selected Tranche A filesystem/resource-custody refinement governs the
following bounded slice rules without beginning the later semantic-plan repair:

- ES bounds discovery, evidence, workload-zone runtime-config, and trust-model
  dependency JSON bodies to 256 KiB each before strict decoding.
- The Admission Policy Layer payload remains bounded to 256 KiB; the primary
  Submit payload is bounded to 32 MiB.
- Governed mount transport remains 8 MiB per mount and 32 MiB aggregate.
  Extracted regular-file bodies remain 8 MiB per mount and 32 MiB aggregate.
  The complete decompressed tar stream is additionally bounded to 16 MiB per
  mount and 64 MiB aggregate before `archive/tar` parsing so headers, PAX/GNU
  extension records, names, padding, bodies, end records, and trailing
  decompressed bytes share one budget. There is no separate ES 4096-entry or
  4096-byte-name rule.
- Runtime-support capture is limited to one stable no-follow regular file of at
  most 32 MiB. Normalized Vault and selected system CA inputs are each limited
  to 256 KiB; the combined bundle is limited to 524,289 bytes.
- Configured staging and results roots are qualified component-by-component
  without symlink traversal. Submit exclusively creates the descriptor-held
  run-root name and refuses every pre-existing object type. It never adopts,
  mutates, quarantines, renames, or recursively deletes a pre-existing run
  root. General residue discovery and cleanup scanning remain prohibited. The
  sole enumeration exception is the bounded operation-local direct-child
  completeness check immediately before handoff; it neither follows nor
  changes an unexpected entry.
- Once exclusive run-root creation succeeds, the visible root is retained on
  every return, including partial materialization, failed or ambiguous Nomad
  registration, successful registration, every terminal lifecycle state, and
  every result-publication outcome. Descriptor-close errors do not replace a
  primary failure or convert an accepted registration into a public failure.
- `openStagingTree` may reopen a retained root read-only solely for result
  packaging. Its handle exposes verification, read-only directory opening, and
  descriptor closure only; it grants no mutation, deletion, adoption, cleanup,
  quarantine, lifecycle, or reclamation authority.
- Incomplete exclusive leaves, unpublished result and normalization temporaries,
  and exclusive startup probe fixtures remain when exact effect-time identity
  for deletion cannot be proved. A pathname alone grants no cleanup authority.
  No scan, recursive cleanup, or later residue-reclamation owner is selected.
- Retained staging increases disk use, sensitive-material residence, capacity
  pressure, and operator burden. Automatic whole-run-root reclamation is not
  implemented; future reclamation requires a separately governed ES-owned
  design and cannot be inferred from lifecycle or retained-result facts.
- Retained-result publication constructs, validates, normalizes, and syncs a
  complete temporary bundle, then publishes it with the existing platform
  no-replace rename primitive. A conflict is idempotent success only after the
  existing final object passes no-follow identity, owner, mode, link-count,
  size, complete-digest, and stable-path validation; existing final objects are
  never owner-reconciled in place.
- Required local filesystem capabilities are probed by behavior at startup.
  Linux uses beneath/no-symlink/no-cross-device opens and no-replace rename;
  Darwin uses no-follow-any opens, exclusive rename, and device verification.
  There is no runtime OS-label branch and no silent capability fallback.

These limits and filesystem requirements are explicit compatibility/security
changes. They do not change public DTOs, routes, current unkeyed Submit,
command/argv, environment precedence, runtime-profile semantics, authority
handoff, Nomad registration count, or successful receipt shape. The Tranche A2
repair must receive a fresh targeted independent audit with no repair defect
before the later Tranche B semantic/docs/assurance repair may begin. Native
Linux validation was not inherited as a pre-B gate. Governed native Linux
observation remains necessary for an operational claim about a deployment
architecture: linux/amd64 for Remote Alpha and linux/arm64 for the
supported-local profile. Cross-compilation is compile evidence only. These
environment-bound lanes are not an automatic pre-commit condition for local
source preservation or integration; a new bounded witness for this candidate
requires a concrete changed-interaction selection.
