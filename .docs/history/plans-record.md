# Execution Substrate Plan Record

This is the closed dated record of `PLANS.md`. On 2026-11-24 it moved here
verbatim from `PLANS.md` at `trunk_dev` commit
`16cbf739eea8c6a673aef8048aefb69cebd5121b`, so that `PLANS.md` opens with
the current plan instead of its history. Nothing in it was reworded. It
keeps the standing it had in `PLANS.md`: a superseded or historical section
stays superseded or historical, and an entry that names an owning `.docs/`
contract leaves the precise wording to that contract.

The record is closed. Do not add entries: a change says what it did in its
pull request description, and `PLANS.md` is edited in place. A test pins this
file's SHA-256, so any edit is deliberate.

It holds, in this order:

- the `Status` entries up to 2026-11-24, newest first, as they stood at the
  top of `PLANS.md`;
- the source publication and selection history of 2026-11-17 and 2026-11-18;
- the superseded Remote Alpha operator facade routes P0n and P0r, which
  stood under `PLANS.md`'s "Highest-Priority Backlog Entry".

## Status

### PR #12 durable admission: Nomad's token on the private path, after PR #31 (2026-11-24)

PR #31 made ES send its Nomad ACL client token on every Nomad request, and
its guard refuses a Nomad request path outside a builder that sets the
token. PR #12's reliable-submit operational provider sent its three
requests to Nomad without one. It now takes ES's token when it is built,
from the same custody as the current submit client's, cannot be built
without one, and sets it in the `X-Nomad-Token` header of every request,
never in the URL. PR #31's guard now covers both Nomad clients, and the fake
Nomad of the handoff tests refuses any request without the token.

The provider has no production caller, and wiring it still needs the
commissioning gate's prerequisites. The gate gains a seventh prerequisite,
`CP-NOMAD-ACL`: grants and exclusive writing for ES's token in the
operational namespace, the access-control check before registration, what
a refused registration means for the claim, and one Nomad identity in ES's
configuration for both clients. Taking up `trunk_dev` after its PRs #43,
#42, #34, #31, #38, #44 and #46 brings PR #31's guard test, whose three
position reads PR #12's position-read test refused; they now read the real
position. That test file is one more path, so the path ceiling of PR #12
plus its repairs is 70 files. A driver string that is not valid UTF-8,
which no caller can send today, is now refused too.

This entry changes no public behaviour, request contract or stored format.
The precise wording is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).

### PR #12 durable admission: repairs after the red-team re-check (2026-11-24)

The red-team's re-check of those repairs found two low defects. Nomad's
client parses each string of a task's driver configuration with HCL, which
drops a byte order mark at the start of the string and rewrites it to
Unicode Normalization Form C. So an argument or a mount target could still
reach the workload in another form than ES admitted, bound and recorded,
and two mount targets that differ only in normal form were one path for the
container. ES now refuses, in each argument and each mount target, a
leading byte order mark, a string that is not in Normalization Form C, and
a code point that is not assigned in the Unicode version of its own
normalization tables, so that a Nomad with tables of a later version leaves
the string unchanged too. And ES accepted `resources.memory_mb` from 1,
while Nomad refuses a task with less than 10; on the private path such a
request took a claim that then stayed ambiguous for good. The request
validation that both paths share now refuses less than 10. The re-check's
tests are adopted unchanged, and the smallest request of the third
red-team's codec test now asks for 10.

The rule imports two packages of `golang.org/x/text`, which the reviewed
dependency list gains; `go.mod` now requires the module directly, at the
version it already selected. Taking up `trunk_dev` after its PRs #33, #41,
#37 and #39 moves one counted test file to `scripts/`, and PR #39's new
test of `internal/testutil` read an adjusted position in three places,
which PR #12's position-read test refuses; they now read the real
position. `go.mod`, the re-check's test file and that test file are three
more paths, so the path ceiling of PR #12 plus its repairs became 69 files.

This entry changes behaviour: a request with such an argument or mount
target, or with less than 10 MB of memory, which ES accepted before, is now
refused with `400 invalid_request` on the ordinary path and with no claim on
the private path. It changes no stored format. The public request contract
gains both refusals, which
[the execution lifecycle contracts](.docs/execution_lifecycle/contracts.md)
state. The precise wording of the private path is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).

### PR #12 durable admission: repairs after the third red-team and the guard coverage review (2026-11-23)

The third red-team found two medium defects. Nomad's client evaluates
`${...}` and `%{...}` in every string of a task's driver configuration as a
template, rewrites the escapes `$${` and `%%{`, and replaces `${name}` in
environment and meta values. So the argv, environment, output id and mount
targets that ran were not the ones ES admitted, bound and recorded. ES now
refuses `${`, `%{` and a NUL byte in each of those strings before anything
is staged or sent: with `400 invalid_request` on the ordinary path, and with
no claim, no reservation and no POST on the private path, which shares the
validation. Other control bytes are passed on as written.
And a private request whose job was too large was admitted, took one of the
claim slots and one of the reservations, and then answered Integrity
forever; four of them closed the domain. ES now projects the job and the
POST body before the claim, with a stage, a job name and a correlation
value of the lengths every run has, and refuses a request that does not fit
as malformed, with no claim. The job bound stays measured on the form
`encoding/json` writes, which is never shorter than the job Nomad's API
returns.

The guard coverage review found that a production file could hold
`//go:cgo_import_dynamic`, which makes a build without cgo load a named
shared library before `main`, with no import that the guard reads. Every
non-test Go file of the repository may now hold only the `//go:` directives
of a reviewed list, today `//go:build` alone. The tests of the red-team and
the review's proposal are adopted unchanged.

Taking up `trunk_dev` after its PRs #27 and #29 adds no path. The mount
target rule is one more production file, the two contracts documents state
the refusal, and seven test files are new, so the path ceiling of PR #12
plus its repairs became 66 files.

This entry changes behaviour: a request that holds one of those strings,
which ES accepted before, is now refused. It changes no stored format. The
public request contract gains the refusal, which
[the execution lifecycle contracts](.docs/execution_lifecycle/contracts.md)
state. The precise wording of the private path is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).

### PR #12 durable admission: taking up trunk_dev after its PRs #23 and #22 (2026-11-23)

Since PR #23, every test package of `trunk_dev` runs its tests under a
temporary directory whose path holds no symbolic link, through a one-line
`TestMain` in a file of its own, and a test fails for a package without
one. The admission state package of PR #12 is a new test package, so it
gets that file. PR #22 added a root test file with two reads of an adjusted
position, which PR #12's position-read test refuses; they now read the real
position. The CI's list of environment-only tests gains two lines for tests
of the handoff: one fails on the runner without its probe binary, and one
skips itself there. The list's check refuses both lines on `trunk_dev`
alone, so they come with PR #12. These are two more test files and the
CI's list, so the path ceiling of PR #12 plus its repairs became 56 files.

This entry adds one test file, changes another, changes the CI's list of
environment-only tests and changes documents. It changes no behaviour, no
stored format and no public contract. The precise wording is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).

### PR #12 durable admission: line directives after the sixth audit (2026-11-23)

The sixth audit, of the repairs after the red-team, found that the raw
pointer rule placed each value in the file that a `//line` or `/*line`
directive names. A file without the `unsafe` import could name a sibling
file that imports it, above a raw pointer road, and pass the rule. The rule
and every other guard now read the real position of the code, and a test
refuses the calls that read an adjusted position in the test files of the
module. Every non-test Go file of the repository is refused such a
directive as well; none held one. New subtests hold the rule in a package
with a sibling file that imports `unsafe`, with and without a directive,
and show that a directive moves no site of a guard inventory. The guard of
Workstream A's source terms reads real lines as well; it is one more test
file, so the path ceiling of PR #12 plus its repairs became 53 files.

This entry changes guard tests and documents only. It changes no
behaviour, no stored format and no public contract. The precise wording is
owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).

### PR #12 durable admission: repairs after the red-team (2026-11-23)

The red-team of the combined PR #12 at
`bff8dda37dbf5484afb3b264d4eca38cf6abf118` found that the behaviour holds
and left one low finding, RT2-1: a production file can import
`modernc.org/libc`, which the SQLite driver brings into the build, and clear
the latches of the admission state with its `memset`, with no `reflect`,
`unsafe` or `C` import. While closing it, two more roads of the same class
were measured: a value whose type has the underlying type `unsafe.Pointer`
converts to a pointer of any type in every file, and both
`golang.org/x/sys/unix.MmapPtr` and the standard library alone, through the
exported `reflect.Type` of `encoding/json`'s error type, hand one out. The
guard now holds all three. The import inventory also counts `plugin` and
every dependency package outside a reviewed list, whose entries are pinned
to the module and version that was reviewed. A new raw pointer rule refuses
such a value in a file that does not import `unsafe`. Raw system calls stay
outside every inventory and are named as part of the limit of the
operating system.

The red-team's tests are adopted as permanent tests: its eleven behaviour
tests, its test of a second process killed at random instants, its guard
test of RT2-1, and its three tests of documented limits, which now fail when
a limit closes or moves without the documents. They are four new test
files, so the path ceiling of PR #12 plus its repairs became 52 files. A
comment in the admission state file says that only an untyped nil owner
gets the closed handle, and the hash pin of that file follows it.

This entry changes guard tests, adopted tests, one comment of production
code and documents. It changes no behaviour, no stored format and no public
contract. The precise wording is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
The bytes of this entry need their own audit before PR #12's merge gate.

### PR #12 durable admission: a limit named after the fifth audit (2026-11-23)

A fresh independent audit of the fourth repair
`bff8dda37dbf5484afb3b264d4eca38cf6abf118` accepted the candidate with one
low finding in the documents. The entry below says what stays possible
outside the admission state package, and the owner document lists the limits
of the guard by name. Neither named one road: code that writes the memory of
its own process through the operating system. The audit cleared the
withdrawal latch of a withdrawn Service that way on linux/amd64, and the
Service's check of current admission answered true again. The function it
used has no `reflect`, `unsafe` or `C` import and names no protected field,
and in one form it changes the result of no test. The road is older than the
package, and no source inventory can hold it in general, because the path
can be put together at run time, so this entry adds no guard rule. It names
the limit instead: every production file of the module and every dependency
is inside the trust boundary of the admission state, and nothing may rely on
the package boundary against code of lower trust in the same process.

The same audit observed that the forms which must not compile outside the
package are judged by the type checker of the standard library and not by
the compiler itself. The owner document now says so.

This entry changes documents and the docs contract test only. It selects
nothing new and changes no production code and no guard. The precise wording
is owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
The bytes of this entry need their own audit, and the red-team review of the
combined PR #12 is still required.

### PR #12 durable admission: the admission state package (2026-11-22)

The fourth audit left one question open: the typed guard keeps the admission
state closed by searching source forms, where a design could make a bypass
fail to compile. The selected answer is to make that change in this
candidate, before the handoff has a production caller. It is not added to
the commissioning gate as a seventh prerequisite, because nothing is left
for a later change to do. This entry moves production code inside the same
selected design. It changes no behaviour, no stored format and no public
contract.

The installed view, the withdrawal and supersession latches and the time of
the last confirmation leave `Service`. They are one unexported struct of a
new package, `es/admission/internal/admissionstate`, under that package's
own lock. The package is one production file that imports neither
`reflect`, `unsafe` nor `C` and performs no I/O. It is internal to
`es/admission`, so it is not a shared package and no other service can
import it. A Service holds a handle to its state, made once in `NewService`,
and a view leaves the package only as a second handle. Each handle is a
struct with one unexported pointer to an unexported struct. Admission
content crosses the boundary as plain data and is copied in both directions.
The admission digest moves with the state and produces the same bytes as
before.

Outside the package the compiler now refuses what the guard searched for: a
selection of a field of the state or of a view, a struct type written in
either shape, and a copy, overwrite or restore of the value. Two things stay
possible there, a call of an exported function of the package and an
assignment of the whole handle, and the guard holds both by exact
inventories: every call site of every exported function, the exported
surface as a closed list, and every access to the handle field. It holds the
one file of the package by the SHA-256 of its content. Reflection and
`unsafe` reach an unexported field of any package, so the module-wide
`reflect`, `unsafe` and cgo import inventory stays as it is.

The proof seam is narrower than before. No test writes a field of the view
any more. Tests read the state through one inspection method that no
production code calls, and they change the policy of a view only by adding
an evaluator behind the selected built-in set, which can refuse a claim or
require an input and cannot allow one.

The precise rules are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This candidate requires a fresh independent audit of its complete committed
bytes, and the red-team review of the combined PR #12 after it.

### PR #12 durable admission: corrections after the fourth audit (2026-11-22)

A fresh independent audit of the third repair
`faacf16b9d5cd5ddc28b79da5c6c30f2bca6c124` accepted its production code and
every correction of the third audit, and did not accept the candidate. The
typed guard read only the packages that the pattern `./...` matches. The go
command compiles a package from a `testdata` directory, or from a directory
whose name begins with a dot or an underscore, as soon as another package
imports it, so the statement of the entry below, that every production
package and file of the module is read, did not hold for those. This entry
corrects the candidate inside the same selected design; it selects nothing
new and changes no production code. The entry above is the production change
of the same repair.

The guard now chooses what it reads by the directory a package is compiled
from. It reads every package in the dependency closure of the module's
packages whose directory lies inside the repository, whatever the directory
is called and whatever the import path, and it fails on a closure package
compiled from anywhere but the repository, the Go root and the module cache.
Its file-set check and its import inventory read every directory of the
repository except `.git`. Three forms that make the go command compile a
module from an unread place fail a test: a directive of `go.mod` outside the
exact list `go`, `module` and `require`, which refuses a `replace` line; a
workspace file in the repository or above it; and a `go.mod` below the
repository root. A file that imports `reflect`, `unsafe` or `C` is held in
the import inventory by the SHA-256 of its content, so a change inside such a
file is a reviewed change like a new import.

One detail of the cancellation rules is stated and tested: when the deadline
of a call passes while the provider is asked about the job, the answer is
`OperationalTimeout` with the stored run, where a cancellation answers
`OperationalCanceled` with the stored run.

The precise rules are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This candidate requires a fresh independent audit of its complete committed
bytes, and the red-team review of the combined PR #12 after it.

### PR #12 durable admission: corrections after the third audit (2026-11-22)

A fresh independent audit of the second repair
`c41e177f0d264318de3d799d8b28e7f494b18c74` accepted its production code and
every correction of the second audit, and did not accept the candidate. The
typed guard still missed a protected field written through a generic function
that another package instantiates, and four low findings showed tests and
documents short of the code. This entry corrects the candidate inside the same
selected design; it selects nothing new and changes no production code.

The three escapes of the typed guard found in review (a whole-value
conversion, a pointer conversion, a generic body) each gave the storage of an
owning type a second set of field names through a struct type of the same
shape. The guard now refuses that class by default instead of one more form
of it. It lists every struct type written in the module whose field names,
order and embedding equal an owning type's (`whole-mirror`), and every type
parameter whose constraint reaches an owning type, at its declaration
(`whole-constrain`). It holds an exact inventory of the type parameters
declared in a package that declares an owning type. It reads the whole-value
occurrences of each owning type in every production package of the module,
not only in the package that declares it, and its file-set check and its
`reflect`, `unsafe` and cgo import inventory cover every production file of
the module. The guard remains a search over source forms with named limits,
not a proof of aliases or dataflow.

A denial that an evaluation returned under a context that ended meanwhile is
pinned as `OperationalDenied`. The commissioning gate gains a sixth
prerequisite, `CP-PUBLIC-MAPPING`: the public mapping of the handoff's
reasons, which includes what a refused first delivery tells its caller, must
be selected before the handoff or commissioning has a production caller. The
outcome table now says where a cancelled call still returns the stored run.
The precise rules are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This candidate requires a fresh independent audit of its complete committed
bytes, and the red-team review of the combined PR #12 after it.

### PR #12 durable admission: corrections after the second audit (2026-11-22)

A fresh independent audit of the durable-admission candidate
`b6d2f7787ec8254134cb48fcae0da72bac0fd02c` accepted its production code and
did not accept the candidate. The typed guard still let a protected field be
written through a pointer converted away from its owning type, and seven low
findings showed documents, tests and code apart. This entry corrects the
candidate inside the same selected design; it selects nothing new.

The typed guard lists a conversion in either direction between an owning type
(or a pointer to or container of it) and any other type, and an instantiation
of a generic function or type with such a type argument. A method inventory
counts a same-named interface or constraint method and its selections as
indirect references, so a gated entry cannot be reached through an interface
of the two packages. A file-set check fails when a production file of the two
packages is compiled for none of the three guarded targets. A cancelled call
answers `OperationalCanceled` wherever the admission returned no refusal of
its own. `OperationalDenied` is stated as what it is, the answer of the
re-judgment of a retained original; a first delivery that ordinary resolution
refuses stores nothing and answers `OperationalUnavailable`, and what a first
delivery tells its caller stays with the public mapping, which the
commissioning gate names as the prerequisite `CP-PUBLIC-MAPPING`. The
store's admission write gains the COMMIT fault seam the claim writers have.
The lock statements now say that the three admission operations and the two
pre-check confirmations hold the custody handle's read lock. The precise
rules are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This candidate requires a fresh independent audit of its complete committed
bytes, and the red-team review of the combined PR #12 after it.

### PR #12 durable admission generation, freshness and v1 removal (2026-11-22)

A fresh independent audit and a red-team review of the committed v2 repair
`e544e0fbe4220dfdd2c2068e3267dcfa454a0cf9` over
`8058561edc08356c46680c204586b3c7796c0ff3` did not accept it. No production
hole was found in the candidate's own model, but that model stranded every
unmarked claim whenever trust, verifier or policy changed, kept a v1 branch
for originals no production caller could have created, left three admission
checks unpinned by behaviour, and its typed guard accepted whole-value and
conversion writes. The owner selected the proper fix on 2026-11-22: amend the
unmerged migration 5 (decision D-1), add the freshness rule in this repair
with a 30 second limit (D-2), and delete `operational_local_v1` (D-3). This
is a **re-derivation** on the reliable-submit **Reopened redesign seam**.

Select one durable **admission row** in schema 5: installation, epoch,
admission generation, admission digest and an enabled or withdrawn state,
with its own triggers, created by the amended migration 5. This reverses the
"No SQL migration" statement of the 2026-11-20 entries for this one purpose;
migrations 1 to 4, the 47 claim columns, codecs 1 to 4 and every stored
encoding keep their meaning. Every codec-5 first-effect writer (establish,
run assignment, intent, pre-stage, stamp and first marker) compares the
presented **admission token** with that row under the SQLite writer lock, and
the post-COMMIT release of a run assignment, intent, stamp or first marker
reads it again; establishment releases nothing and the pre-stage turn is
followed by the stamp turn, so those two have no re-read. Replacing trust, verifier or policy
no longer changes the epoch: a restarted process advances the generation,
in-flight claims are judged again by the new content, and a process holding
an older token commits no further first-effect write. Withdrawal becomes
durable and domain-wide. A process must have confirmed its trust with EGS
less than 30 seconds before every first-effect cut after establishment,
measured inside that cut's writer turn; establishment samples the
confirmation just before its turn, and its turn compares the token only. A
confirmation that differs
latches the process closed, and a failed confirmation extends nothing. A
refusal of a retained original by the current rules reports the value-free
`OperationalDenied`; an absent, fenced, withdrawn, superseded or stale
authority reports `OperationalUnavailable`, and so does a first delivery that
ordinary resolution refuses, which stores nothing. Neither discloses a run.

`operational_local_v1` is removed, not retained: no **Temporary compatibility
edge** remains on this path. The 2026-11-20 and earlier 2026-11-22 entries
below stay as history and are superseded where they select v1, forbid a
migration, bind trust or policy replacement to a new epoch, or describe
withdrawal as local to one Service. Commissioning, advance and withdrawal keep
zero production callers; a maintained gate names the prerequisites
(`CP-ROLLBACK`, `CP-EPOCH`, `CP-POLICY-CUSTODY`, `CP-NATIVE`, `CP-RELEASE`,
`CP-NOMAD-ACL`, `CP-PUBLIC-MAPPING`) that must be answered before one is added. The typed protected-field guard
now treats conversions as transparent, counts whole-value construction,
assignment, conversion and declaration of an owning type, and names its
remaining limits. Public keyed refusal, ordinary unkeyed Submit, what
`Initialize` does, EGS, the original wire format, receipts, staging, the
sender and the provider exchange are unchanged and remain **Current
invariants** or **Bounded slice rules** as before. The precise table, token,
cuts, deadline, outcomes and test obligations are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This candidate requires a fresh independent audit and red-team review of its
complete committed bytes before it can resolve the PR #12 finding.

### PR #12 v2 field-access guard completion (2026-11-22)

The consolidated v2 repair below, recovered unchanged as tree
`433b4891a0e413aff2b0eb6adf316a033a544a24` over
`8058561edc08356c46680c204586b3c7796c0ff3`, is now a committed draft-PR
candidate. Writer review found that its typed protected-field access
classifier still reported range-clause `=` targets, explicit or implicit
address-of, and writes through a selector, index, slice or dereference chain
rooted at a protected field as reads. This **Bounded slice rule refinement**
on the reliable-submit **Reopened redesign seam** classifies those accesses as
assignment, address or write-through, adds maintained same-site regressions,
and reconciles the operational handoff contract's §9 path ceiling with the
repair's five added paths. Production Go code, the operating model, custody
grammar, durable facts, sender and recovery behavior are unchanged. The
candidate still requires a fresh independent audit and red-team review of its
complete committed bytes before it can resolve the PR #12 finding.
Superseded in part by the entry above: its guard is extended there.

### PR #12 v2 authority and evidence repair (2026-11-20)

The fresh independent audit rejected the unstaged 18-path v2 candidate bound
to manifest `ebf8e5a48ed2e4b36d7249abee813a70169d8f9bc1c33b5e1b09eb5d7a24a6b6`.
The rejected predecessor had a source-level repair for eligible v2
continuations but lacked maintained exact authority inventories and
discriminating signed-v2/historical-v1 evidence; its persistence owner also
misattributed strict v1 empty-leaf enforcement to storage. This consolidated
**Bounded slice rule refinement** on the reliable-submit **Reopened redesign
seam** adds exact typed guards and independently built complete v1/v2
wire-and-commitment checks, validly signed association controls, actual retained
policy-context observation, and assigns the historical empty-leaf check to
admission. The selected operating model,
custody grammar, durable facts, sender and recovery behavior remain in force.
The only permitted production insertion is a nil-default, non-authoritative
test observation of the completed retained policy context immediately before
the existing built-in evaluation. This repair is an unstaged writer candidate;
it does not become independently accepted or resolve the PR finding until a
new independent audit of its complete final bytes.
Superseded in part by the 2026-11-22 durable admission generation entry:
the historical-v1 evidence and the v1 empty-leaf check are removed with v1.

### PR #12 retained-current-admission v2 repair (2026-11-20)

PR #12 published the private schema-5 operational handoff at
`8058561edc08356c46680c204586b3c7796c0ff3`. Subsequent review comment
`4644988778` identified an implementation omission: an unmarked retained
original can proceed to its first effect without consulting the current ES
admission owner. The earlier source acceptance applies to its published bytes;
the finding remains unresolved and blocks merge. This is a **Bounded slice rule
refinement** on the reliable-submit **Reopened redesign seam**. Public keyed
refusal, ordinary unkeyed Submit, caller-before-lookup, original and receipt
integrity, and fixture/effect separation remain **Current invariants**.

Select an `operational_local_v2` original carrying the complete signed artifact
evidence from the same successful ordinary resolution. A one-shot Service-owned
snapshot of the loaded trust model, provenance verifier and supported built-in
policy is commissioned for the qualified installation/policy epoch; only
monotonic local effect withdrawal is mutable within that epoch. Bounded local
current-admission qualification on the authenticated retained original governs
unmarked run/intent progression, pre-stage, stamp, first marker, post-COMMIT
release and final sender entry. The already sealed `operational_local_v1` is a
**Temporary compatibility edge**: accepted receipts and positive marked
reconciliation remain readable, while any v1 unmarked first effect refuses
without resealing. No SQL migration, public/native wiring or policy platform is
selected. The precise format, locks, outcomes and test obligations are owned by
[the operational handoff contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md).
This unstaged repair candidate requires a new frozen validation generation and a
fresh independent audit before any additive commit or PR update.
Superseded in part by the 2026-11-22 durable admission generation entry: the
v1 **Temporary compatibility edge**, "No SQL migration", the epoch-bound
snapshot and Service-local withdrawal selected here are no longer in force.

### Pre-stage continuation and transport observation repair (2026-11-20)

Refine the private operational handoff **Bounded slice rule** on the
reliable-submit **Reopened redesign seam** after the independent rejection of
manifest `8808e598683923aff485f5d16d2cf1298f7e93b15ce90d7c780a0250b170a58c`.
An exclusive stage attempt requires the complete successful pre-stage result:
`OperationalNoChange` and `OperationalReasonNone`. A failed rollback, release or
observed cancellation may preserve the semantic NoChange observation but stops
effects and withholds run/receipt without erasing an earlier observed write.
Maintained proof distinguishes direct exchange-method entry, GetConn and receiver
ingress. The final owner-protected cancellation sample and its possibly-delivered
later race remain unchanged. The repair is private, unstaged, runtime-unwired and
pending a fresh independent source audit; no new architecture reset is selected.
Structural public keyed refusal and ordinary unkeyed Submit remain **Current
invariants**.

### Consolidated private operational handoff audit repair (2026-11-20)

Refine the selected private operational handoff **Bounded slice rule** on the
reliable-submit **Reopened redesign seam** after rejection of manifest
`e4d58552913ae21118a51603de65924fd04235fabde930800883f2212ff4ceeb`.
The operational owner governs current qualification, independent write and
disclosure results, authenticated establishment confirmation, and the final
protected synchronous entry cut. Qualify the pre-existing claim count on
operational opening and retain separate logical and local physical old-opener
witnesses. This selection preserves schemas, encodings, immutable receipts,
the permanent marker, and the one live sender. Structural public keyed refusal
and ordinary unkeyed Submit remain **Current invariants**. Independent
acceptance requires a separate audit of the repaired bytes.

The codec-5 decoder amendment permits only the raw optional-BLOB check in
`sqliteClaimRow.record` in `sqlite_store.go`. This implements SQL NULL absence
before phase and fact conversion, retaining the 69-byte operational RunRef
and 32-byte fact and receipt references. The other codecs, shared scanner,
migration literals and stored formats retain their existing contracts.

The private composition rechecks stage metadata through held descriptors,
prepares transport before the owner-protected entry cut, and binds intent,
stage, marker and positive observation to the authenticated original access.
The finite result reports current qualification and the observed write
separately. The local test witnesses and completed generation are tied to
their exact source in the repair evidence.

### Post-PR #11 operational handoff owner-contract candidate (2026-11-19)

PR #11 completed fixture-only private replay/progress source publication at
`ae326b0ddc30ec6b35883ee32945c622405b68b6` on official `trunk_dev`, sole
parent `f1aa8b934cc26c16a966a110c7b408abdaeadce7`, 430-leaf tree
`e066cd4afa77fcb665f31b69bf00465989f9744e`. Current production source is
schema 4 and the private progress path is fixture-only. The entries that
follow record the earlier planning and audit decisions.

Select a candidate **re-derivation of the reliable-submit Reopened redesign
seam** for the private operational handoff and restart slice. The
[operational handoff owner contract](.docs/execution_lifecycle/reliable_submit_operational_handoff.md)
selects schema 5, codec 5 and encoded scope 3, a checked current writer turn,
a permanent marker and one live sender only from the direct acknowledgement
of the applied first-marker COMMIT. It selects exclusive staging custody
without reattachment, positive registration evidence and immutable receipt
recovery. Target, proof profile and native prerequisites are distinct. This
candidate includes private implementation and maintained local proof cases on the selected seam. The local SQLite head is schema 5. Local proof validation and fresh independent
source acceptance remain separate gates.
Public keyed refusal and unkeyed Submit remain **Current invariants**.

### One allowlist-prefix rule for ARS, AGS, and ES (2026-11-23)

This **Current invariant refinement** makes the allowlist half of the
existing invariant "caller authentication and narrow SPIFFE allowlist
authorization remain required" mean one thing at ARS, AGS, and ES. ES refused a too-broad or malformed allowlist prefix at startup, while
ARS and AGS refused only blank values and loaded prefixes such as `service`,
`/operator/local/`, `operator/lo cal`, or a full SPIFFE ID. Caller
authentication hands authorization only canonical paths, so all but the first
of those could never match, and a one-segment prefix granted every identity
below it. Each of the three services also kept its own copy of the prefix
matcher. The rule is now one cross-cutting support package,
`internal/callerallowlist`, recorded in `.docs/system_overview/contracts.md`
section 3A: a prefix is the path of a SPIFFE ID that section 3A accepts,
without its leading slash, with at least two segments; it matches the caller
path that equals it or continues it after a `/`; and a prefix that fails the
rule matches nothing. ARS, AGS, and ES refuse such a prefix at startup. The
package owns no allowlist content and no route: which prefixes each service
configures, and which routes they open, stay service-local. EGS's fixed
caller list and CGS `id.conf` are unchanged. Every repo-owned configuration
already uses canonical two-segment prefixes. In the same change, the root
guard that keeps caller identity reading inside `internal/callerauth` also
type-checks every production package for Linux and macOS, so a read of a
request's TLS state or of a certificate's URI SANs, issuer, or raw extensions
is caught through a variable, alias, or embedded struct too; and the operator
healthcheck TLS status tools read the operator certificate's URI SANs from its
DER encoding instead of OpenSSL's printed text.

### Nomad access control lock (2026-11-23)

ES now submits only to a Nomad that enforces access control (ACLs). ES reads
a least-privilege client token from `nomad.token_file` at startup (submit,
read and logs in namespace `es-submit-v1` only), sends it on every Nomad
request, and before every submit refuses with `503
execution_runtime_unavailable` unless its token resolves as a client token,
ACLs are enabled and no anonymous policy exists. Nomad's bootstrap management
token stays in a root-only file and never reaches ES. Provisioning is
`scripts/nomad_acl_setup.sh` (namespace, policies, ES and read-only observer
tokens, `check`, `rotate`); the supported Linux host setup, full-profile
bring-up, supported-local setup and proof capture, readiness checks and CI's
real Nomad all run with ACLs on. CI proves a real ACL Nomad refuses a job
without ES's token and ES refuses a Nomad without the lock. Nomad's client
now offers only the Docker task driver, through an explicit `plugin "docker"`
block that refuses privileged containers and allows only the seven
capabilities the submit path needs; its configuration and data are
root-owned, and setup, bring-up and readiness refuse a Nomad whose live
driver set, privileged setting or capability list differ. Known limits:
Nomad's API is plain HTTP on loopback (Nomad HTTPS with a pinned server key
is the next part), the lock does not cover the Docker socket, and ES's token
still expresses job shape (mounts, task user). PR 12's reliable-submit
operational provider is not yet covered: its change list is in the Nomad ACL
report.

### One caller authentication rule for the five services (2026-11-23)

This **Current invariant refinement** makes the existing invariant "caller
authentication and narrow SPIFFE allowlist authorization remain required"
mean one thing at every service. ARS, AGS, EGS, CGS, and ES each carried
their own copy of the code that reads the caller's SPIFFE ID from the
verified client certificate, and the copies had drifted: CGS accepted an
identity from any trust domain, ARS indexed the verified chain without
checking it was non-empty, and every service took the first matching URI SAN
of a certificate with several, passed non-canonical paths (for example a
trailing slash or a `..` segment) to prefix matching, and accepted a CA
certificate presented as the caller's leaf. None of them noticed that a
client certificate expired while its connection stayed busy. The rule is now
one cross-cutting support package, `internal/callerauth`, whose contract is
`.docs/system_overview/contracts.md` section 3A: a verified chain that is
still within its validity period at each request, an end-entity leaf (not a
CA, no `keyCertSign` or `cRLSign`, as X.509-SVID requires) with exactly one
URI SAN, a conforming SPIFFE ID with a path, trust domain
`execution.internal` only, then the bootstrap-issuer refusal. Authorization
stays service-local. CGS `id.conf` loading refuses principals that no
authenticated caller could present, and the operator healthcheck TLS status
tools fail an operator certificate with more than one URI SAN, as ES does.
The response codes and texts are unchanged; requests that the old copies let
through or refused with `403` because of a malformed identity, and requests
on a connection whose client certificate has expired, now get `401`. The CGS
authorize request and response shape is unchanged. This is not a Workstream
D policy-input redesign.

### Private replay-progress pre-COMMIT and owner inventory refinement (2026-11-19)

Historical selection state before PR #11 publication.

The latest independent audit rejected manifest
`0812091529c67f4bc46d0bc343b3dea8595e63a461264e143d51606e581e0c06`.
This **Bounded slice rule refinement** on the reliable-submit **Reopened redesign
seam** completes the unpublished opener's pre-COMMIT cleanup routing and aligns
admission §7.4 with the existing typed synchronization inventory. Persistence
ADR §15B.5 requires checked nonmigrating readback after safe pool disposition.
The private scope remains fixture-only and runtime-unwired. Public structural
reliable-request refusal and unkeyed Submit remain current invariants.
Operational cross-restart write-uncertainty authority remains outside this
selection. Independent acceptance of the resulting bytes is a later gate.

### Consolidated private replay-progress repair selected (2026-11-19)

Historical selection state before PR #11 publication.

The fresh read-only audit rejected the thirty-path manifest
`110cef71ba25f61b70297b37cc5a50a68732d639845e0ac4315d06cedcdbc1e3`
over PR #10. Select one **Bounded slice rule refinement** on the
reliable-submit **Reopened redesign seam** in the same unstaged candidate.
Repair migration opening authority and literal namespace qualification,
confirmation eligibility and borrow lifetime, current reconciliation
predicates, definite occupied disposition, fixture terminal assertion
association and scope-1 permit preflight. Add an external test-only
admission lost-response witness under the existing no-effect boundary.
The persistence ADR §15B and submit contract §6B govern the repair.
The selected operating model, formats and migration literals remain
the same. Independent acceptance of repaired bytes is a later gate.

## Post-PR #10 source publication and private replay progress contract candidate (2026-11-18)

Historical selection state before PR #11 publication.

PR #10 completed A1 source publication by squash merge on official `trunk_dev`
at `f1aa8b934cc26c16a966a110c7b408abdaeadce7`, sole parent
`fb9ae55797d9fcc02863c23fe8d3e43d16eac542`, complete 427-leaf tree
`8dd27f9acba98ed70d93736bdef8300ef1aba53f`. That tree also identifies the
preserved local A1 source at `fd2115ca8f44a615627adb08926896a1e052dc30`.
Source publication grants no deployment, native qualification or public
reliable-submit authority. The PR #9 and A1 selection section below records
the previous planning state.

Select private original replay with durable claim progress as one
**Bounded slice rule extension** on the reliable-submit **Reopened redesign
seam**. This candidate advances the SQLite head to schema 4, preserves
immutable private codec 3 in `synthetic_nonoperational_v1` and carries
historical codec 1/2 compatibility. Codec 4 and independently versioned
migration 4 use the same ES
SQLite authority, caller/key occupation, and one original and one attempt.
The separate `synthetic_progress_nonoperational_v1` scope remains fixture-only,
runtime-unwired and effect-ineligible at every phase. Public structural
reliable-request refusal and unkeyed Submit remain current invariants.

The persistence ADR §15B and submit contract §6B own the fixture semantics.
The reconciled proposal keeps one codec-4 reconciliation observation as
historical evidence, with a first fixture marker and independent terminal
evidence for the same run. K1 limits fixture proof to the current row and
each invocation's own write disposition. A later explicit fixture command
uses fresh authentication, a new borrow and the exact current revision.
It cannot resolve an earlier unknown response or supply operational
permission. The full operational Validated No-Dispatch Evidence requirement
remains unchanged. A separately reviewed cross-restart authority for
relevant write dispositions is required before provider wiring. The shared
count/create allocator serves both fixture publishers, including scope 1.
The legacy codec-1/2 predicates and the codec-3 reader remain current source.
Phase 0 is architectural review of the contract and acceptance map. Phase 1
is the local pooled `loadClaim` cleanup repair and its bound regression. Phase
2 implements codec, scope, format and schema. Phase 3 composes durable
successors with authenticated private original replay. Phase 4 validates the
integrated restart, concurrency, unknown-outcome and no-effect behavior.
Phase 5 is one fresh independent audit of the integrated source. The exact
K1 owner contract was selected for bounded implementation. This source
candidate contains the pooled repair, schema 4, codec 4 and the integrated
fixture path. Acceptance depends on the source-bound validation and a
separate independent audit.
The function-owned `loadClaimFresh` reader and codec-3 callers are outside
the cleanup prerequisite. No phase selects a standalone documentation or
reader-only PR. Operational ingress, identity, provider and recovery
qualification require later decisions.

## Post-PR #9 source publication and A1 read cleanup selection (2026-11-18)

PR #8 completed development acceptance, local source preservation, remote
source publication, and the squash merge on official `trunk_dev` at
`2478a24a18852f1abd7d474c0525c46bd2c05e5e`, complete tree
`e7defd3a0df278ad70762f17f0f2a5b1c14a795b`. This source publication
is not artifact publication, operational acceptance, deployment, native
installed-source qualification, or a CI-pass claim. Private codec-3 custody
remains a **Bounded slice rule** on the reliable-submit **Reopened redesign
seam**, limited to `synthetic_nonoperational_v1`: runtime-unwired,
effect-ineligible, and unavailable as public reliable Submit. Public
structural reliable-request refusal and unkeyed Submit remain in force.

PR #9 completed source publication of O2, the bounded historical codec-1/2
CAS cleanup refinement, by squash merge on official `trunk_dev` at
`fb9ae55797d9fcc02863c23fe8d3e43d16eac542`, complete tree
`be8437c8ce48cbcbed53f60a03810283abbd9235`. The persistence ADR
retains O2's accepted contract and physical-close evidence limits. Source
publication does not qualify operational behavior, native installed-source
behavior, deployment, or public reliable Submit.

A1 original-key read cleanup is the selected source-only **Bounded slice rule
refinement** on the reliable-submit **Reopened redesign seam**. Its owner rule
requires request-independent, bounded cleanup or exact-connection disposal
after read-transaction uncertainty, while preserving paired-key snapshot and
key-lifecycle behavior. The private path remains limited to
`synthetic_nonoperational_v1`: runtime-unwired, effect-ineligible, and
unavailable as public reliable Submit. A1 source work does not itself supply
independent acceptance or runtime qualification.

## Historical current-remote-base private synthetic replay custody selection (2026-11-17)

At selection, this candidate contained the accepted `d408877545c16ee94968b04eab236da9e3ad6db0`
private replay-custody delta as its third logical layer on the verified current
remote base. Private codec-3 custody is a **Bounded slice rule** on the
**Reopened redesign seam** for reliable-submit canonical binding and replay
completeness. Its only scope is `synthetic_nonoperational_v1`: source-local,
runtime-unwired, then-unpublished, effect-ineligible, and unavailable as public
reliable submit. It introduces no Service.Submit, HTTP, app, configuration,
provider, staging, deployed key-loader, TTL/GC, backup/restore, or runtime
wiring change. Public structural reliable-request refusal and unkeyed Submit
remain in force.

The private source selection keeps original typed intent, the same parsed
delivery and PB1 recomputation, sealed-file AEAD custody, one-database
claim/key/grant authority, one-use known-committed pre-Seal permission,
bounded identity and mode checks, no-follow and fsync behavior, fail-closed
C1/D1 connection quarantine, permit burn, issuing-store and budget limits,
fixed redaction, and no-effect decisions. Migration 3 appends to the unchanged
migration-1/2 literals and hashes. Codec-1/2 generic domains and historical
compatibility remain; old binaries refuse schema 3. The owner contracts in
`.docs/execution_lifecycle/` govern the exact shape. The pre-existing
historical codec-1/2 CAS cleanup concern remains a separate post-publication,
pre-runtime-wiring hardening tranche, outside that historical candidate and
selected above as O2.

## Historical current-remote-base PB1 binding selection (2026-11-17)

At selection, this candidate contained the accepted predecessor's private admission binding v1
source at `1c44483fcb6978125a3c4f11ff168d094200dd4e` for its second
logical layer. The admission-local HMAC-SHA-256 effective-plan commitment and
fourteen-category completeness witness remain a **Bounded slice rule** on the
**Reopened redesign seam** for canonical binding and replay completeness.
`ES-PRIVATE-ADMISSION-BINDING-V1-20261115-01` was selected on accepted
integration I. It carries the signature-verified returned mount artifact
digest and signed payload digest into the private assessment without changing
legacy admission rejection or acquisition count. There was no production
caller at PB1; the private replay composer is the only later source-local
caller selected in that historical candidate.
The producer is private and runtime-unwired; every assessment remains
effect-ineligible. Current public structural reliable-request refusal, unkeyed
Submit, job/handoff/receipt behavior, result authentication, and lifecycle
authority remain unchanged. This selection adds no public reliable submit,
schema migration, provider route, or key-custody authority.
Reliable submit remains unavailable.

## Historical current-remote-base H/C/T foundation selection (2026-11-17)

At selection, this current-base tranche re-derived the reviewed H/C/T foundation tree on official `trunk_dev` `87d262de8748f49197c5bba6020bd5dddc334bc7`. The 2026-11-13 construction snapshot is historical; the preservation-only T commit grants no publication or operational authority and is not part of this branch ancestry. T's one-time checkpoint exception is consumed. The accepted predecessor source, the then-candidate's validation, independent audit, local commit, and remote publication were separate gates. This tranche preserves the remote P0s/P0t dedicated status-only collector and pre-contact renewal hold while retaining the locally selected effect-free existing-host route retirements.

Current unkeyed Submit retains T's admission-owned semantic plan and fixed B2 public/privacy boundaries while using C's post-`prepareAdmission` execution/placement snapshot. That snapshot begins after successful admission and supplies one staging/results pair through the current Submit resolution, materialization, and handoff. It does not atomically capture concurrently mutated configuration, earlier admission/trust/Vault/policy reads, or later Status/Logs/Result requests. Artifact, capability, target, and profile errors precede placement errors. C's archive, mount, custody, authenticated-result and no-repair rules remain the safety baseline. Incomplete leaves and startup probe fixtures remain retained where exact effect-time identity for removal is unproved. Paired-root proof is an active **Bounded slice rule pending integrated review**; whole-root reclamation remains a **Reopened redesign seam**.

The six named existing-host Remote Alpha ES writable-state/service-user helper routes remain fixed effect-free tombstones. Archived v1 claims are a **Temporary compatibility edge** and not current host truth; no v2 replacement or fresh-host provisioning is selected. The operator-facade evidence-compatibility cutoff is separate and does not retire underlying owner-local producer scripts. Supported-local and unrelated Remote Alpha routes remain outside this retirement. At that point, development acceptance, a later commit, operational rollout, and publication were distinct decisions; PR #8 later completed source publication only. Key isolation, topology, capacity, residence, reclamation, and publication gates remain open. Reliable submit remains unavailable and runtime-unwired.

## Superseded Remote Alpha Operator Facade Routes

These two sections stood under "Highest-Priority Backlog Entry" in
`PLANS.md`. Each records a former Mac-side operator facade route and says it
grants nothing current. The current route rules that followed each of them
there stay in `PLANS.md`, now under headings of their own: the P0o to P0q
rules followed P0n, and the P0s to P0v rules followed P0r.

### Historical P0n workload-auth facade route — superseded and non-authoritative

The following records the former P0n implementation rationale only. It grants
no current operator route, staging authority, evidence compatibility, or
Tranche B prerequisite. P0n formerly added one Mac-side post-reset evidence
route:
`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check
--ssh-target <target> --interactive-tty`. This route exists for the intended
operator topology where the operator runs the ES operator facade from the Mac,
the facade stages bounded helper files to the Remote Alpha host, the human
remains the operator, and secrets never pass through args, env, logs,
artifacts, or Codex. P0n may validate only with static and fake SSH/SCP tests; it must not
run live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure
Manager refresh, support-bundle collection, CP proof, runtime identity
generation, or network-dependent integration tests.

P0n must stage only:

- `scripts/remote_alpha_vault_workload_auth_check.sh`
- `scripts/internal/remote_alpha_vault_workload_auth_check.sh`

It must preserve that public/internal relative layout on the remote host and
invoke only the staged public workload-auth helper. It may run that helper with
root through the explicit interactive TTY route when required, using `ssh -tt`
only because `--interactive-tty` is mandatory. It must not stage
`scripts/remote_alpha_operator.sh`, reset/unseal helpers, runtime identity
helpers, service-user helpers, config/TLS helpers, binary deployment helpers,
bundles, unrelated helpers, or a generic helper dispatcher.

Allowed flags for P0n are only `--help`, `--ssh-target <target>`, and
`--interactive-tty`. P0n must reject `--host-local`, `--dry-run`,
`--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--apply`,
`--interactive-sudo`, `--governed-smoke-command`, workload-auth helper override
flags, Vault address/role/audience/path/proof-path overrides, SPIFFE ID
overrides, config path overrides, summary path overrides, container probe image
overrides, SPIRE socket overrides, arbitrary commands, unknown flags, duplicate
flags, extra positional arguments, equals-form options, and all secret-like
arguments including root tokens, unseal keys, client tokens, Vault tokens,
JWT-SVID payloads, API keys, private keys, passwords, and secret payloads.

P0n keeps the canonical workload-auth evidence artifact on the remote host at
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`.
The operator facade must not copy that summary back to Mac `.out`, print full
summary JSON, create an operator summary, create generated artifacts, tee, run
`script`, capture transcripts, write logs, run Infrastructure Manager,
collect support bundles, run CP proof, run runtime identity generation, run
reset/unseal, or combine workload-auth evidence with reset/unseal. After remote
success it may print only non-secret next steps: the remote summary path, a
recommendation to use `recovery-session --evidence-check` after separately
collecting IM/local evidence, and printed-only IM refresh/support-bundle
commands as separate IM evidence/provenance actions. The workload-auth summary
remains evidence/projection only, not readiness authority, not Vault production
readiness, not governed execution proof, not ES Vault token brokerage, not IM
authority, not CP recovery authority, and not Remote Alpha
production/deployment/reconciliation architecture.

A bounded bugfix/self-audit refinement may extend the same v1 workload-auth
summary with backward-compatible, safe Vault JWT login failure classification
when `auth_smoke.vault_login=fail`. The helper may record only class labels,
HTTP status, error-string count, a `vault_login` failure phase, safe JWT issuer
expected-source/class labels, safe JWT issuer actual-class labels, and
`auth_smoke.vault_login_raw_error_recorded=false`; it must not print or persist
the JWT-SVID, Vault client token, root token, unseal key, proof secret value,
raw Vault login response body, raw HTTP headers, Authorization header, stack
trace, or full Vault login JSON. Classification remains bounded triage over the
host-local evidence artifact, not workload-auth bootstrap, not a claim that a
specific Vault object is missing unless the class safely supports that, and not
ES Vault token brokerage.
The issuer comparison must understand the same `spire-server bundle show
-format spiffe` trust-domain JSON shape used by bootstrap, including
`trust_domains` maps keyed by bare trust-domain labels, so a parseable
repo-derived bound issuer does not degrade to `unknown` before classification.

### Historical P0r runtime-identity facade route — superseded and non-authoritative

The following records the former P0r implementation rationale only. It grants
no current operator route, staging authority, evidence compatibility, or
Tranche B prerequisite. P0r formerly added one Mac-side recovery-session
runtime identity evidence route:
`scripts/remote_alpha_operator.sh recovery-session runtime-identity-summary
--ssh-target <target> --interactive-tty`. This route is evidence/projection
only over the existing host-local runtime identity helper summary script. It
does not settle the reopened runtime-identity handoff seam and does not claim
runtime-profile readiness, submit readiness, retained-result readiness,
governed execution proof, CP proof, or production readiness.

P0r may stage only:

- `scripts/remote_alpha_runtime_identity_helper_summary.sh`

It must resolve that helper from `BASH_SOURCE[0]`, stage it to a
route-specific remote scratch path, invoke only the staged helper over
`ssh -tt`, and attempt remote staged-helper cleanup by default. It must not
stage `scripts/remote_alpha_operator.sh`, `scripts/internal/*`, reset/unseal
helpers, workload-auth helpers, workload-auth bootstrap helpers, service-user
helpers, config/TLS helpers, binary deployment helpers, bundles, unrelated
helpers, or a generic helper dispatcher. It must not source helper scripts,
construct helper paths from user input, use `tee`, run `script`, create
transcripts, capture stdout/stderr to files, create Mac `.out`, copy summaries
back to Mac, create an operator summary, call Infrastructure Manager, collect
support bundles, run CP proof, run reset/unseal, run workload-auth bootstrap or
check, or run runtime identity generation.

Allowed P0r route flags are only `--help`, `--ssh-target <target>`, and
`--interactive-tty`. The route must reject `--host-local`, `--dry-run`,
`--check-only`, `--apply`, `--execute-reset`, `--unseal-only`,
`--post-unseal-check`, `--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, `--prepare-spire-bundle-read`,
`--interactive-sudo`, `--governed-smoke-command`, helper override flags such as
`--output`, `--runtime-support-path`, `--spire-agent-socket-path`,
`--spire-server-socket-path`, `--workload-spiffe-id`, and `--audience`,
arbitrary commands, unknown flags, duplicate flags, extra positional arguments,
equals-form options, and all secret-like arguments including root tokens,
unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, private
keys, passwords, proof secrets, raw identity payloads, and secret payloads.

P0r keeps the canonical runtime identity helper summary on the remote host at
`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`.
The operator facade must not print full summary JSON and must not persist
JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private keys,
passwords, proof secrets, raw identity payloads, or secret material. After
remote success it may print only the canonical remote summary path, a reminder
that the summary is evidence/projection only and non-authoritative, and
printed-only next steps such as the local `recovery-session --evidence-check
--runtime-identity-summary <path>` command to use after separate evidence
collection makes the summary available locally.

P0r validation remains fake/static only. Tests must cover help/plan/inventory
wording and non-claims; `runtime-identity-summary --help`; missing
`--ssh-target`; missing `--interactive-tty`; forbidden host-local, dry-run,
check-only, reset/unseal, workload-auth bootstrap/check, preparation, helper
override, secret-like, unknown, duplicate, equals-form, and positional inputs;
fake SSH/SCP staging of exactly the one public runtime identity helper; use of
`ssh -tt` only for the explicit interactive route; public helper invocation
only with no helper override flags; cleanup attempts; no transcript/`tee`/`script`;
no `.out`, operator summary, support bundle, IM, CP proof, reset/unseal,
workload-auth bootstrap/check, runtime identity generation, generic helper
dispatch, or `scripts/internal/*`; and preservation of the existing
reset/workload-auth/readiness route boundaries.
