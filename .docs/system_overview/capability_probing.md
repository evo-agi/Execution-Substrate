# Capability Probing

## Purpose

This document defines how the system handles environment and runtime capabilities.

Capability probing exists to keep contract enforcement explicit without introducing OS-specific behavior, hidden fallback paths, or service-to-service probing frameworks.

## Core Principle

Use capability-based validation, not OS-based branching.

Services must not use `runtime.GOOS`, OS-version checks, or runtime-label checks to change behavior for capability-sensitive slices.

Capability must be validated by behavior or by local static validation of the configured resource, not by assuming what a named platform should support.

## Model

The system uses two types of checks.

### 1. Static Validation

Static validation covers local checks such as:

- path validity
- file or socket type
- configuration shape
- required names or formats

Static validation is used at:

- startup
- submit, when submit-time drift revalidation is required by contract

### 2. Runtime Capability Probe

Runtime capability probing is behavior-based validation.

It exists for cases where a slice depends on the execution substrate behaving a certain way and local static checks are not enough.

Examples include:

- proving that a topology-specific runtime interface is actually usable inside a workload container

Runtime capability probes are used at:

- startup only

They are not used on every request or submit unless the contract is explicitly widened later.

## Placement Rules

Capability checks must run only at validation boundaries:

- startup
- submit for static validation only

Capability checks must never run inside:

- execution paths after validation has completed
- lifecycle handlers
- ordinary business logic

The system must not add:

- background probing
- polling loops
- implicit health workers for capability validation

## Failure Behavior

If a required capability is not met, the owning service must fail explicitly.

The system must not:

- silently omit capability-dependent behavior
- degrade silently
- switch to fallback behavior
- branch on OS or version labels

Capability failure is a contract-validation failure, not a runtime optimization hint.

## Implementation Rules

Capability probing must remain:

- small
- local to the owning service
- stateless

Allowed:

- small reusable validation and probing functions local to the owning service

Forbidden:

- global capability manager
- cross-service probing framework
- hidden shared state
- centralized runtime capability registry

## Contract Alignment

Capability requirements must be documented in:

- `PLANS.md`
- `.docs/system_overview/`
- `.docs/execution_lifecycle/` when lifecycle semantics are implicated

Probes enforce the documented contract.

Probes do not define new behavior on their own and must not silently widen a service boundary.

## Producer Contract Declarations

Read-only producer contract declarations, such as ES `GET /v1/executions:contract`, are not runtime capability probes.

They may declare static compatibility facts owned by the producer, such as the current governed-execution producer contract, config-enabled runtime-profile names, and mandatory response-evidence carriers. They must not perform background probing, call runtime dependencies, create run state, or replace health/readiness checks.

Consumers may use such declarations as early compatibility gates, but runtime readiness still belongs to the documented validation and readiness boundaries.

## Isolated execution-root candidate

The bounded private synthetic replay-custody fixture has a separate validation
boundary. Its state root and fixed objects/v1 parent must be qualified at
opening/setup by held-parent identity, owner/mode/type checks and behavior or
static resource checks for required exclusive no-follow creation and file plus
directory synchronization. Failure refuses the private fixture; it never
silently substitutes a weaker path or branches on OS labels. Per-object
held/visible identity, size and digest checks are static revalidation during
publication/read, not a new background or submit-time behavioral probe.
This rule does not open an operational state path, runtime startup probe,
public Submit branch or production key loader.

Configured Submit startup validates the staging/results root pair by static path,
type and identity checks plus local behavior probes for no-follow opens,
exclusive claim and no-replace publication. Platform-specific implementations
do not select on `runtime.GOOS` or fall back. Submit-disabled service startup
does not create run staging. Submit rechecks root identity before claim.
Configured Submit startup also creates an exclusive synthetic directory under the qualified
results root and verifies its natural owner and exact `0750` mode without
chown/chmod. A restrictive process mask or owner mismatch refuses configured
Submit startup before work; the small probe directory remains in place because
exact-object unlink ownership is not proven. Configured Submit startup also
creates a `nested` directory inside its staging probe directory after setting
that directory to the stable `0750` stage mode, gives it the roots' owner and
that mode, and verifies both, as staging does inside each claimed run staging
root. A process that cannot give that directory the roots' group, for example
because the roots inherited a group it is not a member of from a setgid parent
directory, refuses configured Submit startup with `nested staging directory
ownership is unavailable`; probes that create entries directly in the roots
cannot see that case. Inside `nested`, startup then stages one directory for
each directory mode staging uses beyond `0750` and one regular file for each
file mode staging uses, and holds each to staging's checks, so an overlay whose
layers are on different file systems, where regular files report another
device than directories, or a file system that does not keep those modes,
refuses startup instead of failing submissions. Those modes include the ones
only governed mounts use (`0755` directories, `0644` and `0755` files), so a
staging file system that cannot keep them refuses startup even though
submissions without governed mounts would work there. Staging refuses any mode
the probe does not stage. Inside the natural result directory probe, startup
creates retention's file modes with retention's checks and renames the
bundle-mode file with the no-replace rename onto a name that exists, which must
be refused as existing, and onto a free name, which must succeed and keep the
file, so a results file system whose rename accepts no flags refuses startup
instead of losing every result. Before it gives any directory it opened by name
the roots' owner, ES refuses one whose owning user is not already the roots'
owning user; it never changes an owning user. A genuinely Submit-disabled service
does not run this configured-Submit startup probe. `BRINGUP_PROFILE=prepare-only`
only changes orchestration; the supported-local generated ES configuration
retains Submit fields, so key loading and root capability qualification still
run before HTTP listening in that profile. The supported-local
`service-root-v1` static preflight checks fresh configured roots at UID:GID
`0:0` and exact `0755` mode without repair; it does not prove the later
container-visible owner, mount topology, or behavioral capability result.
The same read-only validator gates full-profile submit-readiness after the
initial bring-up and ES launcher checks. It requires the selected proof
binding, generated config, service image and Dockerfile, and exact same-path
read-write mounts before readiness can omit the ordinary operator's root-write
test. Generic readiness still requires caller-writable existing roots; an
unknown profile refuses. Static inspection by the operator is sufficient for
the selected service roots, while ES retains its later behavioral checks.
The generic ES launcher runs ES as the caller's numeric effective UID and
primary GID and does not inspect daemon labels; ES's startup checks, not the
launcher, decide whether that identity owns the roots and can read the files
its config names. Those checks include the nested staging directory probe
above, so roots that inherit another group from a setgid parent directory
refuse startup instead of failing at the first submission. On a user-namespace-remapped Docker daemon,
Docker refuses the host networking that bring-up requires before any service
starts.
The fixed setup safe projection records only that static owner/mode check and
explicitly leaves container capability unproved; retained proof evidence does
not promote it into a behavioral result.
Result reads check held identity at their boundary and do not probe capability, repair
ownership or provision roots. The selected native Linux syscall/custody and
test-owned installed-source witness evidence is accepted for its named source
and testing environments; actual running-deployment topology remains an
environment-bound operational/rollout acceptance gate. The development-source
disposition in `PLANS.md` and `.docs/execution_lifecycle/contracts.md` grants
no startup or workload authority.
The Review-20 governed-mount test fixture is a bounded native single-host
qualification witness, not a startup probe or production submit check. Its
offline modeled comparison tests can reject equal-content replacement objects,
but cannot prove an installed mount. A later live fixture must acquire held
staged directory and file anchors before provider registration, keep the actual
container alive through observation, correlate one run/job/task/allocation/
container, and observe directory and file identities inside that container.
On failure, test-owned teardown attempts bounded barrier release or container
stop and cancellation of the exact captured Nomad job; it closes both anchors.
It must establish that host and container coordinates share the same Linux
backing-filesystem domain before comparing them; path strings, content hashes,
or namespace-local mount IDs alone do not establish object identity. A missing
domain, missing observation, or skip leaves topology unqualified. The fixture's
test evidence does not replace a separate running-deployment observation or
grant ES runtime, policy, lifecycle, or acceptance authority.
The Review-21 bounded fixture correction requires a fixed workload readiness
acknowledgement after supervisor result-directory preparation. Running
allocation/container state alone does not prove readiness. An inspected Docker
candidate is admitted only after exact ID, running, allocation and task labels
match, before any container effect. Bounded selected-field Nomad reads and
fixed safe errors replace raw job-response and terminal-log diagnostics on this
witness path. Cleanup distinguishes an attempted control request from observed
termination; inherited stack-startup diagnostics remain a separate limitation.
The Review-22 test-owned task-label prerequisite correction makes the installed
identity sibling opt into a fresh Nomad Docker plugin profile that requests
`extra_labels = ["task_name"]` while keeping volumes enabled and image cleanup
disabled. Ordinary harness and capability-probe agents retain their previous
configuration. The Docker driver must derive the task label from its task
identity; neither ES registration nor the submitted job supplies it. The
historical supplied Review-21 native report records an N4 candidate-admission refusal
before readiness and installed-object observation, no v2 identity record, and
N5 and arm64 not run. Its N1-N3 amd64 passes are separate report claims pending
safe-package inspection. Offline configuration and modeled admission tests do
not prove native label emission or installed identity; a future native witness
and the separate running-deployment observation remain required.
The 2026-11-13 current evidence overlay accepts the selected linux/amd64 and
linux/arm64 N1-N5 native programme under its original source and command
identities, including the bounded Review-22 corrected N4 witness and N5
retained-result observations. The earlier refusal, unstarted selections and
pending package inspection above describe the historical Review-21 report,
not the current selected programme. The old resource refusal's first offending
entry remains unknown. A test-owned witness does not observe the running
deployment, qualify actual key exposure or select a retention policy; source
and evidence limits remain as recorded in `PLANS.md`.
The selected R1 record protocol uses exclusive temporary creation, no-replace
publication, no-follow reopening and file sync. Configured Submit startup must
prove any newly required local filesystem behavior on the configured roots by
behavior rather than OS label; no fallback to unauthenticated reads or a
weaker publication path is permitted. A complete record can become visible
before power-loss durability of its parent directory is established, so this
candidate makes a process-restart claim on the same backing objects only.
Selected native Linux and test-owned mounted-topology evidence is accepted
under its bounded source identities. Actual running-deployment topology and
key isolation remain separate environment-bound operational/rollout gates;
reads perform validation without capability probes or metadata repair.
The isolated candidate retains its small exclusively created startup probe
fixtures under the configured roots. A parent descriptor and randomized child
name cannot establish exact child ownership at a later unlink effect, so the
probe does not delete those names. This is a bounded capacity cost, not a
reclamation policy or a runtime read probe.

## Example: Runtime Identity

For the bounded slice-1 runtime-identity delivery slice:

- static validation must prove:
  - caller mounts do not overlap the reserved runtime-identity workspace and paths
  - the configured runtime-support binary path is absolute and readable
  - the configured SPIRE Workload API socket path is absolute in config
- startup-only runtime capability probes may prove:
  - the platform-owned helper can bind and serve the public endpoint inside the reserved runtime workspace
  - separately selected startup/readiness validation can prove the configured host SPIRE Workload API path refers to a local Unix socket before submit-ready is claimed; the retired Remote Alpha service-user route supplies no such proof
  - the actual runtime mount form in use can carry the helper-private SPIRE source directory into the container so the helper can reach the mounted unix socket
  - the helper-private SPIRE socket remains reachable to the helper and not workload-readable after the runtime boundary is established
  - the workload launch model can drop to the fixed non-root UID/GID with no supplemental groups and no privilege-escalation path
- long-lived ES startup does not need direct read/traverse authority on the raw host SPIRE socket; it only needs the configured path string so submit can build the helper-private mount model
- these checks must still fail closed instead of degrading to workload-owned SPIRE access

This keeps the slice behavior-based, deterministic, and consistent across environments without introducing OS-based branching.

## Execution-root custody and topology proof

Execution-root validation remains capability-sensitive and behavior-based.
Build-selected Linux and Darwin implementations qualify staging and results as
one operation-local descriptor set; there is no runtime platform-label branch
and no fallback when required evidence is missing or inconsistent. Linux
requires complete `fstat`/`statx(AT_EMPTY_PATH)` identity including
`STATX_MNT_ID`, a no-follow rewalk of the descriptor's canonical
`/proc/self/fd` presentation, and a stable mount-ID-selected record from a
bounded 8-MiB/65,536-record mountinfo acquisition. Darwin requires `F_GETPATH`,
no-follow identity rewalk, `fstatfs`, and a bounded `getfsstat` acquisition;
same-FSID distinct presentations reject as unprovable.

Linux parses complete records before asking whether a root value can act as a
pathname coordinate. Mountpoints and ordinary root paths remain absolute and
component-clean. A valid `nsfs` record may instead carry one opaque kernel
namespace-object root of the form `<kind>:[<canonical decimal inode>]`, with
`kind` exactly one of `mnt`, `net`, `uts`, `ipc`, `pid`, `user`, `cgroup`, or
`time`. The decimal text is envelope validation, not numeric authority, and
shares the existing record budget rather than receiving an arbitrary integer
width. The child-view operation names are unsupported as roots because the
kernel renders their canonical `pid` or `time` namespace operation. Unknown or
malformed non-path roots reject. Every accepted opaque record remains in
snapshot count, ID/parent/cycle, stacking, and descendant-mount validation.
Only canonical pathname roots are proof-eligible: selection of an opaque record
fails before device shortcuts, path joining/cleaning, or any governed effect.
The validator never substitutes the mountpoint or configured spelling, and
recognizing the record does not qualify `nsfs` as an execution-root filesystem.

The Linux parser permits an absent parent outside the process-visible mount
tree and exactly one unambiguous self-parent terminal at canonical mountpoint
`/`. It rejects duplicate IDs, nontrivial cycles, multiple top terminals,
non-top self-parent records, malformed or incomplete records, ambiguous
selection, partial identity masks, device disagreement, and unstable reads.
Canonical descendant mounts reject on both platforms. These checks are static
custody/topology revalidation, not content enumeration.

Startup first proves both intended roots without mutation, creates one missing
component through the held descriptor, and reacquires canonical identity and
topology before the next component or effect. Once both roots exist and are
proven separate, startup behavior-probes the staging filesystem's exclusive
claim/no-follow operations and the results filesystem's temporary/no-replace
operations separately. Ordinary effect-boundary revalidation is not a repeated
behavior probe. Failure to prove either capability fails fast and adds no
fallback behavior.

Local modeled records and ordinary filesystem tests do not prove mounted bind
or casefold compatibility. C's selected native observations remain historical
exact-source evidence, not integrated-source execution. Running-deployment
observation, actual mounted cases, and native Linux lanes remain operational
qualification gates for claimed environments, deferred but not waived for
those claims. A new integrated-source bounded witness requires a concrete
changed-interaction selection, not merge ancestry alone.

## Example: Execution-root custody

Tranche A adds one startup-only pair behavior probe when Submit is configured.
It uses the already qualified staging and results descriptors to prove that ES
can:

- create an exclusive run-scoped directory on staging and hold its identity by
  descriptor;
- refuse symlink traversal on staging for the complete opened path;
- stage, inside a nested staging directory, one entry of each mode staging
  uses, with staging's identity checks;
- create, inside a natural result directory, retention's file modes with
  retention's identity checks;
- prove the results no-replace rename both ways: refuse the results no-replace
  publication primitive when the destination already exists, and require it to
  succeed onto a free name while keeping the same file; and
- retain the exclusive startup probe fixtures when exact effect-time deletion
  identity cannot be proved; no pathname cleanup or recursion is selected.

The probe is selected by the Submit capability requirement, not by an OS label.
The platform implementation is compiled separately: Darwin uses
no-follow-any/exclusive-rename primitives, while Linux uses
beneath/no-magic-link/no-symlink/no-cross-device open resolution and
no-replace rename. There is no runtime `GOOS` branch, syscall fallback, or
request-time probe. Failure prevents submit-enabled service startup.

The capability-probe exception does not confer run-root reclamation authority.
Production run roots are retained after exclusive creation on every return;
the exclusive startup fixtures remain under the configured roots until a separately governed reclamation rule exists.

Darwin syscall tests are current local runtime evidence. Linux cross-compilation
is compile evidence only. Actual Linux syscall and mount-crossing tests remain
necessary on governed Ubuntu 24.04 linux/amd64 for an operational Remote Alpha
claim and linux/arm64 for an operational supported-local claim. They are not an
automatic local source-preservation or integration pre-commit gate. The selected
C native programme retains only its original exact-source identity; no
integrated native qualification or narrower architecture claim is inferred.
Tranche B was not blocked on this native evidence.

## Test Harness Use

`es/app` integration tests that exercise submitted Nomad/Docker allocations through the current runtime-identity helper path use the same behavior-based capability shape as a test-harness gate.

The gate proves the local test substrate can run Docker/Nomad allocations and can carry the SPIRE Workload API socket source directory into the workload container so the helper can reach the mounted Unix socket. Unsupported hosts skip those allocation-dependent tests with an explicit runtime-identity capability reason instead of letting expected substrate limitations appear as noisy workload failures.

The native installed-source identity witness also requires a direct Unix socket
at `/var/run/docker.sock`, rather than a symlink substitute, and a readable,
nonempty host boot ID at `/proc/sys/kernel/random/boot_id`. Its test checks
these static resources and the existing behavioral runtime-identity capability
before validating the source envelope. A missing capability produces an
explicit skip and leaves installed-source identity, native witness success,
source binding, runtime readiness, and product authority unqualified. On a
capable host, the unchanged envelope validator still requires authentic
`ES_MOUNT_WITNESS_SOURCE_MANIFEST_SHA256`,
`ES_MOUNT_WITNESS_TRACKED_DIFF_SHA256`,
`ES_MOUNT_WITNESS_RECIPE_ENVELOPE_SHA256`, and
`ES_MOUNT_WITNESS_COMMAND_ID` values, followed by the full live witness.
Missing envelope values alone do not justify a skip. Capability selection uses
behavior and static resources, not OS labels or fallback identity.

This is test hygiene only. It does not change ES public contracts, readiness semantics, startup validation, runtime identity ownership, or runtime failure semantics. Tests that cover prepare-only behavior, caller authorization, static submit/job-spec shape, or submit-time validation without requiring helper socket reachability do not use this gate.

Every test binary of the module runs its tests under a temporary directory
whose path holds no symbolic link. ES refuses a symbolic link in any component
of its configured staging and results roots, key files, runtime support binary
and reliable-submit store roots, and the Remote Alpha TLS status collector and
the supported-local execution-root helper refuse one in the paths they check.
The default temporary directory of macOS lies below `/var/folders/`, behind the
symbolic link `/var` -> `private/var`, and `/tmp` is the symbolic link `/tmp`
-> `private/tmp`. A test that hands ES a path below that directory tests the
refusal instead of what it is named for: a test that expects success fails,
and a test that expects a refusal can pass for the wrong reason.

Each package that has tests therefore declares a `TestMain` whose only
statement is `os.Exit(testtmpdir.Main(m))`, from `internal/testtmpdir`, in a
file without a build constraint. Before any test runs, `testtmpdir.Main`
resolves the temporary directory and, when its path goes through a symbolic
link, sets `TMPDIR` to the physical path of the same directory, so that
`t.TempDir()` and every process the tests start use that path. It changes
nothing where the temporary directory is already physical, as on the Linux CI
runner, an unset `TMPDIR` included. When the directory cannot be resolved, the
test binary runs no test and exits with status 2. A guard test applies the
rule to every package of the module that has test files. The package's own
tests run a test binary under a temporary directory behind a symbolic link and
check what its tests and the processes they start see.

Tests that exercise a refusal of a symbolic link create the link themselves.
This is test hygiene only. It does not weaken any refusal of a symbolic link
and changes no ES contract, startup validation, or capability probe.

`es/admission` unit tests that intentionally exercise chmod-backed filesystem denial use test-local behavior probes before asserting permission-sensitive fail-closed behavior.

The probe must create or mark a temporary fixture with the restrictive mode needed by the test, attempt the same class of operation the assertion depends on, and continue only when the current process receives a permission-denied error. If the current process can bypass the fixture permissions, the test skips with a specific `skipping permission-denied fixture: ...` reason.

This is also test hygiene only. It does not change ES public contracts,
retained-staging semantics, retained-result semantics, readiness boundaries, or
production capability probing placement.

Root-package tests of the Remote Alpha TLS status collector use two kinds of
fixture, and never a mixture. A live fixture uses the collector's real
process-table reads and pidfd operations on real processes. It first attempts
to read its own entry of the process table and skips with an explicit reason
when that read is refused. It never decides by an operating-system label, and
it sets the capability flag only after the collector's real process-capability
probe has passed. A local fixture runs on every host. It replaces the probe
and the whole boundary through which the cleanup reaches the target's process
table: `scan_group_members`, `signal_same_group_members`, and
`read_proc_identity`, each either by a stand-in for the function or by
stand-ins for the operating-system primitives that the function uses.

A fixture must not replace only part of that boundary. The part left real
would read the host on its own: beside identities that the stand-ins
invented on a host that has `/proc`, and without an end on a host that has
neither `/proc` nor `pidfd_open`, where a listed process can never be
confirmed absent and the group-absence hold never returns. The standard local
boundary is therefore one shared test constant. It imports what it uses
itself, so a fixture needs nothing but the loaded collector for it. It also
ends a fixture that reaches a target-only reader, and a fixture that is still
running after a fixed bound, with a nonzero status and a stack trace, so that
a stuck cleanup hold fails one test and does not stop the test binary. A
guard test applies the rule to every fixture script of the package, and one
test runs the shared boundary with `/proc` and the pidfd operations denied.

A stand-in for the probe alone is the same partial replacement. The
collector's entry points run the probe and then declare the capability
themselves, so a fixture that replaces the probe and runs an entry point is a
local fixture: it replaces the whole boundary, or it replaces a function on
every path from that entry point to the fixed command, so that no fixed child
is started. The guard test knows those paths, and one more test holds those
paths against the collector's source, so that a change of the collector's
call graph fails there first.

Each fixed command of the collector also runs in a PID namespace of its own,
which only root can create on Linux. A local fixture and a live fixture
therefore replace the namespace by one shared stand-in that does nothing,
together with the namespace part of the capability probe. A fixture replaces
both or neither, and the same guard test refuses a fixture that replaces only
one of the two. A fixture that uses the stand-in proves nothing about the
containment. The containment has tests of its own. One group puts a
deterministic backend in the place of the kernel operations and runs on every
host. The other group uses the real kernel: each of its tests attempts to
create a PID namespace in a child of its own and skips itself, with an
explicit reason, only when the kernel refuses. The CI job runs that group
once more as root and fails unless each of its tests passes, so a skip never
stands in for the proof there. That step is the only use of root in the CI
job, and only the test binary runs as root.

This is test hygiene only. It changes no collector behavior, capability
criterion, hold, signal, reap, lock, or publication rule.

The noninteractive remote TLS status collector proves its descendant
containment the same way: a descendant capability probe at its one validation
boundary, before any status input is read, sets the capability flag that every
fixed command requires. Root-package tests that call its command runner
directly replace the flag and the descendant drain together, by one shared
stand-in that proves only that the test process has no child left, and a
guard test refuses a script that replaces one of the two without the other.
The drain itself has tests of its own: one group with a deterministic backend
in place of the kernel operations, which runs on every host, and one group with
real processes, which runs as an unprivileged user and skips itself, with an
explicit reason, only when the attempt to make the test process a child
subreaper and to list its children is refused.
