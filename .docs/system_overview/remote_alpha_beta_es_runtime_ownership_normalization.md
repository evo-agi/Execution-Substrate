# Remote Alpha To Beta ES Runtime Ownership Normalization Contract

## 1. Current state

The current accepted Alpha posture is:

- `Temporary compatibility edge`: live `es.service` still runs as
  `root(default)`.
- `Temporary compatibility edge`: the runtime companion starts as root inside
  the Nomad Docker task.
- `Current invariant`: the workload runs as fixed non-root `10000:10000` with
  no supplemental groups and no privilege-escalation path.
- `Observed current implementation path`: the supervisor currently makes
  `/execution/run/result` workload-writable, then performs a post-workload
  normalization pass back to its current target owner and emits the
  ownership-normalization marker when that phase succeeds.
- `Observed current implementation path`: the supervisor currently creates
  `/execution/run/work`, sanitizes the extracted tree, recursively `lchown`s
  it to workload `10000:10000`, and then performs the same post-workload
  normalization pass back to its current target owner.
- `Observed current implementation path`: the supervisor currently `chown`s
  the host-backed `run/platform` subtree to `root:root`.
- `Observed current implementation path`: after successful current
  post-workload normalization, the runtime companion now emits the
  ownership-normalization marker described in this document under the stable
  `run/platform` subtree.
- `Current blocker`: the remaining blocker is no longer absence of a
  normalization contract or repo-local validation. The current branch now has
  the design contract, repo-local tests, and a non-mutating readiness checker,
  but the accepted Alpha posture still runs the long-lived ES service as
  `root(default)`, the runtime companion still normalizes to its current
  target owner, real live-host `es:es` ownership has not been measured, and no
  service-user flip is approved.

This means the current implementation now has a documented design contract for
the future non-root ES ownership bridge, but the accepted Alpha posture still
does not prove that bridge on a live host with a non-root long-lived ES
service.

### 1.1 Current branch readiness status

- `Design-only`: this document now defines the authoritative Option B
  ownership-normalization contract.
- `Repo-local test-backed`: runtime-helper marker emission, marker validation,
  retained-result preflight, cleanup-readiness preflight, and normalized-run
  lifecycle tests now cover success, failed, lost, canceled, invalid-marker,
  and current Alpha-compatible missing-marker behavior.
- `Checker-backed`: the host-local readiness checker now exposes explicit
  `alpha-compat` and `future-non-root-required` modes.
- `Live-host unmeasured`: no current branch evidence proves that a real Remote
  Alpha host already satisfies expected-owner proof for `run/platform`,
  `run/work`, and `run/result` as `es:es`.
- `Blocked`: changing the long-lived ES service user remains unimplemented and
  unapproved. The consolidated readiness ledger lives in
  `.docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md`.

## 2. Target Option B state

Under the recommended Option B direction:

- the long-lived ES service may eventually run as `es:es`
- the root-start runtime companion may remain a bounded compatibility edge
- stable ES writable state remains `es:es`
- host-backed paths that the runtime companion or workload transiently owns
  while the task is active must be normalized back to ES-owned readable and
  deletable state before non-root ES attempts:
  - retained-result packaging
  - successful stage cleanup

The relevant ownership roles are:

- **Long-lived ES service**
  Owns stable staging and results state, stages payloads and mount artifacts,
  packages retained-result bundles, and performs successful-stage cleanup.
- **Root-start runtime companion**
  Owns the temporary runtime-only ownership transitions needed for the current
  helper and workload model, then restores host-backed paths to the target ES
  owner after workload exit.
- **Workload process**
  May write only within the bounded runtime-owned subtrees while it runs.
- **Nomad task/runtime layer**
  Continues to launch the bounded root-start task for Option B, but does not
  become the owner of ES post-run cleanup or retained-result semantics.

## 3. Ownership-normalization contract

The contract below is the design bridge from the current runtime companion to
the future non-root long-lived ES service.

| Path | Before task start | While workload runs | After workload exits | Who performs transition | Root required | Expected failure behavior |
| --- | --- | --- | --- | --- | --- | --- |
| `run/platform` | Host-backed subtree under `<staging_root>/<run_id>/run/platform` is already ES-owned. Required owner or mode: target ES numeric UID:GID, directory `0750`, non-secret files `0640`, runtime support binary `0750`. | It stays ES-owned while the workload runs. The root-start runtime companion may read or execute from it, but it must not reclassify it as a stable root-owned subtree. | It remains ES-owned. No post-run ownership flip is allowed here. | ES stages the subtree before submit. The runtime companion only validates that the stable ES-owned contract still holds. | Transition itself: no. Validation may run as root inside the companion because the current companion already starts as root. | If the companion observes that `run/platform` is not already owned by the target ES UID:GID before workload start, it must fail closed before workload exec. On terminal success, cleanup must not proceed if ES later sees that `run/platform` is not ES-deletable. |
| `run/work` | Absent or an ES-owned placeholder under `<staging_root>/<run_id>/run/work`. If present before task start, it must already be ES-owned and deletable. | Runtime-owned transient subtree. The supervisor creates it, sanitizes the extracted workload tree, and the active tree becomes workload-owned `10000:10000` with sanitized workload modes. | Normalized back to ES-owned state: target ES UID:GID, directories `0750`, regular files `0640`, executable files `0750` only where needed for bounded debugging or later inspection. | Root-start supervisor. It creates the active transient subtree before workload exec and restores ES ownership after workload exit. | Yes under the current Option B helper model, because the current supervisor already starts as root and performs ownership transitions across host-backed bind mounts. | If normalization fails or is partial, ES must not treat `run/work` as cleanup-ready. Successful cleanup is blocked and the full stage root remains retained. Failed or canceled runs remain retained for debugging, with the normalization failure recorded as operator evidence. |
| `run/result` | ES-owned placeholder under `<staging_root>/<run_id>/run/result`, target ES UID:GID, directory `0750`. | Runtime-owned transient result subtree. The supervisor recreates it for the workload. Required active owner: workload `10000:10000`. Required active directory mode: owner-writable and not world-writable. | Normalized back to ES-owned retained-result source tree: target ES UID:GID, directories `0750`, regular files `0640`, executable files `0750` only if an allowed result artifact truly requires execute bits. Unsupported file types remain forbidden. | Root-start supervisor. It creates the active transient result subtree before workload exec and restores ES ownership after workload exit. | Yes under the current Option B helper model. | If normalization fails, retained-result packaging must fail closed, successful cleanup must be skipped, and the run-scoped stage root must remain retained. `GET /result` may return `result_unavailable` until a readable retained bundle exists, or `result_not_found` only if the result tree is valid but empty. |
| Retained-result source tree | Not a separate path before task start. This is the semantic view of `run/result` once the workload has exited and the subtree has been normalized back to ES ownership. | Not applicable while the workload still runs because the source tree is not yet in the post-exit state ES can trust. | ES-owned, readable, and deletable source tree rooted at `<staging_root>/<run_id>/run/result`. This is the only host-backed tree ES may package into an opaque retained bundle. | Root-start supervisor produces it by normalizing `run/result`. ES validates it before packaging. | Supervisor normalization: yes under current compatibility edge. ES validation: no. | Missing or invalid source-tree readiness blocks retained-result packaging and blocks successful cleanup. The stage root remains retained. |
| Final retained bundle | Absent. | Absent. | ES-owned opaque bundle under `<results_root>/<run_id>/result.tar.gz`, owner target ES UID:GID, mode `0600`, parent directory `0750`. | Long-lived ES service writes the bundle after retained-result preflight succeeds. | No. This is the target non-root ES operation being enabled by the normalization contract. | If bundle creation fails, successful cleanup must be skipped for terminal success. The stage root remains retained and `GET /result` fails closed. If the bundle already exists and is readable, repeat fetches may continue even if later cleanup preflights fail on `run/platform` or `run/work`. |

Transition rule:

- ES may trust only two host-backed post-run states:
  - stable ES-owned state that never changed away from the target ES UID:GID
  - transient runtime-owned state that the root-start supervisor has already
    normalized back to the target ES UID:GID

Any third state is contract failure.

## 4. UID/GID model

The recommended UID:GID model is numeric and host-derived.

### 4.1 How the runtime companion learns the host ES UID:GID

The long-lived ES service is the authority for the target ES numeric UID:GID.

Recommended source:

- after the future service-user flip, ES derives the target owner from its own
  process credentials:
  - `os.Geteuid()`
  - `os.Getegid()`

Recommended carrier:

- ES passes those numeric values into the runtime task as reserved internal
  runtime environment values under the existing `EXEC_` reserved prefix
- recommended names:
  - `EXEC_PLATFORM_STATE_OWNER_UID`
  - `EXEC_PLATFORM_STATE_OWNER_GID`
  - `EXEC_PLATFORM_STATE_OWNER_SCHEMA=v1`

These are internal runtime companion facts, not public ES API contract fields
and not caller-provided env.

They are helper-private facts by default. They must not be surfaced to the
workload, made caller-settable, or widened into a general runtime env contract
unless a later design update explicitly justifies that exposure.

### 4.2 Must numeric UID:GID be passed in job spec, env, or config?

Yes. Numeric UID:GID must be passed explicitly into the runtime task as
submit-time internal runtime facts.

Recommended rule:

- **pass them through the runtime environment**
- do **not** add them as mutable operator config
- do **not** rely on an ambient default inside the container
- do **not** expose them to the workload unless a future design re-derivation
  explicitly justifies that exposure

This fits the current design because:

- ES already injects internal `EXEC_*` runtime facts
- the `EXEC_` prefix is already reserved from caller input
- the runtime companion already consumes runtime env and runtime paths from the
  task environment

### 4.3 Is container-side name lookup allowed?

No. Workload-visible or container-side name lookup of `es` is forbidden for
this contract.

Reasons:

- the container image may not define an `es` account
- even if it does, the numeric mapping may not match the host bind-mounted
  filesystem owner
- the host ES service account, not the container passwd database, is the
  authority for post-run host-backed ownership

### 4.4 Must the ES UID:GID be stable across host and container namespaces?

Yes, for the bind-mounted host-backed staging tree this contract requires that
the numeric target UID:GID mean the same owner on the host-visible bind mount
that ES later reads and deletes.

Equivalent capability statement:

- the runtime companion must be able to `chown` or `lchown` the bind-mounted
  host-backed paths so that later host-side `stat` by the long-lived ES service
  reports the expected numeric target UID:GID

If namespace translation, userns remap, or another runtime layer breaks that
property, the contract is unsupported unless a future capability validation can
prove equivalent host-visible semantics.

### 4.5 What happens if UID:GID mismatch is detected?

Mismatch is fail-closed.

Required behavior:

- if the supervisor sees a pre-start mismatch on stable ES-owned state such as
  `run/platform`, it fails before workload exec
- if the supervisor cannot normalize transient runtime-owned paths to the
  declared target UID:GID after workload exit, it records failure and exits
  without claiming normalization success
- if ES preflight stats later show a mismatch against the declared target
  UID:GID, ES must not package retained results and must not clean successful
  staging

## 5. Completion and evidence marker

ES should trust normalization completion only from a combination of companion
evidence plus ES-owned filesystem validation.

Current Alpha compatibility rule:

- `Bounded slice rule`: the runtime companion must emit this marker after a
  successful post-workload normalization phase, and marker write or
  validation failure makes that phase fail.
- `Temporary compatibility edge`: current ES retained-result and cleanup
  preflights remain compatible with the accepted Alpha posture even when the
  marker is absent.
- `Bounded slice rule`: current repo-local ES preflights validate the marker
  if it is present, but a missing marker alone does not block retained-result
  packaging or successful cleanup readiness yet.
- `Bounded slice rule`: once a marker is present, it must satisfy the contract
  below; malformed, inconsistent, or unsafe present-marker state fails closed.
- `Bounded slice rule`: a structurally valid present marker is accepted as
  marker evidence in current Alpha compatibility mode, but target-owner proof
  remains unverified unless ES or a readiness check also supplies the expected
  long-lived ES UID:GID and that expected owner matches `target_uid` and
  `target_gid`.

Two validation modes are required:

- `Alpha compatibility mode`
  - missing marker remains compatible
  - structurally valid present marker is accepted as marker evidence
  - invalid present marker fails closed
  - target-owner proof may remain unverified when expected ES UID:GID is not
    supplied
- `Future non-root-required mode`
  - missing marker is a blocker
  - invalid present marker is a blocker
  - `target_uid` and `target_gid` must match the expected long-lived ES
    service owner
  - ES `stat` or `lstat` preflight must also prove the same expected owner and
    required readability or deletability on the host-backed paths it will use

### 5.1 Recommended contract

1. The runtime companion attempts ownership normalization after workload exit.
2. If normalization succeeds, the runtime companion writes one internal marker
   under the stable platform subtree, for example:
   - `<staging_root>/<run_id>/run/platform/ownership-normalization.json`
   - that marker must remain helper-private evidence under the stable platform
     subtree; it must not be writable or forgeable by the workload
3. ES performs a retained-result or cleanup preflight before using that result.
4. ES trusts normalization only if:
   - in current Alpha compatibility mode, a missing marker may still pass as a
     temporary compatibility edge
   - in future non-root-required mode, the marker exists
   - the marker schema and status are valid whenever the marker is present
   - `target_uid` and `target_gid` are treated only as marker evidence until
     the expected long-lived ES UID:GID is supplied and matched
   - ES `stat` or `lstat` checks confirm the required owner or mode state on
     the relevant host-backed paths

Marker plus filesystem validation is a conjunction, not an alternative. The
marker never replaces ES-owned stat-based preflight.

Current Alpha compatibility bridge:

- the helper now emits the marker after successful current normalization, but
  ES may still use the existing filesystem-only preflights when the marker is
  absent
- a later non-root-required slice may tighten this bridge and make the marker
  mandatory for the non-root ES path

### 5.2 Recommended marker contents

The marker is not a public ES lifecycle field. It is internal bridge evidence.

Recommended minimum fields:

- `schema_version`
- `status`
- `run_id`
- `target_uid`
- `target_gid`
- `paths_normalized`
- `completed_at`

Recommended exact values and formats:

- `schema_version = "execution-substrate.es.runtime-ownership-normalization.v1"`
- `status = "normalized"`
- `target_uid` and `target_gid` record the helper's post-normalization target
  owner, but they are not future non-root-ready proof unless a validator also
  supplies the expected long-lived ES UID:GID and the values match
- `completed_at` is a non-empty RFC 3339 timestamp string

Recommended marker location rule:

- the marker stays inside the stable ES-owned `run/platform` subtree
- the marker path and its parents must not be workload-writable
- the marker must not become a workload-authored success signal

Recommended values:

- `paths_normalized` must at minimum cover:
  - `run/platform`
  - `run/work`
  - `run/result`

### 5.3 Why task event metadata is not enough

Nomad task events or logs may help operators, but they are not authoritative
for host-backed owner or mode state. ES already has direct access to the same
host-backed staging tree it needs to package or delete, so filesystem
validation must remain authoritative.

The repo-owned non-mutating readiness checker for the current host-side slice is
`scripts/remote_alpha_check_es_writable_state_readiness.sh`. It can report
observed marker and ownership state, but it does not replace ES retained-result
or cleanup preflight. When it is assessing future non-root ES readiness with a
known `es` UID:GID, it must treat missing markers or `target_uid` or
`target_gid` mismatch as blockers. When no expected ES UID:GID is available,
it may report a structurally valid present marker only as unverified marker
evidence, not as future non-root-ready proof.

The checker now exposes two explicit non-mutating modes:

- default `--mode alpha-compat`
  - reports current Alpha-compatible marker behavior
  - keeps missing-marker completed-run evidence as warning or not-observed
  - still fails closed on invalid present markers
  - does not by itself approve future non-root ES readiness
- explicit `--mode future-non-root-required`
  - acts as a readiness gate only
  - requires discovered `es` UID:GID, marker presence, target-owner match, and
    stat-backed ES ownership or readability or deletability proofs
  - does not change `es.service` identity, run governed proof, or approve ES
    de-rooting by itself

### 5.4 Retained-result packaging preflight

Before packaging a retained bundle, ES should validate:

- if the normalization marker exists, it is valid
- `run/result` is owned by the target ES UID:GID
- `run/result` is traversable and readable by the long-lived ES service
- the result tree still satisfies existing retained-result restrictions on
  allowed file types and path safety

Current Alpha-compatible preflight rule:

- a missing marker alone does not block retained-result packaging yet
- a structurally valid present marker may remain accepted even when
  `target_uid` and `target_gid` were not checked against an expected ES owner
- a present invalid marker blocks packaging before bundle creation

Future non-root-required preflight rule:

- marker absence becomes a blocker
- `target_uid` and `target_gid` must match the expected long-lived ES
  service UID:GID
- `run/result` and the entries ES will package must be owned by that same
  expected UID:GID and remain traversable or readable to ES
- a present invalid marker blocks packaging before bundle creation

### 5.5 Successful-cleanup preflight

Before deleting a successful run-scoped stage root, ES should validate:

- if the normalization marker exists, it is valid
- `run/platform`, `run/work`, and `run/result` are all owned by the target ES
  UID:GID and are deletable by ES
- retained-result handling has already been attempted

Current Alpha-compatible preflight rule:

- a missing marker alone does not block successful-cleanup readiness yet
- a structurally valid present marker may remain accepted even when
  `target_uid` and `target_gid` were not checked against an expected ES owner
- a present invalid marker blocks cleanup and retains the full stage root

Future non-root-required preflight rule:

- marker absence becomes a blocker
- `target_uid` and `target_gid` must match the expected long-lived ES
  service UID:GID
- `run/platform`, `run/work`, `run/result`, and the entries ES must traverse
  or delete must be owned by that same expected UID:GID and remain deletable
  by ES
- a present invalid marker blocks cleanup and retains the full stage root

### 5.6 Fail-closed behavior

If any validation step fails:

- ES must not claim normalization completed
- ES must not package a retained-result bundle from that tree
- ES must not remove the successful run-scoped stage root
- the stage root remains retained for debugging

## 6. Failure semantics

The contract is fail-closed. Public lifecycle semantics do not become richer,
but ES must refuse to treat ownership normalization as successful unless it can
prove it.

### 6.1 Workload writes unreadable files

- the supervisor attempts normalization after workload exit
- if the files can be normalized into the allowed retained-result model, ES may
  continue
- if they remain unreadable or violate the retained-result file-type rules,
  retained-result packaging fails closed and successful cleanup is skipped

### 6.2 Helper or supervisor fails to normalize

- no success marker is written
- ES retained-result preflight fails
- ES cleanup preflight fails
- the run-scoped stage root remains retained

### 6.3 Helper dies before normalization

- treat as incomplete normalization
- do not infer success from task exit alone
- if a retained bundle already exists from an earlier successful attempt,
  repeat result fetch may still work
- otherwise `GET /result` fails closed and stage cleanup is blocked

### 6.4 Partial normalization

- partial normalization is still failure
- the marker must not report success
- ES preflight stat checks must reject mixed owner or mode state on required
  paths

### 6.5 Task lost or ambiguous

- ES keeps the current bounded behavior of retaining staging for debugging
- normalization cannot be assumed
- no successful cleanup claim is allowed
- retained-result packaging is allowed only if ES can still prove the source
  tree is in the required ES-owned readable state

### 6.6 Canceled run

- a canceled run remains retained for debugging by default
- if the runtime companion still gets a clean post-exit path, it may normalize
  `run/work` and `run/result` for retained debugging
- ES does not auto-clean canceled staging even if normalization succeeds

### 6.7 Failed run retained for debugging

- failed runs remain retained
- normalization is still desirable because it allows non-root ES diagnostics
  and later operator inspection without reintroducing long-lived ES root
- failure to normalize does not change terminal status semantics, but it must
  remain visible as operator evidence

### 6.8 Successful run cleanup blocked because ownership is wrong

- terminal success in Nomad remains terminal success
- if ownership preflight fails, ES skips cleanup and logs the reason
- if retained-result packaging already succeeded, `GET /result` may still serve
  the retained bundle from `execution.results_root_dir`
- the run-scoped stage root stays retained until operator action or a later
  repair path exists

## 7. Test plan before implementation

Required tests before any implementation slice is approved:

The current branch now satisfies several repo-local items in this plan, but
that evidence remains branch-local readiness only. It does not prove live-host
expected-owner state and it does not approve a service-user flip.

- successful retained-result packaging as non-root ES
- successful retained-result fetch as non-root ES
- successful staging cleanup as non-root ES
- failed, lost, and canceled run staging retention
- unreadable result tree fail-closed
- helper normalization failure fail-closed
- UID:GID mismatch fail-closed
- no supplemental groups for the long-lived ES service
- no raw SPIRE socket leak
- workload remains fixed non-root `10000:10000`
- root-start helper remains a bounded compatibility edge rather than becoming
  the owner of ES post-run cleanup semantics

Helpful additional coverage:

- stable ES-owned `run/platform` validation before workload exec
- normalization marker creation and schema validation
- cleanup preflight that rejects any non-ES-owned descendant in
  `run/platform`, `run/work`, or `run/result`
- retained-result preflight that rejects normalized ownership mismatch even if
  the task exited successfully

## 8. Migration and rollback implications

### 8.1 Migration implications

Before a service-user flip:

- migrate stable `execution.staging_root_dir` and `execution.results_root_dir`
  to `es:es` as defined in the writable-state ownership model
- ensure the runtime companion can normalize `run/work` and `run/result` back
  to the target ES numeric UID:GID
- ensure the runtime companion preserves stable ES-owned `run/platform`
  ownership instead of converting it to persistent root-only state
- prove the normalization marker plus ES preflight checks work under the future
  non-root ES service account

### 8.2 Rollback implications

Rollback to the accepted Alpha posture stays straightforward:

- revert the long-lived ES service to `root(default)`
- keep retained stage roots and retained bundles in place
- a root-run ES service can still read or delete `es:es` state, so rollback
  does not require immediate reownership before service recovery

### 8.3 Evidence required before a service-user flip

Before any future service-user flip, the repo should require:

- updated authoritative docs for this normalization contract and the writable
  state model
- proof that the runtime companion can consume the numeric target ES UID:GID
  and normalize the host-backed paths correctly
- proof that non-root ES retained-result packaging works
- proof that non-root ES successful cleanup works
- proof that failure cases remain fail-closed
- proof that the current workload boundary and raw SPIRE protections remain
  intact

## 9. Explicit non-goals

Non-goals of this document are:

- ES de-root implementation
- changing `es.service` `User=` or `Group=` today
- redesigning the Nomad task user model
- redesigning SPIRE selectors
- redesigning helper-private raw SPIRE traversal
- redesigning Vault runtime handoff
- mutating the live host
- running governed proof

## 10. Implementation readiness checklist

Several checklist items are now satisfied on the current branch at the
`design-only`, `repo-local test-backed`, or `checker-backed` level; see the
readiness ledger in
`.docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md`.
Live-host expected-owner proof and the long-lived service-user migration remain
open.

Before a future implementation slice may be approved, all of the following
must be true:

- the writable-state ownership model is accepted and remains aligned with this
  normalization contract
- the target long-lived ES service account and group model is accepted
- the runtime companion has one explicit contract for:
  - stable ES-owned paths
  - transient runtime-owned paths
  - post-exit normalization
- target ES numeric UID:GID is derived from the long-lived ES process and
  passed explicitly into the runtime task as reserved internal runtime facts
- container-side name lookup of `es` is not used
- namespace semantics prove that the target numeric UID:GID means the same
  owner on the host-visible bind mounts that ES later reads and deletes
- the normalization marker format and ES preflight checks are documented
- the non-mutating host readiness checker,
  `scripts/remote_alpha_check_es_writable_state_readiness.sh`, stays aligned
  with the documented ownership and marker contract
- retained-result packaging and successful cleanup both fail closed when the
  normalization contract is not proven
- tests cover success and failure cases for:
  - retained-result packaging
  - retained-result fetch
  - successful cleanup
  - failed, lost, and canceled retention
  - UID:GID mismatch
  - unreadable result trees
  - helper normalization failure
  - no supplemental groups
  - no raw SPIRE leak
  - fixed workload non-root boundary

This checklist is readiness for a future bounded implementation slice only. It
is not approval to start that implementation by itself.
