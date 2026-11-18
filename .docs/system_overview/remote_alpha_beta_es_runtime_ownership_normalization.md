# Remote Alpha ES Runtime Ownership Normalization — Historical Record

## Current status

`Temporary compatibility edge`: this document records the ownership-
normalization context used by an earlier Remote Alpha v1 existing-host
exercise. It is historical evidence only. It is not current readiness,
migration authority, deployment authority, or a reusable host contract.

The Remote Alpha ES writable-state readiness, readiness staging, ES
service-user migration, ownership preparation, generated rollback rehearsal,
and old-root planning implementations are retired. Their public wrappers now
delegate to fixed fail-closed tombstones. Those routes perform no discovery,
inspection, staging, mutation, or evidence production.

## Current ES runtime rule

Ownership-normalization evidence under an execution package may still be read
by retained-result packaging under its existing bounded validation rules. It
does not authorize staging deletion. Every exclusively created run root is
retained after claim, whether Submit fails, registration is ambiguous or
accepted, lifecycle evidence is successful or failed, or result publication is
successful, absent, conflicting, or failed.

Automatic whole-run-root reclamation is not implemented. Governed staging
reclamation is an ES-owned `Reopened redesign seam`. It must address disk and
capacity pressure, sensitive-material residence, and operator burden without
deriving deletion authority from lifecycle or result facts.

## Historical v1 treatment

Archived v1 ownership/readiness/migration artifacts remain historical evidence
only. No live operator route parses or projects their retired schemas. They
cannot project an archived pass, classification, apply-readiness decision,
mutation plan, or rollback result as a current fact. No v2 schema, validator,
fixture, or artifact exists for that retired ES writable-state/service-user
migration family. The unrelated current EGS hardening v2 schema remains
current.

## Infrastructure consequence

Fresh-host provisioning is the required direction for future infrastructure
recovery, but this repository does not currently implement a complete supported
fresh-host ES provisioner. Reuse of an old or nonempty host remains blocked
unless a separately governed existing-host migration contract is selected.
There is no scheduler-drain or submitter-fence contract in this tranche.

Remote Alpha remains bounded proof/support history, not product architecture.

## Historical design record — superseded and non-authoritative

This section is **superseded** and **non-authoritative**. It is **not an
available operator route** and is **not migration, cleanup, or reclamation
authority**. It preserves the useful rationale behind the former ownership-
normalization contract. Historical marker, checker, staged-helper, check-only,
apply, rollback, successful-cleanup, and old-root mechanics are retired unless
the current-status section above independently identifies a narrow internal
read-only behavior.

### Historical ownership roles

The prior design separated four roles:

- **Long-lived ES service.** Owned stable staging/results roots, materialized
  the package, and published retained result bundles.
- **Root-start runtime companion.** Performed the transient ownership changes
  required by the current task model and attempted post-workload
  normalization.
- **Fixed non-root workload.** Ran as `10000:10000` without supplemental groups
  and wrote only inside bounded workload-writable subtrees.
- **Nomad/Docker runtime.** Launched the task but did not acquire ES lifecycle,
  result-publication, or host-state authority.

The useful boundary is that a privileged runtime companion may prepare a
host-backed subtree without becoming the owner of ES retained-result semantics
or any future reclamation decision.

### Historical path-transition rationale

| Path | Historical active-task treatment | Historical post-task rationale | Current consequence |
| --- | --- | --- | --- |
| `run/platform` | ES-owned platform subtree; the companion could widen only the traversal/readability needed for the fixed workload to reach `run/work` and read non-secret trust files. | Restore restrictive ES-owned modes; never make the subtree workload-writable. | The ownership and helper-private rationale remains useful. No state here authorizes staging deletion. |
| `run/work` | Companion-created transient tree owned by workload `10000:10000` after archive sanitization. | Normalize to a stable numeric owner for bounded diagnostics. | Runtime behavior remains distinct from long-lived ES privilege. The whole run root is retained on every outcome. |
| `run/result` | Workload-writable result subtree, owner-writable and not world-writable. | Normalize allowed regular files/directories so ES can package opaque results fail-closed. | `openStagingTree` may read the retained tree for packaging only. Result success or failure cannot clean the run root. |
| Retained result bundle | Absent during the task. | ES publishes an owner/mode-normalized opaque bundle under the separate results root with no-replace semantics. | Active result storage remains separate from staging and confers no staging mutation authority. |
| Ownership-normalization marker | Helper-private evidence under `run/platform`, not workload-authored lifecycle truth. | A validator could combine marker shape with direct filesystem checks; the marker alone was never sufficient. | Archived v1 projections expose only schema, bytes, digest, historical-only, and `authority: none`. An internal marker may be read under existing result validation but cannot authorize cleanup. |

The old design also discussed successful-cleanup preflight. That mechanic is
superseded. Current ES attempts no automatic whole-run-root cleanup after
success, failure, cancellation, loss, ambiguity, or result publication.

### Numeric UID/GID and namespace rationale

The former contract used numeric host ownership rather than container-side
lookup of an `es` name because:

- an image may not contain an `es` account;
- a same-named account may map to different numeric IDs;
- the host-visible bind mount is what the long-lived ES service later reads;
- user-namespace translation can make an apparently valid container owner
  different from the host owner.

The proposed internal carrier used reserved helper-private facts such as
`EXEC_PLATFORM_STATE_OWNER_UID`, `EXEC_PLATFORM_STATE_OWNER_GID`, and
`EXEC_PLATFORM_STATE_OWNER_SCHEMA`. They were not caller-provided public API
fields and were not intended for workload exposure. A mismatch between the
declared target and host-visible ownership was fail-closed.

This reasoning remains relevant to a future runtime-boundary redesign. It does
not authorize a current operator to derive an owner from an archived artifact,
change ownership, or reuse an old run root.

### Marker and filesystem-evidence rationale

The historical marker design required a schema, normalized status, run ID,
target numeric owner, bounded normalized-path list, and completion timestamp.
Its location was intended to be helper-private and not workload-writable. The
core reasoning was:

- task events and logs cannot prove host-backed owner or mode state;
- marker evidence and direct no-follow filesystem validation form a
  conjunction, not alternatives;
- a missing, malformed, inconsistent, workload-forgeable, or owner-mismatched
  marker cannot become a readiness or mutation decision;
- result packaging must still validate allowed file types, readability,
  traversal, and stable identity itself;
- a copied or archived marker is evidence only and never lifecycle truth.

The earlier `alpha-compat` and `future-non-root-required` checker modes,
expected-owner comparisons, helper-staging record, and Infrastructure Manager
artifact flow are retired existing-host mechanics. They are preserved here to
explain why the design distinguished structural evidence from live authority,
not to provide a current command or migration gate.

### Historical failure semantics

The former design treated each of these as fail-closed ownership evidence:

- unreadable or unsupported workload output;
- helper/supervisor normalization failure;
- helper death before normalization;
- partial or mixed-owner normalization;
- UID/GID mismatch;
- lost, ambiguous, canceled, or failed task evidence.

Those failures did not rewrite Nomad lifecycle truth. They prevented an
ownership-normalization success claim and could prevent result packaging. The
current stronger retention rule means they never trigger whole-run-root
cleanup; the visible root remains in place.

### SPIRE and Vault compatibility assumptions

Ownership normalization was intentionally not a SPIRE or Vault redesign:

- the raw SPIRE Workload API channel remained helper-private;
- the current root-start companion and broad historical root selector scope
  were explicit compatibility edges;
- the workload remained fixed non-root with no supplemental groups;
- ES retained typed workload-zone Vault config and non-secret CA/metadata
  staging;
- Vault token, secret, and lease authority remained workload/Vault-owned, not
  ES-owned.

Future work must preserve or explicitly re-derive those boundaries rather than
using filesystem convenience to widen them.

### Retired migration, apply, rollback, and cleanup mechanics

The old rollout sequence contemplated readiness collection, stable-root owner
alignment, service-user apply, backup evidence, rollback notes, normalization
checks, and later cleanup/archive planning. All associated ES existing-host
routes are now fixed tombstones. Therefore:

- there is no current `apply_ready` decision;
- no helper may mutate a host or service through this document;
- no archived pass proves current readiness;
- no rollback artifact authorizes a service-user change;
- no cleanup plan authorizes deletion of old or retained roots;
- no v2 schema or replacement protocol exists for that retired ES family; the
  unrelated current EGS hardening v2 schema is not part of this statement.

Fresh-host provisioning remains the required recovery direction, but a
complete supported provisioner is not implemented. Reuse of an old or nonempty
host requires a newly selected, separately governed contract.
