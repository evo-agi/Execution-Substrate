# Remote Alpha → Beta ES Privileged Operation Matrix

## Current status

| Surface | Current posture | Authority consequence |
| --- | --- | --- |
| ES run-root creation/materialization | Active `Bounded slice rule` | Exclusive no-follow descriptor custody; refuse pre-existing objects; validate exact expected membership before one Nomad handoff |
| Post-claim staging retention | `Current invariant` | Retain on every Submit, lifecycle, cancellation, and result-publication outcome |
| Read-only result packaging reopen | Active narrow read path | `openStagingTree` may read a retained root for packaging; no mutation, deletion, adoption, or reclamation method exists |
| Whole-run-root reclamation | Not implemented; `Reopened redesign seam` | No lifecycle or result fact grants deletion authority |
| Exact operation-local temporary removal | Active bounded exception | Descriptor-relative exact object only; no general scan, recursion, sibling access, or later residue authority |
| Remote Alpha ES writable-state readiness/staging | Retired compatibility edge | Fixed tombstone; no inspection, SSH, host contact, artifact, or authority |
| Remote Alpha ES service-user/ownership migration | Retired compatibility edge | Fixed tombstone; no check-only, apply, simulation, or authority |
| Remote Alpha rollback generation/old-root planning | Retired compatibility edge | Fixed tombstone; archived v1 files are historical only |
| Remote Alpha v2 | Absent | No schema, validator, fixture, artifact, producer, or authority |
| Fresh-host ES provisioning | Incomplete later seam | Required direction, but no complete supported provisioner currently exists |
| Old/nonempty host reuse | Blocked | Requires a separately governed existing-host migration contract |
| Scheduler drain / submitter fence | Undefined later seams | No current contract or authority |

Unrelated Remote Alpha Vault, TLS, runtime-identity, and operator-healthcheck
routes are outside this retirement and retain their separately documented
bounded behavior.

Retained staging increases disk usage, capacity pressure, sensitive-material
residence, and operator burden. A future ES-owned reclamation design must make
those costs and its authority model explicit.

## Historical design record — superseded and non-authoritative

This section is **superseded** and **non-authoritative**. It is **not an
available operator route** and is **not migration, cleanup, or reclamation
authority**. It retains the reasoning behind the former detailed operation
matrix. Historical marker, helper, migration, check-only, apply, rollback, and
cleanup mechanics are retired.

### How the historical matrix separated authority

The old matrix deliberately distinguished:

- long-lived ES service operations;
- per-run runtime-companion operations inside the Nomad task;
- fixed non-root workload operations;
- scheduler control performed through Nomad rather than host root;
- operator maintenance and evidence collection.

This separation prevented “requires privileged operator maintenance” from
becoming “the network-facing ES service should run as root,” and prevented a
root-start helper from becoming the owner of ES lifecycle, result, or cleanup
semantics.

### Historical detailed operation rationale

| Operation | Historical actor and privilege | Touchpoints and retained rationale | Current consequence |
| --- | --- | --- | --- |
| ES config and service TLS reads | Long-lived ES service; the bounded rollout moved this to a dedicated service user with root-owned, group-readable material. | ES config, ES server keypair, ARS and EGS client trust. Read access did not intrinsically require host root. | The accepted service-user boundary remains; the retired migration helper cannot reapply or alter it. |
| Run-root claim and package materialization | Long-lived ES service under the stable staging owner. | Payload, platform support, trust files, mounts, and run directories. Exclusive no-follow creation and stable numeric ownership were required. | Active ES behavior now adds exact child-set validation and retains every post-claim root. |
| Retained-result publication | Long-lived ES service under the results-root owner. | Read-only staging source; separate no-replace result bundle publication. | Active, but publication never grants staging deletion authority. |
| Runtime `run/work` preparation | Root-start supervisor/helper inside the task. | Host-backed working tree temporarily owned/readable by workload `10000:10000`. | Still an explicit runtime compatibility assumption; it is not long-lived ES host-root authority. |
| Runtime `run/result` preparation and normalization | Root-start supervisor/helper inside the task, with workload writes bounded to the result subtree. | Numeric target ownership was used to make later ES reads possible. | Internal normalization evidence may inform fail-closed packaging, but cannot authorize staging cleanup or reclamation. |
| `run/platform` visibility | ES staged platform-owned files; runtime companion provided only bounded workload traversal/readability where required. | Runtime support binary and non-secret Vault/system CA material. | The subtree must not become workload-writable; current retention remains unconditional. |
| SPIRE Workload API access | Runtime helper consumed a helper-private bind-mounted raw socket. | Configured socket directory, fixed helper alias, SPIRE registration selectors. | Long-lived ES need not read the raw socket; workload access remains forbidden; selector redesign is later work. |
| Nomad task launch | Nomad/Docker launched the current task as `0:0`; the companion established the fixed non-root workload. | Task user, supervisor/helper start, capability drop, workload exec. | Root start remains compatibility-labeled, not proof of full runtime de-root. |
| Vault/workload-zone handoff | ES fetched typed config and staged optional CA material; workload authenticated through helper-delivered identity. | ARS blob, Vault HTTPS metadata, `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, JWT auth mount. | ES remains a non-secret handoff owner and must not become a Vault-token broker. |
| Health and producer-contract probes | ES served narrow APIs; operator tooling composed broader readiness. | `/health`, `GET /v1/executions:contract`, dependency readiness. | API service privilege stays distinct from privileged host inspection. |
| Cancellation | ES called Nomad with the existing non-purge semantics. | Public cancel route and Nomad stop endpoint. | Scheduler mutation is not host-root or staging-deletion authority. |
| Support bundle, readiness, migration, and rollback evidence | Operator tooling, sometimes with host root. | Former `/var/tmp` summaries, backups, service posture, and helper staging. | The six ES existing-host routes are tombstones; archived outputs are historical only. |

### Historical Option B cut line

The former bounded cut line moved long-lived ES config/TLS reads, stable
staging/results access, public ES endpoints, Nomad client access, and result
publication to the dedicated service user while leaving these explicit
compatibility assumptions:

- root-start supervisor/helper;
- Nomad task `User: "0:0"`;
- fixed workload `10000:10000` with no supplemental groups;
- helper-private SPIRE traversal and the broad historical root selector scope;
- operator-only root maintenance.

The matrix did not claim full ES/runtime de-root. It also formerly analyzed
successful staging cleanup. That cleanup premise is superseded: every current
post-claim root is retained, including terminal success and every result
publication outcome.

### Historical evidence and helper limits

The prior readiness ledger distinguished design-authoritative, repo-local
test-backed, checker-backed, and live-host-evidenced facts. That distinction is
still useful: a marker or local fixture cannot prove a live host, and a support
bundle cannot create runtime authority. The following mechanics themselves are
retired:

- writable-state readiness and helper-staging collection;
- ownership preparation and service-user migration check/apply;
- generated rollback rehearsal;
- old-root cleanup planning;
- any use of archived `apply_ready`, pass, migration, rollback, or cleanup
  fields as a current decision.

No historical row authorizes SSH, sudo, service restart, ownership change,
migration, cleanup, reclamation, or another rollout. Any future operation must
be selected and documented under a new governed contract.

### Approval boundary retained as design history

Future privilege work must identify the actor, required capability, exact
touchpoints, authority owner, failure behavior, compatibility risk, evidence,
and rollback plan. Runtime-helper, task-user, SPIRE-selector, Vault handoff,
and host-backed ownership changes must be evaluated together when they affect
one another. This historical matrix authorizes none of those changes.
