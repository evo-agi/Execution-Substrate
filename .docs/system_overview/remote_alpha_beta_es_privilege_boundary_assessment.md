# Remote Alpha → Beta ES Privilege Boundary Assessment

## Current status

`Reopened redesign seam`: full ES/runtime privilege-boundary work remains open.
The prior Remote Alpha v1 existing-host writable-state and ES service-user
routes do not settle it and are now retired `Temporary compatibility edge`
history.

The six fixed tombstones cover writable-state readiness, readiness staging,
ownership preparation, ES service-user migration, generated rollback rehearsal,
and old-root planning. They perform no inspection, SSH, staging, mutation,
backup, plan, summary, or evidence production. Archived v1 artifacts are
historical evidence only, no live operator route parses or projects their
retired schemas, and no v2 replacement exists for that retired ES
writable-state/service-user migration family. The unrelated current EGS
hardening v2 schema remains current.

The active boundary remains:

- the long-lived ES service uses the accepted dedicated service-user posture;
- the current Nomad task and root-start runtime-companion model remain explicit
  compatibility assumptions, not proof of full runtime de-root;
- the raw SPIRE Workload API path remains helper-private and the workload stays
  fixed non-root without supplemental groups or a privilege-escalation path;
- ES resolves typed workload-zone Vault configuration and supplies non-secret
  handoff metadata, but does not broker Vault tokens;
- ES exclusively creates and materializes a run root and retains it for every
  post-claim Submit, lifecycle, cancellation, and result-publication outcome;
- result publication grants no staging deletion authority, automatic
  whole-run-root reclamation is absent, and future governed reclamation remains
  ES-owned.

This retirement changes no Coordinator-owned Worker Execution Boundary,
command, observation, fence, capsule, safe-reference, reliable-submit,
cancellation, correlation, retained-result DTO, direct-local, or adapter seam.
It changes no current task argv, environment, mounts, authority handoff,
receipt, one-Nomad-registration behavior, or public lifecycle/result DTO.

Remote Alpha remains bounded proof/support history, not product architecture.
Fresh-host provisioning is the required direction for future infrastructure
recovery, but no complete supported fresh-host ES provisioner currently
exists. Old or nonempty host reuse remains blocked without a separately
governed migration contract. Scheduler drain, submitter fencing, and final
native Linux evidence remain later seams.

## Historical design record — superseded and non-authoritative

This section is **superseded** and **non-authoritative**. It is **not an
available operator route** and is **not migration, cleanup, or reclamation
authority**. It preserves the source-grounded reasoning used during the former
Remote Alpha → Beta privilege assessment so later design work does not have to
recover that reasoning from Git history. Any historical reference to a marker,
checker, staged helper, apply, rollback, cleanup, or old-root plan describes a
retired mechanic only.

### Why privilege separation was treated as structural

The earlier assessment separated three privilege clusters:

1. Long-lived service privilege: ES startup config/TLS reads, staging/results
   root access, network-facing APIs, restart posture, and operator rollback.
2. Runtime-companion privilege: root-start supervisor/helper behavior,
   helper-private SPIRE traversal, selector posture, and identity endpoint
   serving.
3. Workload/task privilege: Nomad task identity, the fixed workload UID/GID,
   transient host-backed ownership, and retained-result readability.

Changing only `es.service` ownership could reduce long-lived network-facing
privilege, but it could not by itself re-derive the task, helper, SPIRE, Vault,
or bind-mounted filesystem boundaries. That distinction remains useful even
though the existing-host rollout helpers are retired.

### Historical dependency map

| Dependency | Historical design fact | Rationale retained for future work |
| --- | --- | --- |
| Staging and results ownership | The long-lived ES service needed to create staging and publish retained bundles under a stable numeric owner model. | Service-user selection and host-backed runtime ownership must be designed together; lifecycle or result facts do not imply deletion authority. |
| Runtime ownership transitions | The root-start companion temporarily prepared workload-writable `run/work` and `run/result` state and normalized useful output back toward the ES owner. | A service user cannot safely depend on ambient container names or unexplained UID translation. Current retention replaces the former successful-cleanup assumption. |
| SPIRE socket traversal | ES carried the configured path into a helper-private mount while the runtime helper consumed the raw socket. | Long-lived ES need not gain direct socket-read authority; selector and helper-principal redesign belongs with the runtime boundary. |
| SPIRE selector scope | The former proof posture used broad root selector compatibility. | That scope was evidence of an unfinished helper identity model, never a reason to expose the raw channel to the workload. |
| Nomad task identity | The task started as `0:0` so the companion could establish the fixed non-root workload boundary. | Changing the task user touches Docker, helper launch, filesystem ownership, SPIRE, and workload execution together. |
| Vault/workload-zone handoff | ES fetched typed config, staged optional CA material, and passed non-secret metadata plus the workload identity endpoint. | ES remains a config and handoff owner, not a Vault-token broker; workload-side JWT authentication remains the authority boundary. |
| Operator maintenance | Root-capable staging, service changes, backups, and rollback evidence were operator activities rather than ES request-path behavior. | Privileged maintenance must stay outside the network-facing service and require separately governed authority. |

### Historical architecture options

The prior assessment compared three options:

- **Option A — keep the long-lived ES service root-run.** This minimized
  compatibility risk but left the largest network-facing privilege unchanged.
  It is superseded for the accepted service-user posture.
- **Option B — de-root only the long-lived ES service while retaining the
  current task/helper model as explicit compatibility.** This was the bounded
  cut line used by the former rollout. The service-user result remains useful
  context, but the retired helpers and artifacts cannot authorize repeating the
  rollout, and their former successful-cleanup premise is no longer current.
- **Option C — re-derive Nomad, runtime helper, SPIRE, Vault, staging, and
  results as one boundary.** This offered the strongest structural improvement
  and the highest compatibility and migration risk. It remains a reopened
  design seam, not authorized implementation.

The useful conclusion was that “long-lived ES is non-root” and “the full
ES/runtime privilege boundary is solved” are different claims. The current
root-start companion, task-user, selector, and helper-private SPIRE assumptions
must remain visible until a separately governed redesign changes them.

### Service-user, SPIRE, and Vault constraints carried forward

- Numeric host ownership, not container-side lookup of an `es` name, is the
  meaningful fact for host bind mounts.
- The fixed workload identity remains separate from both the long-lived ES
  service user and the root-start runtime companion.
- The helper-private raw SPIRE socket must not become workload-readable or a
  general service-user dependency by convenience.
- SPIRE selector narrowing requires an explicit helper-principal design; a
  broad historical root selector is only a compatibility warning.
- ES may own typed Vault configuration, CA staging, and non-secret authority
  metadata without acquiring Vault token, secret, or lease authority.
- Operator support evidence is non-authoritative and must not become ES
  request-path inspection or Infrastructure Manager reconciliation authority.

### Retired rollout and helper mechanics

The former readiness checker, helper staging, writable-state ownership apply,
service-user migration, rollback rehearsal generation, and old-root planning
were designed as a sequenced existing-host rollout with backups and
check-before-apply evidence. Those mechanics are retired. In particular:

- no historical readiness classification or `apply_ready` field is current;
- no archived marker or summary authorizes host mutation;
- no helper may be invoked through this document;
- no historical successful-cleanup analysis overrides current unconditional
  post-claim retention;
- preserved root-era state is not an invitation to adopt, scan, clean, or
  reclaim it.

### Evidence needed before future privilege work

A future design may reuse the questions, not the retired answers. It must state
the chosen service, task, helper, SPIRE, Vault, and filesystem ownership model;
prove the raw SPIRE channel remains helper-private and the workload remains
non-root; preserve ES non-brokerage of Vault credentials; define migration and
rollback authority; and add native evidence for each claimed Linux
architecture. No implementation or live-host action is authorized here.
