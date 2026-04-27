# Remote Alpha To Beta ES Privilege-Boundary Assessment

## 1. Purpose and status

This document is a design-only structural assessment for the next ES
privilege-boundary decisions after the accepted Remote Supported-Host Alpha
state.

It does not authorize implementation by itself. It does not change the current
accepted Alpha posture. It does not treat the ES config/TLS ownership prep
slice as if ES were already de-rooted.

Authoritative inputs for this assessment are:

- `PLANS.md`
- `.docs/system_overview/configuration.md`
- `.docs/system_overview/remote_supported_host_alpha.md`
- `.docs/system_overview/contracts.md`
- `.docs/execution_lifecycle/design.md`
- `.docs/execution_lifecycle/implementation.md`
- current ES runtime/helper code and tests

## 2. Current accepted Alpha posture

The accepted Alpha posture is:

- `Current invariant`: AGS, ARS, and EGS are already de-rooted in the current
  Remote Alpha hardening tranche.
- `Bounded slice rule`: the ES config/TLS ownership prep slice is applied and
  productized through:
  - `scripts/remote_alpha_prepare_es_config_tls.sh`
  - `scripts/remote_alpha_stage_es_config_tls_prep.sh`
  - Infrastructure Manager support-bundle/checkpoint evidence
- `Bounded slice rule`: the ES stable writable-state ownership slice is applied
  and the explicit `future-non-root-required` writable-state gate has passed.
- `Bounded slice rule`: the long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`, with post-apply `/health`,
  `GET /v1/executions:contract`, and the current lowest-cost existing happy
  path all passing.
- `Temporary compatibility edge`: the remote helper proof still depends on the
  broad root selector scope `unix:uid:0` plus `unix:gid:0` for
  `spiffe://execution.internal/workload`.
- `Temporary compatibility edge`: the root-start runtime helper, Nomad task
  `User: "0:0"`, helper-private SPIRE traversal, and Vault/workload-zone
  handoff remain intentionally compatibility-labeled rather than solved
  runtime-boundary architecture.
- `Current invariant`: the raw SPIRE Workload API socket remains helper-private
  and the workload remains fixed non-root `10000:10000` with no supplemental
  groups or privilege-escalation path.
- `Current invariant`: old root-era staging/results roots are preserved as
  rollback/debug/evidence state until a later explicit cleanup/archive action
  after the rollback window expires; they were not recursively re-owned or
  deleted during the migration.
- `Current invariant`: no current Alpha hardening evidence, support bundle,
  checkpoint, or apply summary claims full ES/runtime de-root.

The important implication is that Alpha now has landed bounded long-lived ES
service de-root, but the remaining ES privilege issues are still structural
runtime-boundary issues rather than just file-permission cleanup.

## 3. Dependency map

| Dependency | Current fact | Classification | Why it is not solved by config/TLS prep alone |
| --- | --- | --- | --- |
| Staging/results ownership | ES still owns submit-time host staging under `execution.staging_root_dir`, retains opaque result bundles under `execution.results_root_dir`, and cleans successful staging only after terminal observation. Submit-time staging now fails closed if those two stable roots do not resolve to the same target owner UID:GID. | structural/runtime-boundary | This is tied to ES submit, lifecycle cleanup, opaque retained-result semantics, and host/runtime ownership rather than only startup config readability. |
| SPIRE socket traversal | ES still depends on `execution.spire_workload_api_socket_path`, bind-mounts the containing directory into the helper-private runtime subtree, and the supervisor materializes the helper-private socket alias there. The long-lived ES startup path keeps that path as config-shape and submit input only; operator/readiness flows validate the host socket and the runtime helper consumes the helper-private raw SPIRE path fail-closed at runtime. | structural/runtime-boundary | The helper-private raw SPIRE path is part of the runtime boundary and capability model, not just a host permission setting. |
| SPIRE selectors / root workload registration | Remote Alpha helper proof still uses the broad root selector scope `unix:uid:0` plus `unix:gid:0` for `spiffe://execution.internal/workload`. | mixed | The current selector set is an Alpha-only compatibility edge, but replacing it safely depends on the future helper identity and task-launch model. |
| Runtime-helper root-start model | `es-runtime-support supervisor` and `helper` require `0:0` at start, then the helper drops steady-state capabilities and the workload is exec'd as `10000:10000`. | structural/runtime-boundary | This is the core platform-owned runtime identity boundary today. It is not just a hardening detail. |
| Nomad task user model | ES currently submits one Docker task with `User: "0:0"` and relies on the runtime support binary to create the workload boundary inside the task. | structural/runtime-boundary | Changing this touches Nomad, Docker, helper launch, workload launch, and the SPIRE/Vault runtime contract together. |
| Vault/workload-zone runtime-config handoff | ES resolves typed workload-zone Vault config, stages optional CA material, and injects only non-secret workload-vault metadata plus `EXEC_WORKLOAD_IDENTITY_ENDPOINT`. | mixed | The typed runtime-config handoff is already explicit, but its safe ownership split depends on the future ES/helper/task privilege model. |
| Filesystem ownership and retained-result materialization | The supervisor prepares `/execution/run`, chowns `/execution/run/result` to `10000:10000`, finalizes result readability, and ES later packages opaque retained bundles. | unknown / needs measurement | The current behavior is documented, but the exact ownership/readability/cleanup model for a non-root ES service plus the current runtime helper/task model is not yet derived or measured. |
| Service restart / operator maintenance model | Current host-local maintenance and rollback evidence now covers the applied config/TLS prep slice, the applied writable-state ownership slice, the bounded `User=es` service-user migration, preserved old roots, and the remaining compatibility edges. | implementation-only | This matters for rollout, rollback, packaging, and operator ergonomics, but it should follow the chosen architecture rather than define it. |

## 4. Structural reading of the dependency map

The dependency map separates into three clusters:

1. Long-lived service privilege:
   `es.service`, startup config/TLS readability, stage/results root access,
   restart model, and operator rollback.

2. Runtime identity companion privilege:
   helper root-start, helper-private SPIRE path, selector posture, and endpoint
   serving.

3. Workload/task launch privilege:
   Nomad task `User: "0:0"`, the fixed workload UID:GID `10000:10000`, staged
   runtime filesystem ownership, and retained-result materialization.

The bounded rollout has now addressed cluster 1 for the long-lived ES service,
but it did not re-derive clusters 2 and 3.

## 5. Viable future architectures

### Option A: Keep ES `root(default)` for a bounded Beta

What changes:

- Preserve the current long-lived ES root-run posture for Beta.
- Continue to harden around it with explicit compatibility labeling,
  evidence-first operator flows, and narrower operator guardrails.
- Treat the broad root selector scope and the root-start helper model as
  explicit Beta compatibility edges rather than hidden progress.

What stays the same:

- `es.service` remains `root(default)`.
- Current Nomad task `User: "0:0"` stays.
- Same-container supervisor/helper remains.
- Current helper-private SPIRE boundary, workload UID:GID `10000:10000`,
  workload-vault handoff, retained-result contract, and ES public APIs stay.

Expected security improvement:

- Low. This improves documentation, review discipline, and operator evidence,
  but leaves the long-lived network-facing ES process running as root.

Compatibility risk:

- Low. This is the least disruptive option.

Migration complexity:

- Low.

Test/proof impact:

- Low. Mostly evidence/wording/guardrail refresh.

Rollback complexity:

- Low.

### Option B: De-root the long-lived ES service, keep the current runtime task model explicit

What changes:

- The long-lived ES API/service process is moved off `root(default)`, using the
  already-prepared `root:es` readable config/TLS model as one input.
- Stage/results ownership is explicitly provisioned so the non-root ES service
  can still submit, observe, retain results, and perform successful staging
  cleanup.
- The current runtime helper/task model stays explicit for now:
  - Nomad task still starts `0:0`
  - same-container supervisor/helper remains
  - helper-private SPIRE path remains
  - workload remains fixed `10000:10000`

What stays the same:

- ES public contracts remain unchanged.
- Current runtime identity discovery contract and `authority_handoff` stay.
- Current typed workload-zone Vault runtime-config handoff stays.
- Current retained opaque result bundle contract stays.

Expected security improvement:

- Medium. The long-lived network-facing ES process stops running as root, which
  reduces exposure on the primary API surface.

Compatibility risk:

- Medium. Startup, stage/results ownership, and maintenance assumptions change,
  but the runtime task contract can remain intact for a bounded Beta.

Migration complexity:

- Medium. This required a deliberate ownership model for writable ES state and
  explicit rollout/rollback rules.

Test/proof impact:

- Medium. The repo would need new tests and bounded proof/evidence showing that
  non-root ES still submits correctly, retains results, and preserves current
  runtime identity behavior.

Rollback complexity:

- Medium. Rollback is still feasible because current runtime behavior can stay
  intact and the current root-run service posture remains a clear fallback.

### Option C: Re-derive the full runtime boundary across Nomad, SPIRE, Vault, staging, and results

What changes:

- Re-derive the ES runtime boundary instead of only flipping the long-lived
  service user.
- Replace or narrow the current root-start helper/task model.
- Replace the broad root selector scope with an explicit helper principal or
  another bounded identity model.
- Reconsider the current Nomad task `User: "0:0"` assumption.
- Reconsider staging/results ownership and retained-result materialization in
  the same design package.

What stays the same:

- The high-level ES role can stay: admission, Nomad handoff, lifecycle
  projection, and opaque retained-result delivery.
- The typed workload-zone Vault config surface can stay.
- The workload-visible identity discovery contract may stay if versioning is
  not needed.

Expected security improvement:

- High. This is the only option that directly targets the remaining structural
  root dependencies instead of containing them.

Compatibility risk:

- High. This touches the most sensitive seams:
  runtime identity, task launch, filesystem ownership, selectors, and
  lifecycle-side cleanup/materialization.

Migration complexity:

- High.

Test/proof impact:

- High. This would need a new design package, new tests, and new bounded proof
  expectations before it could be accepted.

Rollback complexity:

- High. Once the runtime boundary changes, the rollback plan must be explicit
  and rehearsed.

## 6. Design conclusion

The repo should not treat “bounded long-lived ES service de-root” as equivalent
to “the full ES privilege boundary is now solved.”

The current root dependencies are split:

- the long-lived ES service is now non-root
- the runtime helper/task model still relies on root start
- the remote helper proof still relies on a broad root selector scope
- the stage/results/readability/cleanup model is improved and live-measured at
  the stable-root boundary, but it is still coupled to those runtime choices

The config/TLS ownership prep slice and the later writable-state plus
service-user slices usefully landed the long-lived service cut line, but they
did not settle the runtime-boundary design.

## 7. Recommended future architecture

The recommended direction remains **Option B as the currently landed Beta cut
line, with Option C left explicitly open as a later structural redesign
track**.

Reason:

- Option A leaves or restores the highest-value long-lived privilege unchanged.
- Option C is the cleanest end-state candidate, but it reopens too many seams
  at once for the next bounded step.
- Option B has already delivered a meaningful security improvement by removing
  root from the long-lived ES API/service surface while keeping the current
  runtime task model explicit and compatibility-labeled instead of pretending
  it is solved.

That recommendation is intentionally narrow:

- The landed Beta cut line keeps the runtime helper/task root-start model
  explicitly documented as a bounded compatibility edge.
- Beta must not claim that the full ES privilege boundary is solved while the
  broad root selector scope, Nomad task `User: "0:0"`, and current root-start
  runtime helper model remain.

## 8. Smallest safe next readiness step

The earlier bounded rollout package is now landed on the current branch and on
the live host as:

- the privileged-operation matrix for ES and the runtime companion path
- the writable-state ownership model
- the runtime ownership-normalization contract
- the non-mutating writable-state readiness checker
- repo-local normalized-run lifecycle coverage for retained-result and cleanup
  semantics
- the bounded binary-deployment helper
- the bounded stable writable-state ownership helper
- the bounded long-lived `es.service` migration helper
- live host evidence that the long-lived `User=es` service, post-apply
  lowest-cost happy path, and future writable-state readiness all passed

The next safe step is therefore sealing and governance only:

- keep the current live long-lived ES service-user posture as the accepted
  bounded cut line
- treat any further privilege-boundary change as explicit Option C or another
  separately documented bounded slice
- preserve the old root-era staging/results roots until an explicit later
  cleanup/archive action is approved after the rollback window

## 9. Hard blockers to full ES/runtime de-root

The hard blockers to a full ES/runtime de-root implementation are:

- the ownership split for root-only operations versus long-lived ES service
  operations is now documented and the long-lived service cut line is
  live-measured, but the runtime/task/helper boundary is still only partially
  re-derived
- current runtime helper and supervisor require root start
- current Nomad task model is still `User: "0:0"`
- current Remote Alpha helper proof still depends on a broad root selector
  scope
- the non-root ownership/readability/cleanup model for staging and retained
  results is now documented, repo-local test-backed, and bounded live-host
  evidenced at the stable-root/service-user cut line, but the deeper
  runtime-boundary redesign remains unfinished
- old root-era staging/results roots are intentionally preserved for
  rollback/debug/evidence state until a later explicit cleanup/archive action

## 10. Required evidence before approving further implementation

Before approving any further ES/runtime privilege-boundary change beyond the
landed long-lived service-user slice, the repo should require:

- updated authoritative docs that describe the chosen architecture and mark the
  retained compatibility edges explicitly
- the privileged-operation matrix, readiness ledger, writable-state ownership
  model, and normalization contract remain aligned about why each remaining
  root operation still exists and who owns it
- tests proving the chosen service user model, task user model, and helper
  boundary
- tests proving the raw SPIRE channel stays helper-private and the workload
  remains non-root with no supplemental groups or privilege-escalation path
- tests proving submit, lifecycle projection, retained-result materialization,
  and successful staging cleanup still work under the chosen ownership model
- evidence showing the selected SPIRE registration/selector model is no longer
  the current broad root proof scope, or is still explicitly compatibility-only
  if intentionally retained
- a documented rollback path that restores the last accepted posture without
  ambiguity
- bounded local and remote-host evidence requirements defined before any
  implementation is treated as complete

## 11. Non-goals of this document

This assessment does not:

- claim full ES/runtime de-root
- authorize changes to Nomad task users
- authorize selector changes
- authorize runtime helper redesign
- authorize host mutation, ES apply, or proof execution

Its role is only to keep future ES privilege-boundary work explicit, structural,
and doc-first.
