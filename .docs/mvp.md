# Milestone 0 MVP Claim Freeze

## Purpose and status

This document is the canonical Milestone 0 planning freeze for the current MVP
claim.

It states what the MVP currently claims, what it explicitly does not claim, and
how MVP-relevant surfaces should be classified before more implementation work
widens by inertia.

This is a documentation/planning slice only. It does not widen Execution
Substrate contracts, promote proof-harness behavior into architecture, or make
generated evidence authoritative.

This classification overlay does not replace the redesign-phase
`Current invariant`, `Bounded slice rule`, `Temporary compatibility edge`, and
`Reopened redesign seam` vocabulary used elsewhere in `AGENTS.md` and
`PLANS.md`. It is a narrower MVP-claim freeze used to keep the current product
story honest.

## Governing sources consulted

- `AGENTS.md`
- `PLANS.md`
- `.docs/system_overview/boundaries.md`
- `.docs/execution_lifecycle/contracts.md`
- `.docs/supported_local_cp_consumer_runbook.md`
- `../../Control Plane/README.md`
- `../../Control Plane/.docs/architecture.md`
- `../../Control Plane/.docs/invariants.md`
- `../../Control Plane/.docs/long-running-operator-mode-contract.md`
- `../../Control Plane/.docs/execution-substrate-integration.md`
- `../../Control Plane/.docs/supported-local-operator-runbook.md`
- `../../Infrastructure Manager/README.md`
- `../../Infrastructure Manager/.docs/architecture.md`
- `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md`
- `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md`

## Frozen MVP claim

The current MVP claims exactly this:

1. Execution Substrate is the core product. ES owns admission composition,
   submission handoff, runtime-profile compatibility, Nomad or Docker-backed
   lifecycle projection, retained opaque result bundles, runtime identity or
   workload-credential handoff boundaries, and what can safely be admitted, run,
   projected, retained, and exposed to callers.
2. Control Plane is the MVP UI or orchestration layer. CP owns objective or
   task progression, review or audit or policy gates, checkpoints,
   quarantine/restore, escalation, human intervention semantics, Temporal shell
   state, and operator-facing control semantics for the current MVP or demo
   path. CP consumes accepted ES surfaces; it does not define ES core contracts.
3. Infrastructure Manager is bootstrap, readiness, provenance, and diagnostics.
   IM owns supported-local or remote-alpha environment bootstrap,
   readiness/profile emission, bridge/provenance tooling, support-bundle
   assembly, and diagnostics. IM outputs are evidence, projection, or
   diagnostics unless an explicit contract says otherwise.
4. App, iMessage, browser, CLI, report, dashboard, notification, and channel
   surfaces are presentation, notification, or guarded action-adapter surfaces
   only. They can present workflow-authoritative facts, notify operators, or
   submit guarded CP actions. They cannot become independent orchestration
   authority, ES runtime authority, or hidden sources of run truth.
5. Remote Alpha is not production, HA, multi-tenant, or a general deployment
   architecture. It is a pre-live or bounded proof or support posture. It does
   not move CP, Temporal, UI, or workers to the remote host, does not provision
   remote hosts, and does not run a governed live job by itself unless a later
   repo-validated contract explicitly changes that claim.

## Explicit non-claims

The current MVP does not claim:

- production readiness
- high availability
- multi-tenant deployment
- a general remote deployment architecture
- CP ownership of ES contracts
- IM ownership of CP run-control truth or ES runtime truth
- `.out/`, reports, traces, support bundles, profiles, logs, retained bundles,
  or proof artifacts as orchestration authority
- app, iMessage, notification, report, dashboard, or channel surfaces as run
  truth
- remote SSH install automation, remote provisioning automation, or a long-lived
  remote reconciler
- that proof-only runner holds, proof Codex shims, or supported-local helper
  scripts are product runtime guarantees
- that proof harnesses define ES admission, lifecycle, runtime-profile,
  runtime-identity, retained-result, or readiness contracts

## Surface classes

| Class | Definition |
| --- | --- |
| `stable contract` | A repo-backed MVP ownership rule or externally consumed semantic boundary that the MVP is explicitly claiming now and that must not change silently. |
| `bounded MVP proof` | A proof, runbook, validation ladder, or support posture that substantiates the current MVP claim without becoming product architecture or a broad runtime guarantee. |
| `compatibility edge` | An active route, field, profile name, or integration path retained for MVP continuity or consumer compatibility, but not promoted to enduring architecture by this freeze. |
| `evidence/projection` | A read model, generated artifact, diagnostic output, profile, summary, or other non-authoritative surface that may inform operators or consumers without owning run truth. |
| `implementation detail` | A realization choice, helper path, local convenience, or proof-storage mechanic that may change without changing the MVP claim, so long as documented contracts and proof claims remain honest. |
| `reopened seam` | An active architecture-defining surface that the current docs explicitly keep open for re-derivation; this freeze records it without settling it. |

## Surface classification

### Execution Substrate

| Surface | Class | Frozen MVP treatment | Source path(s) |
| --- | --- | --- | --- |
| ES primary-program orientation and ES ownership of admission, submission, lifecycle projection, retained results, and runtime handoff boundaries | `stable contract` | Freeze this as the core MVP claim. CP and IM consume it but do not redefine it. This treatment is inferred from planning, boundary, and lifecycle docs together. | `PLANS.md`; `.docs/system_overview/boundaries.md`; `.docs/execution_lifecycle/contracts.md` |
| Nomad as authoritative for submitted execution lifecycle; ES as lifecycle projector rather than parallel scheduler or lifecycle-store owner | `stable contract` | Preserve Nomad authority and the no-parallel-lifecycle-store rule for the MVP. | `PLANS.md`; `.docs/system_overview/boundaries.md`; `.docs/execution_lifecycle/contracts.md` |
| Caller authentication and narrow SPIFFE allowlist on governed execution | `stable contract` | Keep authenticated caller identity and configured narrow allowlists as required governed-execution boundaries. | `.docs/execution_lifecycle/contracts.md`; `.docs/system_overview/contracts.md` |
| `GET /v1/executions:contract` producer declaration | `compatibility edge` | Keep this as the current read-only producer compatibility declaration and early gate. Do not promote it into health, submit readiness, run authority, or a general capability registry. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| `POST /v1/executions:prepare` | `compatibility edge` | Keep this as the current bounded preflight surface. It proves preflight success only and creates no run object or scheduler handoff. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md` |
| `POST /v1/executions:submit` | `stable contract` | Freeze this as the MVP execution handoff surface: async, bounded receipt, and Nomad submission through ES. The long-term request or receipt shape stays open elsewhere in this document. | `.docs/execution_lifecycle/contracts.md`; `.docs/system_overview/boundaries.md` |
| `GET /v1/executions/{run_id}/status` and minimal Nomad-backed status projection | `stable contract` | Keep status as a Nomad-backed projection only. Do not widen it into an ES-owned lifecycle model. | `.docs/execution_lifecycle/contracts.md`; `.docs/system_overview/boundaries.md` |
| `lifecycle_projection` | `stable contract` | Keep `source=nomad` and `revision` as an opaque same-run read-coordination token, not a scheduler id or write guard. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| `outcome_evidence` on status or cancel JSON and successful logs or result responses | `compatibility edge` | Keep the current evidence carriers and labels for the MVP, but do not treat the present vocabulary as the final scheduler, result, log, or cancellation model. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| `authority_handoff` on submit or status | `compatibility edge` | Keep this as bounded non-secret runtime handoff evidence only. It never becomes live credential, lease, approval, or scheduler truth. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| `GET /v1/executions/{run_id}/logs`, `GET /v1/executions/{run_id}/result`, and `POST /v1/executions/{run_id}:cancel` current consumer path | `compatibility edge` | Preserve the current CP-consumed lifecycle, logs, result, and cancel path for MVP continuity without promoting it into a broader orchestration or scheduler contract. | `PLANS.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/system_overview/boundaries.md` |
| ES-retained opaque result bundles | `stable contract` | Freeze the ownership rule that ES retains opaque output bundles and CP interprets them semantically. | `PLANS.md`; `.docs/system_overview/boundaries.md`; `.docs/execution_lifecycle/contracts.md` |
| `control-plane-normal-shell/v1` plus `execution_substrate.runtime_profile` compatibility | `compatibility edge` | Keep this as the accepted opt-in CP normal-shell runtime edge for the MVP. It is not a general package-kind redesign or a transfer of CP control semantics into ES. | `PLANS.md`; `.docs/system_overview/boundaries.md`; `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| Supported-local ES setup, readiness, and proof surfaces such as `scripts/01_bringup.sh`, `scripts/72_supported_local_setup.sh`, and `scripts/73_supported_local_proof.sh` | `bounded MVP proof` | These substantiate the current claim and operator path without becoming the architecture or the public client contract. | `PLANS.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| Proof-only Codex shim behavior and repo helper scripts | `bounded MVP proof` | Freeze these as proof scaffolding only. They may demonstrate the bounded runtime contract without becoming a product Codex or helper-script guarantee. | `PLANS.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| Host staging roots, `.out/es-proof-*`, guest `/tmp` scratch, current helper paths, and similar proof-storage mechanics | `implementation detail` | Treat these as replaceable realization details so long as the documented contracts and proof claims stay honest. | `PLANS.md`; `.docs/system_overview/boundaries.md` |
| ES request model, runtime-profile model, runtime identity path, retained-result behavior or path conventions, and lifecycle vocabulary seams | `reopened seam` | Record these as active and real, but intentionally not settled. Future re-derivation must go through ES planning and docs first. | `PLANS.md`; `.docs/system_overview/boundaries.md`; `.docs/execution_lifecycle/contracts.md` |

### Control Plane

| Surface | Class | Frozen MVP treatment | Source path(s) |
| --- | --- | --- | --- |
| Temporal or workflow-authoritative shell state, task ledger, run-control semantics, and `ExecutionFlowSnapshot v1` read contract | `stable contract` | Freeze workflow query state as run-control truth and the v1 snapshot as the read contract. ES and IM facts can enrich it but not override it. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/invariants.md` |
| Objective or task progression, review, policy gates, checkpoints, quarantine or restore, escalation, and finalization | `stable contract` | Freeze these as CP-owned MVP orchestration semantics. | `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/long-running-operator-mode-contract.md` |
| ES adapter as an explicit bounded provider path, not the default complete normal-shell runtime | `compatibility edge` | Keep ES integration opt-in and bounded behind the substrate port. The local path remains the default shell path. | `../../Control Plane/README.md`; `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/invariants.md`; `../../Control Plane/.docs/execution-substrate-integration.md` |
| `control-plane-normal-shell/v1` opt-in normal-shell path | `compatibility edge` | Keep the opt-in remote normal-shell slice only as the accepted MVP or demo path. Do not silently widen it into default runtime behavior. | `../../Control Plane/README.md`; `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/execution-substrate-integration.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md` |
| Monitoring console, browser, FastAPI, CLI, and app-style operator surfaces | `stable contract` | Treat these as presentation or guarded action-adapter surfaces over CP authority. They render workflow-owned state and submit guarded Temporal updates; they do not become orchestration truth. | `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/long-running-operator-mode-contract.md` |
| Static reports, dashboards, notifications, iMessage, and other channel surfaces | `evidence/projection` | Treat these as projection, export, or best-effort notification surfaces only. They may inform or notify, but they never become run truth or delivery authority. | `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/invariants.md`; `../../Control Plane/README.md` |
| Intervention routes and `expected_actionability_fingerprint` write coordination | `stable contract` | Freeze the run-scoped guarded intervention API and fingerprint-based stale-write protection. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/invariants.md` |
| Compare or experiment wrappers, child-run surfaces, and parent read-only views | `stable contract` | Freeze parent pages as read-only wrapper views and child runs as the intervention targets. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md` |
| Legacy direct orchestration | `compatibility edge` | Keep only as internal compatibility. It is not part of the MVP claim or a normal operator or runtime option. | `../../Control Plane/README.md`; `../../Control Plane/.docs/architecture.md` |
| Local WebAuthn or passkey operator containment | `stable contract` | Keep the current local operator containment and step-up boundary for browser or API writes, without treating it as remote deployment architecture or run authority. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md` |
| Classified artifact routes | `stable contract` | Keep artifact access deny-by-default and scoped to CP-owned classified routes. Artifact serving remains an access boundary, not an authority boundary. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md` |

### Infrastructure Manager

| Surface | Class | Frozen MVP treatment | Source path(s) |
| --- | --- | --- | --- |
| Supported-local `up -> profile -> check -> down` flow | `bounded MVP proof` | Freeze this as the bounded environment or bootstrap proof path for the current MVP consumer slice, not a general deployment platform. | `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/architecture.md`; `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md` |
| Generated CP profile, shell env, instance state, bridge or process state, and readiness-check outputs | `evidence/projection` | Treat these as runnable configuration, provenance, and liveness evidence only. | `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/architecture.md`; `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md` |
| `.out/instances/current-instance.txt` and similar local selection conveniences | `implementation detail` | Keep these as operator convenience only, never as freshness, liveness, submit-ready, or CP authority truth. | `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md` |
| SSH forwards and local TLS or SNI bridge | `compatibility edge` | Keep these as bounded supported-local host-resolution remediation. Do not promote them into the remote product posture. | `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/architecture.md` |
| IM `check` staging of CP preflight and contract probes | `bounded MVP proof` | Keep IM check as a stage-gated handoff proof that reuses CP and ES validation surfaces without claiming live workflow proof by itself. | `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/architecture.md`; `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md` |
| `control-plane.remote-supported-host-profile.v1` Remote Alpha profile emitter | `evidence/projection` | Treat the emitted profile as compatibility or runnable-profile provenance, not CP run-control or ES runtime authority. | `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |
| Remote Alpha doctor vocabulary and remote-doctor output | `evidence/projection` | Keep doctor output as fixed-stage environment provenance only. | `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |
| Remote Alpha live refresh | `evidence/projection` | Keep live refresh as read-only evidence collection and summarization. It does not run governed jobs or install or provision hosts. | `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |
| Remote Alpha readiness report | `evidence/projection` | Keep the combined report as pre-live operator UX evidence, not governed execution proof or runtime truth. | `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |
| Remote Alpha support bundles and hardening checkpoint outputs | `evidence/projection` | Keep bundles and checkpoints as copied, redacted, non-authoritative diagnostics and provenance. | `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md`; `../../Infrastructure Manager/.docs/architecture.md` |
| Remote SSH install, provisioning, reconciler, and general remote lifecycle automation | `reopened seam` | Record these as explicitly not owned by the current MVP. Any later claim needs a separate repo-validated contract. | `../../Infrastructure Manager/.docs/architecture.md`; `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |

### Cross-repo

| Surface | Class | Frozen MVP treatment | Source path(s) |
| --- | --- | --- | --- |
| CP consumption of AGS publish plus ES contract, prepare, submit, status, logs, result, and cancel over HTTPS+mTLS | `compatibility edge` | Freeze the current governed-execution consumer path for MVP or demo continuity without letting it define ES core contracts or the final shell or runtime architecture. | `.docs/supported_local_cp_consumer_runbook.md`; `../../Control Plane/.docs/execution-substrate-integration.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md` |
| CP use of ES `GET /v1/executions:contract` as a producer compatibility gate | `stable contract` | Freeze the rule that real governed attempts gate on the producer declaration before AGS publish, ES prepare, ES submit, or real attempt-manifest creation. | `.docs/execution_lifecycle/contracts.md`; `.docs/supported_local_cp_consumer_runbook.md`; `../../Control Plane/.docs/execution-substrate-integration.md`; `../../Control Plane/.docs/invariants.md` |
| ES provider run ids, lifecycle or outcome or authority or identity facts, retained result refs, and attempt manifests as CP read or review or finalization evidence | `evidence/projection` | Keep these as runtime evidence with provenance only. They inform CP reads, review, and finalization but do not override Temporal run-control truth. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/invariants.md`; `.docs/supported_local_cp_consumer_runbook.md` |
| IM profile, state, bridge, process, or readiness lineage consumed by CP as environment provenance only | `evidence/projection` | Freeze IM lineage as provenance or liveness evidence only. It never becomes CP run-control or ES runtime authority. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Infrastructure Manager/README.md`; `../../Infrastructure Manager/.docs/architecture.md` |
| Supported-local cross-repo proof path | `bounded MVP proof` | Freeze the current ES setup or readiness plus IM handoff plus CP validation-driver or manual-smoke ladder as the bounded proof of the accepted MVP path. | `.docs/supported_local_cp_consumer_runbook.md`; `../../Control Plane/.docs/supported-local-operator-runbook.md`; `../../Infrastructure Manager/.docs/supported-local-operator-runbook.md` |
| Remote Alpha direct HTTPS+mTLS posture | `bounded MVP proof` | Freeze Remote Alpha as a direct Mac-to-AGS or ES HTTPS+mTLS pre-live posture only, with CP, Temporal, UI, and workers still local. | `.docs/system_overview/remote_supported_host_alpha.md`; `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |
| Browser, CLI, app, report, dashboard, notification, iMessage, and channel surfaces | `stable contract` | Freeze these as presentation, notification, or guarded action-adapter surfaces only. They may show authoritative facts or submit guarded CP actions, but they do not become run truth, ES runtime authority, or hidden control paths. | `../../Control Plane/.docs/architecture.md`; `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/README.md` |
| `.out/`, reports, traces, local proof outputs, support bundles, retained bundles, logs, and generated profiles | `evidence/projection` | Freeze all of these as evidence, projection, diagnostics, or operator convenience outputs. None becomes orchestration authority by drift. | `../../Control Plane/.docs/long-running-operator-mode-contract.md`; `../../Control Plane/.docs/invariants.md`; `../../Infrastructure Manager/.docs/architecture.md`; `../../Infrastructure Manager/.docs/remote-supported-host-alpha.md` |

## Validation matrix

This matrix defines what should be validated before presenting the MVP claim. It
does not require every row to be rerun in every documentation-edit session.

### Execution Substrate

| Validation | Minimum gate or command or proof source | Pass condition | Explicit non-claim |
| --- | --- | --- | --- |
| ES ownership doc-alignment test | `go test -run TestPrimaryMilestoneRealignmentPreservesESOwnership -count=1 .` from the ES repo root | The ownership and contract-alignment test passes in the current checkout. | Does not prove live governed execution, supported-local readiness, or Remote Alpha posture. |
| ES repo test suite | `go test ./...` from the ES repo root when practical | Repo tests pass for the current checkout. | Does not prove live Nomad or Docker placement, Vault behavior, or remote host posture. |
| Producer declaration compatibility | `GET /v1/executions:contract` over the real HTTPS+mTLS boundary using the intended caller identity, or the equivalent CP or IM contract probe | `200` plus the current producer schema, enabled governed execution, required runtime profile when applicable, mandatory outcome-evidence carriers, and non-authority labels. | Not service health, submit readiness, run existence, credential truth, or scheduler API proof. |
| Supported-local submit readiness | `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh` from the ES repo | The environment truthfully reports submit-ready for the configured profile. | Not a guarantee of every future workload placement, production Codex availability, or production Vault policy. |
| Supported-local setup or proof path | `scripts/72_supported_local_setup.sh setup` and `scripts/73_supported_local_proof.sh run` when the documented supported-local prerequisites are present | The documented proof path completes and writes the expected proof evidence. | Not production readiness, not live upstream Codex proof, and not a general deployment story. |
| Remote Alpha ES hardening or check summaries | Existing `scripts/remote_alpha_*` check-only or summary artifacts referenced by ES or IM docs | Evidence is present, non-secret, and honestly labeled as bounded hardening or readiness evidence. | Not governed live job proof, not production remote deployment, and not full ES/runtime de-root. |

### Control Plane

| Validation | Minimum gate or command or proof source | Pass condition | Explicit non-claim |
| --- | --- | --- | --- |
| CP repo doc or structure policy | `pytest tests/test_repo_structure_policy.py tests/test_legacy_compatibility_policy.py` from the CP repo | Repo policy tests pass and continue to fence documentation and legacy boundaries. | Does not prove Temporal behavior, ES compatibility, or live operator flow. |
| CP ES adapter or producer-gate behavior | `pytest tests/test_execution_substrate_adapter.py` | The adapter preserves producer-declaration gating, runtime-profile expectations, outcome-evidence requirements, and retained-result handling. | Does not prove supported-local or remote live runtime execution. |
| CP read or intervention contract behavior | `pytest tests/test_execution_flow_snapshot.py tests/test_monitoring_interventions.py` | The v1 snapshot and intervention contracts remain consistent with workflow authority and guarded writes. | Does not prove browser deployment, notifier delivery, or live ES-backed execution. |
| CP supported-local preflight or contract probe | `python tests/manual_smoke/supported_local_validation_driver.py --mode temporal-basic ...` or `--preflight-only` or `--contract-probe-only` as documented | Preflight and the contract probe pass with the intended profile lineage before live proof is claimed. | Does not by itself prove submit, retained results, Temporal history, or final CP semantics. |
| CP opt-in normal-shell boundary | Config plus tests or smokes that require `substrate.adapter=execution_substrate`, `task_attempt_mode=normal_shell`, and `control-plane-normal-shell/v1` | The ES-backed path remains explicit and opt-in, and the local path remains the default shell path. | Not a default remote-runtime flip or a production remote-shell claim. |
| CP presentation or action-adapter boundary | `pytest tests/test_monitoring_run_console.py tests/test_monitoring_compare_console.py tests/test_monitoring_experiment_console.py tests/test_notifier_service.py` | Console or notifier surfaces remain presentation or guarded action adapters and route mutations through Temporal-owned updates only. | Not delivery confirmation, not operator authorization proof by itself, and not run-control truth outside workflow state. |

### Infrastructure Manager

| Validation | Minimum gate or command or proof source | Pass condition | Explicit non-claim |
| --- | --- | --- | --- |
| IM repo boundary or long-running-alignment tests | `pytest tests/test_long_running_contract_alignment.py tests/test_control_plane_check_orchestration.py tests/test_profile_emission.py` from the IM repo | IM tests pass and preserve profile, check, and provenance boundaries. | Does not prove ES runtime behavior or CP orchestration semantics. |
| Supported-local `up -> profile -> check -> down` path | `infra-manager up`, `infra-manager profile`, `infra-manager check`, `infra-manager down` as documented | IM emits the profile, records state, and truthfully stages CP preflight plus contract-probe evidence before handoff. | Not live CP workflow proof or general deployment automation. |
| Remote Alpha profile or doctor or readiness outputs | `pytest tests/test_remote_profile_emission.py tests/test_remote_alpha_readiness_report.py tests/test_remote_alpha_live_refresh.py` or the corresponding CLI commands | Remote Alpha outputs preserve the fixed vocabulary, provenance, and pre-live posture. | Not governed live job proof, not provisioning, and not CP or ES authority. |
| Remote Alpha support-bundle outputs | `pytest tests/test_remote_support_bundle.py tests/test_remote_alpha_live_support_bundle.py` or the corresponding CLI commands | Bundle assembly, redaction, and non-authority labeling pass in the current checkout. | Not runtime health proof, not run-control authority, and not remote deployment architecture. |
| IM provenance-only rule | IM architecture, runbook, and CP consumer docs taken together | Profiles, instance state, bridge state, and checks remain provenance or liveness evidence only. | Not freshness truth, submit-ready truth by themselves, or CP run authority. |

### Cross-repo

| Validation | Minimum gate or command or proof source | Pass condition | Explicit non-claim |
| --- | --- | --- | --- |
| Supported-local CP -> ES proof path | ES setup or readiness gates, IM `check`, and CP validation-driver or manual-smoke proof as documented | The stage-gated path passes in order and the selected live proof records truthful retained-result or workflow evidence. | Not production readiness, not default remote runtime, and not general deployment architecture. |
| Remote Alpha pre-live readiness posture | IM remote profile diagnostic plus remote-doctor plus readiness-report outputs | The posture is reported honestly as direct HTTPS+mTLS pre-live readiness or compatibility-only, without inventing new authority. | Not governed execution proof by itself and not a production rollout claim. |
| Evidence, artifact-redaction, and non-authority checks | CP and IM tests plus the documented artifact or bundle routes and collectors | Generated evidence stays redacted, deny-listed where required, and explicitly non-authoritative. | Not a statement that the underlying runtime is healthy or production-safe. |
| Presentation, notification, and guarded action-adapter checks | CP run-console or intervention or notifier tests and the long-running operator contract | Browser, CLI, report, dashboard, iMessage, notification, and channel surfaces remain presentation, notification, or guarded action adapters only. | Not delivery proof, not alternate orchestration authority, and not hidden run truth. |

## Use of this freeze

Future work should use this document to answer three questions before changing
behavior:

1. Is the surface being changed part of the frozen MVP claim, a bounded proof, a
   compatibility edge, evidence or projection, an implementation detail, or a
   reopened seam?
2. If the change widens or weakens an authority boundary, has that widening been
   explicitly documented first in the owning repo?
3. If the change only affects proof scaffolding or local diagnostics, is it
   still clearly labeled so the MVP does not silently become "whatever the proof
   harness happens to do"?
