# Execution Substrate

This repository contains the current Go implementation of the platform's governed publication, storage, policy, admission, and bounded execution system.

The current system includes these active service boundaries:

- ARS
- AGS
- EGS
- CGS
- ES

Nomad and Docker remain part of the current execution slice, with ES submitting to Nomad and Docker running tasks under Nomad.

## Current Mode

The repository is operating as a bounded platform with explicit reopened seams.

The current system is coherent and implemented. Some architecture-defining seams remain intentionally reopened in `PLANS.md`, but rewrite-by-default is no longer the operating stance. Authoritative design intent lives in `PLANS.md` and `.docs/`, not in the README.

## Where To Start

Read these in order:

1. [AGENTS.md](AGENTS.md) for repository operating rules
2. [PLANS.md](PLANS.md) for current work, redesign scope, and reopened seams
3. [.docs/system_overview/architecture.md](.docs/system_overview/architecture.md) for the top-level system map
4. [.docs/system_overview/contracts.md](.docs/system_overview/contracts.md) for cross-service contracts
5. [.docs/system_overview/boundaries.md](.docs/system_overview/boundaries.md) for ownership and non-ownership
6. [.docs/system_overview/evolution.md](.docs/system_overview/evolution.md) for change-governance rules
7. [.docs/execution_lifecycle/design.md](.docs/execution_lifecycle/design.md) for lifecycle design
8. [.docs/execution_lifecycle/contracts.md](.docs/execution_lifecycle/contracts.md) for lifecycle public contract
9. [.docs/execution_lifecycle/implementation.md](.docs/execution_lifecycle/implementation.md) for lifecycle implementation paths
10. [.docs/supported_local_cp_consumer_runbook.md](.docs/supported_local_cp_consumer_runbook.md) for the canonical ES-side supported-local Control Plane consumer runbook

Supporting references:

- [.docs/system_overview/configuration.md](.docs/system_overview/configuration.md) for current config requirements
- [.docs/system_overview/observability.md](.docs/system_overview/observability.md) for observability rules
- [.docs/system_overview/capability_probing.md](.docs/system_overview/capability_probing.md) for capability-sensitive validation rules

## Operator Quick Start

For the current bounded execution slice, the preferred operator path is:

1. Follow [.runbooks/system/v1_bringup.md](.runbooks/system/v1_bringup.md)
2. Use `scripts/01_bringup.sh up` for the cohesive local bring-up path
3. Use `scripts/01_bringup.sh check` to re-check service health, prepare-ready state, and submit-ready state
4. Use `scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json` for the bounded end-to-end smoke path
5. Use `scripts/01_bringup.sh down` to stop the managed stack

The lower-level readiness helper remains `scripts/10_health_check.sh`. In the current slice, ES `/health` proves only admission-oriented service health; the operator path now layers workload-zone Vault runtime-config validation plus Nomad/Docker checks on top before claiming submit readiness.
For those operator-facing helpers, the current caller credentials are `OPERATOR_CERT` and `OPERATOR_KEY`; `service/deployment` is no longer a co-equal hot-path caller identity for AGS or ES in this bounded slice.
The operator-facing publish / prepare / submit / lifecycle helpers now classify failures into bounded categories and point back to the compact troubleshooting matrix in [.runbooks/system/v1_bringup.md](.runbooks/system/v1_bringup.md). That matrix is the current operator reference for:

- which readiness check is authoritative
- which service logs matter most
- when retained staging is useful
- what next action to take

The bounded diagnostics collector is `scripts/70_diagnostics.sh`. Use `--category auth|trust|runtime-config|readiness|substrate|execution|input` or `--run-id run-...` to gather the exact logs/check outputs already named by that troubleshooting matrix. Then use `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>` to print a compact summary of the collected bundle.

When a later helper reports a readiness or substrate problem, re-run `scripts/01_bringup.sh check` first instead of inferring readiness from a single endpoint call, then use that troubleshooting matrix or `scripts/70_diagnostics.sh`.

In the current bounded execution slice, every exclusively created
`execution.staging_root_dir/<run_id>` remains retained after claim, including
failed, ambiguous, accepted, successful, canceled, lost, and result-publication
outcomes. Workloads may write terminal result files under
`/execution/run/result`; ES may retain those as an independent opaque bundle
under `execution.results_root_dir`, but result publication never authorizes
staging deletion. Automatic whole-run-root reclamation is not implemented.

Remote Alpha existing-host ES writable-state readiness, readiness staging,
service-user migration, ownership preparation, rollback generation, and
old-root planning routes are retired fixed tombstones. Archived v1 artifacts
are historical evidence only, no live operator route parses or projects their
retired schemas, and no v2 replacement exists for that retired ES writable-
state/service-user migration family. The unrelated current EGS hardening v2
schema remains current. Future infrastructure recovery requires a separately
selected fresh-host setup contract, but this
repository does not currently provide a complete supported fresh-host ES
provisioner; old or nonempty host reuse remains blocked without a separately
governed migration contract.

For the bounded supported-local Control Plane consumer path, including the `control-plane-normal-shell/v1` runtime profile, submit-ready meaning, workload-visible identity/Vault/trust-material handoff, retained-result behavior, and ownership boundaries, use the canonical ES-side runbook: [.docs/supported_local_cp_consumer_runbook.md](.docs/supported_local_cp_consumer_runbook.md).

The Control Plane-owned long-running operator mode, releaseability, and scaling freeze lives in the adjacent Control Plane repo at [`.docs/long-running-operator-mode-contract.md`](../Control%20Plane/.docs/long-running-operator-mode-contract.md). ES must not widen this supported-local surface into CP orchestration, review, checkpoint, hold/resume/reject, or release authority without an explicit new contract.

## Repo Structure

High-level layout:

- `ars/`, `ags/`, `egs/`, `cgs/`, `es/` for the active Go services
- `internal/contracts/` for shared cross-service packages
- `internal/observability/` for cross-cutting support code
- `.docs/` for authoritative design, contract, boundary, lifecycle, and governance docs
- `.runbooks/` for operator-facing bring-up and verification steps
- `scripts/` and `.examples/` for local verification helpers and inputs

Use the README as a navigation entrypoint only. For architecture, contracts, boundaries, lifecycle semantics, and redesign intent, defer to the authoritative docs above.
