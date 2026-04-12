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

In the current bounded execution slice, successful runs keep `execution.staging_root_dir/<run_id>` only until ES observes terminal success through the lifecycle path. Workloads may write terminal result files under `/execution/run/result`; ES retains those as an opaque bundle under `execution.results_root_dir` before successful staging cleanup. Failed, canceled, lost, or otherwise ambiguous outcomes retain staging for debugging.

ES also has one bounded opt-in runtime profile for Control Plane remote normal-shell attempts: `control-plane-normal-shell/v1`, selected with `invocation.annotations["execution_substrate.runtime_profile"]`. It uses a configured profile image that provides Python, git, narrow shell utilities, and Codex CLI, and it exposes only non-secret Vault credential-location metadata. The workload remains responsible for using `EXEC_WORKLOAD_IDENTITY_ENDPOINT` and the workload-vault env to fetch Codex material; ES does not broker Codex or Vault tokens.

## Repo Structure

High-level layout:

- `ars/`, `ags/`, `egs/`, `cgs/`, `es/` for the active Go services
- `internal/contracts/` for shared cross-service packages
- `internal/observability/` for cross-cutting support code
- `.docs/` for authoritative design, contract, boundary, lifecycle, and governance docs
- `.runbooks/` for operator-facing bring-up and verification steps
- `scripts/` and `.examples/` for local verification helpers and inputs

Use the README as a navigation entrypoint only. For architecture, contracts, boundaries, lifecycle semantics, and redesign intent, defer to the authoritative docs above.
