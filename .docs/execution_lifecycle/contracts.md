# Execution Lifecycle Contracts

## Lifecycle Contract

Nomad is authoritative for submitted execution lifecycle state.

ES must:

- treat Nomad as the only source of truth for status, logs, and cancellation
- derive lifecycle answers directly from Nomad job and allocation state
- keep lifecycle responses minimal and bounded

ES must not:

- maintain lifecycle state
- persist run records
- cache status, logs, or cancellation state
- reconstruct lifecycle state from local staging directories
- invent private execution phases beyond what Nomad already exposes
- reinterpret Nomad into a richer internal scheduler model
- reinterpret runtime identity endpoint or Vault auth failures into ES-owned lifecycle state

## Data Flow Contract

Lifecycle lookup is defined by a fixed mapping:

- input: `run_id`
- validation rule: `run_id` must match `run-[0-9a-f]{16}`
- derived value: `nomad_job_id = exec-<run_id>`

Status, logs, and cancel are derived from Nomad only:

- status: Nomad job plus latest allocation state
- logs: Nomad stdout for task `task`
- cancel: Nomad job stop with `purge = false`

ES must not consult any other store for lifecycle data.

## Allocation Selection Contract

ES selects the latest Nomad allocation for the derived job.

That is a bounded contract, not a general lifecycle model. It is valid only because the current execution slice disables retries and reschedule, so multiple meaningful allocations are not expected during normal operation.

If retries or reschedule are introduced later, this contract must be revisited explicitly before code changes land. ES must not silently keep treating the latest allocation as the authoritative lifecycle target once multiple real allocations can exist for one run.

## Status Contract

Status is a projection of Nomad state only.

ES must:

- read Nomad job and allocation state
- map that state into the documented response fields
- surface terminal and exit-code information only when Nomad provides it

ES must not:

- synthesize lifecycle phases
- infer hidden execution progress
- reinterpret Nomad state into a richer ES-owned execution model
- fill gaps in Nomad state with ES-owned assumptions

## Logs Contract

The logs endpoint is a fixed contract in this slice:

- task name is `task`
- output source is stdout only
- response type is plain text

ES must not:

- switch tasks dynamically
- aggregate logs across tasks
- merge stdout and stderr
- stream, paginate, or tail logs in this slice

## Failure Model

The lifecycle slice reflects Nomad failures directly instead of masking them.

### Request Errors

- invalid `run_id` -> `400`

### Missing Execution

- Nomad job not found -> `404`

### Logs Not Ready

- allocation not created yet -> `409`
- task state not ready for log retrieval -> `409`
- allocation detail missing during log lookup -> `409`

### Runtime Unavailable

- Nomad unreachable
- Nomad returns unusable lifecycle data
- Nomad returns unexpected runtime errors

These map to `503`.

### Failed Workloads

A failed allocation is not an HTTP error for `status`.

ES must return `200` for status and reflect the failure through Nomad-derived fields such as:

- `allocation_client_status`
- `task_state`
- `exit_code`
- `terminal`

ES must not translate a failed workload into a synthetic ES-specific lifecycle phase.

Runtime identity plumbing does not change this rule:

- failure to reach the mounted workload-identity endpoint
- failure to obtain identity material
- failure to authenticate to Vault

remain ordinary container/workload failures. They do not create a new ES lifecycle phase, readiness state, or health model.

## Constraints

The current lifecycle slice is bounded by these rules:

- single meaningful allocation assumption
- no retries
- no reschedule
- no persistence
- no background processes
- no log streaming
- no log pagination
- no allocation aggregation

The single-allocation assumption is valid only because the submit slice disables retries and reschedule. If that changes later, the lifecycle contract must be updated explicitly before implementation changes.

## Invariants

- ES must remain stateless for lifecycle.
- ES must not broaden `:submit` into a persistence or orchestration surface.
- ES must not change Nomad-backed lifecycle semantics silently.
- Any lifecycle contract change must be reflected in `PLANS.md` before code changes land.
