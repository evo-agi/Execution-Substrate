# Execution Lifecycle Design

## Execution Lifecycle Model

The execution lifecycle is intentionally split into two phases:

1. `POST /v1/executions:submit` performs governed admission, stages the payload, and submits one real Nomad batch job.
2. All later lifecycle inspection and control flows through Nomad-backed endpoints:
   - `GET /v1/executions/{run_id}/status`
   - `GET /v1/executions/{run_id}/logs`
   - `POST /v1/executions/{run_id}:cancel`

ES is not a scheduler. ES submits work to Nomad and then reads or forwards lifecycle state from Nomad. ES does not own execution lifecycle state after submission.

## Core Principles

- Nomad is the source of truth for submitted execution state.
- ES is stateless for lifecycle.
- Lifecycle is read-through and control-through, not stateful orchestration.
- Status is a projection of Nomad state, not an ES-owned execution model.
- ES must not persist run state.
- ES must not run background workers or reconciliation loops.
- ES must not add retry or reschedule behavior.
- ES must not invent a private execution model that diverges from Nomad.

## Why This Design Exists

This design exists to avoid duplicate state and the drift that follows from it.

If ES stored its own lifecycle view, it would immediately create two competing truth sources:

- Nomad job and allocation state
- ES-maintained execution state

The Go slice deliberately avoids that split. ES stays thin by:

- validating and submitting once
- deriving lifecycle answers directly from Nomad
- exposing only minimal mapped responses

That keeps the execution boundary explicit:

- Nomad schedules and runs work
- Docker runs the task container
- ES admits, submits, and reads back Nomad state

## Allocation Selection

The current lifecycle slice assumes one meaningful allocation per submitted execution.

ES resolves lifecycle requests by selecting the latest Nomad allocation for the job. That assumption is only valid because the current submit contract disables retries and reschedule. Under the current bounded execution slice, the latest allocation is expected to be the only relevant allocation.

If retries or reschedule are ever introduced, this assumption must be revisited explicitly. ES must not silently continue treating "latest allocation" as a stable lifecycle rule once multiple meaningful allocations can exist.

## Non-Goals

The current design explicitly does not include:

- durable run persistence
- ES-owned log retention
- sync execution
- retries or reschedule
- allocation aggregation across multiple retries
- background cleanup or repair loops
- a richer scheduler abstraction above Nomad

## Anti-Patterns

The following behaviors are explicitly forbidden in this design:

- caching lifecycle responses instead of reading Nomad
- storing execution lifecycle state inside ES
- synthesizing private lifecycle phases not present in Nomad
- aggregating multiple allocations into a synthetic execution timeline
