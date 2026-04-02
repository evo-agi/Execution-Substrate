# Execution Lifecycle Implementation

## Current Endpoints

- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- `POST /v1/executions/{run_id}:cancel`

## Execution Flow

### 1. Submit

`POST /v1/executions:submit` reuses the full `:prepare` path first.

ES:

- validates the request
- reads artifact facts from ARS
- resolves workload-zone Vault metadata through ACS
- enforces the EGS TrustModel
- validates the bounded runtime constraints for this slice
- fetches the payload blob from ARS
- stages the payload locally
- builds one Nomad batch job with one Docker task
- submits that job to Nomad

The submit response is a bounded receipt only. It returns:

- `run_id`
- `nomad_job_id`
- `nomad_eval_id`
- `artifact_digest`
- `status = "submitted"`

### 2. Run Resolution

Lifecycle requests do not consult any ES-owned run store.

ES validates `run_id` and derives the Nomad job identifier directly:

- `run_id` must match `run-[0-9a-f]{16}`
- `nomad_job_id = exec-<run_id>`

That mapping is the only lifecycle lookup key ES owns.

### 3. Status

`GET /v1/executions/{run_id}/status`:

- fetches the Nomad job
- fetches that job's allocations
- selects the latest allocation by `ModifyIndex`
- fetches allocation detail
- returns a minimal mapped response

The response may include:

- `job_status`
- `allocation_id`
- `allocation_client_status`
- `task_state`
- `exit_code`
- `terminal`

If the job exists but has no allocation yet, ES returns a valid status response with job-level data only.

### 4. Logs

`GET /v1/executions/{run_id}/logs`:

- fetches the Nomad job
- resolves the latest allocation
- reads stdout only for task `task`
- returns `text/plain`

This endpoint is intentionally minimal:

- no streaming
- no pagination
- no stderr aggregation
- no multi-allocation merge

If the allocation or task logs are not ready yet, ES returns `409`.

### 5. Cancel

`POST /v1/executions/{run_id}:cancel`:

- fetches the Nomad job
- stops the job through Nomad
- does not purge the job

The response is a bounded cancellation receipt only:

- `run_id`
- `nomad_job_id`
- `status = "cancel_requested"`

## What ES Actually Does

ES does:

- derive `nomad_job_id` from `run_id`
- query Nomad job state
- query Nomad allocation state
- query Nomad task stdout
- stop Nomad jobs
- map Nomad data into minimal API responses

## What ES Does Not Do

ES does not:

- store lifecycle state
- cache status or logs
- maintain a run registry
- reconstruct missing state from local side effects
- aggregate multiple allocations into a synthetic view
- maintain retries or reschedule policy
- run background lifecycle workers
- own execution state after submission
