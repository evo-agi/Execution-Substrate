# Execution Lifecycle Contracts

## 1. Purpose and status

This document defines the current ES lifecycle and public execution contract during an active redesign phase.

Some lifecycle endpoints are live today but intentionally bounded. This file is authoritative for current endpoint, response, error, and lookup semantics. `.docs/execution_lifecycle/design.md` is the higher-level lifecycle design map, and `.docs/execution_lifecycle/implementation.md` records lower-level implementation behavior.

## 2. How to read this document

- **Observed current contract**: A public endpoint, response, error, or lookup rule enforced by the current Go code and tests.
- **Current contract invariant**: A current rule callers and upstream docs can rely on and that must not change silently.
- **Bounded slice contract**: A live contract rule that is intentionally narrow and should not be treated as permanent architecture by default.
- **Deliberate absence**: A lifecycle capability or response surface the current slice intentionally does not offer.
- **Reopened lifecycle seam**: An active lifecycle surface that `PLANS.md` and the redesign-phase docs explicitly keep open.

These labels are intentionally different. A contract may be live today, relied on now, and still explicitly bounded or reopened.

## 3. Endpoint inventory

| Endpoint | Purpose | Current status | Response type | High-level ownership note |
| --- | --- | --- | --- | --- |
| `POST /v1/executions:prepare` | Return admission and preparation facts without creating execution state | Active and bounded | `200` JSON `PrepareResult` | ES-owned admission composition surface |
| `POST /v1/executions:submit` | Perform real execution submission | Active and bounded | `202` JSON `SubmitResult` | ES hands off to Nomad |
| `GET /v1/executions/{run_id}/status` | Return current execution status view | Active | `200` JSON `ExecutionStatusResult` | Nomad-backed status projection through ES |
| `GET /v1/executions/{run_id}/logs` | Return execution logs | Active and bounded | `200` `text/plain` | Nomad-backed stdout retrieval through ES |
| `POST /v1/executions/{run_id}:cancel` | Request cancellation of a submitted execution | Active and bounded | `200` JSON `ExecutionCancelResult` | Bounded Nomad stop request through ES |

`POST /v1/executions:prepare` is a live public endpoint in the current repo. It must not be omitted from contract documentation just because it is bounded.

## 4. Caller authorization contract

**Observed current contract**

- All five lifecycle/execution endpoints require an authenticated caller identity.
- Bootstrap PKI callers are rejected for execution operations.
- Current accepted caller identities are:
  - `spiffe://monolith.internal/service/deployment`
  - `spiffe://monolith.internal/operator`
- These caller rules apply to:
  - `:prepare`
  - `:submit`
  - `status`
  - `logs`
  - `cancel`

**Current contract invariants**

- Missing authenticated caller identity returns `401`.
- Bootstrap PKI callers return `403`.
- Authenticated callers outside the accepted identities return `403`.

**Response semantics**

- Authorization failures are plain-text responses, not JSON lifecycle error payloads.
- Once authorization succeeds, endpoint failures are returned as JSON `ErrorResponse` payloads except for successful `logs`, which returns `text/plain`.

## 5. Prepare contract

### Purpose

`POST /v1/executions:prepare` returns admission and preparation facts for a requested artifact execution without creating execution state.

### Request contract

**Observed current contract**

- Request body is JSON using the current shared execution request shape also used by `:submit`.
- The current top-level request includes:
  - `schema_version`
  - `invocation`
  - `mode`
  - `timeout_seconds`
  - `resources`
- The current invocation payload includes:
  - `schema_version`
  - `artifact_digest`
  - `derivation_spec_digest`
  - `output_id`
  - optional `argv`
  - optional `env`
  - optional `mounts`
  - optional `annotations`

**Current contract invariants**

- `invocation.artifact_digest` must be a labeled SHA-256 digest.
- `invocation.derivation_spec_digest` must be a labeled SHA-256 digest.
- `invocation.output_id` is required.
- `timeout_seconds` must be non-negative.
- If `resources` is present, both CPU and memory must be greater than zero.
- If `mode` is present, it must be `sync` or `async`.
- Environment keys must not use reserved runtime/control-plane keys.
- If the manifest runtime interface declares allowed environment keys, provided keys must stay within that set.
- If mounts are provided, they must satisfy the current mount contract:
  - artifact-backed
  - read-only
  - absolute cleaned target paths
  - target paths under `/monolith/mounts`
  - no overlap between mount targets

### Response contract

**Observed current contract**

Successful response is `200` JSON with these contract fields:

- `success`
- `artifact_digest`
- `derivation_spec_digest`
- `output_id`
- `intent_digest`
- `artifact_type`
- `provenance`
- `workload`
- `workload_vault`

The response is an admission/preparation fact bundle. It includes current publication signer info, workload identity info, and resolved workload-vault info.

### Current invariants

**Current contract invariants**

- `:prepare` reads the registered artifact descriptor from ARS and follows it to the aggregate artifact-evidence blob.
- `:prepare` requires aggregate artifact evidence and verifies that record before success.
- `:prepare` verifies publish-time evidence and EGS runtime-trust constraints before success.
- `:prepare` resolves workload-zone vault information through ACS and ARS before success.
- `:prepare` does not surface EGS publication metadata as part of its preparation result.
- Successful `:prepare` returns preparation facts only, not execution state.

### Explicit non-effects

- No `run_id` is created.
- No Nomad job or eval ID is returned.
- No scheduler handoff occurs.
- No proto-execution state or durable ES execution record is created.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Malformed request body, invalid request fields, or request/fact mismatch | `400` | `invalid_request` |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Aggregate artifact evidence is structurally invalid or fails signature verification | `403` | `artifact_evidence_invalid` |
| Signer not allowed | `403` | `signer_not_allowed` |
| Signer revoked | `403` | `signer_revoked` |
| Artifact revoked | `403` | `artifact_revoked` |
| Aggregate artifact evidence not registered for the artifact | `404` | `artifact_evidence_not_found` |
| Trust model unavailable | `503` | `trust_model_unavailable` |
| Aggregate artifact evidence blob or response is unavailable after registration | `503` | `artifact_evidence_unavailable` |
| Workload-zone vault lookup or blob unavailable | `503` | `workload_zone_vault_unavailable` |
| Dependency payload invalid or dependency request failed | `503` | current endpoint-specific code is preserved and the logical class remains the same as the missing dependency |

### Bounded slice notes

**Bounded slice contract**

- `:prepare` is active today but intentionally bounded.
- It proves admission and preparation facts only.
- It does not create a long-lived execution object, scheduler record, or wider lifecycle surface.

### Reopened seams

**Reopened lifecycle seams**

- The public role and future of `:prepare`
- The long-term shape of the preparation result
- The extent to which current preparation facts should remain part of a public execution contract

## 6. Submit contract

### Purpose

`POST /v1/executions:submit` performs real execution submission in the current slice.

### Request contract

**Observed current contract**

- Request body uses the same JSON execution request shape as `:prepare`.
- The request is revalidated through the full preparation path before submission proceeds.

**Current contract invariants**

- Omitted `mode` defaults to `async`.
- Only `async` submission is supported in the current slice.
- The current execution slice only accepts:
  - `static-script` artifacts
  - no required runtime capabilities
  - `target_platform` unset or `docker`
- Runtime mounts, when present, must satisfy both the prepare-time mount request rules and submit-time reserved-path checks.
- Submit resolves payload bytes through the explicit payload digest carried in aggregate evidence.

### Response contract

**Observed current contract**

Successful response is `202` JSON with these fields:

- `success`
- `submitted`
- `run_id`
- `nomad_job_id`
- `nomad_eval_id`
- `artifact_digest`
- `status`

**Current contract invariants**

- Successful `:submit` returns a bounded submission receipt.
- The receipt confirms Nomad handoff, not durable ES lifecycle ownership.
- Current successful receipts use `status = "submitted"`.

### Explicit non-effects

- No durable ES lifecycle record is created.
- No sync execution result is returned.
- No retry or reschedule policy is created.
- No richer scheduler abstraction is exposed.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Malformed or invalid request body | `400` | `invalid_request` |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Prepare-time validation or trust errors | same as `:prepare` | propagated |
| Unsupported submission mode | `400` | `unsupported_execution_mode` |
| Unsupported artifact type or target platform | `400` | `unsupported_artifact_type` |
| Unsupported required capabilities | `400` | `unsupported_capabilities` |
| Mount conflict or reserved-path overlap | `409` | `mount_conflict` |
| Invalid or unusable mount artifact | `409` | `mount_artifact_invalid` |
| Payload unavailable | `503` | `payload_unavailable` |
| Execution runtime unavailable | `503` | `execution_runtime_unavailable` |
| Nomad submission failed | `503` | `submission_failed` |

### Bounded slice notes

**Bounded slice contract**

- `:submit` is the real execution surface, but it is intentionally narrow.
- It is async-only.
- Its response is a bounded receipt, not a durable run model.
- It uses the explicit payload reference carried by the ARS descriptor and cross-checks that reference against aggregate evidence rather than treating `artifact_digest` as the payload locator.

### Reopened seams

**Reopened lifecycle seams**

- The long-term receipt shape of `:submit`
- The current async-only public contract
- The current payload-resolution and staging assumptions behind submission

## 7. Status contract

### Purpose

`GET /v1/executions/{run_id}/status` returns the current status projection for a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` is required in the path.
- ES validates `run_id` before any runtime lookup.
- ES derives `nomad_job_id` from `run_id` and uses that as the current lifecycle lookup path.
- Status is read from Nomad job and allocation state.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these current fields:

- `success`
- `run_id`
- `nomad_job_id`
- `job_status`
- optional `allocation_id`
- optional `allocation_client_status`
- optional `task_state`
- optional `exit_code`
- `terminal`

**Current contract invariants**

- Status is a Nomad-backed projection.
- If the job exists but no allocation is yet selected, status still succeeds with job-level data only.
- Failed workloads still return `200`; failure is expressed through Nomad-derived fields such as allocation status, task state, exit code, and terminal state.
- ES must not synthesize richer lifecycle phases than the current Nomad-backed projection exposes.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- Status is intentionally minimal.
- The contract is built around current Nomad projection rather than a richer ES-owned execution model.
- Allocation detail is optional in the successful response.

### Reopened seams

**Reopened lifecycle seams**

- The `run_id -> nomad_job_id` lookup rule
- The current status projection depth
- The extent to which minimal status projection is durable versus slice-bounded

## 8. Logs contract

### Purpose

`GET /v1/executions/{run_id}/logs` returns current execution logs for the selected runtime allocation.

### Lookup contract

**Observed current contract**

- `run_id` validation and `nomad_job_id` derivation follow the same rules as `status`.
- ES resolves logs through the latest selected allocation.

### Response contract

**Observed current contract**

Successful response is:

- `200`
- `Content-Type: text/plain; charset=utf-8`
- stdout payload bytes only

**Current contract invariants**

- Logs are resolved from the latest allocation only.
- Task name is fixed to `task`.
- Output source is stdout only.
- No streaming, pagination, tailing, stderr aggregation, or multi-allocation merge exists in the current contract.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Allocation or logs not ready | `409` | `logs_unavailable` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- Latest-allocation-only lookup is a bounded rule.
- The logs contract is intentionally narrow:
  - task `task`
  - stdout only
  - `text/plain`
  - no streaming
  - no pagination
  - no stderr aggregation

### Reopened seams

**Reopened lifecycle seams**

- Latest-allocation-only log selection
- Current logs minimalism
- The current single-task, stdout-only log contract

## 9. Cancel contract

### Purpose

`POST /v1/executions/{run_id}:cancel` requests cancellation of a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` validation and `nomad_job_id` derivation follow the same rules as `status`.
- ES confirms the job exists, then issues a stop request to Nomad.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these fields:

- `success`
- `run_id`
- `nomad_job_id`
- `status`

**Current contract invariants**

- Current successful cancel receipts use `status = "cancel_requested"`.
- Cancel is a bounded Nomad stop request, not a wider cancellation model.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Nomad unavailable or unusable runtime response | `503` | `execution_runtime_unavailable` |

### Explicit non-effects

- Cancel does not create a richer cancellation state model.
- Cancel does not purge the Nomad job.
- Cancel does not create a durable ES cancellation record.

### Reopened seams

**Reopened lifecycle seams**

- The current bounded cancellation receipt shape
- The long-term scope of the public cancel surface

## 10. Run-ID and scheduler lookup contract

**Observed current contract**

- `run_id` must match `run-[0-9a-f]{16}`.
- Current derived scheduler lookup is `nomad_job_id = exec-<run_id>`.
- Status, logs, and cancel all depend on this derivation today.

**Current contract invariant**

- This mapping is currently authoritative for lifecycle lookup because ES does not own a separate run registry or lifecycle store.

**What this contract does not imply**

- It does not imply ES owns a richer lifecycle namespace.
- It does not imply the current mapping is architecturally untouchable.
- It does not imply a durable ES execution record exists behind `run_id`.

**Reopened lifecycle seam**

- The mapping is active and meaningful today, but it remains explicitly reopened in the redesign phase.

## 11. Allocation-selection contract

**Observed current contract**

- ES selects the latest Nomad allocation by `ModifyIndex`.

**Current contract invariant**

- Current logs and detailed status fields are derived from that selected allocation.

**Bounded slice contract**

- This rule is valid only because retries and reschedule are out of scope in the current slice.
- It is not a general multi-allocation lifecycle model.

**Reopened lifecycle seam**

- If multiple meaningful allocations become normal, this rule must be revisited explicitly before contract changes land.

## 12. Failure and status-code matrix

| Outcome | Endpoints | HTTP | Response form | Current code / note |
| --- | --- | --- | --- | --- |
| Successful prepare | `:prepare` | `200` | JSON | `PrepareResult` |
| Successful submit | `:submit` | `202` | JSON | `SubmitResult`, bounded receipt |
| Successful status | `status` | `200` | JSON | `ExecutionStatusResult` |
| Successful logs | `logs` | `200` | `text/plain` | stdout only |
| Successful cancel | `cancel` | `200` | JSON | `ExecutionCancelResult` |
| Invalid request body, request validation failure, or request/fact mismatch | `:prepare`, `:submit` | `400` | JSON | `invalid_request` |
| Unauthorized caller | all lifecycle/execution endpoints | `401` | plain text | authenticated caller identity required |
| Forbidden caller | all lifecycle/execution endpoints | `403` | plain text | bootstrap or disallowed identity |
| Aggregate artifact evidence invalid during admission | `:prepare`, `:submit` | `403` | JSON | `artifact_evidence_invalid` |
| Aggregate artifact evidence not registered for admission | `:prepare`, `:submit` | `404` | JSON | `artifact_evidence_not_found` |
| Invalid `run_id` | `status`, `logs`, `cancel` | `400` | JSON | `invalid_run_id` |
| Execution not found | `status`, `logs`, `cancel` | `404` | JSON | `execution_not_found` |
| Logs not ready | `logs` | `409` | JSON | `logs_unavailable` |
| Aggregate artifact evidence unavailable after registration | `:prepare`, `:submit` | `503` | JSON | `artifact_evidence_unavailable` |
| Nomad unavailable or malformed runtime response | `status`, `logs`, `cancel`, and submit runtime path | `503` | JSON | `execution_runtime_unavailable` or `submission_failed` depending on operation |
| Workload failure reflected in status | `status` | `200` | JSON | failure is expressed in Nomad-derived fields, not a separate HTTP error |

## 13. Runtime identity and lifecycle edge

**Observed current contract-adjacent conventions**

- ES injects the current endpoint environment convention:
  - `MONOLITH_WORKLOAD_IDENTITY_ENDPOINT=unix:///monolith/runtime-identity/endpoint`
- ES also injects the current non-secret workload-vault runtime inputs derived from `workload_vault`.
- The runtime-identity workspace is mounted as writable tmpfs in the current submit slice.

**Current contract invariants**

- Caller runtime mounts must not overlap the ES-owned subtree that backs the discovered endpoint.
- ES derives the bounded workload-vault handoff from workload-zone vault runtime fields plus `workload_vault_auth.default_mode`.
- ES does not turn runtime identity or Vault-auth failures into a distinct ES lifecycle phase.

**Reopened lifecycle seams**

- The reserved-path conventions
- The endpoint environment convention
- The extent to which runtime identity handoff should remain part of the public execution contract

## 14. Bounded slice rules

**Bounded slice contract**

- `:prepare` is active today but bounded.
- `:submit` is bounded async-only submission.
- Latest-allocation selection is a slice rule, not a general lifecycle model.
- Status is a minimal Nomad-backed projection.
- Logs are a minimal latest-allocation stdout contract.
- No retry or reschedule policy is exposed.
- No rich ES-owned lifecycle model is exposed.

These rules are active today, but they should not be preserved by inertia.

## 15. Deliberate absences

**Deliberate absences**

- No ES-owned run persistence
- No ES-owned lifecycle-state store
- No retry or reschedule control surface
- No multi-allocation aggregation API
- No streaming logs contract
- No stderr or multi-task log contract
- No synthetic ES lifecycle phases
- No public contract for runtime token minting

## 16. Reopened lifecycle seams

- The public role of `:prepare`
- The bounded receipt shape of `:submit`
- The `run_id -> nomad_job_id` lookup rule
- Latest-allocation selection
- Runtime identity reserved-path conventions
- Current logs minimalism
- The extent to which lifecycle minimalism is durable versus slice-bounded

These seams are active today and intentionally not fixed.

## 17. Decision rules for future edits

- Do not omit active endpoints from this contract document.
- Label bounded slice rules as bounded.
- Keep public response and error semantics here instead of leaving them only in code comments.
- Move implementation detail into `.docs/execution_lifecycle/implementation.md`.
- Keep high-level lifecycle ownership in `.docs/execution_lifecycle/design.md`.
- If code and tests disagree with this file, update this file to match reality.
- Do not describe a contract as fixed unless that decision is explicit and intentional.
