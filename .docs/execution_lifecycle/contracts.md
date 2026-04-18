# Execution Lifecycle Contracts

## 1. Purpose and status

This document defines the current ES lifecycle and public execution contract in the repository's bounded platform phase.

Some lifecycle endpoints are live today but intentionally bounded. This file is authoritative for current endpoint, response, error, and lookup semantics. `.docs/execution_lifecycle/design.md` is the higher-level lifecycle design map, and `.docs/execution_lifecycle/implementation.md` records lower-level implementation behavior.

Control Plane may consume the accepted lifecycle surface, including the bounded `control-plane-normal-shell/v1` runtime-profile path, but CP documents, probes, examples, and proof harnesses do not define ES lifecycle contracts. Any widening or breaking change must be planned in `PLANS.md` and the ES docs before implementation spreads outward.

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
| `GET /v1/executions:contract` | Return the narrow producer compatibility declaration for the current governed-execution contract | Active and bounded | `200` JSON `ProducerContractDeclaration` | ES-owned static compatibility declaration, not readiness or run authority |
| `POST /v1/executions:prepare` | Return bounded preflight success without creating execution state | Active and bounded | `200` JSON `PrepareResult` | ES-owned admission composition surface |
| `POST /v1/executions:submit` | Perform real execution submission | Active and bounded | `202` JSON `SubmitResult` | ES hands off to Nomad |
| `GET /v1/executions/{run_id}/status` | Return current execution status view plus bounded projection revision | Active | `200` JSON `ExecutionStatusResult` | Nomad-backed status projection through ES |
| `GET /v1/executions/{run_id}/logs` | Return execution logs | Active and bounded | `200` `text/plain` | Nomad-backed stdout retrieval through ES |
| `GET /v1/executions/{run_id}/result` | Return retained terminal result bundle | Active and bounded | `200` `application/gzip` | ES-owned retained opaque bundle for current static-script slice |
| `POST /v1/executions/{run_id}:cancel` | Request cancellation of a submitted execution | Active and bounded | `200` JSON `ExecutionCancelResult` | Bounded Nomad stop request through ES |

`POST /v1/executions:prepare` is a live public endpoint in the current repo. It must not be omitted from contract documentation just because it is bounded.

## 4. Caller authorization contract

**Observed current contract**

- All lifecycle/execution endpoints require an authenticated caller identity.
- Bootstrap PKI callers are rejected for execution operations.
- Accepted caller identities are the SPIFFE paths whose prefixes match `authorization.allowed_spiffe_path_prefixes` in ES config.
- The current repo-owned runbooks, proofs, and generated helper configs keep that allowlist operator-only:
  - `spiffe://execution.internal/operator`
- The first repo-owned non-operator caller activation path is Control Plane at:
  - `spiffe://execution.internal/service/control-plane`
- The current prefix-based allowlist model is sufficient for that activation when configured narrowly with `service/control-plane`; a broad `service/` allowlist is not required
- The repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`, paired with `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
- That direct example currently exercises AGS publish plus ES submit, status, and logs over the real HTTPS+mTLS API surface by default, and it can additionally exercise `cancel` when `CANCEL_AFTER_SUBMIT=1 FETCH_LOGS=0` is paired with a long-running payload
- When that direct example waits for terminal status outside explicit cancel mode, it now fails fast if ES reports a terminal nonzero workload exit instead of printing a false success marker
- On this Mac, the supported-local guest path is the grounded positive verification path for that bounded `logs` step
- The focused app integration harness at `es/app/control_plane_integration_path_test.go` remains the repo-owned verification layer for the same direct API path, including disallowed-caller failures, while staying bounded to publish, submit, status, and cancel coverage in the host-local harness
- The runbooks, proofs, and helper scripts remain operator-only by default
- These caller rules apply to:
  - `:contract`
  - `:prepare`
  - `:submit`
  - `status`
  - `logs`
  - `result`
  - `cancel`

**Current contract invariants**

- Missing authenticated caller identity returns `401`.
- Bootstrap PKI callers return `403`.
- Authenticated callers outside the configured allowlist return `403`.

**Response semantics**

- Authorization failures are plain-text responses, not JSON lifecycle error payloads.
- Once authorization succeeds, endpoint failures are returned as JSON `ErrorResponse` payloads except for successful `logs`, which returns `text/plain`, and successful `result`, which returns binary `application/gzip`.

## 4A. Producer Contract Declaration

### Purpose

`GET /v1/executions:contract` returns a non-secret, non-run-specific declaration for the current governed-execution producer compatibility surface.

It exists so Control Plane or an infrastructure manager can fail fast when a pointed-at ES instance does not declare the current producer contract before a high-value run is submitted.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these fields:

- `schema_version = "execution-substrate.producer-contract/v1"`
- `service = "execution"`
- `governed_execution`
  - `contract = "governed-execution-producer/v1"`
  - `enabled`
  - optional `disabled_reason`
  - `runtime_profiles`
  - `outcome_evidence`
- `non_authority`

The `outcome_evidence` declaration says that the current governed-execution producer contract requires:

- status JSON to include `outcome_evidence`
- cancel JSON to include `outcome_evidence`
- successful logs responses to preserve `text/plain; charset=utf-8` and expose outcome evidence through `Execution-Substrate-Outcome-*` headers
- successful result responses to preserve `application/gzip` and expose outcome evidence through `Execution-Substrate-Outcome-*` headers

The declared evidence labels are the current bounded vocabulary:

- status observations from Nomad: `nomad_job_projection`, `nomad_projected_allocation`, and `nomad_task_state_projection`
- cancel receipt observation from Nomad: `nomad_stop_request_accepted`
- logs observation from Nomad: `nomad_task_stdout` with access class `plaintext_stdout`
- result observation from the ES retained-result store: `retained_result_bundle` with access class `opaque_result_bundle`

When ES submit configuration is absent, `governed_execution.enabled` is `false` with `disabled_reason = "submit_not_configured"`. This is an early compatibility failure for current live governed-execution clients; it is not a health failure.

Runtime-profile entries are configuration-aware:

- `static-script/default` is `enabled` only when submit is configured
- `control-plane-normal-shell/v1` is `enabled` only when submit is configured and `execution.runtime_profiles.control_plane_normal_shell.enabled=true`

### Current contract invariants

- The declaration is read-only and non-secret.
- The declaration is served only after the same authenticated caller and configured SPIFFE allowlist check used by the execution and lifecycle API.
- The declaration is not service health, submit readiness, artifact-specific admission proof, run existence proof, lifecycle state, lifecycle write coordination, credential possession, policy approval, or scheduler API.
- The declaration must not expose Nomad job IDs, allocation IDs, task IDs, host paths, result filesystem paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, or policy approval state.
- Consumers may use the declaration as an early compatibility gate by requiring `governed_execution.contract = "governed-execution-producer/v1"`, `governed_execution.enabled = true`, and mandatory status/cancel/logs/result outcome-evidence surfaces.
- Consumers that require the bounded Control Plane normal-shell path must also require an enabled `control-plane-normal-shell/v1` runtime-profile entry.
- Consumers must still use `/health`, submit-readiness checks, and `:prepare` for service health, environment readiness, and artifact-specific admission proof.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |

### Bounded slice notes

**Bounded slice contract**

- The declaration is a narrow compatibility-gate surface for the current CP governed-execution producer path.
- It describes the current producer contract; it does not create a broad capability registry or a cross-service probing framework.
- It does not replace the existing submit-ready operator checks.

### Reopened seams

**Reopened lifecycle seams**

- The long-term ES public execution shape remains reopened.
- The declaration is retained as current compatibility support while the request, runtime-profile, lifecycle, and evidence vocabularies remain bounded.

## 5. Prepare contract

### Purpose

`POST /v1/executions:prepare` returns bounded preflight success for a requested artifact execution without creating execution state.

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
- The only currently defined runtime-profile annotation is `execution_substrate.runtime_profile`. Omitted or empty keeps the default current `static-script` runtime behavior; `control-plane-normal-shell/v1` opts in to the bounded Control Plane normal-shell runtime profile.

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
  - target paths under `/execution/mounts`
  - no overlap between mount targets
- If `execution_substrate.runtime_profile` is present, it must name a runtime profile ES supports and has enabled in config. Unsupported or disabled profile selections fail during `:prepare` before any run ID exists.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these contract fields:

- `success`

### Current invariants

**Current contract invariants**

- `:prepare` reads the registered artifact discovery record from ARS and follows it to the aggregate artifact-evidence blob.
- `:prepare` requires aggregate artifact evidence and verifies that record before success.
- `:prepare` verifies publish-time evidence and EGS runtime-trust constraints before success.
- `:prepare` resolves workload-zone vault information through the configured workload-zone Vault config reference and ARS before success.
- `:prepare` does not surface EGS publication metadata or internal composition detail as part of its preparation result.
- Successful `:prepare` returns bounded preflight success only, not execution state.

### Explicit non-effects

- No `run_id` is created.
- No Nomad job or eval ID is returned.
- No scheduler handoff occurs.
- No proto-execution state or durable ES execution record is created.
- No workload-vault plan, signer detail, or workload identity detail is returned.

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
| Unsupported, disabled, or invalid runtime profile selection | `400` | `unsupported_runtime_profile` |
| Dependency payload invalid or dependency request failed | `503` | current endpoint-specific code is preserved and the logical class remains the same as the missing dependency |

### Bounded slice notes

**Bounded slice contract**

- `:prepare` is active today but intentionally bounded.
- It proves preflight success only.
- It does not create a long-lived execution object, scheduler record, or wider lifecycle surface.

### Reopened seams

**Reopened lifecycle seams**

- The public role and future of `:prepare`
- The long-term shape of the preparation result
- The extent to which preflight success should remain part of a public execution contract

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
- `invocation.annotations["execution_substrate.runtime_profile"]="control-plane-normal-shell/v1"` selects the bounded Control Plane normal-shell runtime profile. That profile remains a `static-script` overlay and additionally requires:
  - explicit ES config under `execution.runtime_profiles.control_plane_normal_shell`
  - `network_access=true`
  - a configured profile image
  - an absolute configured Codex CLI path in that image
  - configured workload-vault secret path and field metadata for Codex credential material
- In the repo-owned supported-local runtime surface, submit-readiness for that enabled profile also requires the configured image to be present and Nomad Docker image cleanup to be disabled through `docker.cleanup.image=false`, so repeated client runs from the same prepared environment are not invalidated merely by Nomad's stopped-task image cleanup.
- Runtime mounts, when present, must satisfy both the prepare-time mount request rules and submit-time reserved-path checks.
- Submit resolves payload bytes through the explicit payload digest carried in aggregate evidence.
- Payload staging, mount staging, and runtime-ready package assembly are now localized behind one internal ES-owned execution-package layout rather than being public contract.
- Successful submit staging remains available only while the running workload may still depend on those host bind mounts. Terminal result files written under the bounded reserved runtime result directory are retained outside staging before successful staging cleanup.
- For the current `static-script` slice, ES reserves `/execution/run/result` as a writable workload-authored terminal output directory. The workload may write result files there, and ES treats those files as opaque bundle content rather than interpreting their semantics.

### Response contract

**Observed current contract**

Successful response is `202` JSON with these fields:

- `success`
- `submitted`
- `run_id`
- `status`
- `authority_handoff`

**Current contract invariants**

- Successful `:submit` returns a bounded submission receipt.
- The receipt confirms execution handoff through `run_id`, not durable ES lifecycle ownership.
- Current successful receipts use `status = "submitted"`.
- Successful receipts include the bounded non-secret `authority_handoff` facts ES selected for the submitted runtime handoff.

### Explicit non-effects

- No durable ES lifecycle record is created.
- No sync execution result is returned.
- No retry or reschedule policy is created.
- No richer scheduler abstraction is exposed.
- No live Vault, Codex, SPIRE, lease, token-expiry, or approval state is returned.

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
| Unsupported, disabled, or invalid runtime profile selection | `400` | `unsupported_runtime_profile` |
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
- It uses the explicit payload reference carried by the ARS discovery record and cross-checks that reference against aggregate evidence rather than treating `artifact_digest` as the payload locator.
- `control-plane-normal-shell/v1` is a bounded runtime contract for the CP-owned normal-shell attempt path, not an ES-owned orchestration, review, checkpoint, or finalization contract.

### Reopened seams

**Reopened lifecycle seams**

- The long-term receipt shape of `:submit`
- The current async-only public contract
- The current execution-package layout and container path conventions behind submission

## 7. Status contract

### Purpose

`GET /v1/executions/{run_id}/status` returns the current status projection for a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` is required in the path.
- ES validates `run_id` before any runtime lookup.
- ES resolves `run_id` through an explicit internal execution-locator policy before reading Nomad.
- Status is read from Nomad job and allocation state.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these current fields:

- `success`
- `run_id`
- `status`
- `lifecycle_projection`
  - `source`
  - `revision`
- `outcome_evidence`
  - `source`
  - `observation`
  - `lifecycle_projection`
    - `source`
    - `revision`
  - `provider_terminal_observed`
- optional `authority_handoff`
- optional `exit_code`
- `terminal`

**Current contract invariants**

- Status is a Nomad-backed projection.
- `lifecycle_projection.source` is `nomad` in the current contract because Nomad is the submitted-execution lifecycle authority.
- `lifecycle_projection.revision` is an opaque equality token derived from the Nomad job and selected-allocation modify indexes observed while serving the status request.
- Callers may compare `lifecycle_projection.revision` values for the same `run_id` to detect that ES observed a different lifecycle projection.
- Callers must not parse or order `lifecycle_projection.revision`, treat it as a Nomad job/allocation identifier, or use it as a write precondition for `logs`, `result`, or `cancel`.
- `authority_handoff`, when present, is recovered from the submitted runtime spec and remains a bounded non-secret read fact. It does not make status a run store, scheduler abstraction, live credential observation, or Control Plane orchestration record.
- If the job exists but no allocation is yet selected, status still succeeds with `status = "submitted"`.
- Once an allocation is selected and not terminal, status returns `status = "running"`.
- Once the selected job/allocation path reaches a terminal state, status returns `status = "terminal"`.
- Failed workloads still return `200`; failure is expressed through terminal state plus `exit_code` when available.
- ES must not synthesize richer lifecycle phases than the current Nomad-backed projection exposes.
- `outcome_evidence` is an additive read-only descriptor for the status observation ES just served. In the current slice its `source` is `nomad`; its `observation` label is one of `nomad_job_projection`, `nomad_projected_allocation`, or `nomad_task_state_projection`; its nested `lifecycle_projection` repeats the opaque status read token; and `provider_terminal_observed` says whether this status read observed a terminal provider state.
- When status observes terminal execution, ES first attempts idempotent retention of any files under `/execution/run/result`.
- When status observes terminal success, ES best-effort removes `execution.staging_root_dir/<run_id>/` only after result retention has been attempted.
- Failed, canceled, lost, or otherwise ambiguous terminal outcomes do not trigger staging cleanup through `status`.

### Authority handoff read surface

**Observed current contract**

`authority_handoff` is present on successful `:submit` responses for new submissions and may be present on `status` responses when ES can recover the submitted handoff facts.

Current shape:

- `authority_path`
- `runtime_profile`
  - `name`
- `identity_handoff`
  - `mode`
  - `endpoint_env`
  - `endpoint_uri`
  - `jwt_svid_target`
- `workload_vault`
  - `auth_mode`
  - `address`
  - `auth_mount`
  - `auth_role`
  - `jwt_audience`
  - optional `ca_cert_env`
  - optional `ca_cert_path`
  - optional `tls_bundle_env`
  - optional `tls_bundle_path`
- `runtime_config_refs`
  - `workload_zone_vault_config`
    - `digest`
- optional `codex_credential_location` for `control-plane-normal-shell/v1`
  - `cli_path`
  - `credential_source`
  - `vault_secret_path`
  - `vault_secret_field`
- `evidence`
  - `source`
  - `runtime_profile`
  - `identity_handoff`
  - `workload_vault`
  - `runtime_config_refs`
  - optional `codex_credential_location`

**Current contract invariants**

- `authority_handoff` is additive and read-only.
- It contains only non-secret handoff facts ES selected, derived, or injected at admission/runtime handoff time.
- It must not expose Nomad job IDs, allocation IDs, task IDs, raw SPIRE socket source paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, token expirations, or rich policy/approval state.
- Its evidence labels identify the bounded source family for each fact; they are not write preconditions and not ordering tokens.

**Bounded slice contract**

- The current `authority_path` is `workload_identity_endpoint/workload_vault`.
- The current identity handoff mode is `workload_identity_endpoint`.
- The current JWT-SVID target label is `workload_vault`.
- The current workload-vault auth mode is `vault_identity_jwt`.
- The current `control-plane-normal-shell/v1` profile may include non-secret Codex credential-location metadata whose credential source is `workload_vault`.

**Deliberate absences**

- No claim that the workload has successfully used the endpoint.
- No claim that a JWT-SVID, Vault token, Codex token, or lease exists or is still valid.
- No claim that ES has observed or approved Control Plane review/checkpoint/finalization state.
- No claim that the submitted scheduler job or selected allocation identifiers are public contract.

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
- The public response no longer carries scheduler job/allocation identifiers or task-state detail.
- The projection revision is the only current status lifecycle read-coordination fact; it does not imply an ES-owned lifecycle-state store.
- `authority_handoff`, when present, is a separate runtime-handoff evidence fact, not a lifecycle revision or write-coordination token.
- `outcome_evidence` is a current-slice status evidence descriptor. It does not make Nomad job IDs, allocation IDs, task IDs, task-state detail, or the current latest-allocation rule public contract.

### Reopened seams

**Reopened lifecycle seams**

- The internal execution-locator policy behind `run_id` lookup
- The current status projection depth
- The extent to which minimal status projection is durable versus slice-bounded

## 8. Logs contract

### Purpose

`GET /v1/executions/{run_id}/logs` returns current execution logs for the selected runtime allocation.

### Lookup contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status`.
- ES resolves logs through the currently projected allocation.

### Response contract

**Observed current contract**

Successful response is:

- `200`
- `Content-Type: text/plain; charset=utf-8`
- stdout payload bytes only
- `Execution-Substrate-Outcome-Source: nomad`
- `Execution-Substrate-Outcome-Observation: nomad_task_stdout`
- `Execution-Substrate-Outcome-Access-Class: plaintext_stdout`
- `Execution-Substrate-Provider-Terminal-Observed: true|false`

**Current contract invariants**

- Logs are resolved from the currently projected allocation only.
- Task name is fixed to `task`.
- Output source is stdout only.
- Successful `200` responses may still carry an empty stdout body if the selected allocation has not produced visible stdout bytes yet.
- The successful response headers are additive descriptors for the bytes being returned. They say ES fetched current stdout through the bounded Nomad log path for the selected task; they are not pagination cursors, log revisions, scheduler IDs, stderr indicators, or write preconditions.
- No streaming, pagination, tailing, stderr aggregation, or multi-allocation merge exists in the current contract.
- If logs observes a terminal task, ES first attempts idempotent retention of any files under `/execution/run/result`.
- If logs observes a terminal successful task, ES may best-effort remove `execution.staging_root_dir/<run_id>/` after reading stdout and attempting result retention.

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

- The internal projected-allocation rule used for log selection
- Current logs minimalism
- The current single-task, stdout-only log contract

## 9. Result contract

### Purpose

`GET /v1/executions/{run_id}/result` returns the retained terminal result bundle for a submitted execution when the current bounded `static-script` workload wrote files under the reserved runtime result directory.

### Runtime output convention

**Bounded slice contract**

- The current `static-script` slice reserves `/execution/run/result` as the workload-authored terminal output directory.
- The workload may create arbitrary regular result files and directories there.
- ES packages retained result content opaquely and does not parse Control Plane semantics, checkpoint decisions, review outcomes, or finalization metadata from those files.
- Host staging paths, Nomad allocation IDs, and Docker bind-mount sources are not part of the client-facing result contract.

**Reopened lifecycle seam**

- `/execution/run/result` is active for this bounded result-materialization slice, but it remains part of the reopened execution-package and runtime path convention surface.

### Lookup and retention contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status` and `logs`.
- Retained result bundles are stored outside `execution.staging_root_dir` under `execution.results_root_dir`.
- Retained bundles are keyed by `run_id`.
- The retained bundle is a tar.gz archive of the reserved result directory contents.
- Result retention is idempotent:
  - repeated terminal `status`, `logs`, and `result` calls are safe
  - if the bundle already exists, ES reuses it
  - successful staging cleanup does not remove retained result bundles
- If no retained bundle exists yet, `result` uses the same bounded Nomad-backed terminal observation model as `status` to decide whether retention can be attempted.

### Response contract

**Observed current contract**

Successful response is:

- `200`
- `Content-Type: application/gzip`
- retained tar.gz bundle bytes
- `Execution-Substrate-Outcome-Source: es_retained_result_store`
- `Execution-Substrate-Outcome-Observation: retained_result_bundle`
- `Execution-Substrate-Outcome-Access-Class: opaque_result_bundle`

**Current contract invariants**

- The result endpoint is a retained output retrieval surface, not a lifecycle-state registry.
- ES does not synthesize Control Plane checkpoints, review decisions, or task-finalization outcomes from retained result files.
- ES does not require callers to know host staging paths, Nomad allocation IDs, or Docker bind-mount sources.
- The successful response headers label the body as an opaque ES-retained result bundle. They do not reveal bundle contents, host paths, retention filesystem paths, or any semantic interpretation of the files inside the archive.
- Logs are not the result contract; stdout remains a separate narrow logs surface.

### Error contract

| Outcome | HTTP | Current code / class |
| --- | --- | --- |
| Missing authenticated caller | `401` | plain text |
| Disallowed or bootstrap caller | `403` | plain text |
| Invalid `run_id` | `400` | `invalid_run_id` |
| Execution not found | `404` | `execution_not_found` |
| Execution is not terminal or retained bundle is not ready | `409` | `result_unavailable` |
| Execution is terminal but no retained result bundle exists | `404` | `result_not_found` |
| Nomad unavailable or unusable runtime response while the endpoint still needs terminal lookup | `503` | `execution_runtime_unavailable` |

### Bounded slice notes

**Bounded slice contract**

- The result endpoint is intentionally limited to retained opaque bundles for the current `static-script` slice.
- It does not introduce background lifecycle reconciliation, callbacks, streaming output, or a broad runtime-output platform.
- It does not change ES into the orchestration owner.

## 10. Cancel contract

### Purpose

`POST /v1/executions/{run_id}:cancel` requests cancellation of a submitted execution.

### Lookup contract

**Observed current contract**

- `run_id` validation and internal execution-locator resolution follow the same rules as `status`.
- ES confirms the job exists, then issues a stop request to Nomad.

### Response contract

**Observed current contract**

Successful response is `200` JSON with these fields:

- `success`
- `run_id`
- `status`
- `outcome_evidence`
  - `source`
  - `observation`
  - `provider_terminal_observed`

**Current contract invariants**

- Current successful cancel receipts use `status = "cancel_requested"`.
- Cancel is a bounded Nomad stop request, not a wider cancellation model.
- `outcome_evidence.source` is `nomad`, `outcome_evidence.observation` is `nomad_stop_request_accepted`, and `outcome_evidence.provider_terminal_observed` is `false` on the current successful receipt because ES has only observed Nomad accepting the stop request, not provider termination.

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
- Cancel does not return proof that the workload has stopped. Callers must use status reads for later terminal observation.

### Reopened seams

**Reopened lifecycle seams**

- The current bounded cancellation receipt shape
- The long-term scope of the public cancel surface

## 11. Run-ID and scheduler lookup contract

**Observed current contract**

- `run_id` must match `run-[0-9a-f]{16}`.
- ES owns one explicit internal execution-locator policy for lifecycle lookup.
- The current locator resolves scheduler lookup as `nomad_job_id = exec-<run_id>`.
- Status, logs, and cancel all depend on this derivation today.
- Status responses expose `lifecycle_projection.revision` instead of exposing that internal scheduler lookup target.

**Current contract invariant**

- This internal locator policy is currently authoritative for lifecycle lookup because ES does not own a separate run registry or lifecycle store.
- The status projection revision is derived after this lookup from Nomad observation, and it does not make the locator mapping public contract.

**What this contract does not imply**

- It does not imply ES owns a richer lifecycle namespace.
- It does not imply the current mapping is architecturally untouchable.
- It does not imply a durable ES execution record exists behind `run_id`.

**Reopened lifecycle seam**

- The mapping is active and meaningful today, but it remains explicitly reopened in the redesign phase.

## 12. Allocation-selection contract

**Observed current contract**

- ES uses one explicit internal projected-allocation policy that currently selects the latest Nomad allocation by `ModifyIndex`.

**Current contract invariant**

- Current logs and detailed status fields are derived from that selected allocation.

**Bounded slice contract**

- This rule is valid only because retries and reschedule are out of scope in the current slice.
- It is not a general multi-allocation lifecycle model.

**Reopened lifecycle seam**

- If multiple meaningful allocations become normal, this rule must be revisited explicitly before contract changes land.

## 13. Failure and status-code matrix

| Outcome | Endpoints | HTTP | Response form | Current code / note |
| --- | --- | --- | --- | --- |
| Successful prepare | `:prepare` | `200` | JSON | `PrepareResult` |
| Successful submit | `:submit` | `202` | JSON | `SubmitResult`, bounded receipt |
| Successful status | `status` | `200` | JSON | `ExecutionStatusResult` |
| Successful logs | `logs` | `200` | `text/plain` | stdout only |
| Successful result | `result` | `200` | `application/gzip` | retained opaque tar.gz result bundle |
| Successful cancel | `cancel` | `200` | JSON | `ExecutionCancelResult` |
| Invalid request body, request validation failure, or request/fact mismatch | `:prepare`, `:submit` | `400` | JSON | `invalid_request` |
| Unsupported, disabled, or invalid runtime profile selection | `:prepare`, `:submit` | `400` | JSON | `unsupported_runtime_profile` |
| Unauthorized caller | all lifecycle/execution endpoints | `401` | plain text | authenticated caller identity required |
| Forbidden caller | all lifecycle/execution endpoints | `403` | plain text | bootstrap or disallowed identity |
| Aggregate artifact evidence invalid during admission | `:prepare`, `:submit` | `403` | JSON | `artifact_evidence_invalid` |
| Aggregate artifact evidence not registered for admission | `:prepare`, `:submit` | `404` | JSON | `artifact_evidence_not_found` |
| Invalid `run_id` | `status`, `logs`, `result`, `cancel` | `400` | JSON | `invalid_run_id` |
| Execution not found | `status`, `logs`, `result`, `cancel` | `404` | JSON | `execution_not_found` |
| Logs not ready | `logs` | `409` | JSON | `logs_unavailable` |
| Result not ready | `result` | `409` | JSON | `result_unavailable` |
| Terminal execution has no retained result bundle | `result` | `404` | JSON | `result_not_found` |
| Aggregate artifact evidence unavailable after registration | `:prepare`, `:submit` | `503` | JSON | `artifact_evidence_unavailable` |
| Nomad unavailable or malformed runtime response | `status`, `logs`, `result` when it still needs terminal lookup, `cancel`, and submit runtime path | `503` | JSON | `execution_runtime_unavailable` or `submission_failed` depending on operation |
| Workload failure reflected in status | `status` | `200` | JSON | failure is expressed in Nomad-derived fields, not a separate HTTP error |

## 14. Runtime identity and lifecycle edge

**Observed current contract-adjacent conventions**

- ES injects the current endpoint-discovery environment conventions:
  - canonical `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://<ES-owned run-scoped endpoint>`
- ES also injects the current non-secret workload-vault runtime inputs derived from the resolved workload-vault auth plan.
  - `VAULT_ADDR`
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`
  - when configured, `VAULT_CACERT=/execution/run/platform/workload-vault-ca.pem`
  - when configured, `SSL_CERT_FILE=/execution/run/platform/workload-ca-bundle.pem`
- For `control-plane-normal-shell/v1` only, ES injects non-secret Codex credential-location metadata:
  - `EXEC_CODEX_CLI_PATH`
  - `EXEC_CODEX_CREDENTIAL_SOURCE=workload_vault`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD`
- The runtime-identity workspace is mounted as writable tmpfs in the current submit slice.
- The bounded slice-1 implementation target keeps the workload-visible endpoint but changes the runtime-side owner behind it to a platform-owned helper launched by a platform-owned supervisor.
- ES exposes the same bounded non-secret facts through `authority_handoff` on submit/status when available. That read surface is evidence of the submitted runtime handoff, not evidence of live credential possession.

**Current contract invariants**

- Caller runtime mounts must not overlap the ES-owned subtree that backs the discovered endpoint.
- ES derives the bounded workload-vault handoff from workload-zone vault runtime fields plus `workload_vault_auth.default_mode`.
- If that runtime config supplies Vault CA trust material, ES stages it as workload-visible trust files and uses standard TLS environment rather than disabling verification.
- ES does not turn runtime identity or Vault-auth failures into a distinct ES lifecycle phase.
- ES does not fetch, mint, broker, validate, or store Codex credential material. The selected workload is responsible for using the existing identity endpoint and workload-vault metadata to read that material.
- ES does not expose live runtime credential state through `authority_handoff`.
- The supported-local proof realization may provide a proof-only deterministic Codex shim at `EXEC_CODEX_CLI_PATH` inside the configured profile image. That shim is proof tooling, not a new ES product API or a claim that ES owns Codex service invocation semantics.
- The first platform-owned runtime-identity slice is intentionally limited to platform-controlled non-root workloads with no privilege-escalation path.
- The public runtime identity endpoint must remain a bounded platform endpoint, not a raw SPIRE proxy.

**Reopened lifecycle seams**

- The reserved-path conventions
- The endpoint environment convention
- The extent to which runtime identity handoff should remain part of the public execution contract

## 15. Bounded slice rules

**Bounded slice contract**

- `:prepare` is active today but bounded.
- `:submit` is bounded async-only submission.
- Latest-allocation selection is a slice rule, not a general lifecycle model.
- Status is a minimal Nomad-backed projection.
- Logs are a minimal latest-allocation stdout contract.
- Result retrieval is a bounded retained opaque bundle contract for `/execution/run/result` in the current `static-script` slice.
- `control-plane-normal-shell/v1` is a bounded runtime-profile slice rule layered on the current `static-script` package/runtime path.
- No retry or reschedule policy is exposed.
- No rich ES-owned lifecycle model is exposed.

These rules are active today, but they should not be preserved by inertia.

## 16. Deliberate absences

**Deliberate absences**

- No ES-owned run persistence
- No ES-owned lifecycle-state store
- No retry or reschedule control surface
- No multi-allocation aggregation API
- No streaming logs contract
- No stderr or multi-task log contract
- No ES interpretation of retained result bundle semantics
- No ES-owned checkpoint, review, or terminal-finalization model
- No synthetic ES lifecycle phases
- No public contract for runtime token minting

## 17. Reopened lifecycle seams

- The public role of `:prepare`
- The bounded receipt shape of `:submit`
- The internal execution-locator policy behind `run_id` lookup
- Latest-allocation selection
- Runtime identity reserved-path conventions
- Current logs minimalism
- Current retained-result bundle convention and `/execution/run/result` runtime path
- Current runtime-profile annotation and the bounded `control-plane-normal-shell/v1` overlay
- The extent to which lifecycle minimalism is durable versus slice-bounded

These seams are active today and intentionally not fixed.

## 18. Decision rules for future edits

- Do not omit active endpoints from this contract document.
- Label bounded slice rules as bounded.
- Keep public response and error semantics here instead of leaving them only in code comments.
- Move implementation detail into `.docs/execution_lifecycle/implementation.md`.
- Keep high-level lifecycle ownership in `.docs/execution_lifecycle/design.md`.
- If code and tests disagree with this file, update this file to match reality.
- Do not describe a contract as fixed unless that decision is explicit and intentional.
