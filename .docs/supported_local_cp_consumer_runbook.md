# Supported-Local Control Plane Consumer Runbook

## 1. Purpose and status

This runbook is the canonical Execution Substrate-side operator reference for the bounded supported-local Control Plane consumer path.

It explains what ES owns when Control Plane consumes the accepted supported-local governed-execution surface, how to interpret ES readiness and runtime-contract signals, and where to route common blockers.

Status classification:

- The supported-local CP consumer path is a `Bounded slice rule`.
- `control-plane-normal-shell/v1` is a bounded runtime-profile overlay on the current `static-script` package/runtime path.
- The runtime-profile annotation, retained-result bundle shape, `/execution/...` runtime paths, and runtime identity endpoint convention remain active compatibility-heavy conventions on reopened ES seams.
- This runbook documents accepted current behavior. It does not settle the long-term ES request model, package model, runtime-profile vocabulary, or runtime path layout.

Authority boundary:

- This runbook documents how CP consumes an accepted ES-owned surface; it is not the source of truth for ES core contracts.
- If CP documents, probes, examples, or proof-harness expectations ask for behavior beyond `PLANS.md`, `.docs/system_overview/`, and `.docs/execution_lifecycle/`, treat that as a cross-repo compatibility decision to coordinate rather than as an implicit ES contract.
- Preserving the current CP path matters, but widening ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness semantics requires ES-side planning and boundary-doc updates first.

Use this alongside:

- [Control Plane long-running operator mode contract](../../Control%20Plane/.docs/long-running-operator-mode-contract.md)
- [Remote Supported-Host Alpha 0.3](system_overview/remote_supported_host_alpha.md)
- [system_overview/contracts.md](system_overview/contracts.md)
- [system_overview/boundaries.md](system_overview/boundaries.md)
- [execution_lifecycle/contracts.md](execution_lifecycle/contracts.md)
- [execution_lifecycle/implementation.md](execution_lifecycle/implementation.md)
- [system_overview/supported_linux_host_qualification.md](system_overview/supported_linux_host_qualification.md)

## 2. Accepted scope

This runbook covers the bounded supported-local CP consumer path only.

In scope:

- AGS publication plus ES prepare, submit, lifecycle, logs, result, and cancel over the real HTTPS+mTLS API surface
- the ES-owned governed Docker/Nomad runtime realization for the current supported-local path
- the opt-in `control-plane-normal-shell/v1` runtime profile
- ES submit-readiness truth for that profile in a prepared supported-local environment
- ES workload-visible identity, workload-Vault metadata, and trust-material handoff
- retained opaque result bundles fetched from ES by `run_id`

Out of scope:

- production Codex availability
- production Vault lifecycle, policy, auth-method, token, or secret ownership
- making remote normal-shell the default path
- making `control-plane-normal-shell/v1` a general package-kind redesign or developer image marketplace
- Control Plane orchestration, review, checkpoint, acceptance, revision, failure, hold/resume/reject, escalation, or finalization semantics
- Infra Manager bootstrap, profile emission, long-lived environment lifecycle, or reconciliation ownership
- production-readiness claims for the local proof substrate

The supported-local proof image may provide a deterministic proof-only Codex shim at the configured `EXEC_CODEX_CLI_PATH`. That proves the ES runtime contract for the CP normal-shell path without proving live upstream Codex service behavior.

## 3. Ownership boundaries

ES owns:

- governed execution admission and submit-time runtime realization
- the ES runtime profile selection and configured runtime image choice
- the platform-owned runtime identity handoff boundary
- non-secret workload-Vault auth metadata and Codex credential-location metadata
- staging of non-secret Vault CA trust material when the workload-zone Vault config supplies it
- Nomad-backed status/log/result/cancel projection through public ES endpoints
- the status `lifecycle_projection` source and opaque revision as a bounded read-coordination fact
- additive outcome-evidence descriptors on status/cancel JSON and successful logs/result responses for the exact current response source ES observed or retained
- bounded non-secret `authority_handoff` facts on submit/status for the selected runtime profile, workload identity endpoint handoff, workload-Vault auth metadata, selected workload-zone Vault config digest, and profile credential-location metadata
- retained opaque `result.tar.gz` bundles captured from `/execution/run/result`
- the truth of whether this repo's readiness helpers can honestly claim `submit-ready`

The Control Plane long-running operator mode contract freezes how those ES
facts may be consumed by browser/API operator mode: ES provider run ids,
status/log/result/cancel responses, status projection revisions, retained
bundles, runtime-profile evidence, and submit-readiness are runtime evidence,
not Control Plane orchestration truth. ES retained results remain opaque output
material; Control Plane owns
their semantic validation and any review, checkpoint, hold/resume/reject, or
terminal run decision.

Control Plane owns:

- orchestration, review, checkpoint, finalization, and terminal run semantics
- task-attempt progression and CP proof-harness expectations above the ES API
- semantic interpretation of retained result bundle contents
- Codex invocation semantics above the bounded ES runtime/tooling contract

Infra Manager owns:

- environment bootstrap and lifecycle outside this repo's proof-scoped helpers
- emission of the CP-consumable supported-local profile
- long-lived substrate and service lifecycle coordination outside the bounded ES proof path

ES does not fetch, mint, broker, store, rotate, parse, or validate Vault tokens or Codex tokens for CP. The workload uses the runtime identity endpoint plus workload-Vault metadata to acquire credential material itself.

Releaseability and scaling alignment for CP consumers:

- CP's v1 console/API contract may rely on ES endpoint names, response classes,
  retained opaque bundle behavior, and `control-plane-normal-shell/v1` only as
  the bounded compatibility surface named in the adjacent CP contract.
- ES must not present provider run ids, Nomad lifecycle projection, retained
  bundles, health/readiness signals, helper examples, or supported-local proof
  output as CP release, rollback, orchestration, review, checkpoint, or
  intervention authority.
- Any change that breaks the current CP publish -> prepare -> submit ->
  status/logs/result/cancel sequence, runtime-profile name, or retained opaque
  bundle semantics needs an explicit cross-repo compatibility, drain, or
  versioning plan before CP productization depends on it.
- ES `/health` remains service health. Supported-local submit claims still come
  from the submit-ready check described below, not from a single endpoint probe.
- ES `GET /v1/executions:contract` is the current producer-side compatibility
  declaration for the governed-execution contract and mandatory outcome-evidence
  surfaces. It is not service health, submit readiness, run authority,
  credential truth, lifecycle write coordination, or scheduler API.

## 4. Real client surface

The CP-facing programmatic surface is the HTTPS+mTLS API boundary.

Publication:

- `POST /v1/artifacts:publish` on AGS

Execution and lifecycle:

- `GET /v1/executions:contract` on ES
- `POST /v1/executions:prepare` on ES
- `POST /v1/executions:submit` on ES
- `GET /v1/executions/{run_id}/status` on ES
- `GET /v1/executions/{run_id}/logs` on ES
- `GET /v1/executions/{run_id}/result` on ES
- `POST /v1/executions/{run_id}:cancel` on ES

Status responses include `lifecycle_projection.source` and
`lifecycle_projection.revision`. CP may compare revisions for the same `run_id`
to detect a changed ES lifecycle observation, but must treat the revision as
opaque. It is not a Nomad job/allocation identifier, not a cancel/result/logs
write precondition, and not a Control Plane orchestration checkpoint.

Status and cancel JSON responses include additive `outcome_evidence`.
Successful logs and result responses expose the same outcome-evidence family as
HTTP headers:

- `Execution-Substrate-Outcome-Source`
- `Execution-Substrate-Outcome-Observation`
- `Execution-Substrate-Outcome-Access-Class`
- `Execution-Substrate-Provider-Terminal-Observed` for logs

CP may use these labels to tell whether ES served a Nomad-backed status
projection, accepted Nomad stop request receipt, Nomad task stdout body, or
opaque ES-retained result bundle. CP must not treat them as scheduler IDs,
global run revisions, write preconditions, stdout/stderr completeness, cancel
completion proof, retained-result content meaning, policy truth, or credential
truth.

Submit responses, and status responses when the submitted handoff facts are
recoverable, include `authority_handoff`. CP may use that field as ES-owned
evidence of the submitted runtime authority path: runtime profile,
workload-visible identity endpoint, workload-Vault auth metadata, selected
workload-zone Vault config digest, and bounded profile credential-location
metadata. CP must not treat it as proof that the workload successfully fetched
a JWT-SVID, logged into Vault, holds a token or lease, read a Codex credential,
or reached any CP review/checkpoint/finalization state.

The current repo-owned non-operator caller activation path is:

- `spiffe://execution.internal/service/control-plane`

Configure AGS and ES allowlists narrowly for that caller, for example with `operator/local` and `service/control-plane`. A broad `service/` prefix is not required by the current activation path.

These are helper/proof surfaces, not separate client contracts:

- `scripts/20_publish.sh`
- `scripts/30_prepare.sh`
- `scripts/40_submit.sh`
- `scripts/50_lifecycle.sh`
- `scripts/60_execute_loop.sh`
- `scripts/72_supported_local_setup.sh`
- `scripts/73_supported_local_proof.sh`
- `.examples/control_plane_static_script/run.sh`
- `.examples/control_plane_normal_shell_runtime/entrypoint`

Those helpers and examples are useful for operator diagnosis and repo-owned proof capture. CP consumers should treat the API endpoints above as the real surface.

## 4A. Early Compatibility Gate

Before starting a high-value governed run, CP or Infra Manager may use this
producer-side sequence:

1. Call `GET /v1/executions:contract` over the same HTTPS+mTLS boundary and
   caller identity class intended for governed execution. Require `200`,
   `schema_version = "execution-substrate.producer-contract/v1"`,
   `governed_execution.contract = "governed-execution-producer/v1"`, and
   `governed_execution.enabled = true`.
2. Require the declaration to mark status JSON, cancel JSON, successful logs
   headers, and successful result headers as required `outcome_evidence`
   carriers. For normal-shell clients, also require an enabled
   `control-plane-normal-shell/v1` runtime-profile entry.
3. Call ES `/health` to verify service health. Treat `/health` as service
   health only, not submit readiness and not a producer-contract declaration.
4. Use the environment-owned readiness proof before submit. On the repo-owned
   supported-local path this is `scripts/01_bringup.sh check` or
   `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh`; CP/IM may consume an
   equivalent profile only if it preserves the same submit-ready truth.
5. Use `POST /v1/executions:prepare` for artifact-specific admission proof
   before `:submit` when CP already has the candidate artifact.

A missing `GET /v1/executions:contract`, a non-`200` response, a disabled
governed-execution declaration, missing mandatory outcome-evidence carriers, or
a disabled required runtime profile is an early compatibility failure. Do not
work around that by starting the high-value run and hoping lifecycle responses
carry the required evidence later.

Treat these as producer declaration incompatibility, not runtime/live substrate
readiness failure:

- `governed_execution.enabled=false` with
  `disabled_reason="submit_not_configured"` means the pointed-at ES is not
  configured for submit.
- a missing required runtime-profile entry, or a profile entry with
  `status="disabled"` and `disabled_reason="profile_not_enabled"`, means the
  required runtime profile is unavailable on that producer.
- missing mandatory outcome-evidence support means the producer has not
  declared the status/cancel/logs/result evidence carriers CP requires.

Treat `submit-ready: false`, missing Docker/Nomad/profile-image readiness, and
other readiness-helper failures as runtime/live substrate readiness failure.
Those failures do not by themselves mean the producer declaration is
incompatible.

The declaration does not prove that a run exists, that Nomad can currently place
the workload, that the workload will use the identity endpoint correctly, that
Vault or Codex credential material exists, or that retained result contents have
any CP semantic meaning.

## 4B. Golden producer proof path

For the current governed-execution producer proof, keep the ES checks in one
operator-legible evidence chain:

1. Producer declaration: call `GET /v1/executions:contract` over the same
   HTTPS+mTLS caller boundary intended for governed execution. Require
   `schema_version = "execution-substrate.producer-contract/v1"`,
   `service = "execution"`,
   `governed_execution.contract = "governed-execution-producer/v1"`,
   `governed_execution.enabled = true`, and the `non_authority`
   classifications.
2. CP normal-shell compatibility: for normal-shell clients, require the
   declaration to report `control-plane-normal-shell/v1` as enabled, then use
   `POST /v1/executions:prepare` and `POST /v1/executions:submit` with
   `invocation.annotations["execution_substrate.runtime_profile"] =
   "control-plane-normal-shell/v1"`.
3. Runtime authority handoff evidence: require successful `:submit` responses,
   and `status` responses when recoverable, to carry `authority_handoff`.
   Treat it only as ES-owned evidence of non-secret runtime handoff facts ES
   selected or staged: runtime profile, workload identity endpoint handoff,
   workload-Vault auth metadata, selected workload-zone Vault config digest,
   and bounded profile credential-location metadata.
4. Lifecycle read freshness: require status responses to carry
   `status.lifecycle_projection.revision`. Compare it only as an opaque
   same-run read-coordination token. Do not parse it, order it, treat it as a
   scheduler identifier, or pass it as a write precondition to `logs`,
   `result`, or `cancel`.
5. Mandatory outcome evidence: require `outcome_evidence` in status and cancel
   JSON. Require successful logs responses to keep
   `Content-Type: text/plain; charset=utf-8` and expose
   `Execution-Substrate-Outcome-*` headers. Require successful result responses
   to keep `Content-Type: application/gzip` and expose the same outcome header
   family.
6. Live supported-local validation: after the static declaration gate, use
   `/health`, `scripts/01_bringup.sh check`, `VERIFY_RUNTIME_CONFIG=1
   scripts/10_health_check.sh`, and the supported-local proof path to validate
   Docker, Nomad, profile image, runtime-config, workload identity, Vault, and
   retained-result behavior in the prepared environment.

A passing static contract check without supported-local readiness is not a live
runtime proof. A passing Docker/Nomad-backed proof without the producer
declaration above is not current governed-execution producer compatibility.
Neither path adds authority claims beyond the evidence ES actually declares,
observes, or retains.

## 5. `submit-ready` meaning

For the supported-local CP normal-shell path, `submit-ready: true` means the repo-owned readiness baseline has proved all current preconditions needed before attempting `POST /v1/executions:submit`.

For `BRINGUP_PROFILE=full`, the current readiness helpers require:

- ARS, EGS, AGS, and ES health checks return ready over the strict mTLS boundary
- the workload-zone Vault runtime-config blob named by ES startup config is readable through ARS and structurally valid, including any supplied CA bundle
- ES submit config is present, including Nomad config, staging root, results root, base image, runtime support binary, and SPIRE Workload API socket path requirements
- Docker is reachable through `docker info`
- Nomad has a leader
- Nomad reports `config.DevMode=false`
- at least one ready Nomad client has positive natural `cpu.totalcompute` and a healthy Docker driver
- any enabled runtime-profile image is present in the Docker daemon used by Nomad
- for enabled local runtime-profile images, Nomad Docker image cleanup is disabled through `client.options["docker.cleanup.image"]="false"`
- the same-path staging invariant has been recorded by the bring-up path

For `control-plane-normal-shell/v1`, this additionally means the configured profile image for `execution.runtime_profiles.control_plane_normal_shell.image` exists locally before readiness is claimed.

The image durability condition is narrow. Disabling Nomad Docker image cleanup prevents Nomad's Docker driver from removing the local runtime-profile image after stopped allocations in the supported single-node baseline. It is not a registry guarantee, a general image-cache architecture, or proof that the image can never disappear.

Readiness can still become false after a green check if an operator or external process:

- removes the profile image with `docker image rm`, `docker system prune`, or an equivalent cleanup
- resets or replaces the Docker daemon used by Nomad
- restarts Nomad with config that omits `docker.cleanup.image=false`
- switches ES config to a different runtime-profile image
- changes or removes the SPIRE, Vault, TLS, staging, or results paths that ES submit depends on
- exhausts host resources or introduces placement constraints not covered by the readiness check

After any such change, re-run `scripts/01_bringup.sh check` or `VERIFY_RUNTIME_CONFIG=1 scripts/10_health_check.sh` before treating the environment as submit-ready again.

## 6. Runtime profile selection

The bounded CP normal-shell profile is selected by:

```json
{
  "invocation": {
    "annotations": {
      "execution_substrate.runtime_profile": "control-plane-normal-shell/v1"
    }
  }
}
```

The profile remains a `static-script` overlay. It currently requires:

- `static-script` artifact type
- Docker target platform when a target platform is present
- `network_access=true`
- ES config under `execution.runtime_profiles.control_plane_normal_shell`
- a configured runtime image
- an absolute configured Codex CLI path inside that image
- configured workload-Vault secret path and field metadata for Codex credential material

The selected profile changes the runtime image and injects non-secret runtime metadata. It does not add ES-owned CP lifecycle, review, checkpoint, or finalization semantics.

For this profile, `authority_handoff` may include the non-secret Codex
credential-location metadata ES injected: configured CLI path, credential source
`workload_vault`, and the configured Vault secret path/field labels. It does not
include credential material and does not prove that credential material was read.

## 7. Workload runtime contract

The workload-visible runtime contract for the CP-owned remote normal-shell runner is intentionally bounded.

### Identity endpoint

ES injects:

- `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://<ES-owned run-scoped endpoint>`

The endpoint URI is chosen by ES and is run-scoped. Workloads must read the environment variable and must not assume a fixed socket path.

The current platform helper exposes one newline-delimited JSON request/response protocol:

Request:

```json
{"kind":"jwt_svid","target":"workload_vault"}
```

Response on success:

```json
{"jwt":"<jwt-svid>","expires_at":"<rfc3339 timestamp>"}
```

Response on failure:

```json
{"error":"<bounded error code>"}
```

Only the `jwt_svid` request for the `workload_vault` target is in the current bounded contract. The raw SPIRE Workload API socket remains helper-private and must not be exposed to the workload.

### Workload-Vault metadata

ES injects non-secret workload-Vault metadata derived from the workload-zone Vault runtime config plus ES `workload_vault_auth.default_mode`:

- `VAULT_ADDR`
- `EXEC_WORKLOAD_VAULT_AUTH_MODE=vault_identity_jwt`
- `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
- `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
- `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`

The workload uses the identity endpoint to get the bounded JWT-SVID and performs the Vault JWT login itself.

For `control-plane-normal-shell/v1`, ES also injects non-secret Codex credential-location metadata:

- `EXEC_CODEX_CLI_PATH`
- `EXEC_CODEX_CREDENTIAL_SOURCE=workload_vault`
- `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH`
- `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD`

These values say where the workload can retrieve credential material. They are not credential material.

### Trust-material handoff

When the workload-zone Vault config includes non-secret CA bundle material, ES stages it under the platform runtime directory and injects:

- `VAULT_CACERT=/execution/run/platform/workload-vault-ca.pem`
- `SSL_CERT_FILE=/execution/run/platform/workload-ca-bundle.pem`

`VAULT_CACERT` is the workload-facing Vault CA certificate path. `SSL_CERT_FILE` is a staged combined TLS bundle for the bounded CP normal-shell Python runner path and other standard TLS clients that honor it.

This is verified trust-material handoff. It is not relaxed TLS verification, Vault token brokerage, or production Vault lifecycle ownership.

### Runtime files and result path

Current runtime path conventions include:

- `/execution/run/work` for workload content
- `/execution/run/platform` for platform-staged runtime support and trust material
- `/execution/run/result` for workload-authored terminal result files

These paths are active bounded runtime conventions, not settled long-term architecture. The CP-owned runner should write terminal artifacts it wants ES to retain under `/execution/run/result`.

## 8. Retained-result contract

`GET /v1/executions/{run_id}/result` returns an ES-retained `application/gzip` bundle when ES has captured workload-authored files from `/execution/run/result` for a terminal execution.

ES can return `result.tar.gz` when:

- `:submit` previously returned a valid `run_id`
- Nomad-backed lifecycle observation reaches terminal state
- the workload created at least one result file under `/execution/run/result`
- ES successfully packaged that content into `execution.results_root_dir/<run_id>/result.tar.gz`

`result_not_found` means the execution is terminal but ES has no retained result bundle for that `run_id`. Common causes include:

- the workload never started
- the workload failed before writing result files
- the workload wrote no result files
- the workload wrote output somewhere other than `/execution/run/result`
- the CP-owned runner did not produce the expected artifact set

ES does not fabricate a result bundle from stdout, status, staging metadata, or CP expectations. Logs remain the `GET /v1/executions/{run_id}/logs` surface. Retained results are opaque tar.gz output material, not CP checkpoints, review decisions, or finalization records.

If `/execution/run/result` contains result files for a terminal run and ES still returns `result_not_found`, that is an ES-side retention issue to investigate. If the result directory was never written, route first to the workload or CP runner.

## 9. Blocker routing

Route based on the first failed boundary. Do not over-classify a later symptom until the earliest failed boundary is clear.

| First failed boundary | ES-side interpretation | Likely owner to start with |
| --- | --- | --- |
| CP cannot obtain or use the supported-local profile, service URLs, CA, or client cert/key before reaching AGS/ES | The request did not reach the ES/AGS API contract. Check local profile emission, TLS material, and endpoint wiring. | Infra Manager / local environment, with CP consuming the emitted profile |
| TLS handshake, connection, or mTLS failure before an AGS/ES handler response | The HTTPS+mTLS transport boundary failed. If the services are healthy through ES readiness but CP cannot connect, start with profile/client material. | Infra Manager / local environment / CP profile use |
| `401` or `403` from AGS or ES after a request reaches the service | Caller identity is missing, bootstrap-issued, or outside `authorization.allowed_spiffe_path_prefixes`. | ES/AGS config for allowed callers, plus CP/IM for the presented client identity |
| `GET /v1/executions:contract` is missing, disabled, lacks mandatory outcome-evidence carriers, or lacks an enabled required runtime profile | The pointed-at ES has not declared the current governed-execution producer contract for the requested CP path. | ES version/config first; CP/IM should fail the compatibility gate before submit |
| `POST /v1/artifacts:publish` fails with publish request validation or evidence assembly errors | The artifact publication boundary failed before ES runtime. | CP request construction or AGS publication config, depending on the concrete response |
| `POST /v1/executions:prepare` fails with evidence, trust, runtime-config, unsupported profile, or request/fact mismatch errors | ES rejected the request before runtime handoff. | ES/AGS/ARS/EGS inputs for evidence/trust/config; CP if the request shape or profile annotation is wrong |
| CP contract probe expects routes or fields beyond the listed API surface | The probe is asking for behavior outside the accepted ES client contract. | CP proof harness / contract probe |
| `submit-ready: false`, missing Docker, missing Nomad leader/client, `DevMode=true`, `cpu.totalcompute=0`, missing profile image, or missing `docker.cleanup.image=false` | ES is refusing to claim runtime readiness honestly. The fix is substrate/profile/image lifecycle, not a runtime contract widening. | Local environment / Infra Manager for bootstrap and lifecycle; ES docs define the readiness truth |
| `:submit` returns `execution_runtime_unavailable`, `submission_failed`, or a Nomad/Docker runtime placement problem after readiness | Runtime handoff reached the substrate, but the substrate could not accept or run that workload shape. | ES runtime/profile config or local Nomad/Docker environment, based on the concrete failure |
| `status`, `logs`, `result`, or `cancel` returns `execution_not_found` for a syntactically valid `run_id` | ES has no lifecycle observation for that `run_id` through the current Nomad-backed lookup. This is run lifecycle observation absence, not producer declaration incompatibility or submit readiness. | ES/Nomad lifecycle observation first; CP if the `run_id` was never submitted to this ES instance |
| Workload starts, then identity endpoint or Vault login fails | The run passed ES submit. Check endpoint use, helper-private SPIRE availability, workload-Vault metadata, CA trust, and the proof-scoped Vault target. | ES runtime contract if injected values/files are wrong; workload/CP runner if it misuses them; local environment for SPIRE/Vault availability |
| Workload reaches terminal success but `GET /result` returns `result_not_found` | ES has no retained bundle. If `/execution/run/result` was not written, this is not an ES result-retention bug. | CP runner/workload first, ES only if result files existed and were not retained |
| CP proof harness fails review, finalization, checkpoint promotion, expected Codex semantics, or proof-matrix assertions after ES returned the expected status/log/result contract | ES fulfilled the bounded runtime surface; the failing semantics are above ES ownership. | Control Plane proof harness / orchestration |

## 10. Fast diagnosis checklist

1. Re-run `scripts/01_bringup.sh check` and record whether the environment reports `prepare-ready: true`, `submit-ready: true`, `submit-ready-mode: natural`, and `supported-environment: supported`.
2. Call `GET /v1/executions:contract` and confirm the current producer contract, mandatory outcome-evidence carriers, and any required runtime profile are enabled.
3. Confirm CP is using the direct API surface, not assuming helper script behavior as product contract.
4. Confirm AGS and ES configs allow `spiffe://execution.internal/service/control-plane` narrowly.
5. For `control-plane-normal-shell/v1`, confirm the request sets `invocation.annotations["execution_substrate.runtime_profile"]="control-plane-normal-shell/v1"` and the published artifact has `network_access=true`.
6. Confirm the configured profile image exists in the Docker daemon used by Nomad and Nomad reports `docker.cleanup.image=false`.
7. If the workload starts, inspect logs for endpoint/Vault/trust-material failures before treating the issue as submit readiness.
8. If retained result fetch fails, distinguish `result_unavailable` from `result_not_found`, then check whether the workload wrote result files under `/execution/run/result`.

Use `.runbooks/system/v1_bringup.md` for the broader operator troubleshooting matrix and diagnostics collection. This runbook is the ES-side CP consumer overlay for that same accepted supported-local surface.
