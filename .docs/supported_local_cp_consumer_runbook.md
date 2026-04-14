# Supported-Local Control Plane Consumer Runbook

## 1. Purpose and status

This runbook is the canonical Execution Substrate-side operator reference for the bounded supported-local Control Plane consumer path.

It explains what ES owns when Control Plane consumes the accepted supported-local governed-execution surface, how to interpret ES readiness and runtime-contract signals, and where to route common blockers.

Status classification:

- The supported-local CP consumer path is a `Bounded slice rule`.
- `control-plane-normal-shell/v1` is a bounded runtime-profile overlay on the current `static-script` package/runtime path.
- The runtime-profile annotation, retained-result bundle shape, `/execution/...` runtime paths, and runtime identity endpoint convention remain active compatibility-heavy conventions on reopened ES seams.
- This runbook documents accepted current behavior. It does not settle the long-term ES request model, package model, runtime-profile vocabulary, or runtime path layout.

Use this alongside:

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
- retained opaque `result.tar.gz` bundles captured from `/execution/run/result`
- the truth of whether this repo's readiness helpers can honestly claim `submit-ready`

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

## 4. Real client surface

The CP-facing programmatic surface is the HTTPS+mTLS API boundary.

Publication:

- `POST /v1/artifacts:publish` on AGS

Execution and lifecycle:

- `POST /v1/executions:prepare` on ES
- `POST /v1/executions:submit` on ES
- `GET /v1/executions/{run_id}/status` on ES
- `GET /v1/executions/{run_id}/logs` on ES
- `GET /v1/executions/{run_id}/result` on ES
- `POST /v1/executions/{run_id}:cancel` on ES

The current repo-owned non-operator caller activation path is:

- `spiffe://execution.internal/service/control-plane`

Configure AGS and ES allowlists narrowly for that caller, for example with `operator` and `service/control-plane`. A broad `service/` prefix is not required by the current activation path.

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
| `POST /v1/artifacts:publish` fails with publish request validation or evidence assembly errors | The artifact publication boundary failed before ES runtime. | CP request construction or AGS publication config, depending on the concrete response |
| `POST /v1/executions:prepare` fails with evidence, trust, runtime-config, unsupported profile, or request/fact mismatch errors | ES rejected the request before runtime handoff. | ES/AGS/ARS/EGS inputs for evidence/trust/config; CP if the request shape or profile annotation is wrong |
| CP contract probe expects routes or fields beyond the listed API surface | The probe is asking for behavior outside the accepted ES client contract. | CP proof harness / contract probe |
| `submit-ready: false`, missing Docker, missing Nomad leader/client, `DevMode=true`, `cpu.totalcompute=0`, missing profile image, or missing `docker.cleanup.image=false` | ES is refusing to claim runtime readiness honestly. The fix is substrate/profile/image lifecycle, not a runtime contract widening. | Local environment / Infra Manager for bootstrap and lifecycle; ES docs define the readiness truth |
| `:submit` returns `execution_runtime_unavailable`, `submission_failed`, or a Nomad/Docker runtime placement problem after readiness | Runtime handoff reached the substrate, but the substrate could not accept or run that workload shape. | ES runtime/profile config or local Nomad/Docker environment, based on the concrete failure |
| Workload starts, then identity endpoint or Vault login fails | The run passed ES submit. Check endpoint use, helper-private SPIRE availability, workload-Vault metadata, CA trust, and the proof-scoped Vault target. | ES runtime contract if injected values/files are wrong; workload/CP runner if it misuses them; local environment for SPIRE/Vault availability |
| Workload reaches terminal success but `GET /result` returns `result_not_found` | ES has no retained bundle. If `/execution/run/result` was not written, this is not an ES result-retention bug. | CP runner/workload first, ES only if result files existed and were not retained |
| CP proof harness fails review, finalization, checkpoint promotion, expected Codex semantics, or proof-matrix assertions after ES returned the expected status/log/result contract | ES fulfilled the bounded runtime surface; the failing semantics are above ES ownership. | Control Plane proof harness / orchestration |

## 10. Fast diagnosis checklist

1. Re-run `scripts/01_bringup.sh check` and record whether the environment reports `prepare-ready: true`, `submit-ready: true`, `submit-ready-mode: natural`, and `supported-environment: supported`.
2. Confirm CP is using the direct API surface, not assuming helper script behavior as product contract.
3. Confirm AGS and ES configs allow `spiffe://execution.internal/service/control-plane` narrowly.
4. For `control-plane-normal-shell/v1`, confirm the request sets `invocation.annotations["execution_substrate.runtime_profile"]="control-plane-normal-shell/v1"` and the published artifact has `network_access=true`.
5. Confirm the configured profile image exists in the Docker daemon used by Nomad and Nomad reports `docker.cleanup.image=false`.
6. If the workload starts, inspect logs for endpoint/Vault/trust-material failures before treating the issue as submit readiness.
7. If retained result fetch fails, distinguish `result_unavailable` from `result_not_found`, then check whether the workload wrote result files under `/execution/run/result`.

Use `.runbooks/system/v1_bringup.md` for the broader operator troubleshooting matrix and diagnostics collection. This runbook is the ES-side CP consumer overlay for that same accepted supported-local surface.
