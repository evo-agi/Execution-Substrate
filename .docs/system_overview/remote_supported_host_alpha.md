# Remote Supported-Host Alpha 0.2

## Purpose And Status

Remote Supported-Host Alpha 0.2 is an intermediate alpha for a Control Plane consumer running on a Mac against one remote Linux Execution Substrate host. It extends Alpha 0.1 with Control Plane profile diagnostics and an Infrastructure Manager remote doctor skeleton; it does not change ES runtime semantics.

It is not the final commercial deployment target. Full remote Control Plane, remote Temporal, HA, object storage, and source/workspace sync models remain out of scope for this alpha.

Status classification:

- The direct CP-to-AGS/ES HTTPS+mTLS boundary is a bounded alpha acceptance posture.
- Bridge or tunnel mode is a temporary compatibility edge for supported-local and troubleshooting lineage, not product posture.
- The current `execution_substrate.runtime_profile` annotation, `control-plane-normal-shell/v1`, producer contract version, outcome evidence, lifecycle projection, retained-result behavior, and authority handoff remain unchanged.

## Topology

For Remote Alpha 0.2:

- Control Plane API, UI, worker, and Temporal remain on the Mac.
- Safari on the Mac remains the operator browser for the current alpha.
- ES, AGS, ARS, EGS, Docker, Nomad, SPIRE, Vault, and runtime support run on one remote Linux host.
- CP connects to AGS and ES over direct routable HTTPS with mTLS.
- No shared filesystem is assumed between Mac and remote host.
- Infrastructure Manager may emit profile and doctor outputs, but it is installer/profile/doctor/support-bundle direction only. It is not CP run authority, ES runtime authority, a remote SSH installer, a remote host provisioner, or a long-lived reconciler.

## Direct Remote Requirements

AGS and ES must be reachable from the Mac over the direct remote HTTPS/mTLS boundary.

Requirements:

- AGS and ES listeners can bind routable interfaces suitable for the remote host network.
- AGS and ES server certificates include DNS or IP SANs matching the Control Plane profile endpoint hosts.
- mTLS accepts the Control Plane service identity, currently `spiffe://execution.internal/service/control-plane`, through the configured caller allowlists.
- The same direct boundary reaches service health and governed execution surfaces:
  - ES `/health`
  - ES `GET /v1/executions:contract`
  - AGS `POST /v1/artifacts:publish`
  - ES `POST /v1/executions:prepare`
  - ES `POST /v1/executions:submit`
  - ES `GET /v1/executions/{run_id}/status`
  - ES `GET /v1/executions/{run_id}/logs`
  - ES `GET /v1/executions/{run_id}/result`
  - ES `POST /v1/executions/{run_id}:cancel`
- The producer contract remains `execution-substrate.producer-contract/v1` with `governed-execution-producer/v1` and the enabled `control-plane-normal-shell/v1` runtime profile for the CP normal-shell path.

## Control Plane Non-Dependencies

The remote profile and CP consumer path must not depend on:

- Nomad APIs
- Vault APIs
- SPIRE sockets
- ES staging root paths
- ES results root paths
- remote filesystem paths
- shared Mac/remote filesystem access

Those are ES/runtime/operator environment internals. CP consumes the documented AGS/ES HTTPS APIs, producer declaration, outcome evidence, lifecycle projection, retained opaque result bundle, and bounded authority handoff facts. It must not treat runtime internals as orchestration, review, checkpoint, finalization, intervention, or run-control authority.

## Compatibility Bridge

Bridge or tunnel mode may remain useful as compatibility or troubleshooting evidence, especially for supported-local lineage. It must be labeled compatibility-only and must not be used as Remote Alpha acceptance posture.

Direct HTTPS/mTLS with matching DNS/IP SANs is the acceptance posture for this alpha.

## Doctor And Support-Bundle Vocabulary

Infrastructure Manager doctor output and ES support-bundle expectations use the same Remote Alpha 0.2 stage vocabulary:

- `remote_host_reachable`
- `docker_ready`
- `nomad_ready`
- `runtime_profile_ready`
- `es_services_healthy`
- `cert_trust_ok`
- `producer_contract_compatible`
- `ags_publish_probe`
- `es_prepare_probe`
- `submit_ready`
- `retained_result_fetch`
- `cp_profile_usable`

Those stages are operator diagnostics and support-bundle provenance. They are not ES core lifecycle contracts, not Control Plane run-control authority, not ES runtime authority, not a durable reconciliation loop, and not proof that Control Plane review, checkpoint, finalization, hold/resume/reject, or intervention semantics moved into ES.

Support-bundle summaries for this alpha should preserve product blocker codes tied to the vocabulary above. They should not surface script numbers, Lima implementation details, bridge ports, proof-harness names, or remote filesystem paths as product blocker identifiers.

## Non-Goals

Remote Alpha 0.2 does not add:

- remote SSH install automation
- remote install commands
- remote host provisioning
- live remote host proof in this repository
- full remote CP
- remote Temporal
- HA
- object storage
- source/workspace sync model
- UI changes
