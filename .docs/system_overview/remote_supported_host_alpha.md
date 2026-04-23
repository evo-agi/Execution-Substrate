# Remote Supported-Host Alpha 0.3

## Purpose And Status

Remote Supported-Host Alpha 0.3 is an intermediate alpha for a Control Plane consumer running on a Mac against one remote Linux Execution Substrate host. It extends Alpha 0.2 with a fixture-driven readiness report that combines Control Plane profile diagnostics and Infrastructure Manager remote-doctor output; it does not change ES runtime semantics.

It is not the final commercial deployment target. Full remote Control Plane plus remote Execution Substrate with the operator's Mac browser as the human surface, remote Temporal, HA, object storage, and source/workspace sync models remain out of scope for this alpha.

Status classification:

- The direct CP-to-AGS/ES HTTPS+mTLS boundary is a bounded alpha acceptance posture.
- Bridge or tunnel mode is a temporary compatibility edge for supported-local and troubleshooting lineage, not product posture.
- The current `execution_substrate.runtime_profile` annotation, `control-plane-normal-shell/v1`, producer contract version, outcome evidence, lifecycle projection, retained-result behavior, and authority handoff remain unchanged.
- The combined readiness report is pre-live fixture reporting, not ES service health, submit readiness, retained-result proof, lifecycle truth, runtime authority, or run authority.

## Topology

For Remote Alpha 0.3:

- Control Plane API, UI, worker, and Temporal remain on the Mac.
- Safari on the Mac remains the operator browser for the current alpha.
- ES, AGS, ARS, EGS, Docker, Nomad, SPIRE, Vault, and runtime support run on one remote Linux host.
- CP connects to AGS and ES over direct routable HTTPS with mTLS.
- No shared filesystem is assumed between Mac and remote host.
- Infrastructure Manager may emit profile, doctor, support-bundle, and combined readiness-report outputs, but it is installer/profile/doctor/support-bundle/report direction only. It is not CP run authority, ES runtime authority, a remote SSH installer, a remote host provisioner, a live remote proof runner, or a long-lived reconciler.

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

Infrastructure Manager doctor output, the Alpha 0.3 combined readiness report, and ES support-bundle expectations use the same Remote Alpha stage vocabulary:

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

Those stages are operator diagnostics, readiness-report inputs, and support-bundle provenance. They are not ES core lifecycle contracts, not Control Plane run-control authority, not ES runtime authority, not a durable reconciliation loop, and not proof that Control Plane review, checkpoint, finalization, hold/resume/reject, or intervention semantics moved into ES.

Support-bundle summaries for this alpha should preserve product blocker codes tied to the vocabulary above. They should not surface script numbers, Lima implementation details, bridge ports, proof-harness names, or remote filesystem paths as product blocker identifiers.

## Combined Readiness Report Boundary

The Alpha 0.3 combined report schema is
`remote-supported-host.alpha-readiness-report.v1` and is owned by
Infrastructure Manager as an operator UX artifact. It consumes CP
`control-plane.remote-profile-diagnostic.v1` and IM
`infra-manager.remote-supported-host-doctor.v1` fixture JSON. It may report
`accepted`, `compatibility_only`, `blocked`, or `unknown`.

`accepted` means the supplied fixtures satisfy the direct DNS/SAN HTTPS/mTLS
Remote Alpha posture and all required doctor stages passed or were explicitly
acceptable for pre-live reporting. `retained_result_fetch` may be
`not_exercised` before live proof. Bridge mode is `compatibility_only`, not
accepted.

The report does not install a host, provision a host, call ES, submit a job,
fetch a live retained result, or prove Temporal history. It prepares the next
live remote-host proof without changing ES admission, lifecycle, runtime,
retained-result, outcome-evidence, or authority-handoff semantics.

## Support-Bundle Summary Sections

The first support-bundle contract remains IM-owned at the top level, but ES
owns the bundle's substrate diagnostic summary sections. The intended ES
shareable evidence files are:

- `evidence/execution-substrate/producer-contract-summary.json`
- `evidence/execution-substrate/health-readiness-summary.json`
- `evidence/execution-substrate/probe-summaries.json`

The current ES section schema names are:

- `execution-substrate.producer-contract-summary.v1`
- `execution-substrate.health-readiness-summary.v1`
- `execution-substrate.probe-summaries.v1`

Those sections may contribute only bounded summary evidence:

- producer contract compatibility summary
- health and readiness summary
- AGS publish probe summary
- ES prepare, submit, status, and result summaries
- Nomad, Docker, Vault, and SPIRE structured status summaries
- blocker codes
- byte counts
- digest values
- non-authority labels

Those sections must not contribute:

- raw logs
- raw retained-result bundles
- artifact payload bytes
- private keys, PEM bodies, Vault tokens, JWT-SVIDs, or API credentials
- raw Nomad, Docker, Vault, or SPIRE implementation dumps
- new Control Plane run-control authority
- new Infrastructure Manager runtime authority

These support-bundle summaries are ES-owned runtime and substrate evidence only.
They do not change ES lifecycle semantics, retained-result semantics,
authority-handoff semantics, readiness truth, or the producer declaration
boundary.

## Runtime Identity Helper Proof Slice

The current remote supported-host runtime identity helper proof slice is
intentionally narrower than a live remote governed-execution proof. It is
limited to verifying:

- `/usr/local/bin/es-runtime-support` is installed on the remote host
- remote-host SPIRE server and SPIRE agent health
- the persistent SPIRE workload registration used by the helper
- root-owned local fetch over `/run/spire/sockets/agent.sock`
- helper-private raw SPIRE exposure boundaries
- non-secret host evidence summaries

It does not prove Vault readiness, runtime-profile readiness, ES submit
readiness, producer-contract compatibility, retained-result readiness, or live
run compatibility for a Control Plane consumer.

Because the current helper starts as `0:0`, the current Remote Alpha helper
proof registration also uses the broad root selector set `unix:uid:0` plus
`unix:gid:0` for `spiffe://execution.internal/workload`. That registration is
Alpha-only proof scope, not product posture. Remote product hardening must
narrow or replace that selector model before a broader runtime identity claim
is accepted.

The raw SPIRE Workload API socket remains helper-private. Fixed workload
UID:GID `10000:10000` and other non-helper identities must not receive direct
access to `/run/spire/sockets/agent.sock` or to helper-private raw SPIRE path
aliases.

The current host-local non-secret evidence summary for this slice is
`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`.
That summary, Remote Alpha support bundles, and any repo-retained artifacts
accepted as evidence for this slice must not persist JWT-SVID contents, X.509
SVID bodies, private keys, or other secret material. Old ignored
`.out/es-proof-*` supported-local proof workspaces are not accepted evidence
for this remote helper slice and must not be used to widen its claims.

## Remote Vault/Workload-Auth Slice

Remote Supported-Host Alpha may also prove a separate host-local Vault and
workload-auth slice without installing ES services or widening ES runtime
claims.

That slice is intentionally limited to verifying:

- Vault is installed from an operator-chosen package source and runs as a
  systemd service on the remote Linux host
- the Vault posture is explicitly Alpha/internal rather than production
- the workload-visible Vault HTTPS address is reachable from future
  bridge-networked Docker/Nomad allocations only as broadly as needed for that
  workload-auth path
- the Vault JWT auth mount and role are configured for the helper SPIFFE
  identity path needed by future ES runtime identity handoff
- a root-owned helper-matching process can fetch a SPIRE JWT-SVID for the
  expected audience, log in through the configured Vault JWT auth path, and
  receive a Vault token without printing or persisting the token
- the issued Vault token can perform the bounded self-verification and proof
  operations this slice treats as required: self-lookup over
  `GET /auth/token/lookup-self`, one proof read at
  `proof-secrets/data/runtime-identity-vault-login`, and self-revoke, all
  without persisting the token or secret payload
- non-secret workload-zone Vault configuration material exists for later ES
  startup/config installation
- non-secret host evidence summaries record only bounded metadata and explicit
  not-claimed readiness fields

This slice does not prove ES service health, runtime-profile readiness, submit
readiness, producer-contract compatibility, retained-result readiness, or live
run compatibility for a Control Plane consumer.

The current repo-derived workload-auth target for this slice remains the
bounded helper identity path:

- trust domain `execution.internal`
- SPIFFE ID `spiffe://execution.internal/workload`
- JWT auth method constrained as narrowly as the active repo/runtime supports
- current JWT audience `vault`
- current required proof-read path `proof-secrets/data/runtime-identity-vault-login`

### Alpha Vault posture

Remote Alpha Vault for this slice must stay explicitly internal and
non-productized:

- single-node only
- no CP-facing or operator-product API claims
- no assumption that this alpha posture is a production Vault lifecycle model
- no claim that supported-local Vault dev/test conventions are acceptable as
  remote product posture by default

If the chosen Vault mode requires init, unseal, or root-token material, that
material must remain root-only on the remote host. It must not be copied into:

- Infrastructure Manager `.out`
- Control Plane artifacts
- ES support bundles
- remote Alpha proof summaries
- repo-retained proof workspaces

If init or unseal material cannot be handled that way, the slice must stop
instead of widening evidence or secret persistence.

### Remote Vault evidence

The current host-local non-secret evidence summary for this slice is:

- `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`

The repo-owned check path for this slice is:

- `sudo scripts/remote_alpha_vault_workload_auth_check.sh`

That command is a host-local root check only. It does not install ES, AGS, ARS,
or EGS, does not build the normal-shell image, does not call ES `:prepare` or
`:submit`, and does not change ES public contracts.

The summary schema for that host-local record is:

- `execution-substrate.remote-alpha.vault-workload-auth-summary.v1`

It is a bounded host-local audit record, not an ES lifecycle or readiness
surface. It must not be treated as:

- ES `/health`
- ES submit readiness
- ES service health
- producer-contract compatibility
- retained-result readiness
- Control Plane run-control truth

The current status vocabulary for the summary is:

- `vault_workload_auth_smoke`: `pass` or `fail`
- `auth_smoke.*`: `pass`, `fail`, `not_exercised`, or `unknown`
- `reachability.*`: `pass`, `fail`, `not_exercised`, or `unknown`
- `readiness_not_claimed.*`: literal `not_claimed`

The current required auth-smoke checks for a passing
`vault_workload_auth_smoke` are:

- `auth_smoke.jwt_fetch = pass`
- `auth_smoke.vault_login = pass`
- `auth_smoke.token_lookup = pass`
- `auth_smoke.proof_read = pass`
- `auth_smoke.token_revoked = pass`

`auth_smoke.token_lookup` uses the documented Vault token self-lookup endpoint,
`GET /auth/token/lookup-self`, and therefore requires `read` capability on that
path. The current intended source for that capability is Vault's attached
`default` policy rather than an extra compatibility policy stanza.

Required summary fields for
`execution-substrate.remote-alpha.vault-workload-auth-summary.v1` are:

- `schema_version`
- `checked_at`
- `vault_workload_auth_smoke`
- `host_identity`
- `vault.address`
- `vault.auth_mount`
- `vault.role`
- `vault.audience`
- `vault.policy_names`
- `vault.initialized`
- `vault.sealed`
- `vault.storage`
- `spire.trust_domain`
- `spire.socket_path`
- `workload.spiffe_id`
- `workload.registration_selector_scope`
- `workload.registration_alpha_only`
- `auth_smoke.jwt_fetch`
- `auth_smoke.vault_login`
- `auth_smoke.token_lookup`
- `auth_smoke.proof_read`
- `auth_smoke.token_revoked`
- `auth_smoke_requirements.token_lookup_required`
- `auth_smoke_requirements.proof_read_required`
- `auth_smoke_requirements.token_revoked_required`
- `auth_smoke_requirements.proof_read_path`
- `security.ds_not_in_docker_group`
- `security.passwordless_sudo_for_ds`
- `security.raw_spire_socket_access_ds`
- `security.raw_spire_socket_access_uid_10000`
- `redaction.jwt_persisted`
- `redaction.vault_client_token_persisted`
- `redaction.root_token_persisted`
- `redaction.secret_payload_persisted`
- `readiness_not_claimed.runtime_profile_ready`
- `readiness_not_claimed.submit_ready`
- `readiness_not_claimed.es_services_healthy`
- `readiness_not_claimed.producer_contract_compatible`
- `readiness_not_claimed.retained_result_fetch`

The same summary must also record bounded safe evidence for:

- host reachability to `https://172.17.0.1:8200/v1/sys/health`
- bounded Docker bridge reachability to that same health endpoint when a safe
  pre-existing probe image is available; otherwise `not_exercised`
- validation of
  `/etc/execution-substrate/vault/workload-zone-vault-config.json` against the
  current workload-zone Vault config shape, including labeled digest and CA
  bundle presence

`host_identity` is a safe local host summary only. It must not expand into
remote filesystem truth, SSH-install truth, or an IM/CP support-bundle
contract.

That summary and any derivative support-bundle material must not persist:

- Vault root tokens or client tokens
- JWT-SVID bodies
- X.509 SVID bodies
- unseal keys
- private keys
- secret payloads

Allowed shareable evidence is limited to bounded metadata such as:

- success or failure
- SPIFFE ID
- auth mount and role names
- JWT audience
- token TTL or lease duration
- policy names
- workload-zone Vault config digest
- workload-zone Vault config validation result
- explicit redaction and non-persistence flags
- explicit `not_claimed` readiness fields for surfaces this slice does not prove

## Non-Goals

Remote Alpha 0.3 does not add:

- remote SSH install automation
- remote install commands
- remote host provisioning
- live remote host proof in this repository
- ES runtime semantic changes
- full remote CP
- remote Temporal
- HA
- object storage
- source/workspace sync model
- UI changes
