# Remote Supported-Host Alpha 0.3

## Purpose And Status

Remote Supported-Host Alpha 0.3 is an intermediate alpha for a Control Plane consumer running on a Mac against one remote Linux Execution Substrate host. It extends Alpha 0.2 with a fixture-driven readiness report that combines Control Plane profile diagnostics and Infrastructure Manager remote-doctor output; it does not change ES runtime semantics.

It is not the final commercial deployment target. Full remote Control Plane plus remote Execution Substrate with the operator's Mac browser as the human surface, remote Temporal, HA, object storage, and source/workspace sync models remain out of scope for this alpha.

Status classification:

- The direct CP-to-AGS/ES HTTPS+mTLS boundary is a bounded alpha acceptance posture.
- Bridge or tunnel mode is a temporary compatibility edge for supported-local and troubleshooting lineage, not product posture.
- The current `execution_substrate.runtime_profile` annotation, `control-plane-normal-shell/v1`, producer contract version, outcome evidence, lifecycle projection, retained-result behavior, and authority handoff remain unchanged.
- The combined readiness report is pre-live fixture reporting, not ES service health, submit readiness, retained-result proof, lifecycle truth, runtime authority, or run authority.

## Remote Alpha Access Contract v1 Boundary

`Reopened redesign seam`: the governing ES access-profile and access-status
target is `.docs/system_overview/remote_alpha_access_contract.md`. Tranche A
freezes the schema envelope and state/safety semantics of
`es.remote-alpha.access-profile/v1` and
`es.remote-alpha.access-status/v1` in docs and a contract test only. The exact
OpenSSH grammar, Include closure, system-config interaction, filesystem
acceptance policy, and agent/Keychain/certificate interpretation are reopened
Tranche B implementation-contract decisions, not Tranche A claims of profile
conformance. No validator, access-status emitter, fixed identity-only route,
monitor identity, scheduled remote check, host setup, or TLS repair is
implemented by this addition. Its producer-owned v1
`scheduled_execution_allowed=false` rule remains separate from the existing
monitor-eligible evidence classification below.

`Temporary compatibility edge`: the current operator-owned
`host_to_remote_linux_m75q` alias and existing `--ssh-target` operator
routes are retained without alteration. The P0s/P0t status facade names remain bounded interactive compatibility
routes to a dedicated status-only collector; both renewal names are held
before host contact. P0v remains
an implemented TLS-specific noninteractive status route with scheduling
disabled. Neither is an access-status route or a general Remote Alpha
deployment/management interface. Access evidence does not establish ES
runtime, IM readiness, sudo readiness, TLS correctness, or governed execution.

## Milestone 1 Boundary Reading

Remote Supported-Host Alpha is the current host/operator reading of
Milestone 1: Least-Privilege Runtime/Security Boundary Closeout.

`Current invariant`: the landed long-lived `es.service` posture is already on
the least-privilege side of this milestone baseline: `User=es`, `Group=es`,
`UMask=0027`, with post-apply `/health`,
`GET /v1/executions:contract`, the current lowest-cost existing happy path,
and future writable-state readiness all passing.

Do not call this milestone `rootless everything` or full ES/runtime de-root.

Milestone 1 preserves these current boundaries:

- Nomad remains lifecycle authority after ES submission.
- ES remains a lifecycle projector, not a parallel scheduler.
- The raw SPIRE Workload API socket remains helper-private.
- Workloads see `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, not the raw SPIRE Workload
  API socket.
- Workload-side Vault credential acquisition remains preserved.
- ES does not fetch, mint, broker, store, rotate, parse, or validate Vault
  tokens.
- Infrastructure Manager support bundles and readiness/support artifacts remain
  evidence/projection/diagnostics only. They are not authority and are not
  governed execution proof by themselves.

C4 is the focused tests/docs guardrail slice for runtime identity and Vault
handoff boundaries. C4 is guardrail work, not runtime redesign and not live
helper execution. Runtime identity acquisition is workload-side or
helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
non-secret runtime identity and Vault configuration metadata, but ES must not
mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES must
not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies, private
keys, API keys, proof secrets, root tokens, unseal keys, Vault client tokens,
or secret payloads through public DTOs, lifecycle responses, retained-result
metadata, summaries, logs, reports, `.out`, support bundles, or proof
artifacts. `authority_handoff` may include non-secret credential-location and
configuration metadata only. `authority_handoff` must not carry live
credentials, leases, approvals, Vault tokens, Codex credentials, JWT-SVIDs,
API keys, or scheduler truth. Workload-side Vault auth remains workload-side;
Vault owns token, secret, and lease authority. SPIRE owns identity issuance
and SVID material. ES must not expose raw SPIRE socket access to workloads as
public ES grammar. `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the
workload-facing identity endpoint contract rather than raw SPIRE socket
access. Runtime identity and Vault handoff evidence remains non-authoritative
and redacted. CP may consume runtime identity/Vault handoff evidence, but CP
does not own credential acquisition, Vault tokens, SPIRE identity issuance, or
ES runtime handoff boundaries. IM and Maintenance Agent may report
diagnostics/readiness/status, but do not own runtime identity or Vault
authority. `control-plane-normal-shell/v1` and
`execution_substrate.runtime_profile` compatibility remain preserved unless an
explicit migration/versioning plan exists. Existing workload-auth Remote Alpha
helpers remain bounded operator/support surfaces, not ES token brokerage or
production Vault readiness.

Milestone 1 boundary posture matrix:

| Surface | Posture | Rationale | Current evidence | Removal condition | Explicit non-claim |
| --- | --- | --- | --- | --- | --- |
| Nomad host client/server substrate | `blocker` | Remote Alpha still depends on a pre-managed non-dev Linux Nomad client/server. Upstream least-privilege guidance is to keep Nomad servers as narrow as feasible, but the Linux Nomad client remains a root-managed isolation boundary today and a rootless client is not the current supported/well-tested repo posture. | Remote Alpha doctor vocabulary still treats `nomad_ready` as an environment gate, the supported-path docs still require a pre-managed Nomad baseline, and the landed ES happy paths still hand lifecycle authority to Nomad. | Revisit only if a later separately documented substrate decision proves a supported client posture that does not depend on an unsupported rootless-client assumption while preserving Nomad as lifecycle authority. | Milestone 1 does not claim a rootless Nomad client or full Nomad least-privilege closeout. |
| SPIRE raw-socket traversal and selector posture | `accepted MVP compatibility edge` | The workload-visible contract is already narrowed to `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, but the helper-private raw SPIRE path and the broad root selector scope remain explicit compatibility edges rather than a finished least-privilege identity model. | The runtime-identity helper proof slice, runtime-helper tests that keep the raw SPIRE path out of workload env, and the service-user migration check-only gate all preserve this helper-private boundary. | Revisit only through the later runtime-boundary redesign seam after a narrower helper principal or equivalent traversal model is documented and re-proved. | Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege. |
| Vault workload-side auth / workload-zone handoff | `accepted MVP compatibility edge` | The least-privilege direction is workload-side credential acquisition without ES token brokerage. Remote Alpha preserves that handoff boundary; where Vault host posture is operator-owned, the intended direction is a dedicated unprivileged Vault service account rather than root, but Milestone 1 does not widen ES contracts into full remote Vault lifecycle authority. | Useful credential flow completion is already landed, `sudo scripts/remote_alpha_vault_workload_auth_check.sh` records bounded host-local evidence, and the current `authority_handoff` plus `readiness_not_claimed.*` vocabulary preserve non-brokering, workload-side auth. | Revisit only if a later documented boundary change keeps workload-side auth intact and preserves the no-token-brokerage rule. | ES does not broker Vault tokens, and Vault/readiness summaries do not by themselves prove runtime-profile readiness or governed execution proof. |
| ES runtime helper | `accepted MVP compatibility edge` | The current helper isolates privileged runtime bootstrap from the long-lived ES service path, but it still starts from root and therefore remains a bounded compatibility edge rather than a full runtime de-root result. | The runtime-identity helper proof slice, helper-death/task-fatal behavior, and the remote helper summary all prove the current fail-closed helper boundary. | Revisit only if a later redesign re-proves equivalent runtime identity delivery, workload launch, and result-path guarantees with a narrower startup privilege model. | Milestone 1 does not claim rootless helper startup or full ES/runtime de-root. |
| Nomad task user | `accepted MVP compatibility edge` | The current runtime companion still needs task-start `0:0` so it can create the helper-private SPIRE boundary and exec the workload as fixed non-root `10000:10000`. | The current remote/runtime helper proof and the landed ES happy path still rely on the present task-start contract, and the docs keep `User: "0:0"` explicit rather than implied. | Revisit only as part of a broader runtime-boundary redesign that re-derives helper launch, workload launch, and SPIRE/Vault handoff together. | The current posture is not non-root task launch and not rootless workload orchestration. |
| Evidence/support artifacts | `accepted MVP compatibility edge` | Privilege-sensitive host evidence collection may still be necessary, but it must stay outside ES/CP authority boundaries and must not backdoor a broader runtime claim. | Remote doctor output, support-bundle summaries, staged-helper records, apply summaries, and the combined readiness report are all already documented as evidence/projection/provenance only. | Revisit only if later operator tooling reduces privileged collection without weakening the non-authority and non-proof boundary. | Support bundles, readiness reports, and apply summaries are not ES/CP/IM authority and are not governed execution proof by themselves. |

## Remote Runtime/Security Boundary Checker

Remote Supported-Host Alpha now also carries one bounded host-local
runtime/security boundary posture checker for Milestone 1.

The repo-owned public wrapper is:

- `scripts/remote_alpha_runtime_security_boundary_check.sh`

The sourced internal implementation is:

- `scripts/internal/remote_alpha_runtime_security_boundary_check.sh`

This checker is evidence/projection only. Default behavior is `check_only`,
non-mutating, and must not SSH by default, mutate services, change ownership,
restart services, archive files, or delete anything.

The current schema name for that checker is:

- `execution-substrate.remote-alpha.runtime-security-boundary-check.v1`

The suggested output artifact name is:

- `runtime-security-boundary-check.json`

Required top-level fields for
`execution-substrate.remote-alpha.runtime-security-boundary-check.v1` are:

- `mode`
- `non_mutating`
- `schema`
- `generated_at`
- `host`
- `runtime_inventory`
- `cve_readiness`
- `runtime_chain`
- `surfaces`
- `accepted_compatibility_edges`
- `least_privilege_findings`
- `blockers`
- `not_evaluated`
- `redaction`
- `non_authority_labels`
- `explicit_non_claims`

The checker must classify these current surfaces explicitly:

- Nomad server privilege posture
- Nomad client privilege posture
- whether those Nomad server/client surfaces were independently evaluated or
  are only one combined-service reading
- non-secret host/runtime inventory, including kernel, OS release, package
  versions, relevant service users, Docker/Nomad runtime chain observations,
  Docker storage-driver observation status, FUSE/fuse-overlayfs/rootless
  storage observation status, and Podman/crun/idmapped or `mount_setattr`
  path observation status
- CVE-2026-31431 and CVE-2026-31465 readiness as evidence-only
  classifications of `fixed`, `vulnerable`, `not_affected`,
  `mitigated_not_fixed`, or `unknown`; host-observed vendor status may justify
  a direct classification, while unobserved vendor status must remain
  `unknown`; CVE-2026-31431 `mitigated_not_fixed` requires both
  `algif_aead` currently not loaded and non-mutating modprobe policy evidence
  blocking autoload, and it is not a kernel patch or proof of production safety
- whether the current Nomad client root posture remains an accepted MVP
  substrate dependency
- Nomad task user posture, including the current `User: "0:0"` edge
- ES runtime helper/supervisor root-start posture
- SPIRE helper-private socket traversal
- broad root selector posture
- workload-visible identity endpoint contract through
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- Vault service account posture
- Vault root/unseal/client-token leakage checks
- workload-zone handoff posture
- whether ES is brokering Vault tokens, which must remain false
- whether support/evidence artifacts remain non-authoritative

The current expected classifications for the active Alpha posture are:

- Nomad host client/server least-privilege closeout remains a `blocker`
- Nomad client root is an accepted MVP substrate dependency, not a de-rooted
  client claim
- Nomad task `User: "0:0"` remains an accepted MVP compatibility edge
- the root-start ES runtime helper/supervisor remains an accepted MVP
  compatibility edge
- the raw SPIRE Workload API socket remains helper-private
- workloads see `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, not the raw SPIRE Workload
  API socket
- workload-side Vault credential acquisition and workload-zone handoff remain
  explicit compatibility-heavy handoff posture
- ES Vault token brokerage must remain false
- support bundles and related evidence artifacts remain non-authoritative
- CVE/runtime inventory evidence must not claim service health, submit
  readiness, runtime-profile readiness, governed execution proof, full
  ES/runtime de-root, a rootless Nomad client, support-bundle authority, or
  CVE patch authority

Nomad server/client posture reporting must stay role-aware and honest.

- When safely available, the checker may use local role evidence such as
  readable Nomad config values like `server.enabled` and `client.enabled`,
  plus other local non-mutating Nomad role observations, to identify whether
  the current host is acting as a server, a client, or one co-located
  single-node server+client service.
- A single combined `nomad.service` privilege observation is not by itself
  proof of separate server and client least-privilege posture.
- When one combined service unit is the privilege evidence path for both
  server and client posture, the checker must mark those surfaces
  `independently_evaluated=false`, set
  `evaluation_source=combined_nomad_systemd_unit`, and explain that one
  combined service unit does not prove separate server/client posture.
- Stable Nomad posture fields may include:
  - `nomad_roles_detected`
  - `evaluation_source`
  - `independently_evaluated`
  - `combined_single_node_service`
  - `role_evidence`
- If safe local role evidence is unavailable, the checker must emit an honest
  `not_evaluated` posture or blocker entry rather than reusing one
  `systemctl show nomad` observation as if it independently proved both
  surfaces.

The checker must report missing local tools or unavailable host observations as
honest `blockers` or `not_evaluated` entries. It must not silently convert a
missing observation into a pass.

The checker must fail closed if the emitted output would contain:

- JWT-SVID material
- Vault tokens
- root tokens
- unseal keys
- PEM private keys
- API keys
- Codex credentials
- raw secret payloads

The checker must also fail closed if the emitted output contains overclaim text
such as:

- `full ES/runtime de-root`
- `rootless Nomad client`
- `governed execution proof`
- `Vault production readiness`
- `workload credential success`
- `support-bundle authority`

The `non_authority_labels` and `explicit_non_claims` fields must keep the
surface honest: this checker is not runtime-profile readiness, not submit
readiness, not service health, not producer-contract compatibility, not
retained-result proof, not workload credential success proof, not Vault
production readiness, not support-bundle authority, and not CVE patch
authority. Direct vendor status, when observed and recorded, is evidence for
the CVE classification only.

## Topology

For Remote Alpha 0.3:

- Control Plane API, UI, worker, and Temporal remain on the Mac.
- Safari on the Mac remains the operator browser for the current alpha.
- ES, AGS, ARS, EGS, Docker, Nomad, SPIRE, Vault, and runtime support run on one remote Linux host.
- CP connects to AGS and ES over direct routable HTTPS with mTLS.
- No shared filesystem is assumed between Mac and remote host.
- Infrastructure Manager may emit profile, doctor, support-bundle, and combined readiness-report outputs, but it is installer/profile/doctor/support-bundle/report direction only. It is not CP run authority, ES runtime authority, a remote SSH installer, a remote host provisioner, a live remote proof runner, or a long-lived reconciler.

## Future ES-Owned Remote Alpha Operator Facade

`Bounded slice rule`: a future ES-owned Remote Alpha operator facade is allowed
only as a bounded MVP proof/support helper plus evidence/projection outputs
only. This P0 effort is operator-helper consolidation and manual recovery
minimization, not a new product deployment surface.

Classification:

- bounded MVP proof/support helper plus evidence/projection outputs only

Proposed path:

- `scripts/remote_alpha_operator.sh`

Current implementation/design status through P0u:

- P0b implemented the help, inventory, and print-command skeleton.
- P0e aligned help, inventory, and route wording with the operator
  involvement model: the human remains the operator, the script is a bounded
  ES Remote Alpha operator facade/workflow, and the goal is minimizing manual
  stitching rather than eliminating prompts.
- P0d implements exactly one staged-helper delegation route,
  `es-writable-state-readiness-check`.
- P0f implements exactly one bounded readiness workflow command,
  `readiness-session`, over that existing route.
- P0g implements one safe/local recovery workflow skeleton,
  `recovery-session`, with print-only plan, inventory, next-step guidance, and a
  local evidence-check mode over operator-supplied existing JSON evidence files.
- P0h extends only `recovery-session --evidence-check` with known-schema
  interpretation, `--strict-known-schema`, and non-recursive `--evidence-dir`
  discovery of expected local evidence filenames.
- P0i adds exactly one secret-sensitive recovery-session route,
  `recovery-session vault-unseal-existing --host-local`, which delegates only to
  the public reset helper's `--unseal-only` mode from a fixed script-relative
  path.
- P0j preserves that host-local fallback and adds one Mac-side secret-sensitive
  route, `recovery-session vault-unseal-existing --ssh-target <target>
  --interactive-tty`, which stages only
  `scripts/remote_alpha_reset_disposable_vault.sh` to the remote host and
  invokes only the staged helper's `--unseal-only` mode over an interactive SSH
  TTY.
- P0k adds one Mac-side dry-run-only disposable reset planning route,
  `recovery-session vault-reset-disposable --ssh-target <target> --dry-run`,
  which stages only `scripts/remote_alpha_reset_disposable_vault.sh` to the
  remote host and invokes only the staged helper's `--dry-run` mode.
- P0l is design/static-test prep only. It documents the future Mac-side
  destructive disposable reset contract as
  `recovery-session vault-reset-disposable --ssh-target <target>
  --execute-reset --interactive-tty`, but at P0l it did not implement
  `--execute-reset`; that route remained future until later implementation,
  audit, and live-validation slices.
- P0m implements exactly that Mac-side destructive disposable reset operator
  route, `recovery-session vault-reset-disposable --ssh-target <target>
  --execute-reset --interactive-tty`, with static and fake SSH/SCP validation
  only. P0m does not run live SSH, sudo, Vault, reset, unseal, execute-reset,
  Infrastructure Manager refresh, support-bundle collection, CP proof,
  workload-auth live checks, runtime identity generation, or network-dependent
  integration tests.
- P0n adds one separate Mac-side post-reset workload-auth evidence route,
  `recovery-session vault-workload-auth-check --ssh-target <target>
  --interactive-tty`, with static and fake SSH/SCP validation only. P0n stages
  only `scripts/remote_alpha_vault_workload_auth_check.sh` and
  `scripts/internal/remote_alpha_vault_workload_auth_check.sh`, preserves their
  public/internal relative layout on the remote host, invokes only the staged
  public workload-auth helper over `ssh -tt`, keeps the canonical summary on
  the remote host at
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`,
  does not copy the summary back to Mac `.out`, creates no operator summary,
  captures no transcript, handles no secrets, and keeps IM refresh,
  support-bundle collection, CP proof, runtime identity generation, and
  reset/unseal separate.
- P0o adds one safe local/print-only post-reset Vault workload-auth bootstrap
  planning surface, `recovery-session vault-workload-auth-bootstrap
  [--help|--plan|--inventory]`. It performs no live bootstrap, no SSH, no sudo,
  no Vault command, no root-token prompt, no proof secret creation, no
  workload-auth check, no reset/unseal, no IM execution, no support-bundle
  collection, no CP proof, and no runtime identity generation.
- P0p is design/static-test prep only for the future secret-sensitive execution
  route, `recovery-session vault-workload-auth-bootstrap --ssh-target <target>
  --execute-bootstrap --interactive-tty`. It defines the helper, prompt,
  summary, flag, boundary, and fake/static-test contract for a later
  implementation slice, but it implements no helper, no staging, no Vault
  writes, no root-token or proof-secret prompt, no workload-auth check, no
  reset/unseal, no IM/support-bundle/CP/runtime-identity execution, no summary,
  and no live validation.
- P0q implements exactly that secret-sensitive workload-auth bootstrap helper,
  Mac-side recovery-session route, and bounded remote filesystem preparation
  for the bootstrap summary path, with static and fake tests only:
  `recovery-session vault-workload-auth-bootstrap --ssh-target <target>
  --execute-bootstrap --interactive-tty`, plus
  `recovery-session vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-summary-path --interactive-tty`. P0q stages only
  `scripts/remote_alpha_vault_workload_auth_bootstrap.sh` and
  `scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`, preserves
  their public/internal relative layout, invokes only the staged public helper
  over `ssh -tt`, obtains Vault bootstrap authority and proof secret values
  only from the visible/silent remote helper TTY prompt, uses an in-process
  Vault API client rather than `VAULT_TOKEN` or `vault login`, writes only the
  remote non-secret summary at
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`,
  copies no summary back to Mac `.out`, captures no transcript, and keeps
  workload-auth checks, reset/unseal, IM refresh, support bundles, CP proof,
  and runtime identity work separate. The `--prepare-summary-path` form is
  OS/filesystem preparation only: it prepares the remote summary directory,
  bootstrap summary file ownership/mode when needed, and same-directory temp
  writability before any helper staging or Vault/root/proof prompt.
- P0r implements exactly one Mac-side runtime identity evidence route,
  `recovery-session runtime-identity-summary --ssh-target <target>
  --interactive-tty`, with static and fake SSH/SCP validation only. P0r stages
  only `scripts/remote_alpha_runtime_identity_helper_summary.sh`, invokes only
  that staged helper over `ssh -tt`, keeps the canonical summary on the remote
  host at
  `/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`,
  does not copy the summary back to Mac `.out`, creates no operator summary,
  captures no transcript, handles no secrets, and keeps workload-auth
  bootstrap/check, reset/unseal, IM refresh, support bundles, CP proof,
  runtime identity generation, runtime-profile readiness, submit readiness, and
  retained-result readiness separate.
- P0s/P0t now share only one dedicated fixed-scope status collector. The
  Mac-side `es-service-tls-status` and `es-governance-tls-status` compatibility
  routes stage that one status file, retain visible interactive sudo, and leave
  separate protected status-only summaries on the host. The two renewal names
  and direct public renewal wrapper are held before contact. No P0s/P0t
  backup, install, restart, service probe, or renewal authority is added.
- P0u adds exactly one bounded Remote Alpha host-local operator healthcheck
  client TLS status/renew helper pair and two Mac-side recovery-session routes,
  `recovery-session operator-healthcheck-tls-status --ssh-target <target>
  --interactive-tty` and
  `recovery-session operator-healthcheck-tls-renew --ssh-target <target>
  --interactive-tty --execute-renew`, with static and fake SSH/SCP validation
  only. P0u stages only
  `scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and
  `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`, invokes
  only `--status` or `--execute-renew`, currently fails closed before mutation
  for renew with `unsupported_signing_topology` until a documented CA
  custody/signing design exists, keeps the canonical
  summary on the remote host at
  `/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`,
  does not copy the summary back to Mac `.out`, creates no operator summary,
  captures no transcript, handles no secrets, does not restart ES, and keeps IM
  refresh, support-bundle collection, CP proof, Vault/SPIRE/Nomad changes,
  workload-auth, reset/unseal, runtime identity work, ES service TLS renewal,
  and ES governance TLS renewal separate.
- P0v implements the ES-owned noninteractive read-only operator-healthcheck TLS
  status route
  `recovery-session operator-healthcheck-tls-status-noninteractive
  --ssh-target <target> --format json`. The implemented contract is recorded
  in `.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`; it
  uses a dedicated local Python runtime and a streamed fixed remote collector,
  changes no MA route metadata, allows no scheduled execution, and performs no
  renewal or mutation.
- Implemented subcommands are `help`, `inventory`, `print-refresh-command`,
  `print-support-bundle-command`, `print-im-commands`,
  `es-writable-state-readiness-check`, `readiness-session`, and
  `recovery-session`.
- The writable-state readiness route delegates only to the public staged wrapper
  `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`.
- The route is check-only/non-mutating by construction: it has no `--apply`
  path, rejects `--dry-run`, and requires an explicit `--ssh-target` before the
  helper may run. Host-local execution through the operator facade is not
  enabled in P0d.
- The route accepts only the P0c allowlisted helper flags and rejects unknown
  flags, unknown positional arguments, duplicate route flags, and secret-like
  arguments before helper execution.
- The readiness session accepts only its own allowlisted workflow flags,
  delegates only through the existing readiness route/helper path, preserves
  the two IM-consumed artifact filenames, and prints only non-secret local
  metadata after scanning the artifacts for secret-like content.
- The recovery session accepts only its own allowlisted safe/local flags plus
  the explicit host-local and Mac-side interactive TTY `vault-unseal-existing`
  submodes, the P0k dry-run `vault-reset-disposable` submode, the P0m
  interactive TTY `vault-reset-disposable --execute-reset` submode, the P0n
  Mac-side interactive TTY `vault-workload-auth-check` submode, the P0o safe
  local/print-only `vault-workload-auth-bootstrap` planning submode, and the
  P0q Mac-side interactive TTY `vault-workload-auth-bootstrap
  --execute-bootstrap` submode and bounded
  `vault-workload-auth-bootstrap --prepare-summary-path` preparation submode,
  plus the P0r Mac-side interactive TTY `runtime-identity-summary` evidence
  submode, plus the P0s/P0t Mac-side interactive TTY
  `es-service-tls-status` and `es-governance-tls-status` compatibility
  submodes with both renewal names held before contact, plus the
  P0u Mac-side interactive TTY `operator-healthcheck-tls-status` and
  `operator-healthcheck-tls-renew` submodes.
  Its safe modes
  do not use SSH or remote staging, inspect live host state, dispatch generic
  helpers, or execute destructive or authority-bearing work. Its execution
  submodes remain individually allowlisted and route-specific. Its
  `--evidence-check` mode reads only supplied local JSON evidence paths, scans
  for secret-like content before parsing, and prints only path, byte count,
  SHA-256 digest, schema, and selected safe status/count metadata. Known schemas
  are interpreted through explicit safe-field allowlists; unknown schemas are
  allowed by default and classified as `schema_interpretation=unknown` unless
  `--strict-known-schema` is set.
- The `vault-unseal-existing --host-local` route is secret-sensitive but
  non-destructive. It must be run on the Remote Alpha host where Vault is
  installed and reachable, and the human operator enters any unseal key directly
  into the visible delegated helper/Vault CLI prompt. The facade does not prompt
  for, read, type, log, relay, persist, summarize, or accept secret material.
- The `vault-unseal-existing --ssh-target <target> --interactive-tty` route is
  the Mac-side topology for the same non-destructive unseal-existing workflow.
  It requires a visible local terminal before staging, allocates an interactive
  SSH TTY for the remote helper, stages only the public reset helper to a
  route-specific remote scratch path, invokes only `--unseal-only`, attempts
  staged-helper cleanup by default, and writes no `.out`, transcript, log,
  support bundle, report, generated JSON, or operator summary.
- The `vault-reset-disposable --ssh-target <target> --dry-run` route is the
  Mac-side topology for disposable Vault reset planning only. It does not
  require an interactive TTY, stages only the public reset helper to a
  route-specific remote scratch path, invokes only `--dry-run`, attempts
  staged-helper cleanup by default, and writes no `.out`, transcript, log,
  support bundle, report, generated JSON, or operator summary. It is
  non-destructive: it does not stop Vault, move raft storage, init or unseal
  Vault, run post-unseal checks, run workload-auth checks, run Infrastructure
  Manager, or collect support bundles.
- The `vault-reset-disposable --ssh-target <target> --execute-reset
  --interactive-tty` route is the P0m Mac-side destructive disposable reset
  operator route. It requires a visible local terminal before staging,
  allocates an interactive SSH TTY, stages only the public reset helper to a
  route-specific remote scratch path, invokes only `--execute-reset`, requires
  the existing exact confirmation phrase
  `RESET DISPOSABLE REMOTE ALPHA VAULT` only in the visible remote helper/Vault
  terminal, attempts staged-helper cleanup by default, writes no `.out` summary
  or operator summary, captures no transcript, handles no secrets, and keeps
  post-reset evidence checks as separate later steps. P0m validation is static
  and fake SSH/SCP only; it is not live execute-reset validation.
- The `vault-workload-auth-check --ssh-target <target> --interactive-tty`
  route is the P0n Mac-side post-reset workload-auth evidence route. It
  requires a visible local terminal before staging, allocates an interactive
  SSH TTY, stages exactly the public workload-auth helper and its internal
  implementation helper, invokes only the staged public helper with no helper
  override flags, attempts staged-helper cleanup by default, writes no `.out`
  summary or operator summary, captures no transcript, handles no secrets, does
  not print full summary JSON, and leaves the canonical summary on the remote
  host at
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`.
  The route is evidence/projection only: it is not workload-auth bootstrap, not
  ES token brokerage, not Vault production readiness, not governed execution
  proof, not IM refresh/support-bundle collection, not CP proof, not runtime
  identity generation, and not reset/unseal.
- The `vault-workload-auth-bootstrap [--help|--plan|--inventory]` submode is the
  P0o safe local/print-only planning surface for the P0q bootstrap route. With
  no mode, the submode defaults to printing the plan/help and exiting zero. It accepts only
  `--help`, `--plan`, and `--inventory`. It writes no `.out`, JSON, support
  bundle, report, generated artifact, operator summary, retained bundle, or CP
  artifact and performs no live action.
- The `vault-workload-auth-bootstrap --ssh-target <target>
  --execute-bootstrap --interactive-tty` route is the P0q Mac-side
  secret-sensitive bootstrap route. It requires a visible Mac-side terminal
  before staging, allocates an interactive SSH TTY, stages exactly the
  dedicated workload-auth bootstrap public/internal helper pair, obtains
  bootstrap authority and proof secret values only from TTY prompts owned by
  the human operator in the remote helper, writes only a remote non-secret
  summary, and attempts staged-helper cleanup by default. It must not pass or
  store secrets through args, env, files, logs, `.out`, reports, support
  bundles, retained bundles, CP artifacts, transcripts, helper summaries,
  printed commands, or Codex output.
- The `vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-summary-path --interactive-tty` route is bounded OS/filesystem
  preparation only. It requires a visible Mac-side terminal, allocates an
  interactive SSH TTY, may prompt only for OS sudo, prepares only
  `/var/tmp/execution-substrate-remote-alpha`,
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`,
  and same-directory temp writability, creates no final bootstrap summary,
  does not stage helpers, and does not run Vault, workload-auth checks,
  reset/unseal, IM, support bundles, CP proof, or runtime identity generation.
- The `vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-config-readability --interactive-tty` route is bounded OS/filesystem
  preparation only. It requires a visible Mac-side terminal, allocates an
  interactive SSH TTY, may prompt only for OS sudo, prepares only helper-user
  readability for
  `/etc/execution-substrate/vault/workload-zone-vault-config.json` through
  fixed-path user ACLs when needed, prints no config contents, does not stage
  helpers, and does not run Vault, workload-auth checks, reset/unseal, IM,
  support bundles, CP proof, or runtime identity generation.
- The `runtime-identity-summary --ssh-target <target> --interactive-tty` route
  is the P0r Mac-side runtime identity evidence route. It requires a visible
  local terminal before staging, allocates an interactive SSH TTY, stages only
  `scripts/remote_alpha_runtime_identity_helper_summary.sh`, invokes only the
  staged helper with no helper override flags, attempts staged-helper cleanup by
  default, writes no `.out` summary or operator summary, captures no
  transcript, handles no secrets, does not print full summary JSON, and leaves
  the canonical summary on the remote host at
  `/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`.
  The route is evidence/projection only: it is not workload-auth
  bootstrap/check, not reset/unseal, not ES token brokerage, not runtime
  identity generation, not runtime-profile readiness, not submit readiness, not
  retained-result readiness, not governed execution proof, not IM
  refresh/support-bundle collection, not CP proof, and not production readiness.
- The `es-service-tls-status --ssh-target <target> --interactive-tty` and
  `es-governance-tls-status --ssh-target <target> --interactive-tty` routes
  stage only the dedicated status collector with fixed P0s/P0t scope. Stage
  self-clean precedes status work. Completed evidence remains under the
  protected status root in separate status-only canonical files; no summary
  is copied to Mac `.out` and TTY output is not machine evidence.
- The `es-service-tls-renew` and `es-governance-tls-renew` names are held and
  refuse before staging, SSH, SCP, sudo, or host contact.
- The `operator-healthcheck-tls-status --ssh-target <target>
  --interactive-tty` route is the P0u Mac-side host-local operator healthcheck
  client TLS evidence route. It requires a visible local terminal before
  staging, allocates an interactive SSH TTY, stages exactly the operator
  healthcheck TLS public/internal helper pair, invokes only `--status`,
  attempts staged-helper cleanup by default, writes no `.out` summary or
  operator summary, captures no transcript, handles no secrets, does not print
  full summary JSON, and leaves the canonical summary on the remote host at
  `/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`.
  Status mode is non-mutating.
- The `operator-healthcheck-tls-renew --ssh-target <target>
  --interactive-tty --execute-renew` route is the P0u Mac-side host-local
  operator healthcheck client TLS recovery route. It uses the same staged
  helper pair, invokes only `--execute-renew`, and is bounded to
  `/etc/execution-substrate/tls/operator-client-cert.pem` and
  `/etc/execution-substrate/tls/operator-client-key.pem`. Until a documented
  CA custody/signing design exists, it fails closed with
  `unsupported_signing_topology` before backup, install, service restart, or
  post-renew probes. Any future renewed client certificate must use
  `URI:spiffe://execution.internal/operator/local`. It does not restart ES. It
  is not generic TLS deployment, not IM
  reconciliation, not CP proof, not Vault/SPIRE/Nomad change, not workload-auth,
  not runtime identity, not ES service TLS renewal, not ES governance TLS
  renewal, and not production readiness.
- The `operator-healthcheck-tls-status-noninteractive --ssh-target <target>
  --format json` route is implemented by P0v as a separate no-prompt,
  read-only JSON route. It preserves the current interactive status route,
  requires no local TTY, creates no pseudo-TTY, uses no-prompt SSH, uses no
  prompt-capable sudo, avoids password storage/replay, avoids remote helper
  staging, avoids remote summary mutation, emits only bounded JSON from the
  local runtime, and fails closed when noninteractive auth, protocol shape, or
  redaction cannot be proven.
- The operator-authorized operator-healthcheck TLS replacement design is
  recorded separately in
  `.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`,
  with signing/custody hardening in
  `.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md` and
  resolution criteria in
  `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`,
  plus a blocked signer/custody decision record in
  `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`.
  It is docs/static-test only and does not implement renewal, replacement,
  CP diagnose, IM profile-lineage refresh, Bridge
  authority, Maintenance Agent authority, route eligibility widening, or live
  proof. It preserves `operator-healthcheck-tls-renew` as blocked with
  `unsupported_signing_topology` because signing authority, signer custody, key
  custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check
  semantics remain explicit ES unresolved stop conditions for
  `spiffe://execution.internal/operator/local`.
- The combined `vault-workload-auth-bootstrap --ssh-target <target>
  --execute-bootstrap --prepare-summary-path --prepare-config-readability
  --interactive-tty` route runs summary preparation and then config readability
  preparation before helper staging, helper preflights, any Vault bootstrap
  authority prompt, any proof secret prompt, and any Vault write.
- The script prints Mac-side Infrastructure Manager refresh and support-bundle
  commands only. It does not invoke Infrastructure Manager refresh or
  support-bundle collection; the readiness session prints those commands as
  follow-up evidence/provenance actions only, and the recovery session may print
  those commands as next-step text only.
- P0q implements the safe local/print-only workload-auth bootstrap modes and
  the Mac-side secret-sensitive bootstrap execution route described here, in
  addition to the previously landed reset/unseal, readiness, and workload-auth
  evidence routes. P0r adds the separate Mac-side runtime identity summary
  evidence route. P0s/P0t retain only dedicated status routes for
  ARS/AGS/ES artifact-registry and ES -> EGS trust-model mTLS; their renewal
  names are held. P0u adds
  the separate bounded operator healthcheck TLS status/renew route for the
  host-local operator client identity. P0v adds the implemented read-only
  noninteractive operator-healthcheck TLS status contract, but scheduled
  execution remains false and no consumer authority changes.
  Vault service-user check/apply execution, runtime security
  check, post-unseal check combination, live execute-reset validation, live
  workload-auth bootstrap validation, preinstalled helper bundles, generic
  helper dispatch, and all other staged `es-*` helper delegation remain not
  implemented and require later audited slices.
- Operator facade output is deterministic operator guidance and
  evidence/projection only. The facade itself writes no operator-owned summary,
  support bundle, report, or new authority artifact; the delegated helper
  remains the owner of its existing readiness/provenance artifacts when the
  route or readiness session is intentionally invoked. The recovery session
  creates no summary file, writes no `.out`, and does not wrap the P0i/P0j
  unseal delegation, the P0k reset dry-run delegation, or the P0m execute-reset
  delegation in transcript capture.

### Operator Involvement Model

Human operator involvement is expected and allowed for this facade. The goal is
to minimize manual stitching, copying, and recovery sequencing, not to
eliminate all prompts.

The human operator remains the authority for interactive prompts. The script is
a bounded operator facade/workflow, not the operator and not an authority
source.

Interactive sudo is allowed only under the explicit `--interactive-sudo` route
flag and only from a visible terminal. The P0i `vault-unseal-existing
--host-local` mode may delegate to the existing public reset helper's
`--unseal-only` flow from a visible terminal on the Remote Alpha host. The P0j
Mac-side `vault-unseal-existing --ssh-target <target> --interactive-tty` mode
may stage that same public helper and run only `--unseal-only` through an
interactive SSH TTY from the Mac. The P0k Mac-side
`vault-reset-disposable --ssh-target <target> --dry-run` mode may stage that
same public helper and run only `--dry-run`; it does not require an interactive
TTY because it does not run reset, init, unseal, or secret-producing flows. P0l
fixed the destructive Mac-side
`vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`
contract as an explicit visible-terminal mode, and P0m implements that bounded
operator route without live execute-reset validation. P0n adds the Mac-side
`vault-workload-auth-check --ssh-target <target> --interactive-tty` evidence
route over only the workload-auth public/internal helper pair; it is not
workload-auth bootstrap and not a token broker. P0o adds only the safe
local/print-only `vault-workload-auth-bootstrap` planning surface; it has no
root-token prompt and no live bootstrap execution. P0p defines only the future
prompt-only, TTY-bound execution contract; it still has no implemented
root-token or proof-secret prompt and no live bootstrap execution. P0q
implements the prompt-only, TTY-bound workload-auth bootstrap route over the
dedicated bootstrap public/internal helper pair, with no live validation in
this slice and no ES Vault token brokerage. P0r adds the Mac-side
`runtime-identity-summary --ssh-target <target> --interactive-tty` evidence
route over only the public runtime identity helper summary script; it is not
runtime identity generation, not runtime-profile readiness, and not submit
readiness. P0s/P0t retain the two Mac-side status facade names as temporary
compatibility edges over one dedicated status-only collector. The corresponding
renewal names are held before contact. Neither route grants generic TLS
repair, IM/CP authority, production readiness, or EGS trust-model redesign.
P0u adds the
Mac-side `operator-healthcheck-tls-status --ssh-target <target>
--interactive-tty` and `operator-healthcheck-tls-renew --ssh-target <target>
--interactive-tty --execute-renew` routes over only the fixed operator
healthcheck TLS public/internal helper pair; they are not generic TLS
deployment, IM reconciliation, CP proof, Vault/SPIRE/Nomad change,
workload-auth, runtime identity, ES service restart, or production readiness. In these topologies the
facade itself does not prompt for, read, type, log, relay, persist, summarize,
or accept the unseal key, root token, client token, Vault token, API key,
private key, password, JWT-SVID payload, proof secret material, or secret
payload. Future Vault, reset, unseal, or workload-auth prompts may be allowed
only in explicit secret-sensitive modes, silent where appropriate, and never
through CLI arguments, environment variables, environment files, local or remote
files, logs, reports, `.out`, support bundles, retained bundles, CP artifacts,
helper summaries, readiness outputs, printed commands, or Codex output. The P0m
execute-reset phrase
`RESET DISPOSABLE REMOTE ALPHA VAULT` must be typed by the operator directly in
the visible remote helper/Vault terminal and must not be accepted via CLI args,
environment values, environment files, files, logs, artifacts, or Codex output.
Root tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, TLS
private keys, SPIFFE material, passwords, raw prompts, and secret payloads must
not be recorded by the facade or delegated helpers.

Helper outputs remain evidence/projection only. Infrastructure Manager live
refresh and support-bundle collection remain separate IM
evidence/provenance/diagnostics actions unless a later reviewed contract says
otherwise. Remote Alpha remains bounded proof/support posture only; it is not
production, HA, multi-tenant, general deployment architecture, remote
provisioning, or reconciliation.

Purpose:

- operator ergonomics over existing bounded helpers
- inventory of available ES-owned Remote Alpha helper surfaces
- printing exact commands for existing Mac-side Infrastructure Manager refresh
  and existing ES helper paths
- future staged-wrapper delegation only after each delegated surface has an
  audited sudo and artifact model

Execution-context split:

- Mac-side only: inventory, print IM commands, staged-wrapper delegation for
  existing repo-side staged helpers, P0j
  `recovery-session vault-unseal-existing --ssh-target <target>
  --interactive-tty`, and P0k
  `recovery-session vault-reset-disposable --ssh-target <target> --dry-run`,
  and P0m
  `recovery-session vault-reset-disposable --ssh-target <target>
  --execute-reset --interactive-tty`, and P0n
  `recovery-session vault-workload-auth-check --ssh-target <target>
  --interactive-tty`, while P0o
  `recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]`
  remains safe local/print-only and does not use SSH or staging. P0p defined
  the future Mac-side
  `recovery-session vault-workload-auth-bootstrap --ssh-target <target>
  --execute-bootstrap --interactive-tty` contract, and P0q implements it with
  the dedicated bootstrap public/internal helper pair and fake/static
  validation only. P0q also implements the bounded
  `recovery-session vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-summary-path --interactive-tty` preparation form for summary-path
  writability only. P0r adds the Mac-side
  `recovery-session runtime-identity-summary --ssh-target <target>
  --interactive-tty` evidence route over only
  `scripts/remote_alpha_runtime_identity_helper_summary.sh`, with fake/static
  validation only and no summary copy-back. P0s/P0t retain only the
  `es-service-tls-status` and `es-governance-tls-status` compatibility routes
  over one fixed-scope dedicated collector with separate protected status
  evidence. Both corresponding renew names are held before host contact.
  P0u adds the Mac-side
  `recovery-session operator-healthcheck-tls-status --ssh-target <target>
  --interactive-tty` and `recovery-session operator-healthcheck-tls-renew
  --ssh-target <target> --interactive-tty --execute-renew` routes over only
  `scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and
  `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`, with
  fake/static validation only, no summary copy-back, no helper overrides, and
  no ES restart.
- Remote-host only: P0i `recovery-session vault-unseal-existing --host-local`,
  and Vault service-user check. The host-local runtime identity helper remains
  available as a direct helper, but P0r adds the Mac-side operator topology for
  that evidence route. The old host-local ES service TLS renewal public wrapper now refuses
  locally, and its internal helper is undispatched. P0s/P0t status uses only
  the dedicated collector. The host-local operator healthcheck TLS helper remains
  available as a direct helper, but P0u adds the Mac-side operator topology for
  that bounded host-local client identity status/renew route. The host-local workload-auth helper remains available as
  a direct helper, but P0n adds the Mac-side operator topology for that evidence
  route. P0m does not add a
  host-local execute-reset route through the operator facade; the reset
  helper's direct host-local capability remains outside the P0m
  operator-facade route.
- Not v1 except the P0j unseal-existing route, the P0k reset dry-run planning
  route, the P0m explicit execute-reset operator route, the P0n workload-auth
  evidence route, the P0o safe bootstrap planning surface, and the P0q
  workload-auth bootstrap execution route, the P0r runtime identity summary
  evidence route, the P0s/P0t dedicated TLS status routes with held renewal,
  and the P0u operator healthcheck TLS
  status/renew route: generic remote staging, arbitrary shell passthrough,
  post-unseal/service-user/IM/support-bundle/CP-proof bundling, live execute-reset
  validation, or live Vault workload-auth bootstrap validation.

Proposed v1/v2 slice sequence:

1. docs/static-test prep
2. help/inventory/print-command skeleton
3. staged-helper delegation after sudo-model review
4. host-local Vault unseal-existing after reset-helper tests and audit, with
   destructive reset kept for a later exact-phrase slice
5. Mac-side interactive TTY unseal-existing over the existing reset helper,
   without reset, post-unseal checks, generic helper dispatch, transcripts, or
   generated evidence
6. Mac-side disposable Vault reset dry-run planning over the existing reset
   helper, without destructive reset, init, unseal, post-unseal checks, IM,
   support-bundle collection, generic helper dispatch, transcripts, or
   generated evidence
7. Mac-side disposable Vault reset execute-reset contract prep as
   docs/static-test only, with the P0k dry-run route as prerequisite, exact
   phrase confirmation, visible-terminal-only secret handling, no transcript
   capture, no post-unseal/workload-auth/IM/support-bundle/CP-proof bundling,
   and no implementation
8. Mac-side disposable Vault reset execute-reset implementation with static and
   fake SSH/SCP validation only, no live reset, no secret handling, no
   transcript capture, and no bundled post-reset evidence checks
9. Mac-side post-reset Vault workload-auth evidence route over the fixed
   public/internal workload-auth helper pair, with static and fake SSH/SCP
   validation only, no summary copy-back, no bootstrap, no token brokerage, no
   IM/support-bundle/CP-proof/runtime-identity/reset/unseal bundling, and no
   transcript capture
10. safe local/print-only workload-auth bootstrap planning surface after the
   post-reset evidence route reported a conservative Vault JWT login failure
11. secret-sensitive workload-auth bootstrap execution contract prep as
   docs/static-test only, with a dedicated future helper, prompt-only secret
   handling, remote-only non-secret evidence, fake/static tests, and no
   implementation
12. secret-sensitive workload-auth bootstrap implementation with static and
   fake validation only, no live bootstrap, prompt-only secret handling, no
   transcript capture, and no workload-auth check/reset/unseal/IM/support/CP or
   runtime identity bundling
13. Mac-side runtime identity summary evidence route over only the fixed public
   runtime identity helper summary script, with static and fake SSH/SCP
   validation only, no summary copy-back, no helper overrides, no
   workload-auth/reset/unseal/IM/support/CP bundling, no readiness claim, and no
   transcript capture
14. Mac-side ES service TLS status-only compatibility route over the dedicated
   fixed-scope collector, with protected remote status evidence and renewal held
   before contact
15. Mac-side ES governance TLS status-only compatibility route over the same
   collector's separate fixed execution-governance scope, distinct protected
   summary, and renewal held before contact
16. Mac-side operator healthcheck TLS status/renew route over only the fixed
   operator healthcheck TLS public/internal helper pair, with static and fake
   validation only, no summary copy-back, no helper overrides, no ES restart,
   no Vault/SPIRE/Nomad/IM/CP/runtime identity/workload-auth bundling, and no
   production readiness claim
17. later separate audit/live-validation and post-reset evidence slices before
   any live destructive execute-reset validation or post-reset authority claim

Sudo model:

- prefer one explicit interactive sudo validation followed by `sudo -n` where
  supported
- noninteractive default for staged wrappers that support it
- config/TLS staged wrapper is currently a sudo-model gap unless fixed

The facade is not IM automation or reconciliation, not CP authority, not Vault
production lifecycle, not ES token brokerage, and not deployment architecture.

The facade must not make IM a remote reconciler, CP a Vault/runtime recovery
authority, ES a Vault token broker, or Remote Alpha a production/general
deployment architecture.

The facade must not rename, replace, aggregate, or obscure existing
IM-consumed artifact filenames.

Any optional operator summary is non-secret evidence/projection only, not an
IM input in v1.

The `vault-workload-auth-bootstrap` execution surface is implemented only as
the P0q bounded Remote Alpha helper/facade route, with a separate bounded
summary-path preparation form. Live validation remains blocked/reopened for a
later audited slice. P0q does not implement root-token automation, ES token
brokerage, workload-auth success proof, live validation, or
production/deployment/reconciliation architecture.

### P0c First Staged-Helper Delegation Plan

`Bounded slice rule`: P0c is design/static-test prep only. It does not
implement helper delegation, does not change `scripts/remote_alpha_operator.sh`
behavior beyond existing refusal coverage, and does not route to SSH, sudo,
Infrastructure Manager, Vault, Nomad, Docker, SPIRE, `systemctl`, support
bundle collection, reset/unseal flows, or ES helper execution.

The recommended first staged-helper delegation target for the next
implementation slice is:

- proposed operator subcommand: `es-writable-state-readiness-check`
- exact helper to delegate later:
  `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`
- helper internal implementation:
  `scripts/internal/remote_alpha_stage_es_writable_state_readiness_check.sh`

The later route may pass only these helper flags:

- `--ssh-target <user@host>`
- `--mode <alpha-compat|future-non-root-required>`
- `--run-id <timestamp-or-id>`
- `--output-dir </path/to/output-dir>`
- `--readiness-output </path/to/es-writable-state-readiness.json>`
- `--helper-staging-record-output </path/to/es-writable-state-readiness-helper-staging-record.json>`
- `--provenance-output </path/to/es-writable-state-readiness-helper-staging-record.json>`
- `--interactive-sudo`
- `--keep-staging-on-failure`

The later route must forbid:

- `--apply`
- reset/unseal behavior
- Vault workload-auth bootstrap or workload-auth proof routing
- runtime-identity summary routing
- Vault service-user or ES service-user migration routing
- ES config/TLS apply routing
- ES binary deployment routing
- generic remote staging options
- arbitrary shell or command strings
- secret-like CLI arguments, environment values, logs, reports, summaries, or
  artifacts
- any new aggregate operator summary in the first delegation slice

The first delegation slice must stay check-only/non-mutating. It may rely on
the helper's existing temporary checker staging under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`, but the
operator facade itself must not introduce a generic remote staging framework.
Default sudo behavior must remain the helper's noninteractive `sudo -n`
preflight and structured `sudo_unavailable` evidence. `--interactive-sudo`
may remain available only for a visible terminal when a bounded password
handoff is authorized.

The first delegation slice must preserve the exact existing
Infrastructure Manager-consumed local artifact filenames:

- `es-writable-state-readiness.json`
- `es-writable-state-readiness-helper-staging-record.json`

The route must not rename, replace, aggregate, or obscure those files. It must
not call Infrastructure Manager; the facade may continue to print the
Mac-side IM refresh and support-bundle commands only.

Expected tests for the later implementation slice:

- operator help/inventory documents the new check-only route without widening
  the facade classification
- the new subcommand delegates only to
  `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`
- the route allows only the flags listed above and rejects `--apply`, unknown
  flags, arbitrary command strings, and secret-like arguments before routing
- default route execution passes `--ssh-target`, optional `--mode`, output
  paths, and sudo mode through to the existing helper without changing helper
  artifact names
- the route preserves the helper's `sudo -n` default and structured
  `sudo_unavailable` behavior
- the route writes no aggregate operator summary and does not call
  Infrastructure Manager
- the existing staged-helper tests remain the source of truth for helper
  staging, provenance, JSON validation, and non-mutating evidence acceptance

This target is safer than the other staged candidates because it has no
`--apply` mode, writes only readiness/provenance evidence, stages only the
minimal checker helper tree, already defaults to noninteractive `sudo -n`, and
does not touch config/TLS, binaries, stable writable-state ownership,
long-lived service-user posture, Vault, runtime identity, reset/unseal, or
workload-auth bootstrap. The binary-deployment, writable-state ownership, and
service-user migration wrappers have check-only defaults but also expose
mutation-capable `--apply` paths. The config/TLS staged wrapper is already
called out above as a sudo-model gap unless fixed and also fronts a helper
whose host-local default is apply.

### P0d First Staged-Helper Delegation Implementation

`Bounded slice rule`: P0d implements exactly one Remote Alpha operator route:
`scripts/remote_alpha_operator.sh es-writable-state-readiness-check`.

The implemented route delegates only to:

- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`

It does not source helper scripts, does not invoke `scripts/internal/*`, does
not construct helper paths from user input, and does not introduce generic
staging or generic helper routing.

The route requires:

- `--ssh-target <user@host>`

Host-local execution is intentionally not enabled through the operator facade in
P0d. That keeps this first delegation slice aligned with the existing staged
wrapper contract and avoids turning the facade into a local privileged helper
runner.

The route may pass only these helper flags:

- `--ssh-target <user@host>`
- `--mode <alpha-compat|future-non-root-required>`
- `--run-id <timestamp-or-id>`
- `--output-dir </path/to/output-dir>`
- `--readiness-output </path/to/es-writable-state-readiness.json>`
- `--helper-staging-record-output </path/to/es-writable-state-readiness-helper-staging-record.json>`
- `--provenance-output </path/to/es-writable-state-readiness-helper-staging-record.json>`
- `--interactive-sudo`
- `--keep-staging-on-failure`
- `--help`

The route rejects before helper execution:

- `--apply`
- `--dry-run`
- unknown flags
- unknown positional arguments
- duplicate route flags; the operator does not rely on helper last-one-wins
  parsing
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

The operator facade itself does not call `sudo`, `ssh`, `scp`, Vault, Nomad,
Docker, SPIRE, `systemctl`, Infrastructure Manager refresh, support-bundle
collection, reset/unseal flows, workload-auth bootstrap or checks,
runtime-identity summaries, service-user migration helpers, config/TLS helpers,
binary deployment helpers, or writable-state ownership helpers. SSH/SCP and the
helper's noninteractive `sudo -n` preflight remain inside the existing delegated
staged wrapper and only run when an operator intentionally invokes this route
with an explicit `--ssh-target`.

The implemented route preserves the exact existing Infrastructure
Manager-consumed local artifact filenames:

- `es-writable-state-readiness.json`
- `es-writable-state-readiness-helper-staging-record.json`

It does not rename, replace, aggregate, or obscure those files. It writes no
aggregate operator summary and does not call Infrastructure Manager; the facade
may continue to print the Mac-side IM refresh and support-bundle commands only.

### P0f Readiness Session Workflow

`Bounded slice rule`: P0f implements exactly one Remote Alpha operator
workflow command:
`scripts/remote_alpha_operator.sh readiness-session`.

This session is a bounded workflow consolidation over the already implemented
`es-writable-state-readiness-check` route. It is not a live validation slice by
itself, not a new authority source, not a new helper-dispatch framework, and
not an Infrastructure Manager runner.

The session requires:

- `--ssh-target <user@host>`

The session may accept only these flags:

- `--ssh-target <target>`
- `--mode <alpha-compat|future-non-root-required>`
- `--output-dir </path/to/output-dir>`
- `--run-id <timestamp-or-id>`
- `--interactive-sudo`
- `--keep-staging-on-failure`
- `--ssh-alias <alias>` for printed IM commands only
- `--im-profile-dir </path/to/profile-dir>` for printed IM commands only
- `--support-output-root </path/to/support-bundles>` for printed IM commands
  only
- `--help`

The session rejects before route execution:

- `--apply`
- `--dry-run`
- equals-form options
- unknown flags
- positional arguments
- missing flag values
- duplicate workflow flags
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

When `--output-dir` is omitted, the session must generate a fresh
run-specific directory under the repo-local `.out` tree, such as
`.out/remote-alpha-m75q-readiness-session-<UTC timestamp>`. When
`--output-dir` is supplied, the session must use that directory. In both cases
it must refuse to proceed if the selected directory already contains either
expected artifact:

- `es-writable-state-readiness.json`
- `es-writable-state-readiness-helper-staging-record.json`

The session must not treat pre-existing artifacts as fresh evidence.

After the readiness route returns success, the session verifies:

- both expected artifact filenames exist at the selected paths
- both artifacts pass a secret-like content scan before any JSON fields are
  read
- the readiness artifact schema is
  `execution-substrate.remote-alpha.es-writable-state-readiness.v1`
- the staging record schema is
  `execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`
- readiness `operation_mode` is `check_only`
- readiness `non_mutating` is `true`
- readiness `checker_mode` matches the requested mode
- the staging record indicates `checker_ran=true`

The session may print only non-secret metadata: artifact paths, byte counts,
SHA-256 digests, schema names, overall classification, blocker/warning counts,
operation/checker mode, and sudo/checker status fields. It must not print full
JSON contents and must not write an operator summary file.

At the end, the session may print the Mac-side Infrastructure Manager live
refresh and support-bundle commands as separate follow-up actions. Those
printed commands remain IM evidence/provenance/diagnostics actions only; the
session does not execute them, and they are not authority.

P0f does not add Vault reset/unseal, Vault workload-auth, runtime identity,
service-user migration, config/TLS, binary deployment, writable-state
ownership, generic remote staging, arbitrary shell passthrough, live IM
execution, CP proof, support-bundle collection, or Remote Alpha deployment
architecture.

### P0g Recovery Session Safe Skeleton

`Bounded slice rule`: P0g implements one safe/local Remote Alpha operator
workflow command:
`scripts/remote_alpha_operator.sh recovery-session`.

This session is a recovery sequencing skeleton and local evidence-check only. It
is not a live validation slice, not a new authority source, not a helper-dispatch
framework, not an Infrastructure Manager runner, not Vault token brokerage, and
not Remote Alpha deployment/provisioning/reconciliation architecture.

The supported modes are:

- `--help`
- `--plan`
- `--inventory`
- `--next-steps`
- `--evidence-check`

Calling `recovery-session` with no mode prints the plan/help and exits zero. It
must not run live tools.

The session may accept only these shared flags:

- `--help`
- `--plan`
- `--inventory`
- `--next-steps`
- `--evidence-check`
- `--ssh-alias <alias>` for printed IM commands only
- `--im-profile-dir </path/to/profile-dir>` for printed IM commands only
- `--support-output-root </path/to/support-bundles>` for printed IM commands
  only

The session may accept these evidence path flags only with `--evidence-check`:

- `--vault-workload-auth-summary <path>`
- `--runtime-identity-summary <path>`
- `--vault-service-user-summary <path>`
- `--readiness-summary <path>`
- `--staging-record <path>`

The session rejects:

- `--ssh-target`
- `--interactive-sudo`
- `--apply`
- `--dry-run`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--governed-smoke-command`
- arbitrary command strings
- helper path overrides
- unknown flags
- positional arguments
- duplicate operational flags
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

`--plan` prints the bounded recovery sequence only:

- inventory/status is safe/planned
- unseal-existing is a future explicit secret-sensitive mode
- disposable reset dry-run planning is implemented later in P0k as an explicit
  Mac-side dry-run submode
- disposable reset execute-reset remains a future destructive exact-phrase mode
- workload-auth check execution is a future audited live check
- runtime identity summary generation is a future audited evidence route
- Vault service-user check/apply remains separate
- IM refresh and support-bundle commands are separate IM
  evidence/provenance/diagnostics actions and may be printed only

`--inventory` prints static helper inventory only. It may list the reset helper,
workload-auth check helper, runtime identity helper summary, Vault service-user
migration/check helper, and readiness session, with classifications such as
safe/local, check-only, secret-sensitive, destructive, future, and
blocked/reopened. It must not inspect live host state and must not run any
helper.

`--next-steps` prints command text only. It may include an existing
`readiness-session` example plus the Mac-side Infrastructure Manager refresh and
support-bundle command texts. Those printed IM commands remain separate
IM-owned evidence/provenance actions, not ES execution and not authority.

`--evidence-check` is local-only. If no evidence path flags are supplied, it
prints a non-error message that no evidence paths were supplied. For each
supplied path, it must require that the file exists, compute byte count and
SHA-256 digest, scan for secret-like content before JSON parsing, parse JSON,
and print only non-secret metadata: path, byte count, SHA-256 digest,
`schema_version` when present, and selected safe status/count fields when
present. It must not print full JSON, create a session summary file, write
`.out`, run helpers, run IM, or treat evidence as authority. If secret-like
content is detected or JSON is malformed, it must fail with the path
classification only and must not print file contents.

P0g does not add Vault reset/unseal execution, Vault workload-auth check
execution, runtime identity summary generation, Vault service-user check/apply
execution, config/TLS, binary deployment, writable-state ownership, generic
remote staging, arbitrary shell passthrough, live IM execution, CP proof,
support-bundle collection, or Remote Alpha deployment architecture.

### P0h Schema-Aware Recovery Evidence Interpretation

`Bounded slice rule`: P0h extends only the local
`scripts/remote_alpha_operator.sh recovery-session --evidence-check` mode.

This slice remains local-only evidence interpretation. It does not add live
helper execution, Infrastructure Manager execution, support-bundle collection,
CP proof, reset/unseal behavior, workload-auth live checks, runtime identity
summary generation, Vault service-user apply, generic helper dispatch, generated
session summaries, `.out` writes, or authority-bearing behavior.

The known schemas are:

- `execution-substrate.remote-alpha.es-writable-state-readiness.v1`
- `execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`
- `execution-substrate.remote-alpha.vault-workload-auth-summary.v1`
- `execution-substrate.remote-runtime-identity-helper-summary.v1alpha1`
- `execution-substrate.remote-alpha.vault-service-user-migration-summary.v1`

Known schemas must be interpreted through explicit safe-field allowlists. The
operator facade may print only non-secret metadata: path, byte count, SHA-256
digest, schema, schema interpretation, selected status/classification fields,
booleans, and counts. It must not print full JSON, JWT-SVIDs, Vault tokens,
root tokens, unseal keys, API keys, private keys, passwords, proof secret values,
raw identity payloads, arbitrary smoke-command output, or secret-bearing paths.

Unknown schemas are allowed by default. For unknown schemas, the facade may print
only path, byte count, SHA-256 digest, `schema_version` when present, and
`schema_interpretation=unknown`. With `--strict-known-schema`, unknown schemas
must fail without printing file contents.

`--evidence-dir <path>` is local-only. It may discover these direct filenames
under the supplied directory:

- `es-writable-state-readiness.json`
- `es-writable-state-readiness-helper-staging-record.json`
- `vault-workload-auth-summary.json`
- `runtime-identity-helper-summary.json`
- `vault-service-user-migration-check-only.json`
- `vault-service-user-migration-apply-summary.json`

The directory mode must not recurse, must inspect only files that exist, must
report missing expected filenames as `not_supplied`, and must never write into
the directory.

Schema-aware interpretation remains evidence/projection/diagnostics only. It is
not IM authority, CP recovery authority, ES Vault token brokerage, Vault
production lifecycle, or Remote Alpha deployment/provisioning/reconciliation
architecture.

### P0i Host-Local Vault Unseal Existing Recovery Session

`Bounded slice rule`: P0i adds exactly one secret-sensitive
`recovery-session` route:
`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing
--host-local`.

This route is an explicit host-local operator mode. It must be run on the Remote
Alpha host where Vault is installed and reachable, and it must require
`--host-local` before delegation. The facade does not detect the host, does not
use SSH or remote staging, and does not provide a Mac-side path for unseal.

The route may delegate only to the public helper:

- `scripts/remote_alpha_reset_disposable_vault.sh --unseal-only`

The helper path is fixed relative to the operator script. The route must not
source helper scripts, call `scripts/internal/*`, accept helper path overrides,
construct helper paths from user input, or introduce generic helper dispatch.

P0i preserves the explicit operator prompt model:

- the human remains the operator
- the operator enters any unseal key directly into the visible delegated
  helper/Vault CLI terminal prompt
- Codex and the facade must not receive, type, read, log, relay, persist,
  summarize, or accept unseal keys, root tokens, Vault tokens, API keys,
  passwords, private keys, JWT-SVIDs, or secret payloads
- secret material must never be passed through CLI arguments, environment files,
  logs, `.out`, reports, support bundles, retained bundles, helper summaries,
  readiness outputs, printed commands, or Codex output

Allowed flags for this route are:

- `--help`
- `--host-local`

The route must reject:

- `--ssh-target`
- `--execute-reset`
- `--post-unseal-check`
- `--apply`
- `--dry-run`
- `--interactive-sudo`
- `--governed-smoke-command`
- arbitrary command strings
- helper path overrides
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

P0i is secret-sensitive but non-destructive. It is not destructive reset, not
workload-auth bootstrap or check, not runtime identity summary generation, not
Vault service-user execution, not Infrastructure Manager refresh or
support-bundle collection, not CP proof, and not default noninteractive
readiness validation. It must not write logs, `.out`, transcripts, reports,
operator summaries, support bundles, or retained bundles, and it must not wrap
the delegated helper in transcript capture.

The route remains evidence/projection/diagnostics workflow glue only. It is not
ES Vault token brokerage, IM authority or reconciliation, CP recovery authority,
Vault production lifecycle, and not Remote Alpha
deployment/provisioning/reconciliation architecture.

### P0j Mac-Side Vault Unseal Existing Recovery Session

`Bounded slice rule`: P0j extends only the existing
`recovery-session vault-unseal-existing` surface with one Mac-side interactive
TTY topology:
`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing
--ssh-target <target> --interactive-tty`.

The P0i host-local route remains available:

- `scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing
  --host-local`

The Mac-side route exists because the operator normally works from the
Mac/operator workstation and the Linux Remote Alpha host does not necessarily
have `scripts/remote_alpha_operator.sh`. The Mac-side route keeps one
repo-supported ES operator facade while staging only the approved helper to the
remote host.

Topology rules:

- exactly one topology is required: `--host-local` or `--ssh-target <target>
  --interactive-tty`
- `--host-local` and `--ssh-target` together must fail
- `--interactive-tty` without `--ssh-target` must fail
- `--ssh-target` without `--interactive-tty` must fail
- bare `vault-unseal-existing` execution must fail
- the `--ssh-target` value must be a single SSH target, not an SSH option or
  shell command
- before Mac-side staging or SSH, local stdin and stdout must both be visible
  terminals

Allowed flags for `vault-unseal-existing` are:

- `--help`
- `--host-local`
- `--ssh-target <target>`
- `--interactive-tty`

The route must reject:

- `--execute-reset`
- `--post-unseal-check`
- `--unseal-only`
- `--apply`
- `--dry-run`
- `--interactive-sudo`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- arbitrary command strings
- helper path overrides
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

Mac-side staging behavior:

- stage only `scripts/remote_alpha_reset_disposable_vault.sh`
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage a bundle
- do not source helper scripts
- do not call `scripts/internal/*`
- do not construct helper paths from user input
- do not introduce generic helper dispatch
- use a route-specific remote scratch path
- do not offer `--keep-staging-on-failure`, because the staged helper contains
  destructive reset code even though this route invokes only `--unseal-only`

Remote invocation behavior:

- allocate an interactive SSH TTY only for the explicit Mac-side route
- invoke the staged helper only as
  `remote_alpha_reset_disposable_vault.sh --unseal-only`
- never pass `--execute-reset`, `--post-unseal-check`, workload-auth flags,
  Infrastructure Manager commands, helper path overrides, or arbitrary commands
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- do not create transcripts or logs

Cleanup and evidence behavior:

- cleanup of the staged helper/root must be attempted by default after the
  remote command returns, where safe
- the route writes no `.out`
- the route writes no operator summary
- the route writes no support bundle
- the route writes no report
- the route writes no generated JSON
- process exit plus operator-visible terminal output are the only route result
  surfaces in this slice
- post-unseal evidence checks, Infrastructure Manager refresh, support-bundle
  collection, and workload-auth checks remain separate follow-up actions and
  are not executed here

P0j preserves the explicit operator prompt and secret model:

- the human remains the operator
- the operator enters any unseal key directly into the visible SSH/helper/Vault
  CLI terminal prompt
- Codex and the facade must not receive, type, read, parse, log, relay,
  persist, summarize, or accept unseal keys, root tokens, Vault tokens, API
  keys, passwords, private keys, JWT-SVIDs, or secret payloads
- secret material must never be passed through CLI arguments, environment files,
  logs, `.out`, reports, support bundles, retained bundles, helper summaries,
  readiness outputs, printed commands, or Codex output

P0j is secret-sensitive but non-destructive. It is not destructive reset, not
workload-auth bootstrap or check, not runtime identity summary generation, not
Vault service-user execution, not Infrastructure Manager refresh or
support-bundle collection, not CP proof, and not default noninteractive
readiness validation. It is not ES Vault token brokerage, IM authority or
reconciliation, CP recovery authority, Vault production lifecycle, and not
Remote Alpha deployment/provisioning/reconciliation architecture.

### P0k Mac-Side Disposable Vault Reset Dry-Run Recovery Session

`Bounded slice rule`: P0k adds exactly one Mac-side dry-run planning route:
`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
--ssh-target <target> --dry-run`.

This route helps the operator inspect the disposable reset plan from the
Mac/operator workstation without performing the reset. It is an ES Remote Alpha
operator facade/workflow surface, not Vault lifecycle automation and not a new
authority source.

Topology rules:

- Mac-side only for this slice
- `--ssh-target <target>` is required
- `--dry-run` is required
- `--interactive-tty` is not required for dry-run and is rejected
- `--host-local` is not accepted for this route
- the `--ssh-target` value must be a single SSH target, not an SSH option or
  shell command
- bare `vault-reset-disposable` execution must fail

Allowed flags for `vault-reset-disposable` are:

- `--help`
- `--ssh-target <target>`
- `--dry-run`

The route must reject:

- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--host-local`
- `--interactive-tty`
- `--interactive-sudo`
- `--apply`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- workload-auth flags
- Infrastructure Manager commands
- arbitrary command strings
- helper path overrides
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, passwords, and
  secret payloads

Mac-side staging behavior:

- stage only `scripts/remote_alpha_reset_disposable_vault.sh`
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage a bundle
- do not source helper scripts
- do not call `scripts/internal/*`
- do not construct helper paths from user input
- do not introduce generic helper dispatch
- use a route-specific remote scratch path
- do not offer `--keep-staging-on-failure`, because the staged helper contains
  destructive reset code even though this route invokes only `--dry-run`

Remote invocation behavior:

- invoke the staged helper only as
  `remote_alpha_reset_disposable_vault.sh --dry-run`
- the helper supports `--dry-run`, so the operator facade passes it explicitly
- never pass `--execute-reset`, `--unseal-only`, `--post-unseal-check`,
  workload-auth flags, Infrastructure Manager commands, helper path overrides,
  or arbitrary commands
- do not allocate an interactive SSH TTY for dry-run
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- do not create transcripts or logs

Cleanup and evidence behavior:

- cleanup of the staged helper/root must be attempted by default after the
  remote command returns, where safe
- the route writes no `.out`
- the route writes no operator summary
- the route writes no support bundle
- the route writes no report
- the route writes no generated JSON
- artifacts and outputs remain evidence/projection/diagnostics only, never
  authority

Dry-run non-destructive posture:

- the route does not stop Vault
- the route does not move raft storage
- the route does not run `vault operator init`
- the route does not unseal Vault
- the route does not run post-unseal checks
- the route does not run workload-auth checks
- the route does not run Infrastructure Manager refresh
- the route does not collect support bundles
- the route does not run CP proof or default noninteractive readiness validation

Destructive `--execute-reset` remains a future explicit destructive mode with
the exact confirmation phrase `RESET DISPOSABLE REMOTE ALPHA VAULT`. P0k is not
ES Vault token brokerage, IM authority or reconciliation, CP recovery authority,
Vault production lifecycle, and not Remote Alpha
deployment/provisioning/reconciliation architecture.

### P0l Mac-Side Disposable Vault Reset Execute-Reset Contract Prep

`Bounded slice rule`: P0l was design/static-test prep only. It defined the
destructive disposable reset contract before implementation; it did not
implement `--execute-reset`, did not add a behavior route, and did not run live
SSH, sudo, Vault, reset, unseal, Infrastructure Manager refresh, support-bundle
collection, CP proof, workload-auth checks, or runtime identity generation. At
P0l, execute-reset remained future until later separate implementation, audit,
and live-validation slices.

The already validated P0k dry-run route was the prerequisite for this contract
and remains the prerequisite/planning route for P0m. The validated prerequisite
command shape was:

- `scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
  --ssh-target host_to_remote_linux_m75q --dry-run`

That validation proved non-destructive staging, helper invocation, and
cleanup-attempt behavior for the reset planning path only. It did not prove or
enable destructive reset execution.

Contract command shape:

- `scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
  --ssh-target <target> --execute-reset --interactive-tty`

Topology rules:

- Mac-side only for this operator-facade route
- `--ssh-target <target>` is required
- `--execute-reset` is required for the destructive route
- `--interactive-tty` is required for `--execute-reset`
- `--dry-run` and `--execute-reset` are mutually exclusive
- `--host-local` is not accepted for this operator-facade route in P0l
- bare `vault-reset-disposable` execution must fail
- the `--ssh-target` value must be a single SSH target, not an SSH option or
  shell command
- before staging or SSH, local stdin and stdout must both be visible terminals

Allowed flags for the P0l `vault-reset-disposable --execute-reset` contract are:

- `--help`
- `--ssh-target <target>`
- `--execute-reset`
- `--interactive-tty`

The P0l contract route must reject:

- `--dry-run`
- `--unseal-only`
- `--post-unseal-check`
- `--host-local`
- `--interactive-sudo`
- `--apply`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- workload-auth flags
- Infrastructure Manager commands
- support-bundle commands
- CP proof or governed-smoke commands
- runtime identity summary flags
- helper path overrides
- preinstalled remote bundle assumptions
- arbitrary command strings
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, private keys,
  passwords, and secret payloads

Confirmation behavior:

- the exact confirmation phrase remains
  `RESET DISPOSABLE REMOTE ALPHA VAULT`
- the phrase must be typed by the human operator in the visible remote
  helper/Vault terminal
- the phrase must not be accepted via CLI arguments, environment variables,
  environment files, local files, remote files, helper summaries, readiness
  outputs, `.out`, logs, reports, support bundles, retained bundles, CP
  artifacts, or Codex output
- the phrase must not be logged, summarized, captured, parsed, replayed, or
  relayed by the operator facade
- exact phrase mismatch is a stop condition and must leave no route-level
  attempt to continue reset execution

Secret handling:

- root tokens, unseal keys, client tokens, Vault tokens, API keys, private keys,
  passwords, JWT-SVID payloads, and secret payloads must not be accepted as
  arguments, environment values, environment files, local files, remote files,
  logs, artifacts, or Codex output
- any Vault init output, root token, unseal key, or Vault unseal material is
  handled only by the human operator in the visible remote helper/Vault terminal
- the operator route must not tee, run `script`, record, capture, parse, or
  summarize terminal transcripts
- the operator facade must not receive, type, read, log, relay, persist,
  summarize, or accept secret material

Mac-side staging behavior:

- stage only `scripts/remote_alpha_reset_disposable_vault.sh`
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage a bundle
- do not source helper scripts
- do not call `scripts/internal/*`
- do not construct helper paths from user input
- do not introduce generic helper dispatch
- do not require a preinstalled remote bundle
- use a route-specific remote scratch path
- do not offer `--keep-staging-on-failure`, because the staged helper contains
  destructive reset capabilities

Remote invocation behavior:

- allocate an interactive SSH TTY only for this explicit destructive route
- invoke the staged helper only as
  `remote_alpha_reset_disposable_vault.sh --execute-reset`
- never pass `--dry-run`, `--unseal-only`, `--post-unseal-check`,
  workload-auth flags, Infrastructure Manager commands, support-bundle
  commands, CP proof commands, runtime identity flags, helper path overrides,
  or arbitrary commands
- never include `--post-unseal-check` in the first destructive slice
- never combine reset with workload-auth check, runtime identity summary,
  Infrastructure Manager refresh, support-bundle collection, CP proof, governed
  smoke, or default noninteractive readiness validation
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- do not create transcripts or logs

Cleanup and evidence behavior:

- cleanup of the staged reset-capable helper/root must be attempted by default
  after the remote command returns, where safe
- failure to clean up the staged reset-capable helper is a route failure and a
  stop condition for claiming completion
- no `.out` summary from the ES operator route
- no operator summary file
- no support bundle
- no report
- no generated JSON
- no retained bundle
- no CP artifact
- no Infrastructure Manager execution
- no transcript capture
- process exit and operator-visible helper output are the only route result
  surfaces for this destructive route
- post-reset evidence checks are separate later steps
- evidence/projection output is non-authoritative and must not become IM, CP,
  Vault, or ES runtime authority

Stop conditions for the contract route:

- no visible local TTY
- SSH host-auth prompt or unknown-host authenticity prompt
- any request to pass secrets as CLI args, environment values, environment
  files, local files, remote files, logs, artifacts, or Codex output
- reset helper broad raft path guard triggers
- exact phrase mismatch
- request to run post-unseal check, workload-auth check, Infrastructure Manager
  refresh, support-bundle collection, CP proof, governed smoke, runtime identity
  summary, or default noninteractive readiness validation in the same command
- failure to clean up the staged reset-capable helper

The contract remains bounded ES Remote Alpha proof/support workflow glue only.
The human remains the operator. The script minimizes manual stitching, but does
not eliminate explicit operator prompts. It is not Vault production lifecycle
automation, not ES Vault token brokerage, not IM authority or reconciliation,
not CP recovery authority, not Nomad/SPIRE boundary redesign, not governed
execution proof, and not Remote Alpha production, deployment, provisioning, or
reconciliation architecture.

### P0m Mac-Side Disposable Vault Reset Execute-Reset Recovery Session

`Bounded slice rule`: P0m implements exactly the P0l Mac-side destructive
disposable Vault reset contract as an explicit operator route:

- `scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
  --ssh-target <target> --execute-reset --interactive-tty`

P0m is implementation/self-audit with static and fake SSH/SCP validation only.
It does not run live SSH, sudo, Vault, reset, unseal, execute-reset,
Infrastructure Manager refresh, support-bundle collection, CP proof,
workload-auth live checks, runtime identity generation, or network-dependent
integration tests. The already validated P0k dry-run route remains the
prerequisite/planning route. Live execute-reset must be run only when the human
operator intentionally wants to reset disposable Remote Alpha Vault state.

Topology and mode rules:

- Mac-side only for this operator-facade route
- `--ssh-target <target>` is required
- `--execute-reset` requires `--interactive-tty`
- local stdin and stdout must both be visible terminals before staging or SSH
- `--dry-run` and `--execute-reset` are mutually exclusive
- `--dry-run` remains the non-destructive prerequisite/planning route and does
  not use `--interactive-tty`
- `--host-local` is not accepted for execute-reset through the operator facade
- bare `vault-reset-disposable` execution must fail
- the `--ssh-target` value must be a single SSH target, not an SSH option or
  shell command

Allowed flags for `vault-reset-disposable` in P0m are:

- `--help`
- `--ssh-target <target>`
- `--dry-run`
- `--execute-reset`
- `--interactive-tty`

P0m must reject:

- `--execute-reset` without `--ssh-target`
- `--execute-reset` without `--interactive-tty`
- `--execute-reset` combined with `--dry-run`
- `--execute-reset` combined with `--post-unseal-check`
- `--execute-reset` combined with `--unseal-only`
- `--execute-reset` combined with `--host-local`
- `--interactive-sudo`
- `--apply`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- workload-auth flags
- Infrastructure Manager commands
- support-bundle commands
- CP proof or governed-smoke commands
- runtime identity summary flags
- helper path overrides
- preinstalled remote bundle assumptions
- arbitrary command strings
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, private keys,
  passwords, and secret payloads

Prompt and secret model:

- the exact confirmation phrase remains
  `RESET DISPOSABLE REMOTE ALPHA VAULT`
- the phrase is typed only by the human operator in the visible remote
  helper/Vault terminal
- the phrase must not be accepted through CLI arguments, environment variables,
  environment files, local files, remote files, helper summaries, readiness
  outputs, `.out`, logs, reports, support bundles, retained bundles, CP
  artifacts, or Codex output
- the phrase must not be logged, summarized, captured, parsed, replayed,
  relayed, printed, or persisted by the operator facade
- root tokens, unseal keys, client tokens, Vault tokens, API keys, private
  keys, passwords, JWT-SVID payloads, Vault init output, and secret payloads
  must not be accepted as arguments, environment values, environment files,
  local files, remote files, logs, artifacts, or Codex output
- any Vault init output, root token, unseal key, or Vault unseal material is
  handled only by the human operator in the visible remote helper/Vault terminal
- the operator route must not tee, run `script`, record, capture, parse, or
  summarize terminal transcripts

Mac-side staging behavior:

- stage only `scripts/remote_alpha_reset_disposable_vault.sh`
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage a bundle
- do not source helper scripts
- do not call `scripts/internal/*`
- do not construct helper paths from user input
- do not introduce generic helper dispatch
- do not require a preinstalled remote bundle
- use a fixed helper path resolved from `BASH_SOURCE[0]`
- use a route-specific remote scratch path
- do not offer `--keep-staging-on-failure`, because the staged helper contains
  destructive reset capabilities

Remote invocation behavior:

- allocate an interactive SSH TTY with `ssh -tt`
- invoke the staged helper only as
  `remote_alpha_reset_disposable_vault.sh --execute-reset`
- never pass `--dry-run`, `--unseal-only`, `--post-unseal-check`,
  workload-auth flags, Infrastructure Manager commands, support-bundle
  commands, CP proof commands, runtime identity flags, helper path overrides,
  or arbitrary commands
- never include `--post-unseal-check` in this destructive slice
- never combine reset with workload-auth check, runtime identity summary,
  Infrastructure Manager refresh, support-bundle collection, CP proof, governed
  smoke, or default noninteractive readiness validation
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- do not create transcripts or logs

Cleanup and evidence behavior:

- cleanup of the staged reset-capable helper/root must be attempted by default
  after the remote command returns, where safe
- failure to clean up the staged reset-capable helper is a route failure and a
  stop condition for claiming completion
- no `.out` summary from the ES operator route
- no operator summary file
- no support bundle
- no report
- no generated JSON
- no retained bundle
- no CP artifact
- no Infrastructure Manager execution
- no transcript capture
- process exit and operator-visible helper output are the only route result
  surfaces
- post-reset evidence checks are separate later steps
- evidence/projection output is non-authoritative and must not become IM, CP,
  Vault, or ES runtime authority

Stop conditions for P0m:

- no visible local TTY
- SSH host-auth prompt or unknown-host authenticity prompt
- any request to pass secrets as CLI args, environment values, environment
  files, local files, remote files, logs, artifacts, or Codex output
- reset helper broad raft path guard triggers
- exact phrase mismatch
- request to run post-unseal check, workload-auth check, Infrastructure Manager
  refresh, support-bundle collection, CP proof, governed smoke, runtime identity
  summary, or default noninteractive readiness validation in the same command
- failure to clean up the staged reset-capable helper

P0m remains bounded ES Remote Alpha proof/support workflow glue only. The human
remains the operator. The script minimizes manual stitching, but does not
eliminate explicit operator prompts. It is not Vault production lifecycle
automation, not ES Vault token brokerage, not IM authority or reconciliation,
not CP recovery authority, not Nomad/SPIRE boundary redesign, not governed
execution proof, and not Remote Alpha production, deployment, provisioning, or
reconciliation architecture.

### P0n Mac-Side Vault Workload-Auth Check Recovery Session

`Bounded slice rule`: P0n implements exactly one Mac-side post-reset
workload-auth evidence route:

- `scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check
  --ssh-target <target> --interactive-tty`

P0n is implementation/self-audit with static and fake SSH/SCP validation only.
It does not run live SSH, sudo, Vault, workload-auth checks, reset, unseal,
Infrastructure Manager refresh, support-bundle collection, CP proof, runtime
identity generation, or network-dependent integration tests during validation.
The route is separate from reset/unseal. It is not workload-auth bootstrap, not
ES token brokerage, not Vault production lifecycle automation, not IM
reconciliation, not CP recovery authority, and not Remote Alpha deployment,
provisioning, or reconciliation architecture.

Topology rules:

- Mac-side only for this operator-facade route
- `--ssh-target <target>` is required
- `--interactive-tty` is required
- local stdin and stdout must both be visible terminals before staging or SSH
- `--host-local` is not accepted for this Mac-side route
- bare `vault-workload-auth-check` execution must fail
- the `--ssh-target` value must be a single SSH target, not an SSH option or
  shell command

Allowed flags for `vault-workload-auth-check` in P0n are:

- `--help`
- `--ssh-target <target>`
- `--interactive-tty`

P0n must reject:

- missing `--ssh-target`
- missing `--interactive-tty`
- `--host-local`
- `--dry-run`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--apply`
- `--interactive-sudo`
- `--governed-smoke-command`
- workload-auth helper override flags
- Vault address, role, audience, path, or proof-path overrides
- SPIFFE ID overrides
- config path overrides
- summary path overrides
- container probe image overrides
- SPIRE socket overrides
- Infrastructure Manager commands
- support-bundle commands
- CP proof or governed-smoke commands
- runtime identity summary flags
- helper path overrides
- preinstalled remote bundle assumptions
- arbitrary command strings
- unknown flags
- duplicate flags
- positional arguments beyond the submode
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, TLS private keys, private keys,
  passwords, proof secret material, and secret payloads

Secret model:

- the route must not accept, parse, print, log, relay, persist, summarize, or
  copy JWT-SVIDs, Vault client tokens, proof secret payloads, root tokens,
  unseal keys, API keys, private keys, passwords, or secret payloads
- helper summary redaction remains owned by the existing workload-auth helper
- when the helper reaches Vault JWT login and `auth_smoke.vault_login=fail`,
  it may add only safe failure triage fields to the existing v1 summary:
  `auth_smoke.vault_login_failure_phase`,
  `auth_smoke.vault_login_failure_class`,
  `auth_smoke.vault_login_http_status`,
  `auth_smoke.vault_login_error_count`,
  `auth_smoke.vault_login_error_class`, and
  `auth_smoke.vault_login_raw_error_recorded`, with
  `auth_smoke.vault_login_raw_error_recorded=false`
- login failure classes are bounded labels only:
  `auth_mount_missing_or_unreachable`, `role_missing_or_rejected`,
  `invalid_jwt`, `invalid_audience`, `invalid_subject`,
  `invalid_issuer_or_validation_key`, `permission_denied`,
  `vault_api_error`, `invalid_response`, `tls_or_connectivity_error`, and
  `unknown`
- the helper must not print or persist the raw Vault login response body, raw
  HTTP headers, Authorization header, full Vault login JSON, stack traces,
  JWT-SVID payload, Vault client token, root token, unseal key, proof secret
  value, API key, or private key while producing those labels
- the operator facade must not print full summary JSON
- the operator facade must not tee, run `script`, record, capture, parse, or
  summarize terminal transcripts

Mac-side staging behavior:

- stage only `scripts/remote_alpha_vault_workload_auth_check.sh`
- stage only
  `scripts/internal/remote_alpha_vault_workload_auth_check.sh` as the matching
  internal helper
- preserve the remote `scripts/` and `scripts/internal/` relative layout so the
  public wrapper can source the internal helper
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage reset/unseal helpers
- do not stage runtime identity helpers
- do not stage service-user helpers
- do not stage config/TLS helpers
- do not stage binary deployment helpers
- do not stage bundles or unrelated helpers
- do not source helper scripts from the operator facade
- do not construct helper paths from user input
- do not introduce generic helper dispatch
- do not require a preinstalled remote bundle
- use a fixed helper path resolved from `BASH_SOURCE[0]`
- use a route-specific remote scratch path
- do not offer `--keep-staging-on-failure`

Remote invocation behavior:

- allocate an interactive SSH TTY with `ssh -tt`
- invoke only the staged public helper as
  `remote_alpha_vault_workload_auth_check.sh`
- run the staged public helper with root through the explicit interactive TTY
  path when required
- pass no workload-auth helper override flags
- never pass reset/unseal flags, `--dry-run`, `--execute-reset`,
  `--unseal-only`, `--post-unseal-check`, Infrastructure Manager commands,
  support-bundle commands, CP proof commands, runtime identity flags, helper
  path overrides, or arbitrary commands
- never combine workload-auth evidence with reset, unseal, post-unseal checks,
  runtime identity summary, Infrastructure Manager refresh, support-bundle
  collection, CP proof, governed smoke, or default noninteractive readiness
  validation
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- do not create transcripts or logs

Cleanup and evidence behavior:

- cleanup of the staged workload-auth helper files/root must be attempted by
  default after the remote command returns, where safe
- the canonical summary remains remote at
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`
- no summary is copied back to Mac `.out` in this route
- no `.out` summary from the ES operator route
- no operator summary file
- no support bundle
- no report
- no generated JSON
- no retained bundle
- no CP artifact
- no Infrastructure Manager execution
- no transcript capture
- after remote success, the operator facade may print only non-secret next
  steps: the remote summary path, a recommendation to use
  `recovery-session --evidence-check` after separate IM/local evidence
  collection, and printed-only IM refresh/support-bundle commands as separate
  IM evidence/provenance actions
- the workload-auth summary is evidence/projection only, not readiness
  authority, not Vault production readiness, not governed execution proof, not
  CP recovery authority, not IM authority, and not ES Vault token brokerage

Stop conditions for P0n:

- no visible local TTY
- SSH host-auth prompt or unknown-host authenticity prompt
- any request to pass secrets as CLI args, environment values, environment
  files, local files, remote files, logs, artifacts, or Codex output
- staging the workload-auth route requires more files than the public wrapper
  and internal helper
- helper override flags are accepted
- the operator route copies the summary back to Mac `.out`
- the operator route prints full summary JSON
- the operator route creates operator summaries or generated artifacts
- the operator route runs Infrastructure Manager refresh, support-bundle
  collection, CP proof, reset/unseal, runtime identity generation, or
  workload-auth bootstrap
- the operator route combines workload-auth evidence with reset/unseal
- a generic helper dispatcher is introduced
- generated artifacts are staged or untracked after validation

P0n remains bounded ES Remote Alpha proof/support workflow glue only. The human
remains the operator. The script minimizes manual stitching, but does not
eliminate explicit operator prompts. It is not Vault production lifecycle
automation, not workload-auth bootstrap, not ES Vault token brokerage, not IM
authority or reconciliation, not CP recovery authority, not Nomad/SPIRE
boundary redesign, not governed execution proof, and not Remote Alpha
production, deployment, provisioning, or reconciliation architecture.

### P0o Vault Workload-Auth Bootstrap Planning Surface

`Bounded slice rule`: P0o implements exactly one safe local/print-only
post-reset bootstrap planning surface:

- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap [--help|--plan|--inventory]`

This surface exists because the first post-reset workload-auth evidence route
proved route mechanics far enough to write the canonical summary, but the
functional smoke failed at Vault JWT login. Safe triage fields from that summary
were:

- schema matched
- summary was fresh
- redaction scan passed
- `vault.initialized=true`
- `vault.sealed=false`
- `vault.auth_mount=jwt`
- `vault.role=service_execution`
- `vault.audience=vault`
- `vault_workload_auth_smoke=fail`
- `auth_smoke.vault_login=fail`

The conservative failure classification is only:

- `Vault JWT login rejected or not configured`

That classification means the route mechanics partially passed and the
workload-auth functional failure point is Vault JWT login. It does not prove
which Vault object is missing or mismatched.

P0o is plan/inventory only. It does not run live SSH, sudo, Vault,
workload-auth checks, reset/unseal, Infrastructure Manager refresh,
support-bundle collection, CP proof, runtime identity generation, or network
integration tests. It does not write `.out`, JSON, reports, support bundles,
operator summaries, generated artifacts, retained bundles, or CP artifacts. It
does not stage helpers and does not introduce generic helper dispatch.

The P0o plan/inventory text may describe likely post-reset Vault objects/config
inferred from the existing helper, docs, and tests:

- auth mount: `jwt`
- JWT auth config with SPIRE JWT validation material selected for the workload
  trust domain and bound issuer
- role: `service_execution`
- `role_type=jwt`
- `user_claim=sub`
- `bound_audiences=vault`
- `bound_subject=spiffe://execution.internal/workload`
- policy such as `runtime-identity-proof`
- KV v2 proof secret paths and field shape:
  - `proof-secrets/data/runtime-identity-vault-login`
  - `proof-secrets/data/codex-runtime-profile`
  - field `api_key` present and non-empty, with the value never printed
- workload-zone config alignment:
  - `/etc/execution-substrate/vault/workload-zone-vault-config.json`

Allowed flags for `vault-workload-auth-bootstrap` in P0o are:

- `--help`
- `--plan`
- `--inventory`

With no mode, the submode defaults to printing the plan/help and exiting zero.

P0o must reject:

- `--execute-bootstrap`
- `--ssh-target`
- `--interactive-tty`
- `--host-local`
- `--root-token`
- `--unseal-key`
- `--client-token`
- `--vault-token`
- `--api-key`
- `--jwt-svid`
- `--private-key`
- `--password`
- `--secret`
- `--execute-reset`
- `--dry-run`
- `--unseal-only`
- `--post-unseal-check`
- `--apply`
- `--governed-smoke-command`
- workload-auth helper override flags
- proof secret value flags
- arbitrary commands
- unknown flags
- duplicate flags
- equals-form options
- extra positionals beyond the submode/mode

Future bootstrap execution, if implemented, must be a separately audited
secret-sensitive route. Root tokens must never be accepted as CLI arguments,
environment variables, files, `.out`, reports, support bundles, retained
bundles, or Codex output. Any root-token use must happen only through an
explicit visible or silent operator prompt in a named secret-sensitive mode. The
future route must use no transcript capture, no `tee`, and no `script`. Proof
secret values must never be printed, copied, summarized, or logged.

Bootstrap must not claim workload-auth success; it only configures expected
objects. The workload-auth check remains a separate command after bootstrap.
Any future bootstrap artifact must be non-secret evidence/projection only and
must not become readiness authority, Vault production readiness, governed
execution proof, IM authority, CP recovery authority, ES Vault token brokerage,
or Remote Alpha deployment/provisioning/reconciliation architecture.

### P0p Vault Workload-Auth Bootstrap Execution Contract Prep

`Bounded slice rule`: P0p defines the future secret-sensitive workload-auth
bootstrap execution route before implementation. It is docs/static-test prep
only.

Future command shape:

- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap
  --interactive-tty`

Current safe modes remain:

- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --help`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --plan`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --inventory`

With no mode, the submode must continue to print plan/help and exit zero. P0p
does not implement `--execute-bootstrap`, `--ssh-target` execution, helper
staging, root-token prompts, proof-secret prompts, Vault writes, remote summary
creation, or live validation.

Helper strategy:

- The future implementation should add one dedicated fixed public helper,
  `scripts/remote_alpha_vault_workload_auth_bootstrap.sh`, with one fixed
  sourced internal implementation,
  `scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`.
- The operator facade may stage only that public/internal bootstrap helper
  pair and must preserve their relative layout on the remote host.
- Ad hoc manual Vault write commands are not the preferred execution path
  because they reintroduce stitching and are harder to test and redact.
- The future route must not stage `scripts/remote_alpha_operator.sh`, stage a
  helper bundle, stage reset/unseal helpers, stage the workload-auth check
  helper, stage runtime identity or service-user helpers, source remote helpers
  from the facade, construct helper paths from user input, or introduce generic
  helper dispatch.

Intended Vault objects/config:

- auth mount `jwt`
- JWT auth config with SPIRE validation material selected for the workload trust
  domain and bound issuer
- JWT auth config includes all active JWT-SVID RSA validation public keys for
  the selected workload trust domain, not just the first key
- role `service_execution`
- `role_type=jwt`
- `user_claim=sub`
- `bound_audiences=vault`
- `bound_subject=spiffe://execution.internal/workload`
- policy `runtime-identity-proof`
- KV v2 proof paths:
  - `proof-secrets/data/runtime-identity-vault-login`
  - `proof-secrets/data/codex-runtime-profile`
- proof runtime field `api_key` present and non-empty, with the value never
  printed
- workload-zone config alignment at
  `/etc/execution-substrate/vault/workload-zone-vault-config.json`

Prompt and secret model:

- The human remains the operator.
- ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token
  broker.
- Vault owns token, secret, and lease authority.
- SPIRE owns JWT-SVID issuance.
- If the future route needs a Vault root token or equivalent bootstrap
  authority, it may obtain it only through an explicit visible or silent
  prompt bound to the named `--execute-bootstrap --interactive-tty` mode,
  reading from the interactive TTY only.
- If the future route needs a proof secret value, it may obtain it only through
  the same TTY-only prompt posture.
- Root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API
  keys, private keys, passwords, proof secret values, and secret payloads must
  never enter CLI arguments, environment variables, environment files, local or
  remote files, shell history, logs, `.out`, reports, support bundles, retained
  bundles, CP artifacts, helper summaries, printed commands, terminal
  transcripts, or Codex output.
- The future helper must not rely on token-bearing `VAULT_TOKEN` environment
  variables, token-bearing Vault CLI arguments, token files such as
  `.vault-token`, `tee`, or `script`. If the Vault CLI cannot satisfy that
  posture, the helper must use an implementation path that keeps bootstrap
  authority only in process memory and never exposes it through argv, env,
  files, or output.

Execution boundaries:

- The future route may configure only the intended Vault objects/config.
- It must not run a workload-auth check.
- It must not run reset or unseal.
- It must not run Infrastructure Manager refresh.
- It must not collect support bundles.
- It must not run CP proof.
- It must not run runtime identity summary or runtime identity generation.
- It must not run governed smoke or default readiness validation.
- It must not claim workload-auth success, runtime-profile readiness, submit
  readiness, Vault production readiness, governed execution proof, IM
  authority, CP recovery authority, ES Vault token brokerage, or Remote Alpha
  deployment/provisioning/reconciliation architecture.
- The workload-auth check remains a separate post-bootstrap command.

Summary/evidence behavior:

- The future implementation should write one remote-only non-secret bootstrap
  summary:
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`.
- The schema name should be
  `execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`.
- The first execution slice must not copy that summary back to Mac `.out`.
- The summary is evidence/projection only, not authority and not an IM input.
- The summary may contain only statuses, booleans, path labels, object names,
  byte counts, SHA-256 digests, cleanup status, redaction flags, non-authority
  labels, and explicit non-claims.
- The summary must not contain a root token, unseal key, client token, Vault
  token, JWT-SVID payload, API key value, private key, password, proof secret
  value, secret payload, raw Vault output, or terminal transcript.

Allowed future execution flags:

- `--help`
- `--plan`
- `--inventory`
- `--ssh-target <target>`
- `--execute-bootstrap`
- `--interactive-tty`

Flag and topology rules:

- `--help`, `--plan`, `--inventory`, and `--execute-bootstrap` are mutually
  exclusive route modes.
- `--ssh-target` and `--interactive-tty` are valid only with
  `--execute-bootstrap`.
- `--execute-bootstrap` requires both `--ssh-target <target>` and
  `--interactive-tty`.
- The SSH target must be a single target, not an SSH option or shell command.
- The future Mac-side route must require visible local stdin and stdout before
  staging, allocate an interactive SSH TTY such as `ssh -tt`, stage into a
  route-specific remote scratch root, and attempt staged-helper cleanup by
  default.
- Duplicate route flags, equals-form options, unknown flags, extra
  positionals, and secret-like arguments must fail before staging or live
  action.

Forbidden future execution flags and inputs include:

- `--host-local`
- `--dry-run`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--apply`
- `--interactive-sudo`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- workload-auth helper override flags
- Vault address, role, audience, path, proof-path, SPIFFE ID, config path,
  summary path, container probe image, or SPIRE socket override flags
- arbitrary commands
- helper path overrides
- `--root-token`
- `--unseal-key`
- `--client-token`
- `--vault-token`
- `--api-key`
- `--jwt-svid`
- `--private-key`
- `--password`
- `--secret`
- proof secret value flags
- any secret-like positional argument

Future implementation tests:

- must be fake/static before any live-validation slice
- must not run live Vault, live SSH, sudo, workload-auth checks, reset/unseal,
  Infrastructure Manager refresh, support-bundle collection, CP proof, runtime
  identity generation, or network-dependent integration tests
- should use fake SSH/SCP, a fake staged helper, and fake Vault/API command
  capture when the helper is introduced
- should assert no secret is passed by argv, env, file, printed command,
  transcript, `.out`, report, support bundle, retained bundle, CP artifact,
  helper summary, or Codex-facing output
- should assert no `tee`, no `script`, no token-bearing `VAULT_TOKEN`, no
  token-bearing Vault CLI argument, and no token file such as `.vault-token`
- should assert only the dedicated public/internal bootstrap helper pair is
  staged and cleanup is attempted by default
- should assert summary schema and redaction behavior if the summary is
  implemented
- should assert the future route cannot bundle workload-auth checks,
  reset/unseal, IM refresh, support-bundle collection, CP proof, runtime
  identity summary, runtime identity generation, governed smoke, or default
  readiness validation

### P0q Vault Workload-Auth Bootstrap Execution Route

`Bounded slice rule`: P0q implements the dedicated secret-sensitive
workload-auth bootstrap execution route and bounded summary-path preparation
route plus bounded config-readability and SPIRE bundle-read preparation routes
with fake/static validation only. It does not run live SSH, live sudo,
Vault, workload-auth checks, reset/unseal,
Infrastructure Manager refresh, support-bundle collection, CP proof, runtime
identity summary, runtime identity generation, governed smoke, default
readiness validation, or network-dependent integration tests during validation.

Helper strategy:

- Public helper:
  `scripts/remote_alpha_vault_workload_auth_bootstrap.sh`
- Internal helper:
  `scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`
- The public helper sources only the fixed internal helper from the repository
  relative layout.
- The operator facade may stage only that public/internal bootstrap helper pair.
  It must not stage `scripts/remote_alpha_operator.sh`, reset/unseal helpers,
  the workload-auth check helper, runtime identity helpers, service-user
  helpers, bundles, unrelated helpers, or a generic helper dispatcher.

Mac-side operator route:

- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap
  --interactive-tty`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path
  --interactive-tty`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-config-readability --interactive-tty`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target>
  --prepare-spire-bundle-read --interactive-tty`
- Combined form:
  `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap
  --prepare-summary-path --prepare-config-readability
  --prepare-spire-bundle-read --interactive-tty`

Safe modes remain:

- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --help`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --plan`
- `scripts/remote_alpha_operator.sh recovery-session
  vault-workload-auth-bootstrap --inventory`

Secret prompt model:

- The human remains the operator.
- ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token
  broker.
- Vault owns token, secret, and lease authority.
- SPIRE owns JWT-SVID issuance.
- The helper prompts for Vault bootstrap authority and proof secret values only
  on the visible/silent remote TTY owned by the human operator.
- Root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API
  keys, private keys, passwords, proof secret values, and secret payloads must
  never enter CLI arguments, environment variables, environment files, local or
  remote files, shell history, logs, `.out`, reports, support bundles, retained
  bundles, CP artifacts, helper summaries, printed commands, terminal
  transcripts, `tee`, `script`, or Codex output.
- Before either prompt, and before any SPIRE/Vault operation or Vault write, the
  helper must run a secret-free writability preflight for the canonical summary
  path
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`.
  The preflight may create `/var/tmp/execution-substrate-remote-alpha` when it
  is missing and safe for the helper user to create. If the parent exists but is
  not writable by the helper user, or the summary path cannot be written safely,
  the helper must fail before prompting, print only a non-secret
  `summary_preflight_failed` classification, leave no summary or temp summary
  when possible, and run no Vault writes.
- After summary preflight succeeds, and still before either prompt or any
  SPIRE/Vault operation, the helper must preflight readability of
  `/etc/execution-substrate/vault/workload-zone-vault-config.json`. If the
  config is missing, not regular, or unreadable by the helper user, the helper
  must fail before prompting, write/retain only a safe failure summary when
  summary preflight passed, classify the failure as `config_load` with
  `config_missing`, `config_invalid`, or `config_unreadable`, and run no Vault
  writes.
- After config preflight/load succeeds, and still before either prompt or any
  Vault operation/write, the helper must preflight the fixed SPIRE bundle-read
  command used to obtain public JWT validation material:
  `spire-server bundle show -format spiffe -socketPath
  /run/spire/server/private/api.sock`. If the command fails, returns malformed
  output, or does not contain usable JWT-SVID RSA validation material, the
  helper must fail before prompting, write/retain only a safe failure summary
  when summary preflight passed, classify the failure as `jwt_auth_config` with
  a safe class such as `invalid_response` and a safe message class such as
  `spire_bundle_show_failed`, set
  `operations.spire_jwt_validation_material.status=fail`, and run no Vault
  writes. It must not print raw SPIRE output, raw SPIRE stderr, or bundle
  contents. When the SPIFFE bundle output is a bundle map, the helper must select
  JWT validation material from the workload SPIFFE ID trust domain rather than
  from the first available trust domain. It must configure all active JWT-SVID
  RSA validation public keys for that selected trust domain rather than one
  arbitrary key. The helper may record only safe source/shape labels, selected
  trust-domain labels, key counts, a validation pubkey count, and a digest set or
  aggregate digest; it must not summarize raw public key material or raw bundle
  JSON. This preserves the older safe-diagnostic vocabulary of safe source/shape
  labels, key counts, selected trust-domain labels, and a digest while adding
  the all-key count and digest-set detail.

Summary-path preparation:

- The first real bootstrap attempt failed because the remote summary parent
  `/var/tmp/execution-substrate-remote-alpha` existed as `root:root` mode
  `0755`, and the helper could not write
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`.
  Because the failure occurred at summary writing, that attempt did not prove
  whether Vault objects were or were not configured.
- Commit `e4d7016` added helper-side summary writability preflight before any
  Vault/root/proof prompt. The bounded follow-up operator route adds
  `--prepare-summary-path` so the human operator can explicitly prepare the
  path before retrying live bootstrap.
- Preparation is OS/filesystem setup only. It prepares only
  `/var/tmp/execution-substrate-remote-alpha`,
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`,
  and same-directory temp writability for that summary. It must not run Vault,
  request Vault/root/proof secret material, run workload-auth checks,
  reset/unseal, IM, support bundles, CP proof, runtime identity generation,
  helper staging, or summary copy-back.
- If the parent is missing, preparation creates it. If the parent exists but is
  not writable/executable by the helper user, preparation uses only an explicit
  operator-authorized OS sudo prompt through the visible SSH TTY to make that
  parent helper-user/group owned with mode `0750`. The preparation command must
  keep SSH stdin attached to the visible terminal instead of feeding the remote
  script over SSH stdin, so sudo controls password echo suppression. If the
  bootstrap summary file already exists as a regular file but is not writable by
  the helper user, preparation uses visible sudo to make only that file
  helper-owned with mode `0600`. Preparation does not delete workload-auth check
  summaries or other unrelated evidence files, creates and removes only a hidden
  same-directory temp probe, and creates no final bootstrap summary in
  standalone mode.
- In the combined form, preparation must complete before helper staging,
  helper-side preflight, any Vault bootstrap authority prompt, any proof secret
  prompt, and any Vault write. If preparation fails, the route stops before
  helper execution and prints only non-secret status/classification.

Config-readability preparation:

- After `e4d7016` and `a0efd04`, a live retry reached `config_load` and failed
  before any secret prompt with `secret_prompts_started=false` and
  `vault_operations_started=false`, likely because the helper user could not
  read
  `/etc/execution-substrate/vault/workload-zone-vault-config.json`.
- `--prepare-config-readability` is OS/filesystem setup only. It prepares only
  helper-user readability for the fixed workload-zone config path and the fixed
  parent execute ACLs needed for that path. It must not run Vault, request
  Vault/root/proof secret material, run workload-auth checks, reset/unseal, IM,
  support bundles, CP proof, runtime identity generation, helper staging,
  config content printing, or summary/config copy-back.
- Because this repo does not define a workload-zone-config-specific group
  ownership model, the bounded preparation policy is fixed-path user ACLs when
  needed: require the config file to exist and be regular; if it is already
  readable by the helper user, make no permission change; otherwise use only an
  explicit operator-authorized OS sudo prompt through the visible SSH TTY to
  apply execute ACLs to `/etc/execution-substrate` and
  `/etc/execution-substrate/vault`, and a read ACL to
  `/etc/execution-substrate/vault/workload-zone-vault-config.json` for the helper
  user. It must not world-read the config, chown broad `/etc` directories,
  delete unrelated summaries, or print the config contents. If `setfacl` is
  unavailable or readability is still not proven, preparation fails before
  helper execution with only non-secret status/classification.
- In the combined form, config-readability preparation runs after summary-path
  preparation and before SPIRE bundle-read preparation, helper staging/execution,
  any Vault bootstrap authority prompt, proof secret prompt, or Vault write.
  Inside the helper, summary preflight runs before config readability/load
  preflight, and both complete before the SPIRE bundle-read preflight and before
  any Vault prompt or write.

SPIRE bundle-read preparation:

- After summary-path and config-readability preparation succeeded, a live retry
  reached `jwt_auth_config` before any secret prompt or Vault operation and
  failed while obtaining SPIRE JWT validation material from `spire-server bundle
  show -format spiffe -socketPath /run/spire/server/private/api.sock`.
- `--prepare-spire-bundle-read` is OS/filesystem/capability setup only. It
  prepares only helper-user access for the fixed SPIRE server bundle-read
  command and fixed SPIRE server socket path. It must not run Vault, request
  Vault/root/proof secret material, run workload-auth checks, reset/unseal, IM,
  support bundles, CP proof, runtime identity generation, helper staging, SPIRE
  bundle content printing, or summary/bundle copy-back. The bundle output is
  discarded.
- Because this repo does not define a SPIRE-server-socket-specific group
  ownership model for this recovery route, the bounded preparation policy is
  fixed-path user ACLs when needed: discard-output probe the exact bundle-read
  command first; if it already succeeds, classify the path as
  `spire_socket_present_accessible` and make no permission change. Otherwise
  require `spire-server` to exist, failing with
  `spire_server_command_missing` when absent; if systemd service state is
  available and `spire-server` is not active, fail with
  `spire_server_inactive_or_unknown`.
  The route then uses only the explicit operator-authorized OS sudo prompt
  through the visible SSH TTY to inspect the fixed parents and socket before
  classifying absence, so helper-user traversal denial under `/run/spire/server`
  is not mislabeled as a missing parent. If sudo-visible inspection shows a
  missing fixed parent, missing socket, or wrong socket type, fail with
  `spire_socket_parent_missing`, `spire_socket_missing`, or
  `spire_socket_not_socket`; do not create SPIRE parents or sockets and do not
  restart or reconfigure SPIRE. If sudo-visible inspection shows the fixed
  socket exists as a socket but the helper user lacks traversal or socket
  read/write access, classify it as `spire_socket_present_needs_acl`, require
  `setfacl`, apply execute ACLs only to `/run/spire`, `/run/spire/server`, and
  `/run/spire/server/private` when needed, and apply a read/write ACL only to
  `/run/spire/server/private/api.sock` for the helper user. If the exact
  discard-output bundle-read still fails after fixed-path access prep, fail
  with `spire_bundle_show_failed`. The route must not world-read or world-write
  the socket, chown broad `/run` directories, grant access to workloads, add
  generic command execution, print bundle contents, or copy bundle contents to
  Mac `.out`.
- In the combined form, ordering is summary-path preparation, then
  config-readability preparation, then SPIRE bundle-read preparation, then
  helper staging/execution. Inside the helper, summary preflight runs before
  config readability/load preflight, and the SPIRE bundle-read preflight runs
  before any Vault bootstrap authority prompt, proof secret prompt, Vault
  operation, or Vault write.

Vault API strategy:

- The helper uses an in-process HTTPS client for Vault API writes.
- The helper must not use `VAULT_TOKEN`, `vault login`, token-bearing Vault CLI
  arguments, token files such as `.vault-token`, transcript capture, `tee`, or
  `script`.
- Bootstrap authority may exist only in helper process memory for the duration
  of the helper operation and should be cleared where practical.

Configured Vault objects/config:

- auth mount `jwt`
- JWT auth config with SPIRE validation material selected for the workload trust
  domain and bound issuer
- JWT auth config includes all active JWT-SVID RSA validation public keys for
  the selected workload trust domain, not just the first key
- role `service_execution`
- `role_type=jwt`
- `user_claim=sub`
- `bound_audiences=vault`
- `bound_subject=spiffe://execution.internal/workload`
- policy `runtime-identity-proof`
- KV v2 proof paths:
  - `proof-secrets/data/runtime-identity-vault-login`
  - `proof-secrets/data/codex-runtime-profile`
- proof runtime field `api_key` present and non-empty, with the value never
  printed
- workload-zone config alignment at
  `/etc/execution-substrate/vault/workload-zone-vault-config.json`

Execution boundaries:

- P0q may configure only the intended Vault objects/config.
- It must not run a workload-auth check.
- It must not run reset or unseal.
- It must not run Infrastructure Manager refresh.
- It must not collect support bundles.
- It must not run CP proof.
- It must not run runtime identity summary or runtime identity generation.
- It must not run governed smoke, default readiness validation, or post-unseal
  checks.
- It must not claim workload-auth success, runtime-profile readiness, submit
  readiness, Vault production readiness, governed execution proof, IM
  authority, CP recovery authority, ES Vault token brokerage, or Remote Alpha
  production/deployment/provisioning/reconciliation architecture.
- The workload-auth check remains a separate post-bootstrap command.

Summary/evidence behavior:

- P0q writes only one remote-only non-secret bootstrap summary:
  `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`.
- The schema is
  `execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`.
- The summary is evidence/projection only, not authority and not an IM input.
- The route must not copy that summary back to Mac `.out`.
- The route must not create an operator summary.
- The helper must write the summary through a temp file in the same directory
  and atomically rename it only after redaction checks pass. Temp summary files
  must be removed on failure when possible.
- The summary may contain only schema, generated time, operation mode,
  configured-object labels, operation statuses/booleans, safe failure
  phase/class labels, safe prompt/operation-start booleans, safe last/next
  operation labels, path labels, source labels, shape labels, counts, digests,
  redaction booleans, and explicit non-claims.
- After summary preflight succeeds, failures must write a non-secret
  classification summary when possible: `overall_status=fail`, `failure_phase`,
  `failure_class`, optional sanitized `failure_message_class`,
  `secret_prompts_started`, `vault_operations_started`, and
  `operations.<phase>.status=fail` where applicable. Pre-prompt failures must
  make clear that secret prompts did not start; post-prompt failures may only
  record that prompts started, never prompt values.
- The summary must not contain a root token, unseal key, client token, Vault
  token, JWT-SVID payload, API key value, private key, password, proof secret
  value, secret payload, raw exception string, traceback, raw Vault output, raw
  HTTP headers, operator-entered prompt values, or terminal transcript.

Allowed execution flags:

- `--help`
- `--plan`
- `--inventory`
- `--ssh-target <target>`
- `--execute-bootstrap`
- `--prepare-summary-path`
- `--prepare-config-readability`
- `--prepare-spire-bundle-read`
- `--interactive-tty`

Flag and staging rules:

- `--help`, `--plan`, and `--inventory` are mutually exclusive with
  `--execute-bootstrap`, `--prepare-summary-path`,
  `--prepare-config-readability`, and `--prepare-spire-bundle-read`.
- `--ssh-target` and `--interactive-tty` are valid only with
  `--execute-bootstrap`, `--prepare-summary-path`,
  `--prepare-config-readability`, and/or `--prepare-spire-bundle-read`.
- `--execute-bootstrap`, `--prepare-summary-path`, and
  `--prepare-config-readability`, and `--prepare-spire-bundle-read` each require
  both `--ssh-target <target>` and `--interactive-tty`.
- The SSH target must be a single target, not an SSH option or shell command.
- The route requires visible local stdin and stdout before preparation or
  staging.
- The route allocates an interactive SSH TTY with `ssh -tt` only for the
  explicit `--interactive-tty` preparation/execution path.
- Standalone `--prepare-summary-path` runs only the fixed bounded remote
  preparation command. It does not stage helpers and does not create a bootstrap
  summary.
- Standalone `--prepare-config-readability` runs only the fixed bounded remote
  preparation command for the workload-zone config path. It does not stage
  helpers, print config contents, or create a bootstrap summary.
- Standalone `--prepare-spire-bundle-read` runs only the fixed bounded remote
  preparation command for the SPIRE server bundle-read socket path. It does not
  stage helpers, print SPIRE bundle contents, copy bundle contents, or create a
  bootstrap summary.
- Combined `--execute-bootstrap --prepare-summary-path
  --prepare-config-readability --prepare-spire-bundle-read` runs summary
  preparation, then config preparation, then SPIRE bundle-read preparation
  before helper staging and helper execution.
- The route stages to a route-specific remote scratch root, stages only the two
  bootstrap helper files, invokes only the staged public helper, and attempts
  staged-helper cleanup by default.
- P0q does not offer `--keep-staging-on-failure`.

Forbidden execution flags and inputs include:

- `--host-local`
- `--dry-run`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--apply`
- `--interactive-sudo`
- `--governed-smoke-command`
- `--keep-staging-on-failure`
- helper override flags
- workload-auth helper override flags
- Vault address, role, audience, path, proof-path, SPIFFE ID, config path,
  summary path, container probe image, or SPIRE socket override flags
- arbitrary commands
- helper path overrides
- `--root-token`
- `--unseal-key`
- `--client-token`
- `--vault-token`
- `--api-key`
- `--jwt-svid`
- `--private-key`
- `--password`
- `--secret`
- proof secret value flags
- any secret-like positional argument

P0q tests:

- helper help documents secret posture and non-claims
- helper rejects secret CLI args, equals-form secret args, and secret env vars
- fake Vault API capture proves bootstrap authority is not passed by argv, env,
  file, summary, or Codex-facing output
- fake Vault API capture proves the proof secret value is never printed or
  summarized
- preflight failure before secret prompts proves no root-token prompt, no proof
  secret prompt, no fake Vault API call, and no summary or temp summary
- config readability preflight failure before secret prompts proves no root-token
  prompt, no proof secret prompt, no fake Vault API call, and a safe failure
  summary with `operations.config_load.status=fail`
- SPIRE bundle-read preflight failure before secret prompts proves no root-token
  prompt, no proof secret prompt, no fake Vault API call, and a safe failure
  summary with `operations.spire_jwt_validation_material.status=fail`
- fake bootstrap writes the expected fake Vault objects only
- fake bootstrap writes the Vault JWT auth config with the expected validation
  material and bound issuer shape
- fake bootstrap writes all selected workload-trust-domain JWT-SVID RSA
  validation public keys and ignores non-JWT-SVID RSA keys
- fake workload-auth check JWT claims align with the bootstrap config labels
- fake successful bootstrap records the summary preflight and config load as
  passed, records SPIRE JWT validation material as passed, and stores only a
  digest instead of raw bundle material
- static source tests prove redaction checks run before final summary rename
- summary schema and redaction scans fail on secret-like material
- operator tests prove help, plan, and inventory stay safe
- operator tests reject missing `--ssh-target`, missing `--interactive-tty`,
  forbidden reset/unseal/check/IM/CP/runtime flags, helper override flags,
  secret-like flags, unknown flags, duplicate flags, equals-form options, and
  extra positionals before staging
- fake SSH tests prove `--prepare-summary-path` uses only the bounded remote
  preparation command, may use visible OS sudo only for filesystem preparation,
  does not stage helpers, does not invoke Vault/workload-auth/reset/IM/CP/runtime
  routes, creates no local `.out`, creates no final bootstrap summary, and
  removes its temp probe
- fake SSH tests prove `--prepare-config-readability` uses only the bounded
  fixed-path ACL preparation command, may use visible OS sudo only for
  filesystem preparation, does not print config contents, does not stage helpers,
  does not invoke Vault/workload-auth/reset/IM/CP/runtime routes, and creates no
  local `.out`
- fake SSH tests prove `--prepare-spire-bundle-read` uses only the bounded
  fixed-path ACL preparation command, may use visible OS sudo only for
  filesystem/capability preparation, discards SPIRE bundle command output, does
  not print/copy bundle contents, does not stage helpers, does not invoke
  Vault/workload-auth/reset/IM/CP/runtime routes, and creates no local `.out`
- fake SSH tests prove combined `--execute-bootstrap --prepare-summary-path
  --prepare-config-readability --prepare-spire-bundle-read` runs summary
  preparation, then config preparation, then SPIRE bundle-read preparation
  before helper staging and helper execution
- fake SSH/SCP tests prove exactly the two bootstrap helper files are staged,
  `ssh -tt` is used only for execution, only the public bootstrap helper is
  invoked, cleanup is attempted, no transcript/`tee`/`script` is used, and no
  Mac `.out` copy-back occurs

### P0r Mac-Side Runtime Identity Summary Recovery Session

`Bounded slice rule`: P0r implements exactly one Mac-side runtime identity
evidence route:

- `scripts/remote_alpha_operator.sh recovery-session runtime-identity-summary
  --ssh-target <target> --interactive-tty`

P0r is implementation/self-audit with static and fake SSH/SCP validation only.
It does not run live SSH, sudo, SPIRE commands, Vault, workload-auth
bootstrap/check, reset, unseal, Infrastructure Manager refresh,
support-bundle collection, CP proof, runtime identity summary live, runtime
identity generation, or network-dependent integration tests during validation.

The route is separate from workload-auth bootstrap/check and reset/unseal. It is
evidence/projection only over the existing host-local runtime identity helper
summary script; it is not runtime identity generation, not runtime-profile
readiness, not submit readiness, not retained-result readiness, not governed
execution proof, not CP proof, not production readiness, and not Remote Alpha
deployment/provisioning/reconciliation architecture. It does not settle the
reopened runtime-identity handoff seam.

Topology rules:

- `--ssh-target <target>` is required.
- `--interactive-tty` is required.
- local stdin and stdout must both be visible terminals before staging or SSH.
- `--host-local` is not accepted for this Mac-side route.
- bare `runtime-identity-summary` execution must fail.

Allowed flags for `runtime-identity-summary` in P0r are:

- `--help`
- `--ssh-target <target>`
- `--interactive-tty`

P0r must reject:

- `--host-local`
- `--dry-run`
- `--check-only`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--execute-bootstrap`
- `--prepare-summary-path`
- `--prepare-config-readability`
- `--prepare-spire-bundle-read`
- `--apply`
- `--interactive-sudo`
- `--governed-smoke-command`
- runtime identity helper override flags
- output or summary path overrides
- runtime-support path overrides
- SPIRE socket overrides
- workload SPIFFE ID overrides
- audience overrides
- arbitrary commands
- unknown flags
- duplicate flags
- extra positional arguments
- equals-form options
- secret-like arguments, including root tokens, unseal keys, client tokens,
  Vault tokens, JWT-SVID payloads, API keys, private keys, passwords, proof
  secrets, raw identity payloads, and secret payloads

Secret model:

- The route must not accept, parse, print, log, relay, persist, summarize, or
  copy JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private
  keys, passwords, proof secrets, raw identity payloads, or secret material.
- It must not print full summary JSON.
- It relies on the existing helper's non-secret summary and redaction behavior.

Staging and invocation:

- stage only `scripts/remote_alpha_runtime_identity_helper_summary.sh`
- do not stage `scripts/remote_alpha_operator.sh`
- do not stage `scripts/internal/*`
- do not stage reset/unseal helpers
- do not stage workload-auth helpers
- do not stage workload-auth bootstrap helpers
- do not stage service-user helpers
- do not stage config/TLS helpers
- do not stage binary deployment helpers
- do not stage bundles or unrelated helpers
- do not introduce generic helper dispatch
- allocate an interactive SSH TTY with `ssh -tt`
- invoke only the staged runtime identity helper summary script
- pass no runtime identity helper override flags
- never combine runtime identity evidence with workload-auth bootstrap/check,
  reset, unseal, post-unseal checks, Infrastructure Manager refresh,
  support-bundle collection, CP proof, runtime identity generation, runtime
  profile readiness, submit readiness, or retained-result readiness
- do not capture stdout or stderr to files
- do not use `tee`
- do not run `script`
- cleanup of the staged helper file/root must be attempted by default

Summary/evidence behavior:

- the canonical summary remains remote at
  `/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`
- no summary is copied back to Mac `.out` in this route
- no operator summary file is created
- after remote success, the operator facade may print only the canonical remote
  summary path, a reminder that the summary is evidence/projection only and
  non-authoritative, and printed-only next steps such as
  `recovery-session --evidence-check --runtime-identity-summary <local-path>`
  after separate evidence collection

Stop conditions for P0r:

- staging the route requires more files than the public runtime identity helper
  summary script
- helper override flags are accepted
- secret-bearing inputs are accepted
- JWT-SVIDs, token payloads, raw identity payloads, or secret material are
  printed or copied
- the route copies the summary back to Mac `.out`
- the route prints full summary JSON
- the route creates operator summaries or generated artifacts
- the route runs Infrastructure Manager refresh, support-bundle collection, CP
  proof, reset/unseal, workload-auth bootstrap/check, runtime identity
  generation, or readiness proof
- a generic helper dispatcher is introduced

P0r remains bounded ES Remote Alpha proof/support workflow glue only. It is not
runtime-profile readiness, not submit readiness, not retained-result readiness,
not governed execution proof, not CP proof, not production readiness, and not
Remote Alpha production, deployment, provisioning, or reconciliation
architecture.

### P0s/P0t Dedicated ES TLS Status-Only Collector

`Reopened redesign seam`: P0s/P0t status and renewal cease to share the
committed public/internal helper pair. The status replacement is a bounded
Remote Alpha evidence and repair-support refinement; the old shared
supervisor/renewal candidate is design evidence only. Renewal is held. This
section does not grant host provisioning, production PKI, automatic repair,
service restoration, MA scheduling, IM or CP authority, or governed proof.
P0q legacy use, the P0u hold, and P0v remain separate.

`Temporary compatibility edge`: `recovery-session es-service-tls-status` and
`recovery-session es-governance-tls-status` retain fixed `--ssh-target` and
visible `--interactive-tty` facade forms. They stage only
`scripts/internal/remote_alpha_es_tls_status.py` and call one fixed,
source-controlled root bootstrap through visible sudo with
`/usr/bin/python3 -I -B -c`, fixed locale, and exact scope. TTY output
is operator acknowledgment, never machine evidence; the remote summary is not
copied to `.out`. Both `es-service-tls-renew` and
`es-governance-tls-renew` refuse before stage, SSH, SCP, sudo, or contact.
`--execute-renew` on status refuses before contact. The direct public renewal
wrapper fails locally and does not source the old internal helper. The old
internal helper remains committed, historical, and undispatched.
The fixed remote wrapper is delivered as a bounded, single-quoted SSH remote
command derived only from source-controlled bytes and validated stage
directory, custody identity, scope, and digest operands; it is independent of
SSH stdin. SSH stdin stays attached to the real local operator terminal for
the entire `ssh -tt` invocation, so its remote TTY can service a
password-required sudo prompt. Success requires neither cached sudo
credentials nor NOPASSWD. The sudo password is never captured, relayed outside
that terminal, or retained. Invalid targets or an overlarge command fail
before contact, and the returned custody identity is validated before the
interactive invocation; no arbitrary remote command or caller shell fragment
is accepted.

`Bounded slice rule` prospective failure witness: the fixed root bootstrap
alone may emit at most one diagnostic line on the existing controlling
terminal after a failed P0s/P0t invocation has proved its applicable
stage/descriptor/lock, child and temporary closeout. The collector selects a
private invocation-local phase/reason but never emits. The line is exactly
`ES_TLS_STATUS_FAILURE_V1 scope=<scope> origin=<origin> source=<source> collector_sha256=<digest> phase=<phase> reason=<reason>`
plus LF, ASCII and at most 512 bytes including LF, with one space between
fields. Scope is `artifact-registry`, `execution-governance`, or `unknown`;
`unknown` is allowed only at bootstrap entry before scope validation. Origin
is `bootstrap` or `collector`. Source is `verified` only after the current
stable staged-leaf read has matched its complete SHA-256 to the intended
digest; that exact payload is dispatched from memory. Before verification,
source is `unverified` and digest is `none`; verified digest is exactly 64
lowercase hex digits. Collector-origin selection requires verified source and
a fixed scope. The digest binds intended source bytes, not a trusted remote
attestation. The private phase/reason coupling is closed:

| Origin | Phase | Specific reasons (each phase also allows `interrupted` and `unknown`) |
| --- | --- | --- |
| bootstrap | `bootstrap_entry` | `invocation_unproved`, `caller_identity_unproved` |
| bootstrap | `stage_custody` | `stage_custody_unproved`, `source_unproved` |
| bootstrap | `stage_disposition` | `stage_disposition_unproved` |
| bootstrap | `collector_load` | `collector_load_unproved` |
| collector | `collector_entry` | `invocation_unproved` |
| collector | `protected_ancestry` | `protected_state_unproved` |
| collector | `scope_lock` | `lock_state_unproved`, `lock_acquisition_unproved` |
| collector | `process_capability` | `process_capability_unproved` |
| collector | `prior_snapshot` | `prior_summary_unaccepted`, `prior_read_unproved` |
| collector | `collection` | `fixed_input_unproved`, `fixed_command_unproved`, `openssl_child_unproved`, `openssl_grammar_unaccepted` |
| collector | `record_encoding` | `record_unaccepted` |
| collector | `publication_precommit` | `publication_unproved` |

Selection requires the reached source boundary and exact type-checked literal
`Incomplete.args` membership; any unmapped or hostile exception selects
`unknown`, without stringification. The existing flock `OSError` label does
not prove contention and maps to `lock_acquisition_unproved`. A completed
negative protected record is completed evidence, so emits no incomplete
failure witness. No raw exception, path, subject, PID, command, OpenSSL stream,
config, private material or material digest can enter a witness.

Emission is best effort through one independently opened, output-only,
nonblocking descriptor to the fixed controlling-terminal device, verified as
a terminal. It never changes inherited stream flags or terminal input mode,
captures a sudo/SSH transcript, falls back to a file, waits or retries. A
blocked, short, missing, forged or duplicate line is not accepted diagnosis.
The bootstrap emits only after existing resolved closeout; an unproved stage
may remain as diagnostic residue without a deletion claim. An unresolved
child/member hold, failed close (including a fixed-input leaf or ancestry
descriptor close that a config, certificate, or key consumer wraps as an
`Incomplete`), or uncertain temporary cleanup suppresses output without
releasing a lock early or adding cleanup. Escaped collector
dispatch with unproved disposition is suppressed. For parent-owned protected
ancestry, capability/proc descriptors, selected-anchor pipes, selector and
OpenSSL streams, the pending close token is consumed before the one explicit
close attempt. The first failed close stays unproved across `Incomplete`
wrapping, a stream's `.closed` state, or later cleanup success. A different
still-owned descriptor or stream receives its own close attempt; an ambiguous
numeric descriptor is never retried merely to obtain proof. Child exit/reap
settles only child-owned copies, not the parent's close obligation. This is
private close accounting, with no change to process holds, lock release order,
or accepted result. Successful publication retains immediate `os.replace`
then `os._exit(0)` with no postcommit action.
For fixed inputs, leaf close precedes independent reverse-ancestry attempts;
an invalid newly opened child is settled separately from its retained parent
chain. A missing final leaf is completed absence only when every acquired
input descriptor closes successfully. If any such close fails, the primitive
reports a controlled incomplete input operation after all other applicable
attempts, even if a final-leaf `FileNotFoundError` was already pending. A
close-raised `FileNotFoundError` cannot become completed missing or absent
evidence at a config, certificate, or key caller. The scope lock closes before
the status-directory descriptor, with the second still attempted after an
uncertain first close. Each acquired member
pidfd has one local close obligation; a failed close remains invocation-sticky
while later observed candidates are independently pinned and identity-checked
before any signal. Per-member faults are aggregated after the finite scan into
the existing incomplete child-owner hold. None of these close groups retries
an ambiguous descriptor or converts later cleanup into witness eligibility.
Only the original no-follow final-leaf stat can provisionally observe missing
input. After safe ancestry revalidation and settled input closeout, a private
`_VerifiedFinalLeafAbsent` marker carries that observation to the config,
certificate and reached-key callers. All other `FileNotFoundError` origins
are incomplete, including root/ancestor operations, present-leaf reads and
later rechecks. A settled operation failure can select the existing
`fixed_input_unproved` advisory reason; failed closeout suppresses it. No
public result or protected-reader rule changes.
The facade's fixed post-contact failure acknowledgment covers stage/custody
response, upload, post-stage command construction, and interactive SSH failures.
It reports remote phase unproved and public exit 2; it does not parse the TTY,
infer a root cause from SSH/sudo exit, or claim no helper ran. The witness is not protected status,
reader acceptance, renewal, readiness, restoration, IM/CP/MA or retry authority.
The facade sets the one staged collector to `0600` through a no-follow
descriptor check before sudo; the bootstrap independently verifies stage
custody and removes it before collector observation.
One fixed remote Python stage-creation helper opens the fixed `/tmp` parent,
rejects an existing generated name, creates only that name with mode `0700`,
opens it immediately with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, verifies its
directory type, current caller UID/GID, mode, link rules, empty entry set,
and parent-entry/descriptor identity, and closes every descriptor. Its sole
dynamic output is two strict unsigned decimal device/inode fields, the
**custody-acquisition identity**. POSIX offers no atomic `mkdir`-and-open
identity primitive. The supported operator route trusts its nonroot `ds`
account for this fixed creation helper; concurrent malicious same-UID
substitution before custody acquisition is outside this route's trust
boundary. After acquisition, root still requires that measured identity and
exact digest; correct collector bytes cannot authorize a different directory
identity or scope.

After stage creation the nonroot facade performs no destructive stage cleanup.
SCP, sudo launch/authentication, transport, bootstrap, or earlier setup failure
returns nonzero and retains the stage as diagnostic residue. The stage holds
only the fixed public collector payload and bounded metadata, never a
credential, host key, certificate, private key, config, summary, or raw child
output. The facade emits only a bounded non-sensitive cleanup disposition.
The fixed root bootstrap is the sole supported stage-deletion authority and
requires measured custody identity, caller UID/GID, directory metadata and
entry set, exact leaf, payload identity, and SHA-256 digest before removal.
A substituted or unproved path remains residue. Successful root removal has
no later facade cleanup. No automatic residue sweeper, wildcard cleanup, or
historical-stage migration is introduced. Residue is not accepted evidence,
route success, host readiness, renewal authority, or permission for later
deletion; retaining an unproved object is the bounded compatibility rule.
Facade setup and bootstrap verification and self-cleanup inspect
the final staged entry without following it before any blocking open. FIFO,
socket, symlink, directory, device, and other nonregular entries are promptly
refused and retained. Only a prechecked regular file is opened with
`O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, then immediately `fstat`-matched to the
pre-open device, inode, type, owner, mode, and link count. A substituted or
unproved entry is never removed; failed cleanup is incomplete and preserves
the previous canonical generation.
The facade derives the expected SHA-256 from its exact fixed local collector
source; it accepts no digest override. Root bootstrap operands are only the
generated stage directory, fixed collector basename, internally derived
64-hex digest, one fixed scope, and the strict unsigned decimal custody-acquisition
device and inode derived internally by the facade. The bootstrap opens the
fixed parent, inspects the stage entry no-follow, and opens the stage with
`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. It proves the parent entry and opened
directory are the measured custody-acquisition identity before and after open and
immediately before leaf and directory removal, with exact nonroot caller
UID/GID, owner, mode, links, and one-file entry set. It opens
the observed regular leaf with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, requires
descriptor identity, reads one bounded complete payload, checks its SHA-256,
and rechecks pathname identity. It transfers the directory to root custody,
unlinks only that identity-proved leaf, proves the directory empty, and removes
the exact stage before compiling and executing the already-read bytes in
memory. A same-path replacement, including one with correct digest-bound
bytes, is neither executed nor deleted as the measured stage. Root never
loads an operator-writable pathname. The collector requires
an internal bootstrap marker, latched-signal handoff, and synthetic, non-host-path source
label; direct pathname invocation refuses before any status read or publication.
Substitution, FIFO, symlink, unexpected entry, digest mismatch, or failed
cleanup is incomplete and publishes no new generation. No later
post-publication cleanup acts on the stage.

The collector has one lifecycle-owning Python process and fixed read-only
OpenSSL leaf children. No custom supervisor, child-held lock, background
process-group observer, backup, key/cert generation, install, restart, post-renewal
probe, shell, arbitrary command, path override, or renewal mode is available.
Exactly two immutable source-controlled scopes exist:

| Scope | Fixed role and topology observation |
| --- | --- |
| `artifact-registry` | ARS server cert/key and runtime client CA; AGS artifact-registry client cert/key and runtime root copy; ES artifact-registry client cert/key and root copy. ARS/AGS/ES configs must bind those paths. AGS/ES dependency URLs are HTTPS loopback ARS port 8442. Three cert/key pairs and four fixed CA checks cover AGS/ES clients against ARS CA and ARS server against AGS/ES roots. Related external TLS sharing a covered path is a typed topology failure. |
| `execution-governance` | EGS server cert/key and runtime client CA; ES governance client cert/key and root copy. EGS/ES configs bind those paths. ES dependency URL is HTTPS loopback EGS port 8443 with server name `server.execution-governance.internal`. AGS must have no execution-governance dependency. Two cert/key pairs and two fixed CA checks cover ES client against EGS CA and EGS server against ES root. |

The fixed public certificate roles and paths are:

| Scope | Role label | Certificate path | Role |
| --- | --- | --- | --- |
| P0s | `ars_trusted_runtime_client_ca` | `/etc/execution-substrate/ars-tls/runtime-ca.pem` | CA |
| P0s | `ars_server` | `/etc/execution-substrate/ars-tls/ars-server-cert.pem` | server |
| P0s | `ags_artifact_registry_client` | `/etc/execution-substrate/tls/ags-client-cert.pem` | client |
| P0s | `ags_artifact_registry_root_ca` | `/etc/execution-substrate/tls/runtime-ca.pem` | CA |
| P0s | `es_artifact_registry_client` | `/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem` | client |
| P0s | `es_artifact_registry_root_ca` | `/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem` | CA |
| P0t | `egs_trusted_runtime_client_ca` | `/etc/execution-substrate/egs-tls/runtime-ca.pem` | CA |
| P0t | `egs_server` | `/etc/execution-substrate/egs-tls/egs-server-cert.pem` | server |
| P0t | `es_execution_governance_client` | `/etc/execution-substrate/es-tls/execution-governance-client-cert.pem` | client |
| P0t | `es_execution_governance_root_ca` | `/etc/execution-substrate/es-tls/execution-governance-root-ca.pem` | CA |

The fixed key-pair labels use the matching `ars_server`,
`ags_artifact_registry_client`, `es_artifact_registry_client`, `egs_server`,
and `es_execution_governance_client` roles with, respectively,
`ars-server-key.pem`, `ags-client-key.pem`,
`artifact-registry-client-key.pem`, `egs-server-key.pem`, and
`execution-governance-client-key.pem` beside their certificates. Fixed chain
checks are `ags_client_cert_against_ars_client_ca`,
`es_client_cert_against_ars_client_ca`,
`ars_server_cert_against_ags_root_ca`,
`ars_server_cert_against_es_root_ca`,
`es_execution_governance_client_cert_against_egs_client_ca`, and
`egs_server_cert_against_es_execution_governance_root_ca`. Server checks
use `sslserver` with `server.artifact-registry.internal` or
`server.execution-governance.internal`; client checks use `sslclient`.
P0s checks related AGS/ES/EGS service TLS for covered-path overlap. P0t
checks related ARS/AGS/ES service TLS and other dependency material for
covered-path overlap, and excludes AGS execution-governance dependency.

`Bounded slice rule` for optional related topology: the P0s related EGS
config and P0t related ARS config may be safely absent. Their dedicated
related-config check then records `status=pass, code=absent`; dependent
disjointness checks may pass only when every other input also permits it.
A present, safely read and valid related config records `pass` and is
inspected for covered-path overlap and, for P0t, the fixed dependency
exclusion. A present syntactically or structurally malformed optional config
records `status=fail, code=related_config_malformed` on its related-config
check and the affected disjointness/exclusion checks. A required malformed
config retains `config_malformed` on its required-config check and produces
`related_config_malformed` on affected disjointness/exclusion checks. A
missing required config uses `config_missing` on its required-config check
and affected disjointness/exclusion checks. None may infer a pass from an
empty-object fallback. An unsafe, over-limit, changing, or unexpectedly
unreadable config makes the entire observation incomplete with no new
generation and no completed unreadable code.
Required and present optional configs use strict JSON: duplicate keys,
`NaN`, `Infinity`, `-Infinity`, every parsed non-finite numeric value including
`1e10000`, `-1e10000`, and nested overflow in ignored fields, invalid UTF-8,
trailing data, and non-object top levels are malformed.
Every strict-JSON payload handled by the collector has
`MAX_JSON_CONTAINER_DEPTH = 64`: the top-level object or array is container
depth 1; each nested object or array adds 1; scalars add none. Depth 64 is
accepted only when the separate schema and byte-size limits pass; depth 65
and decoder recursion exhaustion are controlled structural rejections.
Required config retains completed `config_malformed` and its dependent
blocker relationship; a present optional related config retains completed
`related_config_malformed`, never absent/pass. An over-depth protected reader
summary is unaccepted evidence through the controlled reader failure API,
without traceback or raw exception text. The exact summary schema remains an
independent reader acceptance rule.
`Bounded slice rule` for the pre-run canonical target: its private states are
`ABSENT`, `VALID(generation)`, and `INVALID_OR_UNACCEPTED`. `ABSENT` requires
proved safe absence of the verified final leaf; a present target that cannot
yield the snapshot is invalid/unaccepted. A present protected leaf is
`VALID` only if strict JSON provides the selected scope's expected
`schema_version`, `collector_contract`, `finalized=true`, `scope`, and `route`,
plus a string `generation` of exactly 32 lowercase hexadecimal characters.
This bounded snapshot checks identity, not the full accepted-reader semantic
or freshness policy. A stale or completed-fail prior record may be replaced
when snapshot identity is valid; the replacement generation must differ.
Every strict-JSON or snapshot-shape rejection in a present leaf, including
depth, non-finite value, literal constant, duplicate key, invalid UTF-8,
trailing data, non-object root, decoder exhaustion, or mixed defects in any
field order, and every snapshot identity failure is `INVALID_OR_UNACCEPTED`.
After the one
process preflight and status lock, that state stops incomplete before status
collection, material read, OpenSSL spawn, or publication setup. It preserves
the existing canonical bytes and metadata identity; no new generation, raw
exception text, or public evidence code is emitted. Unsafe type, identity,
or read failure remains incomplete under the protected-leaf rule.
A participating certificate, key, or CA path is
accepted only as an absolute lexical canonical POSIX material path: not `/`,
no NUL, empty, `.`, or `..` component, repeated separators or a trailing separator, and
equal to its own lexical normalization. A noncanonical present config takes
the governed malformed typed result. Expected-path and related-material
disjointness compare only accepted canonical values, never raw aliases or
host `realpath`.

The protected status contract is
`execution-substrate.remote-alpha.es-tls-status-evidence/v1` under
`/var/lib/execution-substrate-remote-alpha/v1/status`. Every component from
`/var` down must be verified descriptor-first, real root:root directory,
symlink-free, not group/world writable, without unresolved ACL/equivalent
access. The three protected directories under `/var/lib` are exact `0755`.
Missing directories fail: separate later host preparation owns creation.
There is no `private-backups` use in status.

| Scope | Canonical record | Same-scope lock | Schema |
| --- | --- | --- | --- |
| P0s | `es-service-tls-status-summary.json` | `.es-service-tls-status.lock` | `execution-substrate.remote-alpha.es-service-tls-status-summary.v1` |
| P0t | `es-governance-tls-status-summary.json` | `.es-governance-tls-status.lock` | `execution-substrate.remote-alpha.es-governance-tls-status-summary.v1` |

The names above are relative to the protected status directory. Canonical
records must be root:root `0644`, regular, single-link, no-follow, without
unsafe or unresolved extended access, and at most one MiB. Each persistent
lock is root:root `0600`, regular, single-link, no-follow, opened relative to
the verified status descriptor with `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`
and held by this collector with `flock(LOCK_EX|LOCK_NB)`. Same-scope
contention is incomplete; different scopes may run concurrently. OpenSSL
children never inherit the lock.

Before protected-root access or any config/TLS read, the root bootstrap requires
effective root and matching nonroot `SUDO_UID`/`SUDO_USER` for the fixed
Remote Alpha operator `ds`, validates the
one-file stage directory directly under `/tmp` with exact generated prefix,
owner, `0700` directory, `0600` regular single-link collector, no symlinks,
entry and descriptor identity, transfers the verified stage directory
to root custody, and removes its own file and directory via verified handles.
It latches catchable signals during the cleanup decision.
Failed or unprovable cleanup exits incomplete without a new record. No later
`/tmp` status scratch is used. The collector itself starts only after that
cleanup and cannot infer cleanup authority from its synthetic `__file__` label.

Fixed config, certificate, and key reads traverse verified no-follow ancestor
and leaf descriptors. The final entry is inspected without following it before
any blocking read open. FIFO, socket, symlink, directory, device, or another
nonregular type is rejected promptly without opening it for blocking I/O.
Only a prechecked regular entry is opened with
`O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, then immediately `fstat`-matched on
device, inode, type, owner, mode, link count, and governed metadata. A swap to
another regular file or unsupported type fails closed. Only an absent final
leaf beneath proved safe ancestry and successful input-descriptor closeout is
a completed missing result. The primitive conveys that observation through
the private verified final-leaf marker, never through a generic
`FileNotFoundError`. Unsafe ancestry, type, permission denial, metadata
failure, present-leaf read failure, and race are incomplete.
Bounded bytes
from the verified leaf become an immutable invocation snapshot. Each fixed
OpenSSL metadata, SAN/EKU, key, and verification command receives those exact
bytes through fresh anonymous pipes, never by reopening the mutable source
pathname. Transient key bytes feed only the fixed OpenSSL child; no key bytes
or digest are published or retained afterward. The public fixed certificate
path remains a source label; `/dev/stdin` is the leaf/key invocation operand,
and one inherited `/dev/fd/<n>` is the selected CA operand. Descriptor
setup/support failure is incomplete and creates no retained scratch. One child at a
time uses absolute argv and a fixed environment, no shell, concurrent bounded
stdout/stderr draining, timeout, one bounded TERM/KILL path, and complete
reaping. Unexpected output grammar, timeout, overflow, interruption, or
unreaped child is incomplete. Raw command output and config contents never
enter the summary.

`Bounded slice rule` for subprocess ownership: immediately after a successful
`Popen`, one cleanup owner covers selector construction and registration,
nonblocking pipe setup, collection, parsing, timeout, interruption, and
signaling and wait/poll exceptions. Every incomplete path terminates and reaps that child
and closes selector resources. Spawn failure before a child exists is simply
incomplete. A group-signaling error requires identity-safe same-group member
disposition and an incomplete result, never a direct-child-only fallback; no
returned attempt may leave the fixed child or process group alive. The
collector validates nonreaping waitid and fixed pidfd/proc cleanup capability
exactly once after bootstrap stage removal and status-lock acquisition,
before any status config, certificate, key, trust-anchor, or prior-summary read
and before any OpenSSL spawn. One fixed internal fork child proves
`waitid(P_PID, WEXITED|WNOHANG|WNOWAIT)` observes terminal state without
reaping, proves subsequent exact reap and fixed pidfd/proc member operations;
the probe child closes inherited descriptors, including the status lock,
before its fixed release and is reaped on every path. One successful
invocation-local capability state is required by every fixed OpenSSL command;
no command forks another probe. Failure or indeterminate capability reads no
status input, spawns no OpenSSL child, publishes no generation, and leaves no
probe descriptor or process. On group signal
failure it enumerates only members whose observed PGID equals the reserved
leader PGID, acquires pidfds, revalidates identity and membership, signals
members through pidfds, and repeats bounded scans until nonleader members are
proved gone. An individual member error does not skip other identity-proved
members in that scan; each later candidate must acquire its own pidfd and pass
the exact group/start-time revalidation before signaling. A member pidfd close
failure remains unproved even if later group cleanup succeeds. If group and
member signaling remain unproved, the leader stays
unreaped and lifecycle ownership and status lock stay held without publication.
Every ordinary `Exception` from membership scanning, pidfd acquisition,
identity revalidation, signaling, polling, waiting, or cleanup-state
reporting is contained by this unresolved-cleanup hold. One-shot faults
recover on later iterations; persistent faults retain the invocation and
lock with bounded backoff. No outer retry may return until group absence
and exactly one direct-child reap are proved. No unrelated process is signaled.
Group TERM and KILL occur while the child remains unreaped, so
its PID remains reserved; cleanup never signals a process group after reaping.
Nonreaping `waitid` with `WNOWAIT` detects terminal leader state without
releasing that PID, using the target C runtime when Python lacks a wrapper.
Bounded TERM then KILL when required addresses the fixed group while its
leader PID remains reserved; a known return code never skips disposition.
A zombie-only group may still answer a zero-signal check before reap. After
direct-child reap, the collector uses only a non-signaling, identity-based
proc group scan in the fail-closed group-absence hold and never sends a raw
numeric group signal. Post-exit
wait/poll failure must still contain any descendant while the leader PID is
reserved. The required syscall and group check are capability-sensitive:
unavailable or indeterminate behavior is incomplete, with no new generation
and no OS-label or direct-child-only fallback. No child
inherits the same-scope status lock; no unbounded ordinary child wait or
double reap is allowed. The unresolved-cleanup hold is exceptional.

The exact client verification argv is `/usr/bin/openssl verify -trusted
<selected-ca-fd> -purpose sslclient /dev/stdin`. The server argv is
`/usr/bin/openssl verify -trusted <selected-ca-fd> -purpose sslserver
-verify_hostname <fixed-server-name> /dev/stdin`. The selected descriptor
contains exactly the same observed bytes as the scope's selected anchor:
one PEM `CERTIFICATE` block with only bounded ASCII whitespace around it.
Every fixed P0s/P0t CA-role input is one selected certificate, not a bundle.
Zero or multiple certificate blocks, another PEM block, or non-whitespace
outside the block is completed `trust_anchor_count_mismatch` with null
certificate metadata and dependent `certificate_unavailable` verification.
The same rule applies to the runtime CA and each client trust copy. A later
anchor in the file cannot rescue a wrong first anchor. Broader host references
to a CA bundle do not redefine these status-role inputs. Future bundle
support requires reporting every trusted anchor and a versioned reader/schema
decision. No `-CAfile`, `-CApath`,
`-CAstore`, `-untrusted`, shell, path/purpose/hostname override, or ambient
trust/config environment is admitted. The child environment is fixed with
`LC_ALL=C`; `SSL_CERT_FILE`, `SSL_CERT_DIR`, `OPENSSL_MODULES`,
`OPENSSL_ENGINES`, and other inherited trust/config overrides are absent.
`OPENSSL_CONF=/dev/null` is fixed. `-trusted` excludes default trust sources:
a wrong selected anchor cannot be rescued by ambient trust. Unsupported
`-verify_hostname` or descriptor operands are incomplete. Positive target
capability is a later host-preflight fact, not assumed by local tests.

The OpenSSL response contract is whole-response and command-specific. A
completed result requires an admitted exit status and the complete admitted
stdout/stderr grammar; a recognized word embedded in extra or mixed output
has no standing. Fixed `x509` metadata success requires exactly one each of
subject, issuer, notBefore, notAfter, and one SHA-256 fingerprint field in
that order, with valid values and empty stderr. Public-key PEM success has
the complete `BEGIN PUBLIC KEY`/base64-lines/`END PUBLIC KEY` envelope and
final newline; DER success is one length-consistent ASN.1 SEQUENCE of at
least 64 bytes. Both require exit zero and empty stderr. The `x509 -text`
success boundary is narrower than a full certificate-text parser: exit zero,
empty stderr, a fixed `Certificate:\n    Data:\n` prefix, no carriage-return
or NUL byte, UTF-8 text, and a terminal `    Signature Algorithm: <token>`
line followed by exactly one of two complete signature-tail alternatives:
the existing one or more nine-space-indented lowercase hexadecimal signature
lines with no heading, or exactly one `    Signature Value:` heading followed
by one or more eight-space-indented lowercase hexadecimal signature lines.
The token matches `[A-Za-z0-9-]+`. Each alternative retains the existing
optional terminal colon and newline policy, requires consistent indentation,
and is anchored at end of output. A heading plus nine-space rows, eight-space
rows without a heading, mixed indentation, repeated or unknown headings, and
trailing bytes remain incomplete. The intervening certificate text is not
independently validated as a complete grammar; fixed SAN/EKU extraction
governs the role checks. The earlier bounded text-tail refinement is supported by
local synthetic public material and a retained OpenSSL 3.6.2 response; by
itself it did not qualify the target's reported OpenSSL 3.0.13 binary or the
complete collector run. A subsequent single nonroot synthetic target
observation captured 55 complete native tuples from OpenSSL 3.0.13: 39 were
accepted by the unchanged consumer, 13 were closed-grammar gaps, and three
later malformed-output controls were unreachable at current call sites.
This later evidence supports only the finite negative-response additions
below. It does not establish production material, root-context behavior,
complete P0t inventory, or service readiness. `verify` success requires
exit zero, empty stderr, and exactly
`/dev/stdin: OK\n` on stdout. A generic nonzero status never
means malformed certificate, malformed key, or failed chain.

The admitted malformed-material response is the fixture-proven LibreSSL
3.3.6 tuple: exit 1, empty stdout, and exactly two stderr lines. For `x509`,
the first is `unable to load certificate`; for `pkey`, it is
`unable to load key`. The second is a decimal thread identifier followed by
`:error:09FFF06C:PEM routines:CRYPTO_internal:no start line:`, the fixed
Apple LibreSSL build-path suffix
`/Sources/libressl/libressl-3.3/crypto/pem/pem_lib.c:694:Expecting:`, and
respectively `TRUSTED CERTIFICATE` or `ANY PRIVATE KEY`, then one newline.
The target 3.0.13 observation additionally admits exactly two command-kind
specific malformed tuples. For the fixed certificate metadata command, exit
1, empty stdout and stderr exactly
`Could not read certificate from /dev/stdin\nUnable to load certificate\n`
produce the existing `certificate_malformed` with null metadata and dependent
handling. For the fixed private-key-to-public-DER command, exit 1, empty
stdout and stderr exactly `Could not read key from /dev/stdin\n` produce the
existing `key_malformed`. Neither tuple admits the other command kind. Later
public-PEM, DER and text malformed outputs remain native-only qualification
controls and incomplete at their current call sites. No generic nonzero
failure is admitted.
The admitted fixture-proven chain failure is exit 2, empty stderr, and exactly
three stdout lines: `CN = <token>`,
`error 20 at 0 depth lookup:unable to get local issuer certificate`, and
`/dev/stdin: verification failed: 20 (unable to get local issuer certificate)`.
`<token>` matches `[A-Za-z0-9.-]+`; the final path must be the actual fixed
certificate operand. The additional fixture-proven expiry failure for all
four P0s chain checks has exit 2, empty stderr, and stdout exactly three
repetitions of `CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup:certificate has expired\n`,
then `CN = <DNS token>\nerror 10 at 0 depth lookup:certificate has expired\n`,
then `/dev/stdin: verification failed: 10 (certificate has expired)\n`.
The fixture-proven not-yet-valid server failure has exit 2, empty stderr,
and stdout exactly
`CN = <DNS token>\nerror 9 at 0 depth lookup:certificate is not yet valid\n/dev/stdin: verification failed: 9 (certificate is not yet valid)\n`.
The earlier compact OpenSSL-3-shaped failure remains: exit 2, empty
stdout, and stderr exactly
`CN=<DNS token>\nerror <code> at 0 depth lookup: <reason>\nerror /dev/stdin: verification failed\n`,
with its existing code/reason pairs `(20, unable to get local issuer certificate)`
and `(62, hostname mismatch)`. The latter requires `sslserver` with a nonempty
fixed hostname. The target 3.0.13 observation adds one exact three-line
envelope: exit 2, empty stdout, and stderr
`CN = <subject>\nerror <code> at <depth> depth lookup: <reason>\nerror /dev/stdin: verification failed\n`.
The six alternatives couple every field: code 20/depth 0/`unable to get local
issuer certificate`, code 10/depth 0/`certificate has expired`, and code
9/depth 0/`certificate is not yet valid` use a `[A-Za-z0-9.-]+` subject under
either `sslclient` or `sslserver`; code 10/depth 1/`certificate has expired`
uses exactly `Remote Alpha Internal Runtime Root CA` under either purpose;
code 26/depth 0/`unsuitable certificate purpose` uses a bounded subject under
`sslclient` only; code 62/depth 0/`hostname mismatch` uses a bounded subject
under `sslserver` with its nonempty fixed hostname only. Every admitted
negative tuple returns the existing completed `chain_failed`, even if a
separate certificate validity check already failed. The final operand is
always `/dev/stdin`. Each admitted response is a whole tuple. Code, depth, reason, subject and
context are not independent options. No cross-product, arbitrary RDN, CR/NUL, missing final
LF, changed operand, extra/reordered/repeated error block, warning, mixed
stream or unknown exit is admitted. These narrow grammars are bounded
responses, not a claim that all OpenSSL or LibreSSL versions emit them. An
unknown stack variant, code/depth, signal exit, truncated output, setup
failure or runtime grammar drift is incomplete and publishes no generation.
Raw child output never enters evidence.

The common collector contract is
`execution-substrate.remote-alpha.es-tls-status-collector/v1`. Each completed
record contains its exact scope schema, route, 32-character lowercase-hex
random generation, UTC `checked_at`, `finalized=true`, exact fixed role and
topology records, typed blocker codes, consistent `result.status`/`ok`,
explicit false flags for renewal, backup, material generation/installation,
service restart, and post-renewal probe, and disclosure flags. Completed
`pass` and completed typed `fail` are both accepted observations. Topology
mismatch, missing or malformed fixed config, missing/malformed/expired/not-yet
valid cert, missing key, key mismatch, chain failure, or P0t AGS exclusion
may be completed failure evidence. No raw stdout/stderr, raw config, private
key or key digest, environment value, arbitrary path or command, renewal
backup, or rollback field is allowed. Fixed public certificate paths are
allowed only as frozen scope labels.

The v1 completed-record code vocabulary is closed: topology checks use
`pass`, `absent`, `config_missing`, `config_malformed`,
`topology_mismatch`, `topology_overlap`, `related_config_malformed`, or
`ags_scope_present` according to the fixed check ID; certificate roles use
`pass`, `certificate_missing`, `certificate_malformed`,
`trust_anchor_count_mismatch` only for CA roles, `certificate_expired`,
`certificate_not_yet_valid`, `san_missing`, `san_mismatch`, `eku_missing`, or
`eku_mismatch`; key pairs use `pass`, `certificate_unavailable`,
`key_missing`, `key_malformed`, or `key_mismatch`; and chain
checks use `pass`, `certificate_unavailable`, or `chain_failed`. The reader
requires each record's `status` and code to agree, exact check IDs and
cardinalities, typed public metadata, and blocker set equality. Unsafe or
unprovable config, certificate, and key reads are incomplete observations;
they emit no completed unreadable code.

`Bounded slice rule` semantic table for collector self-validation and reader
acceptance (the certificate record has no `exists` field):

| Record | Required semantic relationship |
| --- | --- |
| Topology | The exact scope-specific ordered check IDs and code sets apply. A required-config check uses only `pass`, `config_missing`, or `config_malformed`. The one optional related-config check uses only `status=pass, code=pass`, `status=pass, code=absent`, or `status=fail, code=related_config_malformed`. A binding or URL check uses only `pass` or `topology_mismatch`. An affected disjointness or exclusion check uses `config_missing` if a required input is missing, or `related_config_malformed` if an input is safely present but malformed; it cannot pass in either case. When all inputs are valid or explicitly safe absent, that check uses its fixed overlap/exclusion code or `pass`. |
| Certificate | Each fixed label binds exactly one scope, public path, and CA/server/client role. `certificate_missing` and `certificate_malformed` have `status=fail` and null date, digest, and SAN/EKU metadata. A CA-only `trust_anchor_count_mismatch` has the same null metadata and means the observed CA bytes did not contain exactly one isolated PEM certificate. Every securely parsed certificate has valid UTC `not_before` and `not_after`, `not_before <= not_after`, all five 64-character SHA-256 fields, and boolean validity flags. One captured UTC `checked_at` governs every role: `expired` is exactly `checked_at > not_after` and `not_yet_valid` is exactly `checked_at < not_before`; equality at either boundary is valid. CA SAN/EKU flags are null; client SAN is null; server SAN and server/client EKU are boolean when present and null only for the respective missing extension. `pass` requires both validity flags false and all applicable role flags true. Failure codes follow validity, then server SAN, then server/client EKU precedence and agree with the reported flags. |
| Key pair | A label binds its one fixed certificate/key relationship. `certificate_unavailable` is possible only when that certificate has no parsed public key hash. Otherwise the fixed key outcome determines `key_missing`, `key_malformed`, `key_mismatch`, or `pass`; `matches` is true exactly for `pass`. |
| Verification | A label binds its one fixed CA, leaf, purpose, and server hostname or empty client hostname. `certificate_unavailable` is possible only when the CA or leaf has no parsed certificate hash. Otherwise only admitted whole-response OpenSSL output determines `chain_failed` or `pass`. |
| Aggregate | Every nested record has its exact field set and no unknown field. Each code belongs to its check type and scope, with `pass` iff its status passes. `blockers` is exactly the sorted distinct set of failed record codes. Overall `pass`/`ok=true` requires every child pass; overall `fail`/`ok=false` requires a failed child and its exact blockers. The collector uses this same validator before publication; any contradiction is incomplete and publishes nothing. |

The evidence commit rule is post-cleanup canonical publication. Before it,
all stage cleanup, status work, OpenSSL reaping, encoding and one-MiB check,
exclusive no-follow temporary write/fsync, temporary mode/identity validation,
and existing-target validation finish. HUP/INT/QUIT/TERM handlers only latch
the first signal; they do no I/O or asynchronous raise. The collector blocks
them and checks both latch and pending set before replacement. A pre-boundary
signal removes only the proven invocation temporary and publishes no new
generation. Once exclusive temporary creation succeeds, one cleanup owner
covers the first `fstat`, mode changes/checks, writes, file fsync, size and
identity checks, existing-target validation, signal closeout, and replacement.
On a pre-replacement failure it closes the temporary descriptor and unlinks
only after revalidating that entry as its own invocation temporary. If this
identity cannot be proved, bounded protected diagnostic residue remains and
the prior canonical generation is unchanged. Successful `os.replace` through
the verified directory is the
last evidence operation; `os._exit(0)` follows immediately, without required
cleanup, callback, directory fsync, post-verify, or machine output. Thus the
record is atomically visible but has no crash-durability claim. After reboot
or uncertain persistence, run a fresh observation. Exit zero means a record
was published, not that TLS passed; facade/transport acknowledgment is a
separate fact.

A reader accepts only via descriptor-first ancestry and canonical-file
checks: exact owner/mode/type/link/ACL, size bound, a complete read equal to the
pre-read file size, stable descriptor metadata and entry identity after the
read, strict JSON decoding that rejects duplicate keys, non-finite
constants, and parsed non-finite numeric values, exact schema and collector
id, `finalized=true`, expected scope and route, 32-character lowercase-hex
generation different from the pre-run snapshot, UTC `checked_at` at most five
minutes old and no more than thirty seconds future, exact fields, role labels,
cardinalities and enum values, consistent result/non-effect flags, and no
unknown fields. Completed `fail` is accepted failure evidence. An unchanged
old generation cannot satisfy a new attempt. The pre-run generation snapshot
uses the same complete-read and stable-file checks before it can be used for
comparison. Route exit plus file presence is
insufficient. No monitor or scheduler consumes this record in this tranche.
Publication existing-target checks, `check_existing`, the pre-run generation
snapshot, and `read_accepted_status` share one canonical-summary regular-leaf
primitive. After no-follow protected ancestry verification it inspects the
final entry without following it, rejecting FIFO, socket, directory, device,
symlink, hard-link anomaly, or unsafe owner/mode/link count before read-open.
Only an observed regular leaf opens with
`O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`. Immediate `fstat` must match the
pre-open identity and governed metadata. Reads use only that descriptor under
the one-MiB bound, require complete stable bytes, and recheck descriptor and
pathname identity afterward. A regular-to-FIFO, symlink, or different-regular
swaps cannot block or pass. Only a safely absent leaf uses the exact governed
absent behavior. An incomplete check or snapshot publishes no new generation;
reader rejection is bounded.

Old `/var/tmp/execution-substrate-remote-alpha/*tls*summary*.json`, old
`*-renew-summary.json`, blocked-candidate summaries, and renewal backups are
historical only: no migration, copy, deletion, overwrite, symlink, fallback,
current status, or renewal/rollback authority. Status validation is static
and fake only. No live SSH, sudo, host config/certificate/key read, service,
Docker, Nomad, IM, CP, P0t package, or host-preparation effect belongs here.

### P0t First-Rejection OpenSSL Grammar Diagnostic

`Bounded slice rule` inside the P0s/P0t reopened seam: the fixed
`recovery-session es-governance-tls-grammar-diagnostic` nonpublishing route is separate from
the two status routes above. It is execution-governance only and records a
newly observed first rejection at one of the existing ten direct
`unexpected_openssl_grammar` guards. It does not reconstruct the consumed
attempt, publish P0t status, prove TLS health/readiness, or grant renewal or
service restoration. Retire or explicitly re-justify this route after the
installed-response issue is resolved and required status observation can
complete. The facade remains a Temporary compatibility edge.

The diagnostic route has only the existing validated `--ssh-target` and
visible `--interactive-tty` live operands, plus contact-free `--verify-only`.
Verify-only checks its single fixed local collector source and worst-case
source-controlled command/custody construction with zero transport, sudo,
native OpenSSL or host-material dispatch. Live use retains real terminal stdin
and visible foreground sudo; no cached sudo/NOPASSWD requirement, password
relay, TTY capture, weakened SSH policy or arbitrary scope/path/argv/entrypoint
is introduced. At most one stage SSH, one source SCP and one interactive SSH
are dispatched; the fixed command stays at most 32768 bytes. The exact
`/tmp/.es-tls-status-[0-9a-f]{32}` one-file stage, measured device/inode,
source digest, no-follow type-first checks and identity-safe root-only disposal
remain in force. An unproved or substituted stage is retained as residue, not
executed or broadly cleaned. Root loads only verified bytes already in memory
under a distinct diagnostic marker and non-`__main__` synthetic module name;
the old status marker and `ES_TLS_STATUS_FAILURE_V1` emitter are not installed
for this branch. A source/custody/load uncertainty has no detailed result.

The diagnostic parent calls only `open_status_dir`, new
`open_existing_scope_lock`, `validate_process_capability`, the production
`preexisting_generation` reader, then `diagnose_first_rejection` if the fresh
snapshot is `ABSENT`. The new lock adapter requires an initially no-follow
root:root regular single-link `0600` size-zero existing lock, opens only its
fixed name through the verified status descriptor with
`O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, checks governed extended access
and full descriptor/path identity before and after `flock(LOCK_EX|LOCK_NB)`,
and never creates, truncates, writes, chmods, chowns, fsyncs, unlinks or
explicitly unlocks it. A missing/unsafe/replaced/held/unproved lock fails
before material work; flock error does not prove contention. Ownership starts
as soon as open succeeds. Every acquired descriptor gets at most one explicit
close attempt; a failed lock close remains sticky while the independently
owned status descriptor is still closed. Child/member/selected-anchor/input
obligations settle before lock release, including existing unresolved owner
holds; no blanket timeout or double-close rescue is added. The prior reader
may read present canonical evidence to refuse it; no canonical, lock or
summary namespace change is made by the diagnostic.
The shared protected-summary reader's one canonical-leaf close attempt marks
disposition unproved and re-raises the same close failure, including
`FileNotFoundError` and interruptions. This is the sole explicit exception to
the original 53-function freeze: its close bookkeeping changes, while the
other 52 original functions remain exact. A successful close never clears an
earlier unproved marker. A settled prior read/metadata failure with successful
close retains its existing `incomplete_other` path after independent lock and
status closeout; the diagnostic does not blanket-suppress prior-reader errors.

The finite traversal reuses `collect_topology` (all four fixed config paths),
then four cert roles, two key-pair roles and two verify roles in existing
execution-governance order. It keeps the exact fixed input snapshots,
OpenSSL argv/environment, selected CA, strict parser predicates, typed
missing/malformed/dependency results and one behavior-based capability child.
Only optional invocation-local context at `cert_metadata`, `cert_role`,
`key_pair` and `verify_chain` observes a returned native tuple after an
unchanged direct guard rejects. At most eighteen attempted fixed calls are
counted, including a pre-spawn attempt and excluding capability children;
first rejection stops later native calls. The all-success graph never reaches
status `collect`, generation, `main`, `encode_document`, `publish`, summary
temp, canonical replacement or publisher `os._exit(0)`. The unchanged
capability child's `os._exit(child_code)` remains required.

After proved source/stage and all child, input, lock and status closeout, root
alone may write one strict ASCII terminal line of at most 2048 bytes including
LF, prefixed `ES_TLS_GRAMMAR_DIAGNOSTIC_V2 `. The closed body includes source
digest, fixed scope, one of `first_grammar_rejection`,
`no_grammar_rejection_reached`, `incomplete_other`, 0–18 attempted fixed-call
count and a coupled first-rejection shape only for that outcome. Its ten site
IDs, seven operation IDs, role/predicate coupling, stream byte/line/UTF-8/LF/
CR/NUL flags, closed exit class and closed verify token are checked with
standard-library code. Recognized verify lines are counted in each original
native stream, requiring exactly one complete LF-terminated occurrence;
cross-stream fragments, repeated identical lines and multiple recognized
lines yield `other`. The formatter rejects impossible LF/non-LF byte
capacity. A specific token must fit one of its two admitted ASCII literal
lengths including LF in one original stream after all other LF bytes are
charged. Any unterminated tail is nonempty, and distinct CR, NUL and invalid
UTF-8 evidence occupies non-LF bytes outside that literal. A sole complete
line without a tail has exactly an admitted literal length and no nonliteral
flag or residual byte. These necessary checks do not reconstruct or
authenticate native bytes from counts.
For `verify_success_stderr_nonempty`, the private formatter requires the full
shape of exact ASCII stdout `/dev/stdin: OK` plus LF: 15 bytes, one line,
nonempty, valid UTF-8, final LF, no CR and no NUL. It does not impose that
shape on `verify_success_stdout_not_exact`, because different bytes can have
identical shape. Private `schema_version` and `scope` have exact string types
before literal comparison; equality-overloaded subclasses are refused.
JSON Schema annotations alone do not enforce these relations. Raw native stdout/stderr, PEM/DER, key/config contents and digests,
subjects/SANs/serials/fingerprints, paths/PIDs, provider text and exceptions
never enter the advisory. Unknown/context-invalid observations map only to a
closed `other` token or refusal, never new parser acceptance. No terminal
retry, tee, file fallback or inherited stream-mode change is allowed. A
completed diagnostic exit acknowledges only diagnostic completion; an
incomplete/transport failure leaves remote phase uncertain. Neither line nor
exit is a protected record, status acceptance, live identity proof, retry
permission, or restoration authority.

The current private diagnostic identity is
`es-p0t-openssl-grammar-diagnostic/v2` for every outcome and first-rejection
site. Its v1 schema and consumed v1 observation remain historical. Only a
first `VERIFY_FAILURE_ENVELOPE_UNADMITTED` receives `verify_projection` from
the already returned tuple. The fixed argv, selected anchor, status parser,
traversal, ownership, closeout and single terminal writer are unchanged.
Each original stream is split only at LF. Its complete lines retain order and
repetitions as `known` (closed code/depth/reason in context),
`context_invalid_unclassified` (no code/reason disclosed),
`unknown_numeric` (canonical code 1–999 and depth 0–9 only), `unclassified`
error-like, exact `terminal`, or `opaque` (including subject-like lines).
Unknown-numeric framing requires a 1–128-byte printable ASCII reason, which
is never emitted. An unterminated tail is separately `error_like_unclassified`
or `opaque`. Both streams retain all six kind counts, complete-line counts,
tail kinds, `known_count` and `recognized_literal_count`. Up to eight complete
lines globally retain both full sequences; above eight both sequences are
empty with explicit cap and incompleteness flags while counts still cover all
bounded bytes. Exact type/field, legacy token and predicate, count/shape,
classified-byte range and nonliteral CR/NUL/invalid-UTF-8 capacity checks
refuse contradictions. A specific legacy token requires one recognized,
context-valid literal; a single context-invalid literal takes the existing
context predicate only when the higher-priority exit and placement predicates
do not apply. Capped counts support only derivable relationships. The
2048-byte single-line bound refuses overlong v2 output without truncation or
v1 fallback. Structural consistency does not authenticate native text or
identify the prior five-line failure.
For exit two with both original streams nonempty, one context-invalid literal
cannot form an admissible advisory: placement retains priority, the unchanged
producer's specific wrong-context token fails the existing formatter, and a
substituted `other` token also fails even above the eight-line sequence cap.
Counts preserve this contradiction when ordered sequences are absent. No
native-response alternative or source-side predicate changes.

### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session

`Bounded slice rule`: P0u implements exactly one bounded Remote Alpha
host-local operator healthcheck client TLS helper pair and exactly two
Mac-side recovery-session routes:

- `scripts/remote_alpha_operator.sh recovery-session
  operator-healthcheck-tls-status --ssh-target <target> --interactive-tty`
- `scripts/remote_alpha_operator.sh recovery-session
  operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty
  --execute-renew`

P0u validation is static and fake SSH/SCP only. It does not run live SSH, sudo,
live OpenSSL against the remote host, Vault, reset, unseal, workload-auth
bootstrap/check, runtime identity summary, Infrastructure Manager refresh,
support-bundle collection, CP proof, SPIRE or Nomad mutation, ES binary
deployment, ES service restart, or network-dependent integration tests. The
route is separate from IM, CP, Vault, SPIRE, Nomad, workload-auth, reset,
unseal, runtime identity, ES service TLS renewal, ES governance TLS renewal,
and general deployment.

Covered topology and fixed paths:

- `/etc/execution-substrate/tls/operator-client-cert.pem`
- `/etc/execution-substrate/tls/operator-client-key.pem`
- `/etc/execution-substrate/tls/combined-service-ca-bundle.pem` only as the
  configured healthcheck server CA bundle for safe mTLS probes
- ES config only to identify the ES server client CA used for operator-client
  certificate verification

Identity rule:

- The current ES authorization allowlist accepts the repo-owned operator path
  `spiffe://execution.internal/operator/local`.
- The previously observed `spiffe://execution.internal/operator` SAN is a
  legacy mismatch for current authorization semantics and must be reported as
  needing renewal.
- Any future renewed operator healthcheck client certificates use subject
  `CN=client.operator` and SAN
  `URI:spiffe://execution.internal/operator/local`.

Status behavior:

- `operator-healthcheck-tls-status` is non-mutating.
- It reports public certificate fields only: subject, issuer, SAN, EKU,
  notBefore, notAfter, expired/not-yet-valid status, file SHA-256, public
  fingerprint, and public-key fingerprint.
- It confirms operator cert/key public-key match without printing private keys.
- It verifies the operator certificate against the ES server client CA bundle
  when that topology is configured.
- It may probe `/health` and `/v1/executions:contract` only with the configured
  healthcheck env and only when the URLs are safe non-mutating local HTTPS
  targets. Probe response bodies are not recorded.

Renew behavior:

- `operator-healthcheck-tls-renew` requires explicit `--execute-renew`.
- Both status and renew require visible `--interactive-tty` and
  `--ssh-target <target>`.
- The Mac-side facade stages only
  `scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and
  `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`.
- The remote command invokes only `--status` or `--execute-renew` through
  `ssh -tt`; it passes no helper override flags.
- Current renewal is design-blocked because no authoritative Remote Alpha CA
  custody/signing topology exists for this host-local operator client
  identity.
- The helper must not assume a retained remote CA private key such as
  `/etc/execution-substrate/tls/runtime-ca-key.pem` and must not accept ad hoc
  signing material.
- It fails closed with `unsupported_signing_topology` before backup, install,
  service restart, or post-renew probes.
- It records explicit next-step text requiring a future documented CA
  custody/signing design.
- It does not restart ES; client certificate renewal is recorded as not
  requiring service restart in this bounded route.

Summary/evidence behavior:

- The canonical summary remains remote at
  `/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`.
- The schema is
  `execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1`.
- The summary is evidence/projection only, never authority and not an IM input.
- The operator facade must not print full summary JSON and must not copy the
  summary back to Mac `.out`.
- Allowed summary fields include paths, byte counts, public certificate
  metadata, certificate file SHA-256, public fingerprints, validity windows,
  identity classification, key-public-digest match status, verification
  statuses, unsupported-signing-topology failure classification, next-step
  text, not-run backup/install/probe metadata, and explicit non-claims.
- Forbidden summary/output content includes private key PEM bodies, full
  certificate PEM bodies, private-key backup digests, Vault tokens, root
  tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, passwords,
  proof secrets, terminal transcripts, support-bundle content, raw retained
  bundles, raw workspace contents, and raw secret-bearing command output.

Allowed flags for P0u are:

- `--help`
- `--ssh-target <target>`
- `--interactive-tty`
- `--execute-renew` only for `operator-healthcheck-tls-renew`

P0u must reject:

- `--host-local`
- `--dry-run`
- `--check-only`
- `--status`
- `--scope`
- `--apply`
- `--execute-reset`
- `--unseal-only`
- `--post-unseal-check`
- `--execute-bootstrap`
- `--prepare-summary-path`
- `--prepare-config-readability`
- `--prepare-spire-bundle-read`
- `--interactive-sudo`
- `--governed-smoke-command`
- helper override flags
- output or summary path overrides
- TLS/config/path overrides
- arbitrary commands
- unknown flags
- duplicate flags
- extra positional arguments
- equals-form options
- secret-like arguments, including private keys, root tokens, unseal keys,
  client tokens, Vault tokens, JWT-SVID payloads, API keys, passwords, proof
  secrets, and secret payloads

P0u tests:

- status detects an expired operator certificate
- status detects a valid operator certificate
- status detects the legacy `spiffe://execution.internal/operator` URI mismatch
- renew mode refuses without `--execute-renew`
- renew/status modes refuse without `--interactive-tty` and `--ssh-target`
- secret-like arguments fail before staging
- fake SSH/SCP tests prove exactly the fixed public/internal operator
  healthcheck TLS helper pair is staged
- fake renew tests prove private key PEM bodies are not printed or persisted to
  summaries
- fake renew tests prove `unsupported_signing_topology` before backup,
  install, service restart, or post-renew probes
- fake/static renew tests prove no retained remote CA private key is required
- docs tests preserve non-authority, non-production, non-IM, and non-CP claims
- existing P0s/P0t service and governance TLS tests remain passing

Stop conditions for P0u:

- the needed operator identity would not be
  `spiffe://execution.internal/operator/local`
- staging the route requires more files than the fixed helper pair
- helper override flags are accepted
- private keys or full certificate PEM bodies are printed or copied into
  summaries, reports, `.out`, support bundles, retained bundles, raw workspace
  output, or Codex output
- the route touches Vault, SPIRE, Nomad, workload-auth, runtime identity,
  reset/unseal, IM refresh/support-bundle collection, CP proof, ES service
  restart, or generic deployment/provisioning/reconciliation
- generated artifacts appear outside the documented remote summary/backup path
  or test temp fixtures

P0u remains bounded ES Remote Alpha proof/support workflow glue only. It is not
generic TLS deployment, not Infrastructure Manager reconciliation, not Control
Plane authority, not Vault/SPIRE/Nomad authority, not workload-auth or runtime
identity authority, not production readiness, and not Remote Alpha production,
deployment, provisioning, or reconciliation architecture.

### External TLS Single-Use Incident Authorization

`Bounded slice rule`: ES records one documentation-only incident authority in
`.docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md`.
Report-derived certificate-validity failures are an incident input, not live
repository truth; read-only inventory must establish the prior state before
effect. The authority covers one proof/support host, incident, execution, and
fresh role-separated external family. It is separate from internal service and
governance TLS, adds no operator route, and leaves reusable P0u renewal blocked
with `unsupported_signing_topology`.

Remote Alpha remains bounded proof/support infrastructure. ES acceptance
precedes any separately governed IM projection, and neither IM nor MA gains
recovery authority. Terminal closure must remove or convert this active
authorization and its tests and remove the four P0u cross-references.

### P0v Operator Healthcheck TLS Noninteractive Status Implementation

`Bounded slice rule`: P0v implements the ES-owned read-only operator
healthcheck TLS noninteractive status route:

```text
scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json
```

The authoritative route contract is
`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`.

P0v chooses a new route id, `operator-healthcheck-tls-status-noninteractive`,
instead of adding a mode flag to the current interactive
`operator-healthcheck-tls-status` route. The existing interactive route remains
the current implemented foreground operator route with required
`--interactive-tty`, local stdin/stdout TTY preflight, `ssh -tt`, visible
sudo/password prompt behavior, fixed helper-pair staging, and remote summary
retention. P0v does not change P0u behavior or MA route metadata.

The implemented route contract requires:

- no local stdin/stdout TTY requirement
- no pseudo-TTY creation
- no prompt-capable SSH or sudo path
- fixed Bash facade argument parsing and contact-free local prerequisite checks
- a dedicated checked-in local Python runtime as the sole final JSON emitter
- a fixed checked-in remote Python collector streamed over SSH stdin
- no Bash JSON assembly and no fallback emitter
- fail-closed behavior when noninteractive auth is not already ready
- no password storage or replay
- no certificate, key, trust bundle, profile, env, support-bundle,
  retained-bundle, proof artifact, SQLite state, or remote-state mutation
- no remote helper staging and no remote summary mutation
- JSON-only bounded status evidence using schema
  `execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`
- internal remote protocol
  `execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1`
- no raw stdout/stderr transcripts, helper transcripts, SSH transcripts, PEM
  bodies, private keys, env values, endpoint secrets, remote paths, raw logs,
  TLS/SPIFFE/Vault material, connector/workspace/org IDs, raw payloads,
  support-bundle content, retained-bundle content, or unsafe local paths
- evidence/projection-only semantics for CP, IM, MA, Bridge, and Coordinator
  consumers

No fallback emitters are allowed. ES machine-readable route JSON is promised
only after declared route prerequisites pass. Missing local runtime, local
`ssh`, fixed runtime source, or fixed collector source is a contact-free exit
`2` refusal, not ES route-output fallback. The Bash facade performs no SSH,
SCP, sudo, staging, cleanup, or summary behavior for P0v.

Failure classes include `noninteractive_auth_required`,
`ssh_batch_mode_failed`, `remote_status_unavailable`,
`cert_metadata_expired`, `cert_metadata_not_yet_valid`,
`trust_chain_unavailable`, `trust_chain_failed`, `identity_mismatch`,
`key_pair_mismatch`, `unexpected_output_shape`, `forbidden_output_material`,
and `remote_status_failed`.

P0v status evidence remains non-authoritative. CP consumes nothing in this
tranche; IM consumes nothing in this tranche; MA consumes, invokes, and
schedules nothing in this tranche; Bridge invokes and synthesizes nothing in
this tranche; Coordinator consumes nothing in this tranche.
Bridge/MA/CP/IM/Coordinator must not wrap missing ES prerequisites into ES
status truth. Route metadata records `requires_interactive_tty=false`,
`supports_noninteractive=true`, `current_status=implemented`, and
`scheduled_execution_allowed=false`. CP diagnose rerun and IM profile-lineage
refresh remain future owning-repo tranches.

Stop conditions for P0v:

- the route would require a local TTY, pseudo-TTY, SSH prompt, sudo prompt, or
  password storage/replay
- the route would need fallback JSON assembly because local runtime, schema, or
  redaction prerequisites are unavailable
- the route would stage helpers, mutate a remote summary, or mutate certificate,
  key, trust, profile, env, support, retained, proof, SQLite, or remote state
- bounded JSON redaction cannot be guaranteed
- forbidden output material or unsafe path/token/env/cert/log content could be
  emitted or retained
- the route would be treated as renewal, CP run-control truth, ES runtime
  truth, IM authority, MA authority, Bridge authority, production readiness,
  live proof, operational acceptance, or infrastructure reconciliation truth

### Remote Alpha Maintenance Monitor Boundary

This section is documentation/contract alignment only. It does not implement a
monitor, create a new project, add a scheduler, invoke helpers, run proof, or
renew anything.

`Bounded slice rule`: a future Mac-side Remote Alpha maintenance project may
exist only as scheduler, notifier, local-evidence summarizer, and allowlisted
invoker of ES-owned commands. ES remains the owner of all Remote Alpha status,
renewal, repair, helper routing, topology validation, mutation semantics, and
route contracts.

External schedulers may invoke documented allowlisted ES commands, but they may
not define command semantics, infer route eligibility from implementation
details, bypass ES topology checks, construct helper paths from user input,
pass secrets through args/env/logs/notifications, or become ES runtime
authority, IM readiness/provenance authority, CP run-control authority, a
hidden remote reconciler, or broad provisioning automation.

Remote Alpha remains bounded proof/support posture only. Maintenance summaries,
helper summaries, support bundles, proof summaries, IM readiness reports, and
CP warnings are evidence/projection/diagnostics. They are not production
readiness, deployment authority, lifecycle truth, renewal authority, or run
authority.

Maintenance route eligibility:

| Route | Read-only monitor | Operator-approved renewal now | Future automatic renewal | Boundary |
| --- | --- | --- | --- | --- |
| `es-service-tls-status` | future candidate; no current monitor | not a renewal route | not a renewal route | non-mutating ES-owned status over ARS/AGS/ES artifact-registry TLS; fresh reader acceptance required |
| `es-service-tls-renew` | held | held | held | no supported renewal dispatch or monitor authority |
| `es-governance-tls-status` | future candidate; no current monitor | not a renewal route | not a renewal route | non-mutating ES-owned status over ES -> EGS execution-governance TLS; fresh reader acceptance required |
| `es-governance-tls-renew` | held | held | held | no supported renewal dispatch or monitor authority |
| `operator-healthcheck-tls-status` | eligible | not a renewal route | not a renewal route | non-mutating status over the host-local operator client certificate |
| `operator-healthcheck-tls-renew` | blocked/status-only | not eligible | blocked | missing authoritative CA custody/signing topology; future identity must be `spiffe://execution.internal/operator/local` |
| binary deployment check | eligible | not a renewal route | not eligible | check-only deployment evidence; no monitor-driven apply |
| binary deployment apply | evidence may be summarized after an operator-run helper | not eligible through a monitor | not eligible | deployment/provisioning-like mutation, not maintenance renewal |
| workload-auth check | eligible | not a renewal route | not eligible | evidence/projection only |
| workload-auth bootstrap | evidence may be summarized after an operator-run helper | not eligible through a monitor | not eligible | authority-bearing Vault/bootstrap surface, not renewal |
| runtime identity summary | eligible | not a renewal route | not eligible | monitorable evidence only; not runtime identity authority |

Automatic renewal eligibility requires all of the following before a route can
be marked eligible: route-specific docs, route-specific tests, audit evidence,
idempotence, backup-before-replace, post-renew verification, fail-closed
topology and capability behavior, explicit no-secret monitor-controlled
surfaces, explicit notification/audit records, and an ES-owned helper that
defines the full mutation semantics. No route may become auto-renew eligible by
inference from an existing helper.

Stop conditions for the future monitor:

- any doc or implementation implies the monitor owns ES renewal semantics
- any route becomes auto-renew eligible without route-specific docs, tests, and
  audit gates
- any renewal requires secrets in monitor-controlled args, env, logs, evidence,
  or notifications
- any scheduler behavior becomes a hidden remote reconciliation loop
- binary deployment apply, workload-auth bootstrap, CP proof, IM refresh, or
  support-bundle collection is treated as renewal authority
- operator healthcheck renewal proceeds before CA custody/signing topology is
  documented

### P0d Interactive Validation Evidence

The P0d interactive validation artifact directory
`.out/remote-alpha-m75q-p0d-alpha-compat-interactive-20260524T033740Z` is
operator-workstation-to-remote interactive-sudo validation evidence only. It is
generated output, not tracked source, not design authority, and not an ES, CP,
or IM authority surface.

The reported run validated the P0d operator route handoff to the staged
writable-state readiness helper, remote temporary staging, checker execution,
readiness and staging-record artifact schemas, transient-staging cleanup
evidence, and the secret-like redaction scan. The readiness record used schema
`execution-substrate.remote-alpha.es-writable-state-readiness.v1`,
`operation_mode=check_only`, `non_mutating=true`,
`checker_mode=alpha-compat`, `overall_classification=warning`,
`blockers_count=0`, and `warnings_count=2`. The staging record used schema
`execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`,
`sudo_mode=interactive`, `staging_occurred=true`, `checker_ran=true`,
`sudo_unavailable=false`, `wrapper_exit_code=0`, `checker_exit_code=0`,
`transient_staging_removed=true`, and
`staging_retained_for_diagnostics=false`.

The evidence did not validate the default noninteractive `sudo -n` path. It
did not prove governed execution, CP orchestration, production readiness, Vault
workload authentication, IM authority, submit readiness, runtime-profile
readiness, retained-result readiness, or Remote Alpha deployment architecture.

Digest summary for the untracked evidence files:

- `es-writable-state-readiness.json`: sha256
  `ab52a79b478877368dd4613430c1eaf30498f9f25363912d5593fbae67ec718e`,
  290018 bytes.
- `es-writable-state-readiness-helper-staging-record.json`: sha256
  `dac32b552d6da8b39411839099a3f704e6d70890da147caf2bccbad10a4c59e7`,
  5245 bytes.

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

The repo-supported generator for that host-local summary is
`scripts/remote_alpha_runtime_identity_helper_summary.sh`. Operators run the
generator on the Remote Alpha host, normally with `sudo`, so it can exercise
the helper-local SPIRE fetch smoke as root while still recording only
non-secret status. The generator writes
`execution-substrate.remote-runtime-identity-helper-summary.v1alpha1` JSON to
`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`
by default and must keep the summary readable by Infrastructure Manager live
refresh. It records the installed `/usr/local/bin/es-runtime-support` metadata,
SPIRE server/agent health, the Alpha-only
`spiffe://execution.internal/workload` registration, helper-local fetch status
without JWT-SVID bodies, raw SPIRE socket non-exposure checks for `ds` and UID
`10000`, Docker/Nomad status, non-authority labels, and explicit redaction
markers.

The generator is a Remote Alpha evidence generator only. It is not governed
execution proof, not CP run-control authority, not ES submit authority, not
runtime-profile readiness, not Vault readiness, not production posture, and not
a replacement for the Milestone 3 proof. `--dry-run`/`--check-only` mode must
skip the SPIRE JWT fetch smoke, write nothing, and print only non-secret
diagnostic JSON.

## Remote Normal-Shell Runtime Image Slice

Remote Supported-Host Alpha may also record a separate host-local normal-shell
runtime image slice before any ES services are installed or started.

That slice is intentionally limited to verifying:

- the current repo-derived runtime image reference for
  `control-plane-normal-shell/v1` is present in the host Docker daemon
- host Docker service activity plus successful `docker info`
- host Nomad still reports at least one ready node after the image is loaded
- a bounded minimal container smoke on the existing image proves Python, git,
  and the configured Codex CLI path inside that image
- the current no-real-credential Codex realization posture for this slice can
  be proved from the bounded recipe evidence plus the bounded container smoke
- non-secret host evidence summaries

This slice does not prove ES service health, runtime-profile readiness, submit
readiness, producer-contract compatibility, retained-result readiness, or live
run compatibility for a Control Plane consumer.

The current repo-derived values for this slice are:

- image ref `execution-substrate/control-plane-normal-shell:supported-local`
- repo-owned build recipe `scripts/remote_alpha_build_normal_shell_runtime_image.sh`
- current configured Codex CLI path `/usr/local/bin/codex`
- current no-real-credential realization `proof`

The repo-owned build recipe for this slice is:

- `sudo scripts/remote_alpha_build_normal_shell_runtime_image.sh`

That wrapper pins the current Remote Alpha recipe and invokes
`scripts/build_control_plane_normal_shell_image.sh` with the explicit repo-owned
values:

- `CONTROL_PLANE_NORMAL_SHELL_IMAGE=execution-substrate/control-plane-normal-shell:supported-local`
- repo-owned Dockerfile `es/runtimeprofiles/control_plane_normal_shell/Dockerfile`
  resolved under the current repo root
- `CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH=/usr/local/bin/codex`
- `CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION=proof`

Conflicting caller overrides for those recipe-defining variables are not part
of this slice. The wrapper must fail fast instead of silently honoring a
different image ref, Dockerfile, Codex CLI path, or Codex realization.

The repo-owned host-local check path for this slice is:

- `sudo scripts/remote_alpha_normal_shell_runtime_image_check.sh`

That command is a host-local check only. It does not build or rebuild the image
by default, does not install or start ES, AGS, ARS, or EGS, does not call ES
`:prepare` or `:submit`, and does not change ES public contracts.

For this sealed slice, the host-local checker must not accept
`REMOTE_ALPHA_RUNTIME_IMAGE_REF`, `REMOTE_ALPHA_CODEX_CLI_PATH`,
`REMOTE_ALPHA_BUILD_SCRIPT`, `--image-ref`, or `--codex-cli-path` as mutable
inputs. The checker must fail fast instead of silently honoring a non-slice
image ref, Codex CLI path, or recipe wrapper.

The summary schema for that host-local record is:

- `execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1`

The current host-local non-secret evidence summary for this slice is:

- `/var/tmp/execution-substrate-remote-alpha/normal-shell-runtime-image-summary.json`

It is an ES-owned host-local audit record, not an ES lifecycle or readiness
surface. It must not be treated as:

- ES `/health`
- ES submit readiness
- ES service health
- producer-contract compatibility
- retained-result readiness
- Control Plane run-control truth

It is also not yet:

- an Infrastructure Manager doctor stage payload
- an Infrastructure Manager support-bundle section
- a combined readiness-report input

Required summary fields for
`execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1` are:

- `schema_version`
- `checked_at`
- `image.ref`
- `image.present`
- `image.image_id`
- `image.repo_digests`
- `image.architecture`
- `image.os`
- `build.expected_recipe_script`
- `build.expected_recipe_script_present`
- `build.expected_recipe_script_sha256`
- `build.build_context_files`
- `build.recipe_matches_slice`
- `build.codex_realization`
- `build.codex_credential_posture`
- `build.real_codex_credentials_required_for_build`
- `host.hostname`
- `host.docker_service_active`
- `host.nomad_ready`
- `validation.image_present`
- `validation.docker_info_ok`
- `validation.minimal_container_run.status`
- `validation.minimal_container_run.safe`
- `validation.minimal_container_run.stdout_lines`
- `validation.minimal_container_run.stderr_lines`
- `validation.codex_realization_expected`
- `security.ds_not_in_docker_group`
- `security.passwordless_sudo_for_ds`
- `security.no_real_codex_credentials_in_build_context`
- `security.no_api_keys_or_tokens_printed`
- `readiness_not_claimed.runtime_profile_ready`
- `readiness_not_claimed.submit_ready`
- `readiness_not_claimed.es_services_healthy`
- `readiness_not_claimed.producer_contract_compatible`
- `readiness_not_claimed.retained_result_fetch`

The current status vocabulary for the summary is:

- `validation.image_present`: `pass` or `fail`
- `validation.minimal_container_run.status`: `pass`, `fail`, or
  `not_exercised`
- `build.recipe_matches_slice`: `true` only when the current repo snapshot
  still carries the expected repo-owned wrapper for this slice and that wrapper
  still pins the documented image ref, Dockerfile, Codex CLI path, and
  realization
- `build.codex_realization`: literal `proof` for the current repo-owned slice
- `validation.codex_realization_expected`: `true` only when the bounded minimal
  container smoke proves the current `proof` realization
- `readiness_not_claimed.*`: literal `not_claimed`

The summary must record only bounded safe evidence such as:

- image ref plus safe image metadata
- expected recipe-script path, presence, digest, and bounded build-context file
  list
- Codex realization posture
- Docker service activity and Nomad ready-state summary
- bounded minimal container smoke output lines for Python, git, and the Codex
  CLI realization check
- explicit non-claim vocabulary for readiness surfaces this slice does not
  prove

That build evidence verifies the expected repo-owned recipe for this slice in
the current repo snapshot. It does not, by itself, prove that the current image
was historically built through that wrapper unless separate build-time evidence
exists.

That summary and any derivative artifacts accepted as evidence for this slice
must not persist:

- OpenAI or Codex credentials
- API keys
- Vault tokens
- JWT-SVIDs
- private keys
- PEM bodies
- secret payloads
- raw build logs
- raw retained-result bundles

## Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche

Remote Supported-Host Alpha currently carries one bounded service hardening
tranche: `AGS sealed + ARS de-root + EGS de-root`.

AGS, ARS, and EGS are already de-rooted in this tranche. The EGS helper and
summary schema remain documented because they still define preserved tranche
state that later ES slices must not disturb.

That tranche is intentionally limited to:

- preserving the landed `ags.service` non-root `ags:ags` posture plus the
  narrowed shared TLS readability needed by AGS
- preserving the landed `ars.service` non-root `ars:ars` posture plus its
  dedicated TLS and writable-state ownership model
- moving only `egs.service` from the default root service context to a
  dedicated non-root `egs:egs` account
- preserving direct HTTPS/mTLS from the Mac to AGS `/health` and
  `POST /v1/artifacts:publish`, plus direct HTTPS/mTLS from the Mac to ES
  `/health` and `GET /v1/executions:contract`
- preserving the current EGS internal-only loopback listener at
  `https://127.0.0.1:8443`
- preserving AGS publication to ARS over the current loopback/internal HTTPS
  dependency path
- preserving ES local `/health` and producer-contract compatibility surfaces
- recording non-secret host-local summaries for the landed AGS step, the
  landed ARS step, and the landed EGS de-root step
- leaving `es.service` in its current posture for this tranche
- leaving the current SPIRE selector model unchanged for this tranche
- preserving the current no-bridge and no-shared-filesystem remote path facts

This tranche does not prove a new remote happy path, does not start a new
hardening tranche, does not move ES off root, does not change ES public
contracts, does not change current Control Plane, ES, or Infrastructure
Manager ownership boundaries, does not widen the current SPIRE selector model,
and does not widen into broader proof expansion.

### Landed AGS Seal Step

The AGS step in this tranche is already landed. It remains documented because
the landed helper, summary schema, and ownership model are still part of the
tranche state that must remain preserved while later service-account steps in
this tranche land.

The repo-owned host-local hardening command for that landed step is:

- `sudo scripts/remote_alpha_harden_ags_service.sh`

That command must be run as root because the current live Alpha posture keeps
AGS config and TLS material root-owned before the slice is applied, and `ds`
must still not rely on passwordless sudo for this path.

For this sealed AGS step within the current hardening tranche, the host-local
hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the landed AGS step away
from the repo-owned AGS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

The summary schema for that host-local step record is:

- `execution-substrate.remote-alpha.ags-service-hardening-summary.v1`

The current host-local non-secret evidence summary for that landed step is:

- `/var/tmp/execution-substrate-remote-alpha/ags-service-hardening-summary.json`

It is a host-local hardening record for the landed AGS step, not a new
happy-path proof and not an ES lifecycle, readiness, runtime-profile, or
producer-contract surface.

Required summary fields for
`execution-substrate.remote-alpha.ags-service-hardening-summary.v1` are:

- `schema_version`
- `checked_at`
- `slice.classification`
- `slice.not_a_new_happy_path_proof`
- `service.name`
- `service.user`
- `service.group`
- `service.binary_path`
- `service.config_path`
- `service.health_url`
- `service.publish_url`
- `dependencies.artifact_registry.base_url`
- `dependencies.server_tls.cert_file`
- `dependencies.server_tls.key_file`
- `dependencies.server_tls.client_ca_file`
- `dependencies.artifact_registry.client_cert_file`
- `dependencies.artifact_registry.client_key_file`
- `dependencies.artifact_registry.root_ca_file`
- `dependencies.signer.material_location`
- `dependencies.local_state_paths`
- `dependencies.log_sink`
- `ownership_model.config_file`
- `ownership_model.tls_directory`
- `ownership_model.tls_files`
- `ownership_model.systemd_dropin`
- `validation.local_health`
- `validation.local_publish_probe`
- `validation.ars_service_posture`
- `validation.egs_service_posture`
- `validation.es_service_posture`
- `validation.mac_health_probe`
- `validation.mac_publish_probe`
- `preserved_remote_path.direct_https_mtls`
- `preserved_remote_path.no_bridge`
- `preserved_remote_path.no_shared_filesystem`
- `security.ds_not_in_docker_group`
- `security.passwordless_sudo_for_ds`
- `not_claimed.es_runtime_hardening`
- `not_claimed.submit_runtime_profile_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

That summary must record only bounded safe evidence such as:

- the AGS service user/group and AGS ownership model
- the exact AGS binary, config, TLS, and ARS dependency file paths AGS needs
- AGS local `/health` and focused publish-probe results
- the preserved direct HTTPS/mTLS, no-bridge, and no-shared-filesystem facts
- explicit non-claim vocabulary for ES runtime hardening, submit/runtime-profile
  changes, SPIRE selector-model changes, and new happy-path proof claims

Current reruns of the landed AGS step must preserve the current ARS `ars:ars`,
EGS `egs:egs`, and ES `User=es`, `Group=es`, `UMask=0027` service postures
while recording validation only as bounded hardening evidence.

That summary and any derivative artifacts accepted as evidence for this step
must not persist:

- signer private-key bytes
- TLS private-key PEM bodies
- client cert private keys
- JWT-SVIDs
- Vault tokens
- API keys
- raw secret payloads
- raw retained-result bundles

The active repo-derived AGS service inputs for that landed step remain:

- service name `ags`
- service user `ags`
- service group `ags`
- binary path `/usr/local/lib/execution-substrate/bin/ags`
- config path `/etc/execution-substrate/ags.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- systemd unit path `/etc/systemd/system/ags.service`
- systemd drop-in dir `/etc/systemd/system/ags.service.d`
- systemd drop-in path `/etc/systemd/system/ags.service.d/10-account.conf`

### Landed ARS De-root Step

The ARS step in this tranche is already landed. It remains documented because
its helper, summary schema, and dedicated ownership model remain part of the
tranche state that must stay preserved while EGS is de-rooted.

That step is intentionally limited to:

- preserving the landed `ars.service` non-root `ars:ars` account
- preserving the current ARS internal-only loopback listener at
  `https://127.0.0.1:8442`
- preserving AGS local `/health` plus a focused
  `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback
  dependency path
- preserving the current AGS `ags:ags` posture
- recording a non-secret host-local summary for the landed step
- preserving the current EGS `egs:egs` posture and the current ES `User=es`,
  `Group=es`, `UMask=0027` posture on any current rerun of this landed step
- leaving the current SPIRE selector model unchanged for this tranche
- preserving the current no-bridge and no-shared-filesystem remote path facts

The repo-owned host-local hardening command for that landed ARS de-root step
is:

- `sudo scripts/remote_alpha_harden_ars_service.sh`

That command must be run as root because the current live Alpha posture keeps
ARS config, the current source TLS material, and ARS writable state root-owned
before the slice is applied, and `ds` must still not rely on passwordless sudo
for this path.

Because the current shared `/etc/execution-substrate/tls` directory is already
narrowed for the landed AGS seal at `root:ags`, this ARS de-root step must not
widen that shared TLS directory and must not introduce a shared Unix-account
model. Instead, it stages only the ARS server cert, ARS server key, and ARS
client-CA bundle into dedicated ARS-readable paths under
`/etc/execution-substrate/ars-tls`.

For this sealed ARS de-root step within the current hardening tranche, the
host-local hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the ARS de-root step away
from the repo-owned ARS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

The summary schema for that host-local step record is:

- `execution-substrate.remote-alpha.ars-service-hardening-summary.v1`

The current host-local non-secret evidence summary for that ARS step is:

- `/var/tmp/execution-substrate-remote-alpha/ars-service-hardening-summary.json`

It is a host-local hardening record for the landed ARS de-root step, not a new
happy-path proof and not an ES lifecycle, readiness, runtime-profile, or
producer-contract surface.

Required summary fields for
`execution-substrate.remote-alpha.ars-service-hardening-summary.v1` are:

- `schema_version`
- `checked_at`
- `slice.classification`
- `slice.not_a_new_happy_path_proof`
- `service.name`
- `service.user`
- `service.group`
- `service.binary_path`
- `service.config_path`
- `service.health_url`
- `dependencies.server_tls.cert_file`
- `dependencies.server_tls.key_file`
- `dependencies.server_tls.client_ca_file`
- `dependencies.blob_root`
- `dependencies.index_file`
- `dependencies.local_state_paths`
- `dependencies.log_sink`
- `ownership_model.config_file`
- `ownership_model.tls_directory`
- `ownership_model.tls_files`
- `ownership_model.state_root`
- `ownership_model.blob_root`
- `ownership_model.index_file`
- `ownership_model.systemd_dropin`
- `validation.local_ars_health`
- `validation.local_ags_health`
- `validation.local_ags_publish_probe`
- `validation.state_ownership`
- `validation.ags_service_posture`
- `validation.egs_service_posture`
- `validation.es_service_posture`
- `preserved_remote_path.ars_loopback_only`
- `preserved_remote_path.direct_https_mtls`
- `preserved_remote_path.no_bridge`
- `preserved_remote_path.no_shared_filesystem`
- `security.ds_not_in_docker_group`
- `security.passwordless_sudo_for_ds`
- `not_claimed.es_or_egs_hardening`
- `not_claimed.es_public_contract_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

That summary must record only bounded safe evidence such as:

- the ARS service user/group and ARS config, TLS, and writable-state ownership
  model
- the exact ARS binary, config, TLS, blob-root, and index-file paths ARS needs
- ARS local `/health`, AGS local `/health`, and focused AGS publish-probe
  results after the change
- the preserved direct HTTPS/mTLS, no-bridge, and no-shared-filesystem facts
- explicit non-claim vocabulary for ES or EGS hardening, ES public-contract
  changes, SPIRE selector-model changes, and new happy-path proof claims

That summary and any derivative artifacts accepted as evidence for this step
must not persist:

- TLS private-key PEM bodies
- JWT-SVIDs
- Vault tokens
- API keys
- raw secret payloads
- raw retained-result bundles

The active repo-derived ARS service inputs for that ARS step remain:

- service name `ars`
- service user `ars`
- service group `ars`
- binary path `/usr/local/lib/execution-substrate/bin/ars`
- config path `/etc/execution-substrate/ars.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- ARS bind `https://127.0.0.1:8442`
- current source server cert `/etc/execution-substrate/tls/ars-server-cert.pem`
- current source server key `/etc/execution-substrate/tls/ars-server-key.pem`
- current source client CA / runtime root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- dedicated ARS-readable TLS dir `/etc/execution-substrate/ars-tls`
- ARS-readable server cert `/etc/execution-substrate/ars-tls/ars-server-cert.pem`
- ARS-readable server key `/etc/execution-substrate/ars-tls/ars-server-key.pem`
- ARS-readable client CA / runtime root CA `/etc/execution-substrate/ars-tls/runtime-ca.pem`
- blob storage root `/var/lib/execution-substrate/ars/blobs`
- index file `/var/lib/execution-substrate/ars/index.json`
- systemd unit path `/etc/systemd/system/ars.service`
- systemd drop-in dir `/etc/systemd/system/ars.service.d`
- systemd drop-in path `/etc/systemd/system/ars.service.d/10-account.conf`

### EGS De-root Step

The EGS step in this tranche is already landed. It remains documented because
its helper, summary schema, and preserved evidence shape still define tranche
state that later ES slices must not disturb.

That step is intentionally limited to:

- moving only `egs.service` from the default root service context to a
  dedicated non-root `egs:egs` account
- preserving the current EGS internal-only loopback listener at
  `https://127.0.0.1:8443`
- preserving AGS local `/health` plus a focused
  `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback
  dependency path
- preserving local ES `/health` plus
  `GET /v1/executions:contract` through the current direct HTTPS/mTLS path
- preserving the current AGS `ags:ags` posture
- preserving the current ARS `ars:ars` posture
- recording a non-secret host-local summary for the landed step
- preserving the current ES `User=es`, `Group=es`, `UMask=0027` posture
- leaving the current SPIRE selector model unchanged for this tranche
- preserving the current no-bridge and no-shared-filesystem remote path facts

The repo-owned host-local hardening command for that EGS de-root step is:

- `sudo scripts/remote_alpha_harden_egs_service.sh`

That command must be run as root because the current live Alpha posture keeps
EGS config, the current source TLS material, and the inline signer material in
that config root-owned before the slice is applied, and `ds` must still not
rely on passwordless sudo for this path.

If the target host already has an `egs` user/group, the helper must prove that
the pre-existing service account is still acceptably narrow for this slice
before it is reused. At minimum, that check must confirm primary group `egs`,
no supplementary groups, and no unexpected extra members in the `egs` group
itself; otherwise the helper must fail instead of silently claiming a
dedicated narrow account/group.

Because the current shared `/etc/execution-substrate/tls` directory remains
narrowed for the landed AGS seal at `root:ags`, this EGS de-root step must not
widen that shared TLS directory and must not introduce a shared Unix-account
model. Instead, it stages only the EGS server cert, EGS server key, and EGS
client-CA bundle into dedicated EGS-readable paths under
`/etc/execution-substrate/egs-tls`.

For this sealed EGS de-root step within the current hardening tranche, the
host-local hardening helper must not accept `REMOTE_ALPHA_SERVICE_NAME`,
`REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`,
`REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`,
`REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`,
`REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`,
`--service-name`, `--service-user`, `--service-group`, `--binary-path`,
`--config-path`, `--healthcheck-env-path`, `--service-unit-path`,
`--service-dropin-dir`, or `--service-dropin-path` as mutable inputs. The
helper must fail fast instead of silently retargeting the EGS de-root step away
from the repo-owned EGS service posture. Only `--summary-path` and
`REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement.

The summary schema for that host-local step record is:

- `execution-substrate.remote-alpha.egs-service-hardening-summary.v2`

The current host-local non-secret evidence summary for that EGS step is:

- `/var/tmp/execution-substrate-remote-alpha/egs-service-hardening-summary.json`

It is a host-local hardening record for the EGS de-root step, not a new
happy-path proof and not an ES lifecycle, readiness, runtime-profile, or
producer-contract surface.

Required summary fields for
`execution-substrate.remote-alpha.egs-service-hardening-summary.v2` are:

- `schema_version`
- `checked_at`
- `slice.classification`
- `slice.not_a_new_happy_path_proof`
- `service.name`
- `service.user`
- `service.group`
- `service.binary_path`
- `service.config_path`
- `service.health_url`
- `dependencies.server_tls.cert_file`
- `dependencies.server_tls.key_file`
- `dependencies.server_tls.client_ca_file`
- `dependencies.signer.material_location`
- `dependencies.runtime_trust.material_location`
- `dependencies.publication.material_location`
- `dependencies.local_state_paths`
- `dependencies.log_sink`
- `ownership_model.account.group_members`
- `ownership_model.config_file`
- `ownership_model.tls_directory`
- `ownership_model.tls_files`
- `ownership_model.runtime_state`
- `ownership_model.systemd_dropin`
- `validation.local_egs_health`
- `validation.local_ags_health`
- `validation.local_ags_publish_probe`
- `validation.local_es_health`
- `validation.local_es_contract_probe`
- `validation.service_account_narrowness`
- `validation.service_account_narrowness.group_members`
- `validation.service_account_narrowness.unexpected_group_members`
- `validation.ownership`
- `validation.ags_service_posture`
- `validation.ars_service_posture`
- `validation.es_service_posture`
- `preserved_remote_path.egs_loopback_only`
- `preserved_remote_path.direct_https_mtls`
- `preserved_remote_path.no_bridge`
- `preserved_remote_path.no_shared_filesystem`
- `security.ds_not_in_docker_group`
- `security.passwordless_sudo_for_ds`
- `security.shared_unix_account_model_introduced`
- `not_claimed.es_de_root`
- `not_claimed.es_public_contract_changes`
- `not_claimed.spire_selector_model_changes`
- `not_claimed.new_remote_happy_path_proof`

For this EGS host-local summary, the preserved-remote/security facts above are
not all the same kind of evidence:

- `validation.service_account_narrowness` must prove the `egs` account remains
  narrow for this slice before the summary may describe it as dedicated. At
  minimum that proof requires primary group `egs`, no supplementary groups, and
  no unexpected extra members in the `egs` group itself.
- `validation.service_account_narrowness` must record the actual primary group,
  supplementary groups, and effective `egs` group members seen by the helper.
- `preserved_remote_path.direct_https_mtls` must be an inference record
  derived from current AGS/ES host config plus the host-local HTTPS+mTLS
  probes. It is not a Mac-side reachability proof.
- `preserved_remote_path.no_bridge` and
  `preserved_remote_path.no_shared_filesystem` must be explicit operator
  assertion records unless a future slice adds proof inputs that can validate
  them directly.
- `security.shared_unix_account_model_introduced` must be derived from
  `validation.service_account_narrowness`. It must not report `false` unless
  the helper has proved the EGS account remained narrow for this slice.

That summary must record only bounded safe evidence such as:

- the EGS service user/group and EGS config/TLS ownership model
- the exact EGS binary, config, TLS, and signer/runtime-trust/publication
  material locations EGS needs
- the explicit fact that EGS has no dedicated writable state in this slice
- EGS local `/health`, AGS local `/health`, focused AGS publish-probe, ES local
  `/health`, and ES local `GET /v1/executions:contract` results after the
  change
- the preserved direct HTTPS/mTLS, no-bridge, and no-shared-filesystem facts
- explicit non-claim vocabulary for ES de-root, ES public-contract changes,
  SPIRE selector-model changes, and new happy-path proof claims

Current reruns of the landed EGS step must preserve the current AGS `ags:ags`,
ARS `ars:ars`, and ES `User=es`, `Group=es`, `UMask=0027` service postures
while recording validation only as bounded hardening evidence.

That summary and any derivative artifacts accepted as evidence for this step
must not persist:

- signer private-key bytes
- TLS private-key PEM bodies
- JWT-SVIDs
- Vault tokens
- API keys
- private keys
- raw secret payloads
- raw retained-result bundles

The active repo-derived EGS service inputs for that EGS step remain:

- service name `egs`
- service user `egs`
- service group `egs`
- binary path `/usr/local/lib/execution-substrate/bin/egs`
- config path `/etc/execution-substrate/egs.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- EGS bind `https://127.0.0.1:8443`
- current source server cert `/etc/execution-substrate/tls/egs-server-cert.pem`
- current source server key `/etc/execution-substrate/tls/egs-server-key.pem`
- current source client CA / runtime root CA `/etc/execution-substrate/tls/runtime-ca.pem`
- dedicated EGS-readable TLS dir `/etc/execution-substrate/egs-tls`
- EGS-readable server cert `/etc/execution-substrate/egs-tls/egs-server-cert.pem`
- EGS-readable server key `/etc/execution-substrate/egs-tls/egs-server-key.pem`
- EGS-readable client CA / runtime root CA `/etc/execution-substrate/egs-tls/runtime-ca.pem`
- signer material location `/etc/execution-substrate/egs.json`
- runtime-trust policy location `/etc/execution-substrate/egs.json`
- publication metadata location `/etc/execution-substrate/egs.json`
- no EGS-local writable state paths
- systemd unit path `/etc/systemd/system/egs.service`
- systemd drop-in dir `/etc/systemd/system/egs.service.d`
- systemd drop-in path `/etc/systemd/system/egs.service.d/10-account.conf`

## Remote ES Config/TLS Ownership Prep Slice

Remote Supported-Host Alpha may also apply one separate ES config/TLS
ownership prep slice without changing the live ES service user.

Current live bounded ES state on Remote Alpha is now:

- ES config/TLS prep is applied.
- ES stable writable-state roots are prepared.
- the current live long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`.
- post-apply `/health`, `GET /v1/executions:contract`, the retained-result
  fetch/materialization flow, and the current lowest-cost existing happy path
  all passed.
- future writable-state readiness passed with the long-lived service already at
  `es:es`.
- Infrastructure Manager readiness is accepted.
- this does not claim full ES/runtime de-root.
- the root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad selector posture, and Vault/workload-zone handoff
  remain bounded compatibility edges.
- old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by the migration.

The config/TLS, binary-deployment, and writable-state subsections below still
describe earlier bounded slices whose own apply summaries intentionally record
`root(default)` at those earlier steps. That historical wording remains true
for those slice-specific artifacts and should not be read as the current live
service posture after the later bounded `User=es` service-user migration.

This slice is intentionally limited to:

- introducing dedicated ES-readable config ownership plus a dedicated
  ES-readable TLS directory for the current ES runtime config
- preserving the current direct HTTPS/mTLS ES `/health` and
  `GET /v1/executions:contract` path
- preserving the current AGS, ARS, and EGS service postures
- preserving the current SPIRE selector posture, SPIRE socket traversal, and
  Vault/runtime-helper semantics
- preserving the current Nomad task user model
- leaving ES staging and retained-results ownership untouched
- recording one non-secret host-local summary for the prep step
- leaving `es.service` in its then-live `root(default)` posture for this
  earlier slice
- preserving the current no-bridge and no-shared-filesystem remote path facts

This slice is a `Bounded slice rule` on host-local ES-readable ownership only.
Its defining `Temporary compatibility edge` is that, at that earlier step, live
`es.service` remained `root(default)` while dedicated `root:es` readable
config/TLS material was prepared for the later ES de-root slice.

The preferred repo-side operator wrapper for that slice is:

- `scripts/remote_alpha_stage_es_config_tls_prep.sh`

That productized wrapper runs from the operator repo, stages only the minimal
helper tree onto the remote host, defaults to non-mutating check-only, records
the required staging provenance, executes only from the root-owned staged
helper path, and requires `--apply` before any live mutation is attempted.

The remote staged helper entrypoint for that slice remains:

- `scripts/remote_alpha_prepare_es_config_tls.sh`

The remote host does not need a full Execution Substrate repo checkout for
this slice. The current accepted live-host invocation model is transient
helper staging from the operator repo into a root-owned staging tree under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/`.

At minimum, the operator must stage the repo-owned wrapper
`scripts/remote_alpha_prepare_es_config_tls.sh` and its sourced helper
`scripts/internal/remote_alpha_prepare_es_config_tls.sh`, preserving their
relative layout under that staging tree so the staged wrapper path is:

- `/var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`

Execution must run from that root-owned staged tree, not from a user-writable
upload path. Any user-scoped upload directory is transport only and must not
be used as the execution path for the live helper invocation.

The staged wrapper must still be run as root because the current live Alpha
posture keeps ES config and the current shared TLS material root-owned before
the slice is applied, and `ds` must still not rely on passwordless sudo for
this path.

The required operator-staged provenance record for that transient helper tree
must include:

- the local git commit when available
- the sha256 of each staged helper file
- the remote staged path
- the remote owner/mode proving the staged tree is root-owned rather than a
  user-writable upload path

The required operator-staged flow for this slice is:

1. Prefer the repo-side wrapper
   `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host>`
   for the default non-mutating check-only path. That wrapper must stage only
   the minimal helper tree from the local operator repo snapshot; a full
   remote repo checkout is not required.
   Copy only the minimal helper tree from the local operator repo snapshot; a
   full remote repo checkout is not required.
2. Install that helper tree into
   `/var/tmp/execution-substrate-remote-alpha/helper-staging/` as a root-owned
   staged tree, record the required provenance above, and execute the staged
   wrapper from that location.
3. Run the staged wrapper with `--check-only` before any live apply.
4. Review the `--check-only` JSON report. Apply may proceed only when
   `result.ok=true`, `plan.blockers` is empty,
   `plan.service_identity_would_remain_root_default=true`, and
   `validation.config_rewrite_scope.status=pass`; the planned writes must stay
   limited to `/etc/execution-substrate/es.json`,
   `/etc/execution-substrate/es-tls`, the files beneath that dedicated TLS
   directory, and the configured summary path.
5. Run the staged wrapper without `--check-only` only after those gates pass.
6. Preserve the apply summary, backup path, rollback notes, live
   `es.service` identity, and post-apply `/health` plus
   `GET /v1/executions:contract` status as the bounded post-apply evidence
   set.
7. Remove the transient helper staging tree after that bounded evidence is
   collected, while preserving the apply backup and summaries under
   `/var/tmp/execution-substrate-remote-alpha/`.
8. Do not run governed proof as part of this staged operator flow.

This operator-staged flow is ownership prep only. It is not ES de-rooting.

The preferred productized operator commands are:

- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host>`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --apply`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q`
- `scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q --apply`

The wrapper's default invocation above must remain check-only. The second form
must run apply only after the wrapper's repo-side gate validation accepts the
check-only JSON report for this slice.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local evidence
artifacts with the filenames Infrastructure Manager consumes directly:

- `es-config-tls-check-only.json`
- `es-config-tls-helper-staging-record.json`
- `es-config-tls-apply-summary.json` when `--apply` is used
- `es-config-tls-apply-stdout.txt` when `--apply` is used

Those local artifacts are hardening evidence/provenance only. They are not a
new governed proof, they do not authorize a wider ES prep slice, and they do
not change the host-local apply summary contract under
`/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`.

That machine-readable prep record must keep the live bridge explicit through
`slice.classification`, `slice.not_a_new_happy_path_proof`, and
`slice.temporary_compatibility_edge`; the last field must continue to name the
active `root(default)` service-user posture as the temporary compatibility edge
for this ownership-prep-only slice.

The required first step before any live apply is:

- `sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`

## Remote ES Writable-State Readiness Evidence Flow

Remote Supported-Host Alpha may also record one separate ES writable-state
readiness evidence flow without mutating the live ES host state.

This flow is intentionally limited to:

- staging only the minimal repo-owned checker helper tree needed to run the
  current non-mutating writable-state readiness checker
- preserving the then-live `es.service` `root(default)` posture
- preserving the current AGS, ARS, and EGS service postures
- preserving the current SPIRE selector posture, SPIRE socket traversal, and
  Vault/runtime-helper semantics
- preserving the current Nomad task user model
- collecting readiness evidence and staging provenance only
- leaving ES config/TLS ownership, staging ownership, retained results, and
  service identity unchanged
- preserving the current no-bridge and no-shared-filesystem remote path facts

This flow is `Checker-backed` operator evidence only. It is non-mutating
except for temporary checker staging under the helper staging tree. It is
readiness evidence only. It is not governed proof. It is not approval to
de-root ES.

The preferred repo-side operator wrapper for this flow is:

- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`

The remote staged helper entrypoint for this flow remains:

- `scripts/remote_alpha_check_es_writable_state_readiness.sh`

The checker's sourced internal helper remains:

- `scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`

The remote host does not need a full Execution Substrate repo checkout for
this evidence flow. The current accepted live-host invocation model is
transient helper staging from the operator repo into a root-owned staging tree
under `/var/tmp/execution-substrate-remote-alpha/helper-staging/`.

At minimum, the operator must stage only:

- `scripts/remote_alpha_check_es_writable_state_readiness.sh`
- `scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`

The staged helper layout must preserve those relative paths under the
root-owned staging tree so the staged checker path is:

- `/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/scripts/remote_alpha_check_es_writable_state_readiness.sh`

Execution must run from that root-owned staged tree, not from a user-writable
upload path. Any user-scoped upload directory is transport only and must not
be used as the execution path for the staged checker invocation.

The staged checker must still be run as root because the accepted Alpha
posture keeps live ES writable-state and runtime-helper semantics in the
current root-compatible model. The default wrapper path must perform a
noninteractive `sudo -n` preflight and fail cleanly with structured
`sudo_unavailable` evidence if passwordless sudo is not available. An explicit
`--interactive-sudo` mode may be used only from a visible terminal when a
bounded password handoff is authorized. Batch execution must stay bounded and
must not rely on a forced-PTY heredoc path. Interactive collection must write
stage-stat and checker outputs to user-owned remote artifact files and fetch
them afterward rather than redirecting tty-backed SSH stdout directly into the
local evidence files. The interactive privileged portion of the staged checker
flow should complete within one visible sudo-backed SSH session so the
operator does not need to re-enter the password for separate staged-install,
stage-stat, and checker legs.

The wrapper must default to `--mode alpha-compat`. Operators must request
explicit `--mode future-non-root-required` when they want a non-mutating
future-readiness gate. Those blocker findings were expected before the
now-applied long-lived service-user migration, and they remain valid readiness
evidence rather than wrapper failure by themselves when the gate is rerun
against later host drift or rollback-window changes.

The required operator-staged provenance record for this transient helper flow
must include:

- the local git commit when available
- the sha256 of each staged helper file
- the remote staged path
- the remote owner/mode proving the staged tree is root-owned rather than a
  user-writable upload path
- the requested checker mode
- the sudo mode used for staged execution
- whether staging occurred
- whether the checker ran
- whether transient staging was removed
- whether `sudo_unavailable` blocked noninteractive root-owned staging
- whether `wrapper_tooling_error` blocked execution before checker evidence was
  accepted
- any sudo or preflight blocker if staging could not proceed

The required operator-staged flow for this evidence slice is:

1. Prefer the repo-side wrapper
   `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host>`
   for the default noninteractive path. That wrapper must stage only the
   minimal helper tree from the local operator repo snapshot; a full remote
   repo checkout is not required.
   Use `--interactive-sudo` only when the default noninteractive `sudo -n`
   preflight reports `sudo_unavailable` and a visible terminal is available
   for the bounded password handoff.
2. Install that helper tree into
   `/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/` as a
   root-owned staged tree, record the required provenance above, and execute
   the staged checker from that location. Batch execution must use bounded
   remote commands that terminate and must not drop into an interactive shell.
   Interactive runs must keep sudo prompts on the visible terminal instead of
   hiding them behind local stdout redirection, and should not reopen separate
   password-backed SSH legs for staged install, stage-stat capture, and
   checker execution.
3. Run the wrapper's default `--mode alpha-compat` flow when collecting
   current Alpha-compatible readiness evidence.
4. Use `--mode future-non-root-required` only when the repo wants an explicit
   non-mutating future readiness gate. A checker result with
   `overall_classification=blocker` is still valid measurement evidence when
   the JSON is structurally valid and honest.
5. Review the local `es-writable-state-readiness.json` artifact. Collection
   must fail closed only when the staged helper tree is not root-owned, staged
   files are group-writable or world-writable, checker output is malformed,
   checker output claims mutation, or checker output does not match the
   requested mode.
6. Preserve the local
   `es-writable-state-readiness-helper-staging-record.json` artifact as
   provenance only. That staging record is not proof and is not readiness by
   itself.
7. Remove the transient helper staging tree after successful collection.
   `--keep-staging-on-failure` may retain it for diagnostics.
8. Do not run governed proof as part of this staged operator flow.

This operator-staged flow is readiness evidence only. It is not proof. It is
not approval to de-root ES.

The preferred productized operator commands are:

- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host>`
- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host> --mode future-non-root-required`
- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q`
- `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host> --output-dir .out/remote-alpha-m75q --keep-staging-on-failure`

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local evidence
artifacts with the filenames Infrastructure Manager consumes directly:

- `es-writable-state-readiness.json`
- `es-writable-state-readiness-helper-staging-record.json`

Those local artifacts are readiness evidence and provenance only. They are not
a governed proof, they did not by themselves authorize the later bounded
service-user migration, and they do not claim full ES/runtime de-root.

## Remote ES Binary Deployment Surface

Remote Supported-Host Alpha may now carry one bounded repo-side operator
surface for resolving live ES/runtime-helper binary parity against the current
repo snapshot before any writable-state or service-user mutation is attempted.

This surface is intentionally limited to:

- the live `es` binary at `/usr/local/lib/execution-substrate/bin/es`
- the live runtime helper binary at `/usr/local/bin/es-runtime-support`
- default non-mutating `--check-only` plus explicit `--apply` for any later
  live operator use
- preserving the accepted ES config/TLS ownership prep bridge
- preserving the accepted live `es.service` identity for the current host
  slice without changing `User=`, `Group=`, or `UMask=`
- preserving ES public contracts, lifecycle semantics, retained-result
  semantics, `authority_handoff`, staging/results ownership, and all current
  bounded runtime compatibility edges
- refusing to run governed proof as part of the helper flow

Historical note:

- the earlier live-host-evidenced binary-parity apply happened before the
  later bounded service-user migration, so those earlier apply summaries
  honestly record `root(default)`
- current post-migration binary refreshes must instead preserve the accepted
  long-lived `User=es`, `Group=es`, `UMask=0027` posture and must not treat
  that accepted service identity as drift
- current post-migration binary refreshes must block any root-like service
  identity instead of silently preserving it; if operators ever need to return
  to a root-era service posture, that is a separate rollback/service-user
  surface rather than a binary-deployment helper mode

The preferred public repo-side/operator surface is:

- `scripts/remote_alpha_deploy_es_binaries.sh`

Its sourced internal implementation is:

- `scripts/internal/remote_alpha_deploy_es_binaries.sh`

When remote staging is used through `--ssh-target`, the helper must stage only
the minimal helper files plus the built linux/amd64 binary payloads required
for this surface:

- `scripts/remote_alpha_deploy_es_binaries.sh`
- `scripts/internal/remote_alpha_deploy_es_binaries.sh`
- one staged payload file for `/usr/local/lib/execution-substrate/bin/es`
- one staged payload file for `/usr/local/bin/es-runtime-support`
- one staged payload provenance file `payload/build-provenance.json`

The repo-side upload step must preserve the exact remote relative paths the
root-owned install step later consumes:

- `<upload-root>/scripts/remote_alpha_deploy_es_binaries.sh`
- `<upload-root>/scripts/internal/remote_alpha_deploy_es_binaries.sh`
- `<upload-root>/payload/es`
- `<upload-root>/payload/es-runtime-support`
- `<upload-root>/payload/build-provenance.json`

Execution must still run only from a root-owned staged path under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`, not from
a user-writable upload directory, and the staged provenance record must include
the local git commit when available, whether the worktree was dirty, the
sha256 of each staged helper or payload file, the remote staged path, and the
remote owner or mode proving the staged tree was root-owned before execution.

The required operator flow for this binary-deployment surface is:

1. Run `scripts/remote_alpha_deploy_es_binaries.sh --ssh-target <user@host>`
   first. That default invocation must remain non-mutating `--check-only`.
   The default staged-wrapper path must perform a noninteractive `sudo -n`
   preflight and fail cleanly with structured `sudo_unavailable` evidence
   before any helper upload or root-owned staging when passwordless sudo is
   unavailable. An explicit `--interactive-sudo` mode may be used only from a
   visible terminal when a bounded password handoff is authorized. Interactive
   staged execution must fetch check-only/apply outputs from user-owned remote
   artifact files rather than redirecting tty-backed SSH stdout directly into
   the local evidence files. The wrapper must validate the local staged upload
   tree before upload and treat any missing staged helper or payload path as
   structured `wrapper_tooling_error` evidence rather than surfacing a raw
   root-owned `install: cannot stat` failure.
2. Treat check-only as planning evidence only. It must build or locate the
   repo-owned linux/amd64 artifacts through the established repo build path,
   record dirty-worktree or build provenance, compare local and live hashes,
   and report hash differences as `deployment_needed` rather than as a failed
   host mutation.
3. Use `--apply` only after explicit approval and after the helper reports no
   blockers other than `deployment_needed`, with
   `plan.service_identity_matches_current_supported_posture=true`.
4. Preserve the apply summary, backup path, rollback notes, exact changed
   binary paths, preserved live `es.service` identity, and post-restart
   `/health` plus `GET /v1/executions:contract` validation as the bounded
   post-apply evidence set. The helper staging record must distinguish
   `sudo_unavailable` from `wrapper_tooling_error`, record whether staging
   occurred, whether the check-only helper ran, and whether transient staging
   was removed.
5. Remove transient staging after collection unless
   `--keep-staging-on-failure` is requested. Deferred cleanup must remove the
   user-owned remote upload root, the user-owned remote artifact root, and any
   root-owned helper staging root that was created for the run.
6. Do not widen this helper flow into service-user changes, config/TLS
   rewrites, staging/results ownership changes, Nomad task-user changes,
   helper or selector redesign, Vault handoff redesign, or governed proof.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local
artifacts:

- `es-binary-deployment-check-only.json`
- `es-binary-deployment-helper-staging-record.json`
- `es-binary-deployment-apply-summary.json` when `--apply` is used

Those local artifacts are deployment evidence and provenance only. They are
not governed proof. Historical earlier-slice artifacts may preserve the then
live `root(default)` service identity, while current post-migration artifacts
must preserve the accepted `User=es`, `Group=es`, `UMask=0027` service
identity instead of treating it as drift. Those artifacts still do not by
themselves authorize writable-state or service-user mutation.

## Remote ES Writable-State Ownership Surface

Remote Supported-Host Alpha may now carry one bounded repo-side operator
surface for preparing only the stable staging/results roots required before the
long-lived `es.service` can later run as `es:es`.

This surface is intentionally limited to:

- `execution.staging_root_dir` from `/etc/execution-substrate/es.json`
- `execution.results_root_dir` from `/etc/execution-substrate/es.json`
- default non-mutating `--check-only` plus explicit `--apply` for any later
  live operator use
- preserving the then-live `es.service` `root(default)` posture during this
  earlier slice
- preserving ES public contracts, lifecycle semantics, retained-result
  semantics, `authority_handoff`, and the root-start runtime compatibility
  edges
- refusing to recursively re-owner retained run or debug trees
- refusing to run governed proof as part of this helper flow
- allowing a separate explicit non-empty-root maintenance window to stop/start
  `es.service` once while preserving the then-live `root(default)` identity for
  that earlier slice

The preferred public repo-side/operator surface is:

- `scripts/remote_alpha_prepare_es_writable_state_ownership.sh`

Its sourced internal implementation is:

- `scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`

When remote staging is used through `--ssh-target`, the helper must stage only
the minimal helper files required for this surface:

- `scripts/remote_alpha_prepare_es_writable_state_ownership.sh`
- `scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`

The repo-side upload step must preserve the exact remote relative paths the
root-owned install step later consumes:

- `<upload-root>/scripts/remote_alpha_prepare_es_writable_state_ownership.sh`
- `<upload-root>/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`

Execution must still run only from a root-owned staged path under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`, not from
a user-writable upload directory, and the staged provenance record must include
the local git commit when available, the sha256 of each staged helper file, the
remote staged path, and the remote owner or mode proving the staged tree was
root-owned before execution.

The required operator flow for this writable-state ownership surface is:

1. Run
   `scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host>`
   first. That default invocation must remain non-mutating `--check-only`.
   The default staged-wrapper path must perform a noninteractive `sudo -n`
   preflight and fail cleanly with structured `sudo_unavailable` evidence
   before any helper upload or root-owned staging when passwordless sudo is
   unavailable. An explicit `--interactive-sudo` mode may be used only from a
   visible terminal when a bounded password handoff is authorized. Interactive
   staged execution must fetch check-only/apply outputs from user-owned remote
   artifact files rather than redirecting tty-backed SSH stdout directly into
   the local evidence files.
2. Review the machine-readable check-only JSON before any later live apply.
   Apply readiness must stay blocked unless the helper reports:
   - a narrow `es:es` account/group
   - exact target paths from `es.json`
   - current owner/mode state for both stable roots
   - current owner/mode/manageability state for the minimal common parent
     traversal directory or directories needed to reach those roots
   - empty roots or an explicit `--rotate-nonempty-roots`
     maintenance-window path proving no retained run/debug content would be
     re-owned implicitly
   - no active-run or drain ambiguity the helper cannot classify safely
   - any legacy run directories without retained-result or normalization-
     marker evidence are classified read-only through the existing configured
     Nomad connection only, using the current internal locator mapping
     `run_id -> exec-<run_id>`
   - any scheduler-backed stale/orphan acceptance remains an explicit
     maintenance-window decision rather than a silent quarantine default
   - any later bounded artifact reconciliation plan is limited to direct
     retained-result artifacts under `execution.results_root_dir` and direct
     run-scoped stage roots under `execution.staging_root_dir`, with explicit
     quarantine targets for anything that cannot be repaired in place without
     fabricating evidence
   - a rollback path
3. Treat check-only as planning evidence only. It is not proof and it is not a
   host mutation.
4. Use `--apply` only after explicit approval and after the helper reports no
   blockers. Apply must change only the two stable roots to the documented
   `es:es` ownership model, must not recursively `chown` arbitrary run/debug
   trees, and must not delete retained staging or result content. When
   non-empty roots require explicit maintenance-window rotation, apply may:
   - stop `es.service` while it remains `root(default)`
   - move the old configured roots aside to timestamped root-owned quarantine
     paths
   - create fresh live roots at the configured paths as `es:es` `0750`
   - start `es.service` again and require `/health` plus
     `GET /v1/executions:contract` validation
   If legacy run directories remain only as terminal or stale/orphan
   filesystem state, apply must require explicit `--rotate-nonempty-roots`
   plus explicit `--accept-stale-orphaned-runs`; default behavior must remain
   blocked.
   When the roots already match `es:es` but the shared traversal parent still
   blocks future non-root ES, apply may use a separate explicit parent-chain
   flag such as `--fix-parent-chain` only to preserve the existing parent
   owner and grant group `es` mode `0750` traversal access. Under the current
   live layout that means `/var/lib/execution-substrate/es` becomes
   `root:es` `0750`. That parent-only apply must not revisit old quarantined
   roots and should avoid any `es.service` restart unless a measured host
   proves it is required.
   When the live roots already match the documented owner model but specific
   legacy retained-result or run-scoped staging artifacts still block future
   readiness, apply may use a separate explicit flag such as
   `--reconcile-artifacts` only to:
   - repair the retained run directory, retained bundle, and preserved
     normalization sidecar when that direct bounded set already exists
   - quarantine legacy retained run directories that still lack preserved
     normalization evidence outside the live results root instead of
     fabricating a new sidecar
   - quarantine inactive incompatible run-scoped stage roots outside the live
     staging root instead of recursively re-owning arbitrary descendants
   - preserve rollback notes, exact changed/quarantined paths, and explicit
     confirmation that no service restart occurred unless a measured host
     proves one is required
5. Preserve the apply summary, backup path, rollback notes, exact changed
   root paths, preserved `es.service` identity, explicit confirmation that old
   roots were preserved rather than recursively re-owned, and either explicit
   confirmation that no service restart occurred or the bounded maintenance-
   window stop/start record when non-empty-root rotation was used as the
   bounded post-apply evidence set. Parent-only traversal apply must likewise
   report the exact changed parent path or paths, preserved owner strategy,
   unchanged quarantined roots, and whether any restart occurred. Bounded
   artifact-reconciliation apply must likewise report the exact repaired or
   quarantined retained/stage paths, the evidence that each stage-root
   quarantine was inactive, and the fact that no recursive ownership rewrite
   occurred. The helper
   staging record must distinguish
   `sudo_unavailable` from `wrapper_tooling_error`, record whether staging
   occurred, whether the check-only helper ran, and whether transient staging
   was removed.
6. Remove transient staging after collection unless
   `--keep-staging-on-failure` is requested.
7. Do not widen this helper flow into recursive retained-run ownership
   migration, config/TLS rewrites, service-user changes, Nomad task-user
   changes, helper or selector redesign, Vault handoff redesign, or governed
   proof.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local
artifacts:

- `es-writable-state-ownership-check-only.json`
- `es-writable-state-ownership-helper-staging-record.json`
- `es-writable-state-ownership-apply-summary.json` when `--apply` is used

Those local artifacts are ownership evidence and provenance only. They are not
governed proof, they preserve the earlier slice-specific fact that
`es.service` still ran as `root(default)` at that step, and they did not by
themselves authorize or prove the later `es.service` user flip.

## Remote ES Service-User Migration Surface

Remote Supported-Host Alpha may now carry one bounded repo-side operator
migration surface for the long-lived `es.service` user flip.

This surface is intentionally limited to:

- the long-lived `es.service` only
- default non-mutating `--check-only` plus explicit `--apply` for any later
  live operator use
- preserving the accepted ES config/TLS ownership prep bridge
- preserving the documented writable-state ownership model and runtime
  ownership-normalization contract as readiness inputs
- preserving ES public contracts, lifecycle semantics, retained-result
  semantics, and `authority_handoff`
- preserving the root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, broad root selector scope, and
  Vault/workload-zone handoff semantics as bounded compatibility edges
- refusing to claim full ES/runtime de-root
- refusing to run governed proof as part of the helper flow

The preferred public repo-side/operator surface is:

- `scripts/remote_alpha_migrate_es_service_user.sh`

Its sourced internal implementation is:

- `scripts/internal/remote_alpha_migrate_es_service_user.sh`

When remote staging is used through `--ssh-target`, the helper must stage only
the minimal helper files required for this migration surface:

- `scripts/remote_alpha_migrate_es_service_user.sh`
- `scripts/internal/remote_alpha_migrate_es_service_user.sh`
- `scripts/remote_alpha_check_es_writable_state_readiness.sh`
- `scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`

The repo-side upload step must preserve the exact remote relative paths the
root-owned install step later consumes:

- `<upload-root>/scripts/remote_alpha_migrate_es_service_user.sh`
- `<upload-root>/scripts/internal/remote_alpha_migrate_es_service_user.sh`
- `<upload-root>/scripts/remote_alpha_check_es_writable_state_readiness.sh`
- `<upload-root>/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`

Execution must still run only from a root-owned staged path under
`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/`, not from
a user-writable upload directory, and the staged provenance record must include
the local git commit when available, the sha256 of each staged helper file, the
remote staged path, and the remote owner/mode proving the staged tree was
root-owned before execution.

The required operator flow for this migration surface is:

1. Run `scripts/remote_alpha_migrate_es_service_user.sh --ssh-target <user@host>`
   first. That default invocation must remain non-mutating `--check-only`.
   The default staged-wrapper path must perform a noninteractive `sudo -n`
   preflight and fail cleanly with structured `sudo_unavailable` evidence
   before any helper upload or root-owned staging when passwordless sudo is
   unavailable. An explicit `--interactive-sudo` mode may be used only from a
   visible terminal when a bounded password handoff is authorized. Interactive
   staged execution must fetch check-only/apply outputs from user-owned remote
   artifact files rather than redirecting tty-backed SSH stdout directly into
   the local evidence files, and interactive check-only should avoid reopening
   multiple password-backed SSH legs for staged install, stage-stat capture,
   and helper execution.
2. Review the machine-readable check-only JSON before any later live apply.
   Apply readiness must stay blocked unless the helper reports:
   - a narrow `es:es` account/group
   - readable ES config/TLS material for `es:es`
   - passing long-lived ES startup validation for the target service user
   - manageable `execution.staging_root_dir` and
     `execution.results_root_dir` for `es:es`
   - no active runs and no runs that cannot be ruled out safely
   - passing `future-non-root-required` writable-state readiness evidence
   - a valid helper-private SPIRE runtime input path proved as operator-side readiness evidence rather than as a direct `es:es` raw-socket read requirement
   - a plannable systemd service-user change and rollback path
3. Treat check-only as planning evidence only. It is not proof and it is not a
   host mutation.
4. Use `--apply` only after explicit approval, rollback readiness, and the
   check-only gate above all pass.
5. Preserve the apply summary, backup path, rollback notes, exact
   `es.service` drop-in change, unchanged bounded compatibility edges, and
   post-apply `/health` plus `GET /v1/executions:contract` validation as the
   bounded post-apply evidence set.
   The helper staging record must distinguish `sudo_unavailable` from
   `wrapper_tooling_error`, record whether staging occurred, whether the
   check-only helper ran, and whether transient staging was removed.
6. Remove transient staging after collection unless
   `--keep-staging-on-failure` is requested.
7. Do not widen this helper flow into Nomad task-user changes, helper or
   selector redesign, Vault handoff redesign, or governed proof.

When `--output-dir` points at an Infrastructure Manager profile directory such
as `.out/remote-alpha-m75q`, the wrapper must write predictable local
artifacts:

- `es-service-user-migration-check-only.json`
- `es-service-user-migration-helper-staging-record.json`
- `es-service-user-migration-apply-summary.json` when `--apply` is used
- `es-service-user-migration-apply-stdout.txt` when `--apply` is used

Those local artifacts are migration evidence and provenance only. They are not
governed proof, they do not prove full ES/runtime de-root, and they do not
change the accepted Alpha fact that the root-start helper, Nomad task user
model, helper-private SPIRE traversal, broad selector scope, and workload-zone
Vault handoff remain bounded compatibility edges until a later redesign slice
changes them explicitly.

For later preserved-root cleanup/archive planning only, the repo-local helper
surface is:

- `scripts/remote_alpha_plan_old_root_cleanup.sh`

That helper must consume only local `*-apply-summary.json` artifacts. It must
not SSH, must not use `sudo`, must not mutate the live host, and must not
archive or delete anything. While the rollback window remains active, its
default recommendation must stay `retain`.

The current branch does not yet implement a live preserved-root
cleanup/archive executor. Any later operator helper for that action must stay
separate from this planner, must require explicit `check-only` and `apply`
modes, must run only after the rollback window is explicitly closed and
preserved old-root evidence is archived elsewhere or explicitly deemed
unnecessary, must require operator signoff, must not recursively `chown` old
roots, and must not delete by default.

The current bounded live state after that later apply is now the converse of
the earlier check-only posture: the long-lived `es.service` is already running
as `User=es`, `Group=es`, `UMask=0027`; ES config/TLS prep is applied; stable
writable-state roots are prepared; post-apply `/health`,
`GET /v1/executions:contract`, the current lowest-cost existing happy path, and
future writable-state readiness all passed; and the old root-era staging/results
roots remain preserved as rollback/debug/evidence state. This still does not
claim full ES/runtime de-root.

For bounded rollback rehearsal after that completed service-user change, the
repo now carries the local-only checker
`scripts/remote_alpha_es_service_user_rollback_rehearsal.sh`. Its default
input is `.out/remote-alpha-m75q`, and it emits:

- `es-service-user-rollback-rehearsal.json`
- `es-service-user-rollback-rehearsal.md`

That rehearsal is non-mutating and local-evidence-only. It must not SSH, use
`sudo`, mutate the live host, execute rollback, run ES apply, run governed
proof, or do PR/merge prep. It must classify findings as `pass`, `warning`, or
`blocker` while verifying that the service-user backup path is recorded, the
previous service unit/drop-in state is recorded, the bounded drop-in remains
limited to `User=es`, `Group=es`, and `UMask=0027`, rollback notes exist, the
binary-deployment backup plus writable-state backup/quarantine paths are
referenced, old root-era staging/results roots remain preserved as
rollback/debug/evidence state, and no recorded rollback instruction requires
recursive chown or broad deletion.

The current branch does not require or implement a live rollback executor
while the current `User=es`, `Group=es`, `UMask=0027` service posture remains
healthy. Any later rollback execution helper must remain recovery-only, must
stay bounded with explicit `check-only` and `apply` modes, and must not be run
live unless operationally necessary.

`--dry-run` is an accepted alias for that same non-mutating repo-side check.
That check-only path must perform discovery and validation only. It must emit a
machine-readable JSON plan/report to stdout and must not create users or
groups, call `chown` or `chmod`, rewrite systemd units or drop-ins, create a
backup directory under `/var/tmp/execution-substrate-remote-alpha/`, restart
`es.service`, delete staging/results, or run governed proof. It may inspect the
current `es.service` posture, current config/TLS dependency paths, writable
state owner/mode state, active-run evidence, and the
`future-non-root-required` writable-state readiness checker output.

Before any apply-mode mutation primitive runs, the helper must create a
timestamped backup directory under
`/var/tmp/execution-substrate-remote-alpha/`. That backup directory must:

- copy the pre-apply ES config into `es.json`
- copy the current `es.service` unit fragment plus any current drop-ins
- write `pre-apply-snapshot.json`
- record the pre-apply config/TLS path, owner, group, mode, and sha256 for
  each current ES TLS/dependency input path
- record the current `es.service` `User`, `Group`, `ActiveState`, and
  `SubState` before apply
- record staging/results root owner/mode summary plus active-run evidence
- record rollback notes for restoring the pre-apply service-user posture

If the target host already has an `es` user/group, the helper must prove that
the pre-existing service account is still acceptably narrow for this slice before
it is reused. At minimum, that check must confirm primary group `es` and no
supplementary groups; otherwise the helper must fail instead of silently
claiming a dedicated narrow account/group.

For this sealed ES service-user migration slice, the host-local helper must not
accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`,
`REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`,
`REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`,
`REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`,
`REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`,
`--service-group`, `--binary-path`, `--config-path`,
`--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or
`--service-dropin-path` as mutable inputs. The helper must fail fast instead of
silently retargeting the service-user migration away from the repo-owned ES
posture. Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for
apply output placement.

The summary schema for this host-local migration record is:

- `execution-substrate.remote-alpha.es-service-user-migration-summary.v1`

The current host-local non-secret apply summary for that migration step is:

- `/var/tmp/execution-substrate-remote-alpha/es-service-user-migration-summary.json`

Apply mode writes that file. Check-only must not create it; instead it must
emit stdout JSON in the same schema family with `mode.name=check_only`,
`mode.non_mutating=true`, `proof.check_only_is_not_proof=true`,
`proof.host_mutation_performed=false`, a boolean `plan.apply_ready`, a
`bounded_compatibility_edges` array, and
`not_claimed.full_es_runtime_deroot=true`. Apply may change only the bounded
`es.service` account drop-in needed to set `User=es`, `Group=es`, and
`UMask=0027`, run `systemctl daemon-reload`, restart `es.service` at most once,
and validate `User=es`, `Group=es`, `/health`, and
`GET /v1/executions:contract` afterward. This is a bounded service-user
migration record only; it is not governed proof, not full ES/runtime de-root
evidence, and not a redesign of the accepted compatibility edges above.

The summary must stay limited to bounded safe evidence such as:

- preflight blocker and warning classification for service-account narrowness,
  config/TLS readability, target-service-user startup-validation readiness,
  helper-private SPIRE runtime-input validation, writable-state
  manageability, active-run/drain evidence, future-non-root-required
  readiness evidence, and the plannable systemd drop-in change
- the explicit list of bounded compatibility edges left unchanged
- the pre-mutation backup path plus rollback notes
- the exact `es.service` drop-in lines applied in live mode
- post-apply `User=es`, `Group=es`, `/health`, and
  `GET /v1/executions:contract` validation results
- explicit non-claim vocabulary for full ES/runtime de-root, Nomad task-user
  changes, helper-private SPIRE traversal changes, selector-model changes,
  Vault/workload-zone handoff changes, and governed proof

That summary and any derivative artifacts accepted as evidence for this step
must not persist TLS private keys, JWT-SVIDs, Vault tokens, API keys, other
secret payloads, or raw retained-result bundles.

The active repo-derived inputs for this migration helper remain:

- service name `es`
- service account user `es`
- service account group `es`
- binary path `/usr/local/lib/execution-substrate/bin/es`
- config path `/etc/execution-substrate/es.json`
- healthcheck env path `/etc/execution-substrate/healthcheck.env`
- systemd unit path `/etc/systemd/system/es.service`
- systemd drop-in dir `/etc/systemd/system/es.service.d`
- systemd drop-in path `/etc/systemd/system/es.service.d/10-account.conf`

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
  `proof-secrets/data/runtime-identity-vault-login`, one exact proof-runtime
  secret read at `proof-secrets/data/codex-runtime-profile` for field
  `api_key`, and self-revoke, all without persisting the token or secret
  payload
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
- current required proof-runtime secret path `proof-secrets/data/codex-runtime-profile`
- current required proof-runtime secret field `api_key`

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

### Disposable Vault reset/rebootstrap helper

When the Remote Alpha Vault contents are disposable and the Shamir unseal key
is unavailable, operators may use one repo-owned reset helper to rebootstrap
the Alpha/internal Vault instance:

- `scripts/remote_alpha_reset_disposable_vault.sh`

This helper is a bounded recovery path for the sealed-and-unrecoverable Remote
Alpha Vault case. It is not production Vault lifecycle automation, not
Infrastructure Manager reconciliation, not a CP/ES governed proof, not submit
readiness, not runtime-profile readiness, and not a general deployment
architecture.

Required behavior for this helper:

- default to `--dry-run` and perform read-only inspection only
- require `--execute-reset` for destructive reset
- allow `--unseal-only` when the operator has the existing Shamir unseal key
  and wants to bypass raft reset and Vault init
- require interactive stdin and stdout before destructive or secret-producing
  steps
- print the raft storage path and require the exact confirmation phrase
  `RESET DISPOSABLE REMOTE ALPHA VAULT` before moving any storage
- reject empty, non-absolute, or broad raft paths such as `/`, `/var`,
  `/var/lib`, `/opt`, `/home`, `/etc`, `/usr`, or `/tmp`
- stop the Vault systemd service before moving storage
- move the old raft path to a timestamped sibling backup rather than deleting
  it
- recreate the raft path for the Vault service user and group with restrictive
  permissions
- start Vault and run `vault operator init -key-shares=1 -key-threshold=1` in
  the operator's interactive terminal without redirecting, teeing, or logging
  the output
- pause so the operator can store the printed unseal key and root token in a
  private password manager
- run `vault operator unseal` interactively and never pass the unseal key as a
  command-line argument
- verify the post-unseal state reports `sealed=false`
- optionally run the repo-supported workload-auth checker after unseal when
  the operator requests `--post-unseal-check`
- print the Mac-side Infrastructure Manager live-refresh command after
  completion

The helper must use `set +x`, `umask 077`, and must not write generated secret
values to repo files, `.out`, logs, support bundles, retained bundles, reports,
shell history, or script output. The helper may print non-secret status such
as service state, config path, selected raft path, timestamped backup path,
Vault initialized/sealed booleans, and checker paths. It must not print,
capture, persist, or relay Vault unseal keys, root tokens, client tokens,
TLS private keys, SPIFFE private material, API keys, raw prompts, JWT-SVID
bodies, or secret payloads.

`--unseal-only` is non-destructive but still secret-sensitive. It may start the
Vault service when needed, wait until the Vault CLI can read seal status, run
`vault operator unseal` interactively, verify `sealed=false`, optionally run
the repo-supported workload-auth checker after unseal, and print the Mac-side
Infrastructure Manager refresh command. It must not move the raft path, run
`vault operator init`, create reset backups, or ask for the destructive reset
confirmation phrase.

After a manual reset/rebootstrap, operators must refresh Infrastructure
Manager evidence from the Mac side before treating runtime-identity readiness
as current:

```bash
cd "/Users/ds/Repositories/Infrastructure Manager"
PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \
  --profile-dir ".out/remote-alpha-m75q" \
  --ssh-alias host_to_remote_linux_m75q
```

Only after that refresh reports unsealed, fresh Vault/workload-auth evidence
should operators consider rerunning the bounded CP/ES proof path. The reset
helper itself must never run the full CP/ES proof.

### Remote Vault evidence

The current canonical non-secret evidence summary for this slice remains on the
Remote Alpha host at:

- `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`

The repo-owned direct host-local check path for this slice is:

- `sudo scripts/remote_alpha_vault_workload_auth_check.sh`

That command is a host-local root check. The P0n Mac-side operator facade route
may stage only the public wrapper and its internal helper to the Remote Alpha
host and invoke only the staged public helper through:

- `scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check
  --ssh-target <target> --interactive-tty`

The Mac-side route does not copy the summary back to Mac `.out`, does not print
full summary JSON, and does not create an operator summary. Both the direct
helper path and the Mac-side staged route are evidence/projection only. They do
not install ES, AGS, ARS, or EGS, do not build the normal-shell image, do not
call ES `:prepare` or `:submit`, do not change ES public contracts, do not
bootstrap workload auth, and do not make ES a Vault token broker.

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
- `auth_smoke.proof_runtime_secret = pass`
- `auth_smoke.token_revoked = pass`

`auth_smoke.token_lookup` uses the documented Vault token self-lookup endpoint,
`GET /auth/token/lookup-self`, and therefore requires `read` capability on that
path. The current intended source for that capability is Vault's attached
`default` policy rather than an extra compatibility policy stanza.

When JWT fetch passes but Vault JWT login fails, the same v1 summary may include
backward-compatible safe triage fields under `auth_smoke`: login failure phase
`vault_login`, a safe `vault_login_failure_class`, optional
`vault_login_http_status`, `vault_login_error_count`,
`vault_login_error_class`, and `vault_login_raw_error_recorded=false`. The
helper may also record `auth_smoke.jwt_issuer_verified` as `true`, `false`, or
`unknown`, `auth_smoke.jwt_issuer_expected_source`,
`auth_smoke.jwt_issuer_expected_class`, and
`auth_smoke.jwt_issuer_actual_class` when it can compare the JWT issuer to the
repo-derived bound issuer without printing the JWT. For issuer comparison, the
helper must understand the same SPIRE bundle JSON shape
used by bootstrap, including `trust_domains` maps keyed by bare trust-domain
labels, so a parseable repo-derived bound issuer does not degrade to `unknown`.
For an
`invalid_issuer_or_validation_key` login failure, it may record
`auth_smoke.vault_login_failure_alignment_hint` as a safe label such as
`issuer_mismatch`, `validation_key_mismatch_or_rotation`, or
`issuer_or_key_unknown`. The safe classes are:
`auth_mount_missing_or_unreachable`, `role_missing_or_rejected`,
`invalid_jwt`, `invalid_audience`, `invalid_subject`,
`invalid_issuer_or_validation_key`, `permission_denied`, `vault_api_error`,
`invalid_response`, `tls_or_connectivity_error`, and `unknown`. These labels do
not persist raw Vault error strings, raw Vault response bodies, raw HTTP
headers, Authorization headers, stack traces, JWT-SVIDs, Vault tokens, root
tokens, unseal keys, proof secret values, API keys, or private keys.

### Remote Vault service-user migration

Remote Supported-Host Alpha may also use one separate bounded Vault
service-user migration surface without changing ES public contracts, Nomad
task-user behavior, SPIRE socket exposure, or Vault token brokerage.

The repo-owned public wrapper for that surface is:

- `scripts/remote_alpha_migrate_vault_service_user.sh`

Its sourced implementation is:

- `scripts/internal/remote_alpha_migrate_vault_service_user.sh`

The summary schema for both the check-only and apply artifacts is:

- `execution-substrate.remote-alpha.vault-service-user-migration-summary.v1`

The default local artifact names for that surface are:

- `/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-check-only.json`
- `/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-apply-summary.json`

Default behavior must stay `check_only` and non-mutating. That preflight must:

- validate the target dedicated Vault service account, typically `vault:vault`
  or a configured equivalent
- inspect the current Vault service identity without mutating it
- inspect the planned Vault systemd drop-in or equivalent unit changes
- validate the Vault config read path, any local storage path, any log path,
  any audit-device path, and TLS read paths needed by Vault
- fail closed if the summary would persist Vault tokens, root tokens, unseal
  keys, JWT-SVIDs, PEM private keys, API keys, Codex credentials, or raw
  secret payloads
- preserve workload-side Vault JWT login through
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- preserve `es_vault_token_brokerage=false`

When that non-mutating check-only collection cannot actually run because the
documented root prerequisite is missing, the helper must still emit the same
canonical check-only artifact as honest blocked evidence instead of silently
omitting Vault evidence or claiming success.

- if `id -u != 0`, the helper must probe noninteractive root with a behavioral
  check such as `sudo -n true`
- if that prerequisite probe fails, the helper must emit
  `vault-service-user-migration-check-only.json` in the same schema family with
  `collection_status = "preflight_blocked"` or equivalent
- that blocked artifact must record the exact missing prerequisite, the
  attempted prerequisite command, `mode.name = "check_only"`,
  `mode.non_mutating = true`, `plan.apply_ready = false`,
  `apply_performed = false`, `governed_smoke_performed = false`, `blockers`,
  `skipped_checks`, `redaction`, `non_authority_labels`, and the explicit
  non-claim labels below
- the blocked artifact must not claim that Vault service-user migration passed,
  that apply ran, that Vault is production-ready, that governed execution was
  proved, that full ES/runtime de-root or a rootless Nomad client was reached,
  or that ES brokers Vault tokens
- if noninteractive root is available later, the existing real check-only
  behavior must remain intact and must continue to produce the same canonical
  check-only artifact path with real discovery results

Apply for that surface must require explicit `--apply` and a successful
check-ready preflight artifact or equivalent rerun of the same checks. Before
mutation it must create backup evidence and rollback notes. The mutation scope
must stay limited to the dedicated Vault service account posture, the Vault
systemd drop-in, and the minimum config or storage or log or audit or TLS
ownership or readability changes needed for Vault.

The apply summary must record changed paths, backups, rollback path,
post-apply checks, skipped checks, redaction status, and explicit non-claims.
Required post-apply checks are Vault `/v1/sys/health` or an equivalent local
health check, ES `/health`, and ES `GET /v1/executions:contract`. Lowest-cost
governed execution smoke must run only when the operator supplies the
documented smoke profile plus command; otherwise the summary must record that
smoke as `skipped`, not passed.

The explicit non-claims for that surface must stay label-based and include:

- `not_vault_production_ready`
- `not_governed_execution_proof`
- `not_full_es_runtime_deroot`
- `not_full_nomad_client_deroot`
- `not_spire_redesign`

Required non-authority labels for the check-only artifact, including the
blocked prerequisite case, must stay label-based and include at least:

- `not_service_health`
- `not_submit_readiness`
- `not_runtime_profile_readiness`
- `not_producer_contract_compatibility`
- `not_retained_result_readiness`
- `not_governed_proof`
- `not_workload_credential_success_proof`
- `not_vault_production_ready`
- `not_support_bundle_authority`

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
- `auth_smoke.jwt_issuer_verified`
- `auth_smoke.jwt_issuer_expected_source`
- `auth_smoke.jwt_issuer_expected_class`
- `auth_smoke.jwt_issuer_actual_class`
- `auth_smoke.vault_login_failure_alignment_hint`
- `auth_smoke.vault_login`
- `auth_smoke.token_lookup`
- `auth_smoke.proof_read`
- `auth_smoke.proof_runtime_secret`
- `auth_smoke.token_revoked`
- `auth_smoke_requirements.token_lookup_required`
- `auth_smoke_requirements.proof_read_required`
- `auth_smoke_requirements.proof_runtime_secret_required`
- `auth_smoke_requirements.token_revoked_required`
- `auth_smoke_requirements.proof_read_path`
- `auth_smoke_requirements.proof_runtime_secret_path`
- `auth_smoke_requirements.proof_runtime_secret_field`
- `proof_runtime_secret.status`
- `proof_runtime_secret.path`
- `proof_runtime_secret.field`
- `proof_runtime_secret.field_present`
- `proof_runtime_secret.field_nonempty`
- `proof_runtime_secret.field_shape`
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
