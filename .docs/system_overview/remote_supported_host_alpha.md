# Remote Supported-Host Alpha 0.3

## Purpose And Status

Remote Supported-Host Alpha 0.3 is an intermediate alpha for a Control Plane consumer running on a Mac against one remote Linux Execution Substrate host. It extends Alpha 0.2 with a fixture-driven readiness report that combines Control Plane profile diagnostics and Infrastructure Manager remote-doctor output; it does not change ES runtime semantics.

It is not the final commercial deployment target. Full remote Control Plane plus remote Execution Substrate with the operator's Mac browser as the human surface, remote Temporal, HA, object storage, and source/workspace sync models remain out of scope for this alpha.

Status classification:

- The direct CP-to-AGS/ES HTTPS+mTLS boundary is a bounded alpha acceptance posture.
- Bridge or tunnel mode is a temporary compatibility edge for supported-local and troubleshooting lineage, not product posture.
- The current `execution_substrate.runtime_profile` annotation, `control-plane-normal-shell/v1`, producer contract version, outcome evidence, lifecycle projection, retained-result behavior, and authority handoff remain unchanged.
- The combined readiness report is pre-live fixture reporting, not ES service health, submit readiness, retained-result proof, lifecycle truth, runtime authority, or run authority.

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

Current implementation status through P0n:

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
  interactive TTY `vault-reset-disposable --execute-reset` submode, and the
  P0n Mac-side interactive TTY `vault-workload-auth-check` submode. Its safe
  modes do not use SSH or remote staging, inspect live host state, dispatch
  generic helpers, or execute destructive or authority-bearing work. Its
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
- The script prints Mac-side Infrastructure Manager refresh and support-bundle
  commands only. It does not invoke Infrastructure Manager refresh or
  support-bundle collection; the readiness session prints those commands as
  follow-up evidence/provenance actions only, and the recovery session may print
  those commands as next-step text only.
- P0n implements only the explicit Mac-side workload-auth evidence route
  described here, in addition to the previously landed reset/unseal and
  readiness routes. Runtime identity summary, Vault service-user check, runtime
  security check, post-unseal check combination, live execute-reset validation,
  workload-auth bootstrap, preinstalled helper bundles, generic helper
  dispatch, and all other staged `es-*` helper delegation remain not
  implemented and require later audited slices.
- `vault-workload-auth-bootstrap` remains blocked/reopened and unavailable in
  v1.
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
workload-auth bootstrap and not a token broker. In these topologies the facade
itself does not prompt for, read, type, log, relay, persist, summarize, or
accept the unseal key, root token, client token, Vault token, API key, private
key, password, JWT-SVID payload, proof secret material, or secret payload.
Future Vault, reset, unseal, or workload-auth prompts may be allowed only in
explicit secret-sensitive modes, silent where appropriate, and never through
CLI arguments, environment variables, environment files, local or remote files,
logs, reports, `.out`, support bundles, retained bundles, CP artifacts, helper
summaries, readiness outputs, printed commands, or Codex output. The P0m
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
  --interactive-tty`.
- Remote-host only: P0i `recovery-session vault-unseal-existing --host-local`,
  runtime identity summary and Vault service-user check. The host-local
  workload-auth helper remains available as a direct helper, but P0n adds the
  Mac-side operator topology for that evidence route. P0m does not add a
  host-local execute-reset route through the operator facade; the reset
  helper's direct host-local capability remains outside the P0m
  operator-facade route.
- Not v1 except the P0j unseal-existing route, the P0k reset dry-run planning
  route, the P0m explicit execute-reset operator route, and the P0n
  workload-auth evidence route: generic remote staging, arbitrary shell
  passthrough, post-unseal/runtime identity/IM/support-bundle/CP-proof
  bundling, live execute-reset validation, or Vault workload-auth bootstrap.

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
10. later separate audit/live-validation and post-reset evidence slices before
   any live destructive execute-reset validation or post-reset authority claim
11. separate workload-auth bootstrap design only if still needed

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

The proposed `vault-workload-auth-bootstrap` surface is blocked/reopened for
now. The repo currently has reset/unseal/check helpers but no safe Remote
Alpha helper that bootstraps Vault JWT auth, Vault roles, or proof secrets
after reset without root-token handling. This docs/static-test prep slice does
not design root-token automation.

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
