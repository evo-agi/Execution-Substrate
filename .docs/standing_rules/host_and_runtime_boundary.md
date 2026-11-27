# Host And Runtime Boundary Standing Rules

These are the standing rules of the current host and runtime boundary slices:
the named slice rules for the supported-local execution roots and the users the
bring-up launchers run as, the Remote Alpha hardening history and current
retirement, Milestone 1 (the least-privilege runtime/security boundary
closeout), the Remote Alpha ES config/TLS ownership prep slice, and the Remote
Alpha host network boundary slice. They moved here unreworded from `PLANS.md`
at `trunk_dev` commit `0b9278ca74404b46b5e9f0e1701874b52687f5e8`, so that
`PLANS.md` holds intent and order. The first section holds the four named rules
that were bullets of "Current bounded implementation status" in the `PLANS.md`
section "Document Scope And Current Implementation"; the other sections are the
`PLANS.md` sections of the same names.

The detailed Remote Alpha host contracts are in
`.docs/system_overview/remote_supported_host_alpha.md`.

Edit a rule here in place when it changes. Do not add dated status entries: say
what a change did in its pull request description. Cite this file by section
heading, never by line number.

## Supported-local execution roots and launcher users

- `SUPPORTED-LOCAL-ROOT-OWNER-01` is a bounded supported-local configured-consumer integration refinement. The selected rootful, identity-mapped generic ES service profile is UID:GID `0:0`: canonical setup must require a fresh proof root and create only its two fresh configured execution roots as `0:0` with exact `0755` directory mode through a narrow noninteractive privileged helper. The generated profile requires one read-only validator of that static owner/mode contract, proof binding, service image, config, and exact same-path read-write mounts in prepare-only bring-up, the ES launcher, and full-profile submit-readiness (including direct health check and diagnostics use). The ordinary operator needs static inspection access, not write authority to service-owned roots. Generic callers without this explicit profile retain caller-writable readiness; unknown profiles refuse. A fixed safe setup projection records that static owner/mode check in retained proof evidence without paths, key material, or a claim that container capability passed. Existing failed proof roots remain for separately bounded cleanup rather than in-place owner migration. Prepare-only orchestration retains configured Submit, key loading and root capability qualification before listening. ES's `0750` per-run natural-directory capability rule, external result-auth key, and workload `10000:10000` boundary remain unchanged. Review-15's failed full check did not capture its first failed subcheck; this source-demonstrated readiness mismatch does not retrospectively identify that subcheck. Offline fixtures do not qualify a future container view or live supported-local proof; independent review and live proof remain open.
- `R14-ROOT-CUSTODY-01` refines only that helper's fresh-child custody: it must bind each visible fixed child to the same held descriptor before owner/mode normalization, retain both descriptor identities through a final pair check, and refuse drift without repair or cleanup. The operator-owned proof parent permits an independent writer to replace an entry between `mkdir` and descriptor acquisition; those calls are not atomic creation-and-open proof. No protected creation namespace or proof-parent ownership change is selected here. This bounded source repair closes the initialized-descriptor/reopened-name substitution, while arbitrary concurrent pre-acquisition interference remains an explicit design and live-proof limit.
- `GENERIC-ES-LAUNCHER-USER-01` is a **Bounded slice rule** refinement of the generic (no-profile) ES launcher. That path creates missing execution roots as the calling operator and requires them to be caller-writable, while configured-Submit startup requires ES's naturally created `0750` result directory to carry the roots' UID and GID. The launcher therefore runs the ES container as the caller's effective UID and primary GID instead of the image's default root user, so ES holds no more host authority than the operator who started it. It reads both IDs with `id` before any image, root or container effect and refuses unless both are numeric, because `docker run --user` with an empty UID runs as root. Docker gives that identity no supplementary groups, so the roots must carry the caller's UID and primary GID, and every file the ES config names must be readable by that UID or GID. ES's behavioral startup checks stay the only capability gate; the launcher does not branch on daemon labels. On a user-namespace-remapped Docker daemon, Docker itself refuses the host networking that bring-up requires, so bring-up stops at its host-loopback check and ES never starts; rootless Docker is untested and unsupported for bring-up. The `service-root-v1` profile keeps the image's default user for its `0:0` roots. `GENERIC-SERVICE-LAUNCHER-USER-01` applies the same identity to the other bring-up services.
- `GENERIC-SERVICE-LAUNCHER-USER-01` is a **Bounded slice rule** refinement of the bring-up launchers for ARS, EGS and AGS. They run their containers as the caller's numeric effective UID and primary GID instead of the image's default root user, through the same `control_plane_operator_user` helper as the generic ES launcher, which refuses before any image, storage or container effect unless both IDs are numeric. None of the three needs root in bring-up: the documented ports (8442 to 8445) are unprivileged, so a configured port below 1024 now fails to bind unless the host allows unprivileged binding there, and none of them changes file ownership. EGS and AGS only read their config and TLS files. ARS writes its blob store and index as `0600` files, so `scripts/02_start_ars.sh` (and `scripts/01_bringup.sh up`, before starting any service) first checks that ARS can use its storage. On the host, as the caller, the check only reads the config: `storage.root_dir` and `storage.index_file` must be absolute and written in normal form, as Python's `os.path.normpath` writes it (no `.` or `..` component, no repeated or trailing slash, no leading or trailing whitespace; POSIX keeps a leading `//`), because ARS opens both exactly as written while the mounts it gets use the normal form, so only a path in normal form means the same file to both; the refusal names the form to write. A missing storage root is created as the caller instead of letting Docker create the bind source as root, and the index file must already exist as a regular file, not a symbolic link (ARS refuses to start without it, and replaces it with a regular file at its first write). The check then does what ARS does with that storage in a short-lived container that runs exactly as ARS will: the control-plane image, the UID:GID that `control_plane_operator_user` printed, so with no supplementary groups, the mounts `control_plane_mount_specs ars` gives ARS, and ARS's container name, so Docker refuses the check while an ARS container still exists (`02_start_ars.sh` removes the container it replaces first). In that container it changes into every directory on the way to the storage root and the index directory, creates and removes a file in the index directory, creates a file in every directory under the storage root and finds it again by listing that directory, opens the index and every regular file under the root for reading, refuses any other entry under the root (a symbolic link or special file, which ARS never creates, and a link ARS would pass through at a blob or shard path), removes the files it created in batches and refuses the first directory where ARS could not remove its own file, and last, only when all of that passed, writes the index the way ARS does: a new `0600` file with the index's content, renamed over it. The kernel, and on macOS Docker Desktop's file sharing, therefore decides every step for that identity through the mounts ARS will see; owners, groups, modes, POSIX ACLs and the sticky rule are not emulated, and UID 0 gets what root gets in a container. A passing check leaves the index owned by that identity with mode `0600`, as ARS's first write would. Stopped by SIGHUP, SIGINT or SIGTERM, which covers Ctrl-C and the way `scripts/01_bringup.sh` stops ARS's launcher when `up` fails, the check passes the first such signal on to its probe and waits until the probe has removed its files and ended, however often it is signalled again; a probe killed outright, for example by `docker rm -f`, can leave at most one batch of its empty `.ars-storage-check.*` files, those of 256 directories, which the next check reads as ordinary files. The check needs `/bin/sh` with `mktemp`, `xargs`, `rm`, `cat`, `chmod` and `mv` in the image, which the generated image's Alpine BusyBox provides. Its walk uses only shell built-ins per directory and starts no process per directory, because ARS's blob layout `sha256/xx/yy/<digest>` grows to 65,794 directories with the root; at that size the check took 10 to 20 s in the cloud test container, varying from run to run. `TestARSStorageCheckScalesToARSFullFanOut` pins that cost by structure, not by time: it counts the processes the check starts at that size, about 540 with removal in batches of 256 directories, and requires fewer than one per 32 directories. `scripts/01_bringup.sh up` runs the check itself and ARS's launcher runs it again before it starts ARS; ARS's readiness wait (`READY_TIMEOUT_SECONDS`) starts only once the launcher reports that its check passed, through a file `02_start_ars.sh` writes after the check, so the check's time never counts against ARS's readiness and the report cannot skip the check. If the launcher stops before that, `up` fails with the end of its log. `scripts/01_bringup.sh up` derives that identity before any image, storage or container effect, like the launchers. Storage that an earlier bring-up wrote as root, or that is shared through another group, fails that check with the exact `sudo chown` that hands it back, and a directory above the storage that the identity cannot search is refused with its path; the check does not repair ownership itself. Every file named in an ARS, EGS or AGS config must be readable by the caller's UID or primary GID, because Docker gives the container no supplementary groups. The `service-root-v1` profile concerns only ES's roots, so these services run as the caller under it too.

## Remote Alpha Hardening History and Current Retirement

`Temporary compatibility edge`: archived v1 evidence records an earlier Remote
Supported-Host Alpha hardening exercise. It is historical evidence only and is
not current host truth, readiness, migration authority, or permission to reuse
an old or nonempty host. Current ES-owned existing-host writable-state,
service-user, ownership, staging, rollback-generation, and old-root-planning
routes are retired through fixed fail-closed tombstones. No v2 replacement is
defined for that retired ES writable-state/service-user migration family. The
unrelated current EGS hardening v2 schema remains current.

- AGS is already de-rooted and sealed in this tranche; preserve the landed
  `ags:ags` service posture and its existing host-local summary/evidence shape.
- ARS is already de-rooted in this tranche; preserve the landed `ars:ars`
  service posture, its dedicated TLS/state ownership model, and its existing
  host-local summary/evidence shape.
- EGS is already de-rooted in this tranche; preserve the landed `egs:egs`
  service posture and its existing host-local summary/evidence shape.
- ES config/TLS prep is applied and productized for the live host.
- Archived v1 files may record that an earlier host had prepared ES writable
  roots, ran `es.service` as `User=es`, `Group=es`, `UMask=0027`, and passed
  bounded checks. Those records do not establish current state, readiness, or
  apply authority and cannot be refreshed by the retired routes.
- This tranche does not claim full ES/runtime de-root.
- The root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad root selector posture, and Vault/workload-zone
  handoff remain bounded compatibility edges. Workstream F slice F1 removes
  the broad root selector posture and the one shared Vault role with WI-3; it
  keeps the other three.
- The long-lived ES startup path keeps
  `execution.spire_workload_api_socket_path` as a config-shape and submit
  input only; runtime-helper failure to use that helper-private raw SPIRE path
  remains explicit and fail closed. The retired helpers no longer prove that
  host dependency.
- Old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by inertia.
- The former old-root cleanup/archive planner is retired. Archived summaries
  cannot authorize archive, deletion, ownership change, drain, fence, or any
  other host mutation.
- This tranche must not change ES public contracts or Control
  Plane/Infrastructure Manager ownership boundaries.
- This tranche preserves the direct Mac -> AGS/ES HTTPS+mTLS posture, the
  current EGS loopback-only dependency path, the landed AGS/ARS service
  postures, and the no-bridge/no-shared-filesystem remote posture.
- This tranche may now use one separate operator-owned Vault service-user
  migration helper. That helper must stay check-only by default, explicit
  apply only, bounded to Vault host/service hardening, and must not widen into
  ES public API changes, Nomad task-user changes, SPIRE boundary changes, or
  Vault token brokerage.
- This tranche may carry one disposable Remote Alpha Vault reset/rebootstrap
  operator script for the sealed-and-unrecoverable Shamir-key case. That script
  must stay dry-run by default, require an interactive TTY plus the exact
  destructive confirmation phrase before reset, move the existing Vault raft
  path to a timestamped backup rather than deleting it, run Vault init/unseal
  only in the operator's interactive terminal, and never persist or relay
  unseal keys, root tokens, client tokens, TLS private keys, SPIFFE material,
  API keys, or raw prompts. It is a bounded Alpha recovery helper only; it is
  not IM automation, Vault production lifecycle, CP/ES proof, submit
  readiness, runtime-profile readiness, or a broader deployment architecture.
  The same helper may provide a non-destructive `--unseal-only` path for the
  case where the operator still has the Shamir unseal key; that mode must not
  move storage or run Vault init, and must still require an interactive TTY and
  interactive `vault operator unseal` with no key material on the command line.
- This tranche is bounded host/service hardening only. Do not widen it into a
  runtime-boundary redesign or broader proof expansion.

## Milestone 1: Least-Privilege Runtime/Security Boundary Closeout

`Bounded slice rule`: Milestone 1 is named `least-privilege runtime/security
boundary closeout`.

Archived v1 evidence records a prior long-lived `es.service` service-user
change to `User=es`, `Group=es`, `UMask=0027`. That historical record is not a
current invariant, current readiness proof, or migration authority.

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
| Nomad host client/server substrate | `blocker` | The current supported substrate still depends on a pre-managed non-dev Linux Nomad client/server. Upstream least-privilege guidance is to keep Nomad servers as narrow as feasible, but the Linux Nomad client remains a root-managed isolation boundary today and a rootless client is not the current supported/well-tested repo posture. | Supported-host qualification still requires a pre-managed non-dev Nomad baseline, `scripts/01_bringup.sh check` still treats Nomad readiness as an environment gate, and the landed ES happy paths still hand lifecycle authority to Nomad rather than replacing it. | Revisit only if a later separately documented substrate decision proves a supported client posture that does not depend on an unsupported rootless-client assumption while preserving Nomad as lifecycle authority. | Milestone 1 does not claim a rootless Nomad client or full Nomad least-privilege closeout. |
| SPIRE raw-socket traversal and selector posture | `accepted MVP compatibility edge` | The workload-visible contract is already narrowed to `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, but the helper-private raw SPIRE path and the broad root selector scope remain explicit compatibility edges rather than a finished least-privilege identity model. | Slice `1A`/`1B` proof, runtime-helper source and tests that keep the raw SPIRE path out of workload env, and the remote runtime-identity helper summary preserve the helper-private boundary. Retired existing-host migration artifacts are historical evidence only and are not current boundary proof. | Revisit only through the later runtime-boundary redesign seam after a narrower helper principal or equivalent traversal model is documented and re-proved. Workstream F slice F1 removes the broad root selector scope with WI-3 and keeps the helper-private raw SPIRE path. | Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege. |
| Vault workload-side auth / workload-zone handoff | `accepted MVP compatibility edge` | The least-privilege direction is workload-side credential acquisition without ES token brokerage. The repo preserves that handoff boundary; where Vault host posture is operator-owned, the intended direction is a dedicated unprivileged Vault service account rather than root, but Milestone 1 does not widen ES contracts into full remote Vault lifecycle authority. | Useful credential flow completion is already landed, `scripts/remote_alpha_vault_workload_auth_check.sh` records bounded host-local evidence, and the current `authority_handoff` plus `readiness_not_claimed.*` vocabulary already preserve non-brokering, workload-side auth. | Revisit only if a later documented boundary change keeps workload-side auth intact and preserves the no-token-brokerage rule. | ES does not broker Vault tokens, and Vault/readiness summaries do not by themselves prove runtime-profile readiness or governed execution proof. |
| ES runtime helper | `accepted MVP compatibility edge` | The current helper isolates privileged runtime bootstrap from the long-lived ES service path, but it still starts from root and therefore remains a bounded compatibility edge rather than a full runtime de-root result. | Runtime-helper tests, supported-local proof, helper-death/task-fatal behavior, and the remote runtime-identity helper summary all prove the current fail-closed helper boundary. | Revisit only if a later redesign re-proves equivalent runtime identity delivery, workload launch, and result-path guarantees with a narrower startup privilege model. | Milestone 1 does not claim rootless helper startup or full ES/runtime de-root. |
| Nomad task user | `accepted MVP compatibility edge` | The current runtime companion still needs task-start `0:0` so it can create the helper-private SPIRE boundary and exec the workload as fixed non-root `10000:10000`. | The landed happy path still uses the current job-spec model, job-spec tests preserve `User: "0:0"`, and the runtime-helper/workload-boundary tests still depend on that task-start contract. | Revisit only as part of a broader runtime-boundary redesign that re-derives helper launch, workload launch, and SPIRE/Vault handoff together. | The current posture is not non-root task launch and not rootless workload orchestration. |
| Evidence/support artifacts | `accepted MVP compatibility edge` | Privilege-sensitive host evidence collection may still be necessary, but it must stay outside ES/CP authority boundaries and must not backdoor a broader runtime claim. | Remote doctor output, support-bundle summaries, staged-helper records, and apply summaries are all already documented as evidence/projection/provenance only. | Revisit only if later operator tooling reduces privileged collection without weakening the non-authority and non-proof boundary. | Support bundles, readiness reports, and apply summaries are not ES/CP/IM authority and are not governed execution proof by themselves. |

Milestone 1 now also carries one repo-owned Remote Alpha runtime/security
boundary posture checker as a bounded host-local evidence surface:

- `scripts/remote_alpha_runtime_security_boundary_check.sh`
- `scripts/internal/remote_alpha_runtime_security_boundary_check.sh`

That checker must default to `check_only`, stay non-mutating, classify the
current Nomad/runtime-helper/SPIRE/Vault/evidence posture honestly, and fail
closed if its output contains secret-like material or overclaim text. By
default it must not SSH, mutate services, change ownership, restart services,
archive files, or delete anything. It records evidence/projection only; it
does not change ES submit behavior, runtime-helper behavior, the current Nomad
task user, the helper-private raw SPIRE boundary, Vault token brokerage, or
governed execution proof claims. The same evidence surface may record
non-secret host/runtime/CVE inventory fields, including kernel and package
versions, Docker/Nomad runtime chain observations, FUSE/fuse-overlayfs,
Podman/crun, idmapped or `mount_setattr` path observations, and
vendor-observed CVE readiness classifications for CVE-2026-31431 and
CVE-2026-31465. CVE readiness classifications are `fixed`, `vulnerable`,
`not_affected`, `mitigated_not_fixed`, or `unknown`. For CVE-2026-31431,
`mitigated_not_fixed` may only mean vendor/package evidence still reports a
vulnerable host while non-mutating local evidence shows `algif_aead` is not
loaded and modprobe policy blocks autoload. That state is not a kernel patch,
not proof of production safety, and remains a blocker unless the checker is
run with an explicit bounded internal Remote Alpha mitigation-risk acceptance
flag.
Those fields remain evidence/projection only: they are not service health,
submit readiness, runtime-profile readiness, governed execution proof, full
ES/runtime de-root, rootless Nomad client proof, support bundle authority, or
CVE patch authority. Direct vendor status observation is evidence for CVE
classification only.

## Current Remote Alpha ES Config/TLS Ownership Prep Slice

`Bounded slice rule`: Remote Supported-Host Alpha may now extend the current
host-local hardening work with one separate ES config/TLS ownership prep slice.

`Current invariant`: this earlier bounded slice is already applied on the live
host and remains the source of truth for the dedicated `root:es` readable
config/TLS model consumed by the current `User=es` long-lived ES service.

- This slice introduces a dedicated ES-readable config ownership model and a
  dedicated ES-readable TLS directory for the current ES runtime config.
- This slice may create a narrow dedicated `es:es` prep account only to own
  readable ES config/TLS material for a later ES de-root step; it must not
  introduce a shared `execution-substrate` Unix-account model.
- At apply time, this slice kept the live `es.service` user/group posture
  unchanged.
- This slice must not change ES public contracts, the current SPIRE selector
  posture, current SPIRE socket traversal, Vault/runtime-helper semantics, or
  Nomad task user model.
- This slice must not move ES writable state, including staging and retained
  results ownership.
- This slice preserves the current AGS, ARS, and EGS service postures plus the
  direct Mac -> ES HTTPS+mTLS posture.
- This slice is bounded host-local config/TLS ownership preparation only. Do
  not widen it into ES de-root, Control Plane or Infrastructure Manager
  changes, or broader proof reruns; rerun only the small verification needed to
  validate the ES host-side apply and refresh the non-secret summary.

## Current Remote Alpha Host Network Boundary Slice

`Bounded slice rule`: Remote Supported-Host Alpha may carry one operator-run
host firewall for the box on the home network, defined in the section
"Remote Alpha Host Firewall" of
`.docs/system_overview/remote_supported_host_alpha.md`. It closes findings
INF-01 (containers reach the home LAN), INF-13 (ES and AGS listeners open to
the whole LAN) and INF-23 (SSH password login from everywhere, SSH on public
IPv6) of the 2026-11-23 infrastructure audit, as a short-term bridge until
the named workload identities, network grants and egress lanes of
Workstream F slice F1 land.

- Scripts: `scripts/remote_alpha_host_firewall.sh`,
  `scripts/internal/remote_alpha_host_firewall.sh` and
  `scripts/internal/remote_alpha_host_firewall.py`. Modes `--plan`
  (default, read-only), `--apply`, `--confirm`, `--status`, `--probe`,
  `--rollback`, `--render`.
- It owns only the nftables tables `inet es_host_firewall` and
  `bridge es_host_firewall`, its files under
  `/etc/execution-substrate/host-firewall`, the unit
  `es-host-firewall.service`, the sshd drop-in
  `/etc/ssh/sshd_config.d/00-execution-substrate-host-access.conf` and a
  transient rollback timer. It never touches Docker's, ufw's or other rules,
  other sshd files, Vault, Nomad or ES, and reads no secrets.
- One chain in its own table keeps the box's own connections to Vault on the
  bridge address as their source (an identity snat ahead of Docker's
  masquerade rule), so the Vault role's bridge-subnet limit sees the box as
  the bridge address and not as its LAN address. It is the ruleset's only
  address rewrite.
- The operator's choices live in the root-owned settings file
  `/etc/execution-substrate/host-firewall/settings.env`; adding a device that
  may call ES and AGS is a one-line change there.
- `--apply` arms an automatic rollback that only `--confirm` from an SSH
  connection opened after `--apply` cancels.
- Validation: rendering against a golden ruleset, real-kernel tests in
  network namespaces, a real-sshd test of the drop-in, fakes for the
  apply/confirm/rollback order, and a container probe on the box.
- Workstream F slice F1 builds on this firewall rather than replacing it.
  Until WI-4, the only egress lane is `unrestricted`, which is the current
  `bridge` network under this firewall. WI-4 keeps the firewall as the second
  wall under egress lanes: lane networks get its rules, and each workload
  Vault role's bound CIDRs cover the lane subnets.

`Bounded slice rule`: the same tranche refines the P0q workload-auth
bootstrap helper (INF-04, INF-05, and the root-token half of INF-06):

- role `service_execution` gets `token_ttl` (default `15m`),
  `token_max_ttl` (default `30m`) and `token_bound_cidrs` (default
  `172.17.0.0/16`), validated before any prompt;
- every earlier version and the metadata of both proof paths are deleted
  before the new value is written;
- `REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key` replaces a standing root
  token: the helper makes a root token from the single unseal key share,
  uses it once for a 15-minute orphan token, revokes it with the next
  request, and revokes the 15-minute token before it exits; SIGINT,
  SIGTERM, SIGHUP and SIGQUIT wait until the root token is revoked and
  Vault's configuration is back, and Ctrl-Z (SIGTSTP, SIGTTIN, SIGTTOU)
  takes effect only then; core dumps are off before anything is read;
- `REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config` adds
  `enable_unauthenticated_access = ["generate-root"]` to Vault's
  configuration only for the generate-root step and puts the file back byte
  for byte through a reload (Vault 2.x refuses unauthenticated generate-root
  by default), after the root token is revoked; it refuses a Vault that
  allows generate-root without the file saying so;
- with the 15-minute token, the helper counts root tokens that never
  expire, and `REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke` revokes
  them, which is how a run killed by SIGKILL or a power loss is cleaned up;
- `REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate` writes a random value nobody
  sees, which discards the Codex key.

Its validation adds one test against a real local Vault server (raft, TLS,
one key share; CI installs Vault 2.2.2). It still runs no live box, SSH or
sudo. These refinements do not make ES a Vault token broker and do not
change ES public contracts.
