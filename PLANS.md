# Execution Substrate Current Plan

## Status

This document is the authoritative planning document for the current Execution Substrate workstreams, bounded platform hardening, and explicitly reopened seams.

It supersedes the earlier slice-lock plan that treated ACS, ARS, AGS, EGS, CGS, ES, and the now-removed legacy signing kernel as near-final architectural endpoints.

The repository currently contains a coherent but constrained architecture that is visible directly in:

- `ars/`
- `ags/`
- `egs/`
- `cgs/`
- `es/`
- `.docs/system_overview/`
- `.docs/execution_lifecycle/`

That implementation remains useful evidence of current behavior. It is no longer the default answer to what the long-term architecture must be.

The redesign focus in this phase is the architecture-defining core:

- cross-service contracts
- invariants
- package and kernel boundaries
- publish, store, verify, and execute flow
- policy and authorization surfaces
- runtime identity and execution handoff

Docker scripts, runbooks, environment polish, and deployment helper glue are not the primary redesign target of this phase.

The repo has now reached a practical architecture-freeze line for the current bounded slice. Further architectural changes require explicit stop-condition justification. Primary implementation effort should now prefer:

- bootstrap automation
- startup graph hardening
- Docker/Nomad substrate normalization
- execution-path reliability
- operator and integration ergonomics
- operator failure-guidance hardening in scripts and runbooks, with `scripts/01_bringup.sh check` remaining the readiness source of truth

Current bounded implementation status:

- Slice 0 is functionally proved on Linux in the bounded sense the repo now claims: the real operator path has run on a real Linux VM through containerized ARS/EGS/AGS/ES, config-driven non-dev Nomad, ES `:submit`, Nomad allocation, Docker execution, and the same-path staging invariant.
- Supported-environment qualification for slice 0 is now proved on the current Apple Silicon Mac through a Lima `qemu` guest running Ubuntu 24.04 arm64 with Docker healthy, a packaged pre-managed non-`-dev` `nomad.service`, positive natural `cpu.totalcompute`, and no `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` override.
- The previously investigated Ubuntu 24.04 VMware/aarch64 local guest remains unsupported on this Mac for the slice-0 `supported` claim: under the real root-managed non-`-dev` service path it still leaves the ready node at `cpu.totalcompute=0` even though Docker is healthy and Nomad leadership is present.
- The previously investigated Lima `vz` Ubuntu 24.04 arm64 local guest also remains unsupported on this Mac for the same natural supported-host claim: the real root-managed non-`-dev` service path still leaves the ready node at `cpu.totalcompute=0`.
- Those unsupported local results are host/profile-specific qualification facts, not evidence that Ubuntu is unsupported in general, that Apple Silicon local Linux guests are unsupported in general, or that Docker/Nomad are the wrong bounded substrate direction for this phase.
- Supported-environment qualification for slice 0 is now narrower than the original local bring-up convenience path: the intended supported story is a Linux host/VM where Docker is healthy and a pre-managed non-dev Nomad client/server is already running in a naturally schedulable mode with positive `cpu.totalcompute`.
- The script-managed local Nomad path remains useful evidence and troubleshooting scaffolding, but it is now treated as a bounded fallback/operator convenience path rather than the clean supported-environment story for Linux.
- The operator readiness path must not silently treat `nomad agent -dev` as that supported profile; a pre-managed dev-mode agent is unsupported for the slice-0 support claim even if it reports healthy Docker and positive compute.
- Docker host networking remains temporary slice-0 compatibility scaffolding, not the final control-plane network architecture.
- Slice `1A` and slice `1B` are now landed in the bounded sense the repo claims: the real ES -> Nomad -> Docker path now proves a same-container platform-owned supervisor/helper, helper-private SPIRE channel, bounded workload-visible `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, fixed non-root workload launch boundary, bounded real SPIRE-backed JWT-SVID delivery for the `workload_vault` target, and helper-death/task-fatal behavior.
- That first workload-identity slice is intentionally compatibility-narrow: no root workloads, no arbitrary image-user execution, no shared helper/workload UID, and no supplemental groups that collapse the helper/workload boundary.
- Useful credential flow completion is now also landed in the bounded sense the repo claims: one workload can use the platform-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT` plus the bounded workload-vault metadata to authenticate to a real Vault dev/test target and read one secret through the real ES -> Nomad -> Docker path, without reintroducing workload-authored bridging or platform-owned Vault token brokerage.
- The current supported local proof path is now repo-owned and converged with the bounded useful credential-flow proof: `scripts/72_supported_local_setup.sh` prepares the guest-side supported-local proof environment, including a proof-scoped real SPIRE server/agent path plus a proof-scoped real Vault dev/test target, while `scripts/73_supported_local_proof.sh run` is the canonical host-side supported-local proof wrapper on this Mac. That path records canonical proof workspaces under `.out/es-proof-<id>/`, keeps generated proof bootstrap material in `managed-secrets.conf`, and uses guest `/tmp` scratch only as an internal Lima implementation detail because the mounted repo tree is read-only inside the guest.
- The first bounded Control Plane normal-shell runtime contract is now an explicit opt-in ES runtime profile named `control-plane-normal-shell/v1`. It remains a bounded slice rule on the reopened ES runtime/package seam: CP still owns orchestration, review, checkpoint, and finalization semantics, while ES owns the governed Docker/Nomad runtime realization, platform-owned runtime identity delivery, the profile image selection, and non-secret credential-location metadata needed for workload-side Codex credential retrieval.
- The supported-local runtime surface for enabled local runtime-profile images now also owns the narrow Nomad/Docker image-lifecycle guardrail needed for repeated client runs from the same prepared environment: the supported single-node Nomad baseline disables Nomad Docker image cleanup through `client.options["docker.cleanup.image"]="false"`, and submit-readiness for enabled runtime-profile images refuses to claim ready when that guardrail is absent. This is a bounded slice rule for local image durability, not a general registry or image-cache architecture.
- The supported-local proof realization for that profile now uses a repo-owned deterministic proof Codex shim at the configured `EXEC_CODEX_CLI_PATH`, invokes it through the bounded normal-shell profile path, proves workload-side Vault credential acquisition, creates a deterministic workspace mutation and runner-style artifacts, fetches the retained ES result bundle, and validates the expected proof artifacts without depending on a live upstream Codex service.
- Remote Supported-Host Alpha may now extend the narrower helper-install proof with a separate host-local Vault/workload-auth proof slice: install a single-node Alpha/internal Vault system service on the remote Linux host, constrain it to the helper SPIFFE identity JWT path needed by future ES runtime identity, and record only non-secret host evidence without claiming `runtime_profile_ready`, `submit_ready`, `es_services_healthy`, `producer_contract_compatible`, or retained-result readiness.
- Remote Supported-Host Alpha may now also use one separate operator-owned Vault service-user migration helper slice: default `check_only`, require explicit `--apply`, stay bounded to the dedicated Vault service account, the Vault systemd drop-in, and the minimum config/storage/log/audit/TLS ownership or readability changes needed for Vault, record backup plus rollback evidence before mutation, and run honest post-apply Vault plus ES health or contract checks. That helper must preserve workload-side Vault JWT login, the ES-owned `EXEC_WORKLOAD_IDENTITY_ENDPOINT` handoff, and the no-ES-Vault-token-brokerage rule; it does not claim `runtime_profile_ready`, `submit_ready`, Vault production readiness, governed execution proof, full ES/runtime de-root, full Nomad client de-root, or SPIRE redesign.

## Highest-Priority Backlog Entry

P0: ES Remote Alpha operator-helper consolidation and manual recovery
minimization.

This P0 is bounded to operator ergonomics over the existing Remote Alpha proof
and support helpers. Implementation must be split into small audited slices,
starting with docs/static-test prep, then help/inventory/print-command
ergonomics, then narrowly reviewed delegation to existing staged helpers, and
only later any secret-sensitive reset/unseal routing after reset-helper tests
and audit. It must not widen ES public contracts, CP orchestration semantics,
IM authority, Nomad task-user semantics, SPIRE exposure boundaries, or Vault
token brokerage. It must preserve Remote Alpha as bounded proof/support
posture only, preserve existing IM-consumed artifact filenames, and keep any
operator summary as non-secret evidence/projection rather than a v1 IM input.
The objective is one repo-supported ES operator facade/workflow/script that
minimizes manual stitching, copying, and recovery sequencing across bounded
operator work. Operator involvement is expected and allowed: success does not
mean eliminating every prompt. Explicit interactive modes are valid when they
are named, bounded to a mode or subcommand, visible to the operator, and
secret-safe. Default noninteractive sudo remains an ergonomic optimization for
helpers that support it, not a universal success criterion for the operator
facade. The facade must remain a helper workflow and evidence surface, not an
authority source, Vault token broker, IM reconciler, CP recovery authority, or
Remote Alpha deployment/reconciliation system.
The P0b implementation slice is limited to an inert
`scripts/remote_alpha_operator.sh` help/inventory/print-command skeleton:
it may document available and future surfaces, print exact Mac-side
Infrastructure Manager refresh/support-bundle commands, and refuse blocked or
not-yet-implemented subcommands. It must not route to Remote Alpha helpers,
run IM collection commands, stage generic remote helpers, invoke sudo or SSH,
perform Vault reset/unseal behavior, add Vault workload-auth bootstrap, or
write generated artifacts.

The P0c design/static-test prep slice is also docs/static-test only. It may
record the first staged-helper delegation boundary for a later implementation
slice and add static refusal assertions, but it must not make
`scripts/remote_alpha_operator.sh` delegate yet. The selected first future
delegation target is the existing ES writable-state readiness staged wrapper,
`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`, exposed
later as the proposed operator subcommand `es-writable-state-readiness-check`.
That future route is limited to check-only/non-mutating readiness evidence:
`--apply` is forbidden in the first delegation slice, no reset/unseal, Vault
workload-auth, runtime-identity, service-user migration, config/TLS apply,
binary deployment apply, generic remote staging, arbitrary shell passthrough,
or new aggregate operator summary is allowed, and the exact existing
Infrastructure Manager-consumed filenames `es-writable-state-readiness.json`
and `es-writable-state-readiness-helper-staging-record.json` must be
preserved. The future route must reuse the helper's existing minimal staging
and sudo model, including noninteractive `sudo -n` preflight by default and
explicit `--interactive-sudo` only for a visible terminal. The facade may
continue to print IM commands only; it must not call IM.

The P0d implementation slice is limited to exactly that one check-only route:
`scripts/remote_alpha_operator.sh es-writable-state-readiness-check`. The route
must require an explicit `--ssh-target`, accept only the P0c allowlisted helper
flags, reject `--apply`, `--dry-run`, unknown flags, unknown positional
arguments, duplicate route flags, and secret-like arguments before helper
execution, and delegate only to the public staged wrapper
`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`. It must not
source helpers, invoke `scripts/internal/*`, construct helper paths from user
input, add generic staging or helper routing, call Infrastructure Manager,
create an operator-owned summary, rename helper artifacts, or add any reset,
unseal, Vault workload-auth, runtime-identity, service-user migration,
config/TLS, binary deployment, or writable-state ownership route.

The P0f combined slice may fold in the P0e help/inventory wording alignment
and add one bounded workflow subcommand:
`scripts/remote_alpha_operator.sh readiness-session`. This command is an
operator-workflow consolidation over the already approved writable-state
readiness route, not a live validation slice and not a new authority source.
It must minimize manual stitching without implying zero operator involvement:
the human remains the operator, explicit interactive sudo remains allowed only
when named, bounded, visible, and secret-safe, and noninteractive sudo remains
an ergonomic optimization rather than a universal success criterion. The
session must require an explicit `--ssh-target` for execution, accept only its
own allowlisted flags, delegate only through the existing
`es-writable-state-readiness-check` route/helper path, use a fresh
run-specific output directory by default unless `--output-dir` is supplied,
refuse pre-existing readiness or staging-record artifacts in the selected
directory, verify the two expected artifacts after a successful route return,
scan those artifacts for secret-like content before reading JSON fields, and
print only non-secret metadata such as paths, byte counts, SHA-256 digests,
schema names, blocker/warning counts, and sudo/checker status. It must not run
Infrastructure Manager, support-bundle collection, sudo, SSH, Vault, Nomad,
Docker, SPIRE, `systemctl`, reset/unseal flows, or live validation except
through the intentionally invoked readiness route. It must print IM refresh and
support-bundle commands as follow-up evidence/provenance instructions only,
write no operator summary file, preserve the existing IM-consumed artifact
filenames, and add no generic helper dispatch or additional Vault, reset,
unseal, runtime identity, service-user, config/TLS, binary, or writable-state
ownership route.

The P0g combined slice may add one bounded safe/local recovery workflow surface:
`scripts/remote_alpha_operator.sh recovery-session`. This command is a recovery
sequencing skeleton plus local evidence-check only. Its supported safe modes are
`--help`, `--plan`, `--inventory`, `--next-steps`, and `--evidence-check`; the
default no-mode behavior must print the plan/help and exit zero without running
live tools. `--plan`, `--inventory`, and `--next-steps` are print-only. IM
refresh and support-bundle commands may be printed as separate
evidence/provenance instructions only, never executed by ES and never described
as authority. `--evidence-check` may read only operator-supplied local JSON
evidence paths, require files to exist, scan for secret-like content before JSON
parsing, compute byte counts and SHA-256 digests, parse JSON, and print only
non-secret metadata such as path, byte count, digest, `schema_version`, and
selected safe status/count fields. It must not print full JSON, create a
session summary, write `.out`, inspect live host state, dispatch helpers, run
sudo, SSH, Vault, Nomad, Docker, SPIRE, `systemctl`, Infrastructure Manager,
support-bundle collection, CP proof, reset/unseal flows, workload-auth live
checks, or runtime identity summary generation. It must reject `--ssh-target`,
`--interactive-sudo`, `--apply`, `--dry-run`, `--execute-reset`,
`--unseal-only`, `--post-unseal-check`, `--governed-smoke-command`, arbitrary
command strings, helper path overrides, positional arguments, unknown flags,
duplicate operational flags, equals-form options, and secret-like arguments.
Unseal-existing, disposable reset, workload-auth check execution, runtime
identity summary generation, and Vault service-user check/apply remain separate
audited future slices. P0g must not add Vault token brokerage, IM authority, CP
recovery authority, or Remote Alpha deployment/provisioning/reconciliation
architecture.

The P0h combined slice may extend only
`scripts/remote_alpha_operator.sh recovery-session --evidence-check` with
schema-aware interpretation of known local evidence summaries. It remains
local-only and may recognize the readiness summary, readiness staging record,
Vault workload-auth summary, runtime identity helper summary, and Vault
service-user migration summary schemas. Recognized schemas must use explicit
safe-field allowlists and print only non-secret status, classification, boolean,
count, schema, byte-count, and SHA-256 metadata. Unknown schemas are allowed by
default with `schema_interpretation=unknown`; `--strict-known-schema` may fail
unknown schemas. `--evidence-dir <path>` may inspect only direct expected
filenames in that directory, report missing expected filenames as
`not_supplied`, and must not recurse or write into the directory. P0h must not
print full JSON, create a session summary, write `.out`, run live tools,
dispatch helpers, run IM, support-bundle collection, CP proof, reset/unseal
flows, workload-auth live checks, runtime identity generation, or Vault
service-user apply. Schema interpretation is evidence/projection only and must
not add IM authority, CP recovery authority, ES Vault token brokerage, or Remote
Alpha deployment/provisioning/reconciliation architecture.

The P0i implementation/self-audit slice may add exactly one secret-sensitive
`recovery-session` route:
`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing
--host-local`. This route is host-local only, must require explicit
`--host-local`, and may delegate only to the public helper
`scripts/remote_alpha_reset_disposable_vault.sh --unseal-only` through a fixed
path resolved from the operator script. It must not use SSH, remote staging,
host detection, helper path overrides, generic helper dispatch, `scripts/internal`
paths, `tee`, transcripts, logs, `.out`, reports, support bundles, retained
bundles, or an operator summary. It must not run or add destructive reset,
post-unseal workload-auth checks, runtime identity generation, Vault service-user
execution, Infrastructure Manager execution, support-bundle collection, CP
proof, or default noninteractive readiness validation.

P0i preserves the operator prompt model: the human remains the operator, and any
unseal key entry happens directly in the visible terminal owned by the delegated
helper and Vault CLI. Codex and the operator facade must not receive, type, read,
log, relay, persist, summarize, or accept unseal keys, root tokens, Vault
tokens, API keys, passwords, private keys, JWT-SVIDs, or secret payloads through
CLI arguments, environment files, logs, `.out`, reports, support bundles,
retained bundles, helper summaries, readiness outputs, printed commands, or
Codex output. The route is secret-sensitive but non-destructive evidence/support
workflow glue only; it must not make ES a Vault token broker, IM a reconciler, CP
a recovery authority, or Remote Alpha deployment/provisioning/reconciliation
architecture.

The P0j implementation/self-audit slice may extend exactly that
`recovery-session vault-unseal-existing` surface with one Mac-side interactive
TTY topology:
`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing
--ssh-target <target> --interactive-tty`. The P0i `--host-local` route remains
available only for an operator already on the Linux Remote Alpha host. The
Mac-side route must require explicit `--ssh-target` plus `--interactive-tty`,
must fail before staging when local stdin or stdout is not a visible terminal,
and must reject bare execution, `--host-local` combined with `--ssh-target`,
`--ssh-target` without `--interactive-tty`, and `--interactive-tty` without
`--ssh-target`. The `--ssh-target` value must be a single SSH target, not an
SSH option or shell command.

P0j may stage only the public helper
`scripts/remote_alpha_reset_disposable_vault.sh` to a route-specific remote
scratch path and may invoke the staged helper only as
`remote_alpha_reset_disposable_vault.sh --unseal-only` over an interactive SSH
TTY such as `ssh -tt`. It must not stage `scripts/remote_alpha_operator.sh`,
stage a helper bundle, source helpers, call `scripts/internal/*`, construct
helper paths from user input, introduce generic helper dispatch, offer
`--keep-staging-on-failure`, capture transcripts, use `tee`, run `script`, or
write `.out`, logs, reports, summaries, support bundles, retained bundles, or
generated JSON. It must attempt remote staged-helper cleanup by default. P0j
must not run or add destructive reset, post-unseal workload-auth checks,
workload-auth bootstrap, runtime identity generation, Vault service-user
execution, Infrastructure Manager execution, support-bundle collection, CP
proof, or default noninteractive readiness validation.

P0j preserves the same secret posture as P0i: the human remains the operator,
and unseal key entry happens only inside the visible SSH/helper/Vault terminal
prompt. Codex and the operator facade must not receive, type, read, parse, log,
relay, persist, summarize, or accept unseal keys, root tokens, Vault tokens,
API keys, passwords, private keys, JWT-SVIDs, or secret payloads through CLI
arguments, environment files, logs, `.out`, reports, support bundles, retained
bundles, helper summaries, readiness outputs, printed commands, or Codex
output. The route remains bounded proof/support workflow glue only; it must not
make ES a Vault token broker, IM a reconciler, CP a recovery authority, or
Remote Alpha deployment/provisioning/reconciliation architecture.

The P0k implementation/self-audit slice may add exactly one Mac-side disposable
Vault reset planning route:
`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
--ssh-target <target> --dry-run`. This route is dry-run-only and
non-destructive. It may stage only the public helper
`scripts/remote_alpha_reset_disposable_vault.sh` from a fixed path resolved
from `BASH_SOURCE[0]`, and it may invoke the staged helper only in the helper's
documented `--dry-run` mode. Because the helper supports `--dry-run`, the
operator facade must pass `--dry-run` explicitly.

P0k must require explicit `--ssh-target` plus `--dry-run`, must not require
`--interactive-tty`, and must reject `--host-local`, `--interactive-tty`,
`--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--apply`,
`--interactive-sudo`, `--governed-smoke-command`,
`--keep-staging-on-failure`, helper path overrides, workload-auth flags,
Infrastructure Manager commands, arbitrary commands, unknown flags, duplicate
flags, extra positional arguments, equals-form options, and all secret-like
arguments. It must not stage `scripts/remote_alpha_operator.sh`, stage a
bundle, source helper scripts, call `scripts/internal/*`, introduce generic
helper dispatch, capture transcripts, use `tee`, run `script`, or write
`.out`, logs, reports, summaries, support bundles, retained bundles, generated
JSON, or any operator-owned artifact. It must attempt cleanup of the staged
reset-capable helper by default and must not offer
`--keep-staging-on-failure`.

P0k is planning/inspection only. It must not stop Vault, move raft storage, run
`vault operator init`, unseal Vault, run post-unseal checks, run workload-auth
checks, refresh Infrastructure Manager evidence, collect support bundles, run
CP proof, or validate default noninteractive readiness. Destructive
`--execute-reset` remains a future explicit destructive mode with the exact
confirmation phrase `RESET DISPOSABLE REMOTE ALPHA VAULT`. P0k outputs remain
operator-visible evidence/projection/diagnostics only, never authority. The
route must not make ES a Vault token broker, IM a reconciler, CP a recovery
authority, or Remote Alpha deployment/provisioning/reconciliation architecture.

The P0l design/static-test prep slice may define, but must not implement, the
future Mac-side destructive disposable Vault reset route:
`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
--ssh-target <target> --execute-reset --interactive-tty`. The already validated
P0k dry-run route is the prerequisite for this design: commit `b1a561a` passed
live validation of
`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
--ssh-target host_to_remote_linux_m75q --dry-run`, proving the non-destructive
staging, invocation, and cleanup-attempt behavior for reset planning. P0l stayed
docs/static-test only; at P0l, `--execute-reset` remained future until later
separate implementation, audit, and live-validation slices.

P0l fixes the future destructive contract as a Mac-side operator-facade route
only. It must require `--ssh-target` plus `--interactive-tty`, and
`--execute-reset` must require `--interactive-tty`. `--dry-run` and
`--execute-reset` are mutually exclusive. The future route must not add a
host-local execute-reset path through the operator facade in this slice. It may
stage only `scripts/remote_alpha_reset_disposable_vault.sh` from a fixed
script-relative path and invoke only the staged helper with `--execute-reset`.
It must never include `--post-unseal-check` in the first destructive slice and
must never combine reset with workload-auth checks, runtime identity summaries,
Infrastructure Manager refresh, support-bundle collection, CP proof, governed
smokes, preinstalled remote bundles, generic helper dispatch, or arbitrary
commands. It must attempt cleanup of the staged reset-capable helper by default
and must not offer `--keep-staging-on-failure`.

The P0l confirmation model is human-visible and non-capturing. The exact
confirmation phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT`; the operator
must type it directly in a visible terminal owned by the remote helper/Vault
session. The phrase must not be accepted through CLI arguments, environment
variables, environment files, local or remote files, helper summaries, readiness
outputs, `.out`, logs, reports, support bundles, retained bundles, CP artifacts,
or Codex output, and it must not be logged, summarized, captured, parsed, or
relayed by the operator facade. Root tokens, unseal keys, client tokens, Vault
tokens, API keys, private keys, passwords, JWT-SVID payloads, and secret payloads
must never be accepted as arguments, environment values, files, logs, artifacts,
or Codex output. Any Vault init/unseal material is handled only by the human
operator in the visible remote helper/Vault terminal.

P0l evidence is process exit plus operator-visible helper output only. The
future ES operator route must not tee, run `script`, record, capture, parse, or
summarize terminal transcripts; must write no `.out` summary, operator summary
file, support bundle, report, generated JSON, retained bundle, or CP artifact;
and must not execute Infrastructure Manager. Post-reset evidence checks are
separate later steps. Stop conditions for the future route include no visible
TTY, SSH host-auth prompts, any request to pass secrets as args/env/files,
reset-helper broad raft path guard failures, exact phrase mismatch, any request
to combine post-unseal checks, workload-auth checks, IM refresh, support-bundle
collection, or CP proof in the same command, and failure to clean up the staged
reset-capable helper. The route remains bounded Remote Alpha proof/support
workflow glue only; it must not make ES a Vault token broker, IM a reconciler,
CP a recovery authority, or Remote Alpha production/deployment/reconciliation
architecture.

The P0m implementation/self-audit slice may implement exactly the Mac-side
destructive disposable Vault reset route defined by P0l:
`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable
--ssh-target <target> --execute-reset --interactive-tty`. P0m may validate only
with static and fake SSH/SCP tests; it must not run live SSH, sudo, Vault, reset,
unseal, execute-reset, Infrastructure Manager refresh, support-bundle
collection, CP proof, workload-auth live checks, runtime identity generation,
or network-dependent integration tests. The P0k dry-run route remains the
prerequisite/planning route, and P0m must preserve the existing P0k dry-run,
P0i/P0j unseal-existing, recovery-session evidence/plan/inventory, readiness
session, and writable-state readiness routes.

P0m's execute-reset route must require `--ssh-target` and
`--interactive-tty`; `--execute-reset` without either must fail before staging.
`--dry-run` and `--execute-reset` are mutually exclusive. There is no
host-local execute-reset route through the operator facade in this slice. The
route may stage only `scripts/remote_alpha_reset_disposable_vault.sh` from the
fixed script-relative helper path and invoke only
`remote_alpha_reset_disposable_vault.sh --execute-reset` over an interactive
SSH TTY. It must never pass `--dry-run`, `--unseal-only`,
`--post-unseal-check`, workload-auth flags, Infrastructure Manager commands,
support-bundle commands, CP proof commands, runtime identity flags, helper path
overrides, or arbitrary commands in execute-reset mode. It must not offer
`--keep-staging-on-failure`, because the staged helper contains destructive
capabilities, and cleanup of the staged reset-capable helper must be attempted
by default.

P0m preserves the human-visible prompt and secret model. The exact confirmation
phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT` and is typed only by the
operator in the visible remote helper/Vault terminal. The route must not accept
the phrase, root token, unseal key, client token, Vault token, API key, private
key, password, JWT-SVID payload, Vault init output, or secret payload through
CLI arguments, environment values, environment files, local or remote files,
logs, `.out`, reports, support bundles, retained bundles, CP artifacts, or
Codex output. The operator facade must not receive, parse, log, store, echo,
summarize, persist, tee, run `script`, capture, or transcript terminal content.
P0m writes no `.out` summary, operator summary, report, support bundle,
generated JSON, retained bundle, or CP artifact. Process exit and
operator-visible helper output are the only route result surfaces. Post-reset
evidence checks remain separate later steps. P0m remains bounded Remote Alpha
proof/support workflow glue only; it must not make ES a Vault token broker, IM
a reconciler, CP a recovery authority, or Remote Alpha
production/deployment/reconciliation architecture.

The P0n implementation/self-audit slice may add exactly one Mac-side
post-reset evidence route:
`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check
--ssh-target <target> --interactive-tty`. This route exists for the intended
operator topology where the operator runs the ES operator facade from the Mac,
the facade stages bounded helper files to the Remote Alpha host, the human
remains the operator, and secrets never pass through args, env, logs,
artifacts, or Codex. P0n may validate only with static and fake SSH/SCP tests; it must not
run live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure
Manager refresh, support-bundle collection, CP proof, runtime identity
generation, or network-dependent integration tests.

P0n must stage only:

- `scripts/remote_alpha_vault_workload_auth_check.sh`
- `scripts/internal/remote_alpha_vault_workload_auth_check.sh`

It must preserve that public/internal relative layout on the remote host and
invoke only the staged public workload-auth helper. It may run that helper with
root through the explicit interactive TTY route when required, using `ssh -tt`
only because `--interactive-tty` is mandatory. It must not stage
`scripts/remote_alpha_operator.sh`, reset/unseal helpers, runtime identity
helpers, service-user helpers, config/TLS helpers, binary deployment helpers,
bundles, unrelated helpers, or a generic helper dispatcher.

Allowed flags for P0n are only `--help`, `--ssh-target <target>`, and
`--interactive-tty`. P0n must reject `--host-local`, `--dry-run`,
`--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--apply`,
`--interactive-sudo`, `--governed-smoke-command`, workload-auth helper override
flags, Vault address/role/audience/path/proof-path overrides, SPIFFE ID
overrides, config path overrides, summary path overrides, container probe image
overrides, SPIRE socket overrides, arbitrary commands, unknown flags, duplicate
flags, extra positional arguments, equals-form options, and all secret-like
arguments including root tokens, unseal keys, client tokens, Vault tokens,
JWT-SVID payloads, API keys, private keys, passwords, and secret payloads.

P0n keeps the canonical workload-auth evidence artifact on the remote host at
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`.
The operator facade must not copy that summary back to Mac `.out`, print full
summary JSON, create an operator summary, create generated artifacts, tee, run
`script`, capture transcripts, write logs, run Infrastructure Manager,
collect support bundles, run CP proof, run runtime identity generation, run
reset/unseal, or combine workload-auth evidence with reset/unseal. After remote
success it may print only non-secret next steps: the remote summary path, a
recommendation to use `recovery-session --evidence-check` after separately
collecting IM/local evidence, and printed-only IM refresh/support-bundle
commands as separate IM evidence/provenance actions. The workload-auth summary
remains evidence/projection only, not readiness authority, not Vault production
readiness, not governed execution proof, not ES Vault token brokerage, not IM
authority, not CP recovery authority, and not Remote Alpha
production/deployment/reconciliation architecture.

A bounded bugfix/self-audit refinement may extend the same v1 workload-auth
summary with backward-compatible, safe Vault JWT login failure classification
when `auth_smoke.vault_login=fail`. The helper may record only class labels,
HTTP status, error-string count, a `vault_login` failure phase, safe JWT issuer
expected-source/class labels, safe JWT issuer actual-class labels, and
`auth_smoke.vault_login_raw_error_recorded=false`; it must not print or persist
the JWT-SVID, Vault client token, root token, unseal key, proof secret value,
raw Vault login response body, raw HTTP headers, Authorization header, stack
trace, or full Vault login JSON. Classification remains bounded triage over the
host-local evidence artifact, not workload-auth bootstrap, not a claim that a
specific Vault object is missing unless the class safely supports that, and not
ES Vault token brokerage.
The issuer comparison must understand the same `spire-server bundle show
-format spiffe` trust-domain JSON shape used by bootstrap, including
`trust_domains` maps keyed by bare trust-domain labels, so a parseable
repo-derived bound issuer does not degrade to `unknown` before classification.

The P0o combined implementation/self-audit/merge-readiness slice may add exactly
one safe local/print-only planning surface for a future post-reset Vault
workload-auth bootstrap route:
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap [--help|--plan|--inventory]`. This slice is
allowed to update docs, tests, and the operator facade's inert print-only
behavior only. It must not implement live bootstrap execution,
`--execute-bootstrap`, `--ssh-target` execution, `--interactive-tty` execution, Vault
writes, root-token prompts, proof secret creation, workload-auth check
execution, Infrastructure Manager execution, support-bundle collection, CP
proof, reset/unseal behavior, runtime identity generation, `.out` writes,
JSON/report/summary creation, transcripts, `tee`, `script`, helper staging, or
generic helper dispatch.

P0o records the conservative post-reset triage from the canonical workload-auth
summary: schema matched, the summary was fresh, redaction passed, Vault reported
`initialized=true` and `sealed=false`, and the safe configuration fields were
`auth_mount=jwt`, `role=service_execution`, and `audience=vault`; the smoke
failed at `auth_smoke.vault_login=fail`. The safe failure classification is
therefore only `Vault JWT login rejected or not configured`. The route mechanics
partially passed, but P0o must not claim that any individual Vault object is
missing unless a later reviewed secret-safe check proves it.

The P0o plan/inventory output may describe likely post-reset bootstrap objects
inferred from the existing helper, docs, and tests: auth mount `jwt`; JWT auth
config with SPIRE JWT validation material selected for the workload trust domain
and bound issuer; role
`service_execution` with `role_type=jwt`, `user_claim=sub`,
`bound_audiences=vault`, and
`bound_subject=spiffe://execution.internal/workload`; a policy such as
`runtime-identity-proof`; KV v2 proof paths
`proof-secrets/data/runtime-identity-vault-login` and
`proof-secrets/data/codex-runtime-profile`; proof-runtime field shape
`api_key` present and non-empty with the value never printed; and workload-zone
config alignment at
`/etc/execution-substrate/vault/workload-zone-vault-config.json`.

Allowed P0o bootstrap flags are only `--help`, `--plan`, and `--inventory`;
with no mode, the submode defaults to printing the plan/help and exiting zero.
The submode must reject
`--execute-bootstrap`, `--ssh-target`, `--interactive-tty`, `--host-local`,
`--root-token`, `--unseal-key`, `--client-token`, `--vault-token`, `--api-key`,
`--jwt-svid`, `--private-key`, `--password`, `--secret`, `--execute-reset`,
`--dry-run`, `--unseal-only`, `--post-unseal-check`, `--apply`,
`--governed-smoke-command`, workload-auth helper override flags, proof secret
value flags, arbitrary commands, unknown flags, duplicate flags, equals-form
options, and extra positionals beyond the submode/mode before any live action.

Any future bootstrap execution must be a separate audited secret-sensitive route.
Root tokens must never be accepted as CLI arguments, environment variables,
files, `.out`, reports, support bundles, retained bundles, or Codex output. If a
root token is needed, it may only be entered by the human operator through an
explicit visible or silent prompt in a named secret-sensitive mode, with no
transcript capture, no `tee`, and no `script`. Proof secret values must never be
printed, copied, summarized, logged, or persisted by the operator facade.
Bootstrap must only configure expected Vault objects; it must not claim
workload-auth success, runtime-profile readiness, submit readiness, Vault
production readiness, governed execution proof, IM authority, CP recovery
authority, or ES Vault token brokerage. Workload-auth check remains a separate
post-bootstrap command.

The P0p design/static-test prep slice may define, but must not implement, the
future secret-sensitive workload-auth bootstrap execution route:
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap
--interactive-tty`. P0p stays docs/static-test only. It must not add live
bootstrap execution, Vault writes, helper files, helper staging, root-token
prompts, proof-secret prompts, workload-auth checks, reset/unseal behavior,
Infrastructure Manager execution, support-bundle collection, CP proof, runtime
identity generation, summary generation, `.out` writes, transcript capture,
`tee`, `script`, or network-dependent validation.

P0p fixes the preferred helper strategy for the later implementation slice:
add one dedicated fixed workload-auth bootstrap helper surface, preferably a
public wrapper `scripts/remote_alpha_vault_workload_auth_bootstrap.sh` that
sources a fixed internal implementation
`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`. The future
operator route may stage only that public/internal helper pair, preserving the
relative layout on the remote host. It must not print ad hoc manual Vault write
commands as the primary execution mechanism, stage `scripts/remote_alpha_operator.sh`,
stage reset/unseal helpers, stage the workload-auth check helper, stage runtime
identity or service-user helpers, source staged helpers from the facade, create
a preinstalled helper bundle, or introduce generic helper dispatch.

The future execution route's safe modes remain `--help`, `--plan`, and
`--inventory`, with no mode defaulting to plan/help and exiting zero. The only
future execution shape P0p authorizes for later implementation is
`--ssh-target <target> --execute-bootstrap --interactive-tty`; `--ssh-target`
and `--interactive-tty` are valid only with `--execute-bootstrap`, and
`--execute-bootstrap` requires both. `--help`, `--plan`, `--inventory`, and
`--execute-bootstrap` are mutually exclusive route modes. Duplicate route
flags, equals-form options, unknown flags, extra positionals, and secret-like
arguments must fail before staging or live action. The SSH target must remain a
single target, not an SSH option or shell command. The future Mac-side route
must require visible local stdin and stdout before staging, allocate an
interactive SSH TTY such as `ssh -tt`, stage to a route-specific remote scratch
root, and attempt staged-helper cleanup by default. It must not offer
`--keep-staging-on-failure`.

The intended Vault objects/config for that later execution route are exactly
the documented workload-auth bootstrap objects and names, with no secret values
in docs, args, logs, summaries, or output: auth mount `jwt`; JWT auth config
with SPIRE validation material selected for the workload trust domain and bound
issuer; role `service_execution` with
`role_type=jwt`, `user_claim=sub`, `bound_audiences=vault`, and
`bound_subject=spiffe://execution.internal/workload`; policy
`runtime-identity-proof`; KV v2 proof paths
`proof-secrets/data/runtime-identity-vault-login` and
`proof-secrets/data/codex-runtime-profile`; field `api_key` present and
non-empty with the value never printed; and workload-zone config alignment at
`/etc/execution-substrate/vault/workload-zone-vault-config.json`.

The future prompt and secret model is prompt-only and operator-owned. If a
Vault root token or equivalent bootstrap authority is required, the human
operator may enter it only through an explicit visible or silent prompt bound
to the named secret-sensitive execution mode, reading from the interactive TTY
only. If a proof secret value is required, it must use the same TTY-only prompt
posture. The operator facade and helper must never accept root tokens, unseal
keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, private keys,
passwords, proof secret values, or secret payloads through CLI arguments,
environment variables, environment files, local or remote files, shell history,
logs, `.out`, reports, support bundles, retained bundles, CP artifacts, helper
summaries, printed commands, transcripts, or Codex output. The future helper
must not rely on token-bearing `VAULT_TOKEN` environment variables,
token-bearing Vault CLI arguments, token files such as `.vault-token`, `tee`,
or `script`; if the Vault CLI cannot satisfy that posture, the helper must use
an implementation path that keeps bootstrap authority only in process memory
and never exposes it through argv, env, files, or output.

The future execution route may configure only the intended Vault objects. It
must not run a workload-auth check, reset, unseal, Infrastructure Manager
refresh, support-bundle collection, CP proof, runtime identity summary,
runtime identity generation, governed smoke, default readiness validation, or
post-unseal check, and it must not claim workload-auth success. The workload-auth
check remains a separate post-bootstrap command.

P0p chooses a remote-only non-secret bootstrap summary for the later
implementation slice. The path should be
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`
and the schema name should be
`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`.
That summary is evidence/projection only, never authority, and in the first
execution slice it must not be copied back to Mac `.out`. It may contain only
statuses, booleans, path labels, object names, byte counts, SHA-256 digests,
cleanup status, and redaction/non-authority flags. It must not contain a root
token, unseal key, client token, Vault token, JWT-SVID payload, API key value,
private key, password, proof secret value, secret payload, raw Vault output, or
terminal transcript.

Future implementation tests for P0p's contract must remain fake/static before
any live-validation slice: no live Vault, live SSH, sudo, workload-auth check,
reset/unseal, IM refresh, support-bundle collection, CP proof, runtime identity
generation, or network-dependent integration test. Tests should use fake
SSH/SCP, a fake staged helper, and fake Vault/API command capture where the
helper is introduced; assert that no secret is passed by argv, env, file,
printed command, transcript, `.out`, support bundle, retained bundle, CP
artifact, or Codex-facing output; assert no `tee`, `script`, token files, or
token env path; assert only the dedicated bootstrap helper pair is staged;
assert cleanup is attempted; assert summary schema/redaction behavior if the
summary is implemented; and assert the route cannot bundle workload-auth
checks, reset/unseal, IM, support bundles, CP proof, or runtime identity work.
SPIRE follow-up tests should include fake SPIRE bundle-read preparation over
only the bounded fixed-path ACL command.

The P0q implementation/self-audit/merge-readiness slice may implement exactly
one dedicated secret-sensitive workload-auth bootstrap helper, exactly one
Mac-side recovery-session execution route, one bounded preparation form for the
bootstrap summary path, and one bounded preparation form for fixed workload-zone
config readability, and one bounded preparation form for fixed SPIRE server
bundle-read access:
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap
--interactive-tty`, plus
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path
--interactive-tty`, plus
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability
--interactive-tty`, plus
`scripts/remote_alpha_operator.sh recovery-session
vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read
--interactive-tty`. P0q may add the public helper
`scripts/remote_alpha_vault_workload_auth_bootstrap.sh` and the internal helper
`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`, plus static
and fake tests for that bounded route. P0q must not run live bootstrap, live
SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure Manager
refresh, support-bundle collection, CP proof, runtime identity generation,
runtime identity summaries, or network-dependent integration tests.

P0q preserves the P0o safe modes: `vault-workload-auth-bootstrap --help`,
`--plan`, and `--inventory` remain safe local/print-only modes, and no mode
still defaults to printing plan/help and exiting zero. The execution route is
available as `--ssh-target <target> --execute-bootstrap --interactive-tty`.
Preparation routes are available as `--ssh-target <target>
--prepare-summary-path --interactive-tty` and `--ssh-target <target>
--prepare-config-readability --interactive-tty` and `--ssh-target <target>
--prepare-spire-bundle-read --interactive-tty`. The combined form
`--ssh-target <target> --execute-bootstrap --prepare-summary-path
--prepare-config-readability --prepare-spire-bundle-read --interactive-tty` is
allowed only when summary preparation runs first, config-readability preparation
runs second, SPIRE bundle-read preparation runs third, and all preparation
completes before helper staging, helper preflights, Vault/root/proof prompts,
and Vault writes. `--ssh-target` and `--interactive-tty` are valid only with
`--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, and/or `--prepare-spire-bundle-read`; all action
flags require both target and TTY;
and safe modes are mutually exclusive with execution/preparation. Duplicate
route flags, equals-form options, unknown flags, extra positionals, helper
override flags, forbidden reset/unseal or IM/CP/runtime flags, and secret-like
arguments must fail before staging or preparation.

P0q's helper prompt model is visible/silent remote helper TTY prompt only.
Vault bootstrap authority and proof secret values must never be accepted through
CLI arguments, environment variables, environment files, files, shell history,
logs, `.out`, reports, support bundles, retained bundles, CP artifacts,
summaries, transcripts, `tee`, `script`, printed commands, or Codex output. The
helper may hold those values only in process memory for the duration of the
bootstrap operation and should clear variables where practical. It must not use
`VAULT_TOKEN`, `vault login`, token-bearing Vault CLI arguments, or Vault token
files such as `.vault-token`.

The first real bootstrap attempt failed after the Vault operation flow because
`/var/tmp/execution-substrate-remote-alpha` existed as `root:root` mode `0755`
and the helper could not write the canonical bootstrap summary. Commit
`e4d7016` added the helper-side secret-free writability preflight before
secrets. The explicit `--prepare-summary-path` follow-up is OS/filesystem
preparation only: it prepares only `/var/tmp/execution-substrate-remote-alpha`,
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`,
and same-directory temp writability for that summary. It must not stage helpers,
run Vault, ask for Vault/root/proof secrets, run workload-auth checks,
reset/unseal, IM, support bundles, CP proof, or runtime identity generation, or
write Mac `.out` artifacts or operator summaries. If sudo is needed, it is only
an OS sudo prompt through the visible SSH TTY; the preparation command must keep
SSH stdin attached to that terminal rather than feeding the remote script over
SSH stdin, so sudo controls password echo suppression. The deterministic
mode/ownership policy is: create the parent directory when missing; if the
parent exists but is not writable/executable by the helper user, use visible
operator-authorized sudo to make that parent owned by the helper user/group with
mode `0750`; if the bootstrap summary file already exists and is a regular file
but is not writable by the helper user, use visible sudo to make only that file
helper-owned mode `0600`; do not delete or rewrite unrelated summaries; create
and remove only a hidden same-directory temp probe; and create no final
bootstrap summary in standalone preparation.

After the summary-path fix and failure-classification fix, a live retry reached
`config_load` and failed before secret prompts with `secret_prompts_started=false`
and `vault_operations_started=false`, likely because the helper user could not
read `/etc/execution-substrate/vault/workload-zone-vault-config.json`. The
explicit `--prepare-config-readability` follow-up is OS/filesystem preparation
only. It prepares only helper-user readability for that fixed config file and
the two fixed parent execute ACLs needed for
`/etc/execution-substrate/vault/workload-zone-vault-config.json`; it must not
print config contents, copy config to Mac `.out`, stage helpers, run Vault, ask
for Vault/root/proof secrets, run workload-auth checks, reset/unseal, IM,
support bundles, CP proof, or runtime identity generation. Because this repo
does not define a workload-zone-config-specific group ownership model, the
deterministic narrow policy is fixed-path user ACL based when preparation is needed:
require the file to exist and be regular, use visible operator-authorized OS
sudo through the SSH TTY only when the helper user cannot already read the file,
apply execute ACLs only to `/etc/execution-substrate` and
`/etc/execution-substrate/vault`, apply read ACL only to
`/etc/execution-substrate/vault/workload-zone-vault-config.json`, and fail with
a non-secret classification if `setfacl` is unavailable or readability is still
not proven. It must not world-read the config, chown broad `/etc` directories,
delete unrelated summaries, or create a bootstrap summary in standalone
preparation.

After summary-path and config-readability preparation succeeded, a live retry
reached `jwt_auth_config` before any secret prompt or Vault operation and failed
while obtaining SPIRE JWT validation material from `spire-server bundle show
-format spiffe -socketPath /run/spire/server/private/api.sock`. The helper must
therefore treat the fixed SPIRE bundle-read command as a pre-prompt preflight:
after summary and config preflights/load succeed, and before Vault bootstrap
authority prompts, proof secret prompts, or Vault writes, it obtains only the
public JWT validation material for the workload SPIFFE ID trust domain, selects
all active JWT-SVID RSA validation public keys for that trust domain, records
`operations.spire_jwt_validation_material` as pass or fail, records only safe
source/shape labels, key counts, selected trust-domain labels, a validation
pubkey count, and a digest set or aggregate digest on success, and records only
safe phase/class labels such as
`failure_phase=jwt_auth_config`,
`failure_class=invalid_response`, and
`failure_message_class=spire_bundle_show_failed` on failure. It must not print
raw SPIRE stderr/stdout, copy bundle contents to Mac `.out`, include bundle
contents in the summary, or expose prompt values.
This preserves the older safe-diagnostic vocabulary of safe source/shape
labels, key counts, selected trust-domain labels, and a digest while adding the
all-key count and digest-set detail.
This is the SPIRE bundle-read preflight before prompts and Vault writes.

The explicit `--prepare-spire-bundle-read` follow-up is OS/filesystem/capability
preparation only. It prepares only helper-user access to the fixed command
`spire-server bundle show -format spiffe -socketPath
/run/spire/server/private/api.sock`; it must not stage helpers, run Vault, ask
for Vault/root/proof secrets, run workload-auth checks, reset/unseal, IM,
support bundles, CP proof, or runtime identity generation, write Mac `.out`
artifacts, or print/copy SPIRE bundle contents. Because this repo does not
define a SPIRE-server-socket-specific group ownership model for this recovery
route, the deterministic narrow policy is fixed-path user ACL based when
preparation is needed: first discard-output probe the exact command; if it
already succeeds, classify the path as `spire_socket_present_accessible` and
make no permission change. Otherwise require `spire-server` to exist, failing
with `spire_server_command_missing` when absent; if systemd service state is
available and `spire-server` is not active, fail with
`spire_server_inactive_or_unknown`. The route must then use only visible
operator-authorized OS sudo through the SSH TTY to inspect the fixed parent
directories and socket path before classifying absence, so helper-user traversal
denial under `/run/spire/server` is not mislabeled as a missing parent. If
sudo-visible inspection shows a missing fixed parent, missing socket, or wrong
socket type, fail with `spire_socket_parent_missing`, `spire_socket_missing`,
or `spire_socket_not_socket`; do not create SPIRE parents or sockets and do not
restart or reconfigure SPIRE. If sudo-visible inspection shows the fixed socket
exists as a socket but the helper user lacks traversal or socket read/write
access, classify it as `spire_socket_present_needs_acl`, require `setfacl`,
apply execute ACLs only to `/run/spire`, `/run/spire/server`, and
`/run/spire/server/private` when needed, and apply read/write ACL only to
`/run/spire/server/private/api.sock` for the helper user. If the exact
discard-output bundle-read still fails after the fixed-path access prep, fail
with `spire_bundle_show_failed`. The route must not world-read or world-write
the socket, chown broad `/run` directories, grant access to workloads, add
generic command execution, print bundle contents, or copy bundle contents.

P0q's helper must still run a secret-free writability preflight for the
canonical remote bootstrap summary path before any Vault bootstrap authority
prompt, proof secret prompt, config load, SPIRE/Vault operation, or Vault write.
After summary preflight succeeds, it must also run a secret-free readability
preflight for
`/etc/execution-substrate/vault/workload-zone-vault-config.json` before any
Vault/bootstrap/proof prompt, SPIRE/Vault operation, or Vault write. The summary
preflight may create `/var/tmp/execution-substrate-remote-alpha` when it is
missing and safe for the helper user to create, and it must prove that a temp
file can be created and removed in the same directory as
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`.
If the parent exists but is not writable by the helper user, or the summary path
cannot be written safely, the helper must fail before prompting, print only a
non-secret failure classification such as `summary_preflight_failed`, leave no
summary or temp summary when possible, and run no Vault writes. This preflight
does not add root-token argument handling, Mac `.out` copy-back, IM,
support-bundle collection, workload-auth checks, reset/unseal, CP proof, or
runtime identity generation. If config readability fails after summary preflight
passes, the helper must write a safe failure summary with `failure_phase` such as
`config_load`, `failure_class` such as `config_unreadable` or `config_missing`,
`secret_prompts_started=false`, `vault_operations_started=false`, and
`operations.config_load.status=fail`, without raw exception strings or config
contents.

P0q's helper may use an in-process Vault API client for the documented objects:
auth mount `jwt`; JWT auth config with all active SPIRE JWT-SVID RSA validation
public keys selected for the workload trust domain and bound issuer; role
`service_execution` with
`role_type=jwt`, `user_claim=sub`,
`bound_audiences=vault`, and
`bound_subject=spiffe://execution.internal/workload`; policy
`runtime-identity-proof`; KV v2 proof paths
`proof-secrets/data/runtime-identity-vault-login` and
`proof-secrets/data/codex-runtime-profile`; field `api_key` present and
non-empty with the value never printed; and workload-zone config alignment at
`/etc/execution-substrate/vault/workload-zone-vault-config.json`. P0q must not
invent additional policy paths, mounts, roles, proof fields, or identities.

P0q execution writes only one remote-only non-secret bootstrap summary at
`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`
with schema
`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`.
The summary is evidence/projection only, never authority and not an IM input.
It may contain only schema, generated time, operation mode, configured-object
labels, operation statuses/booleans, safe failure phase/class labels, safe
prompt/operation-start booleans, safe last/next operation labels, path labels,
source labels, shape labels, counts, digests, redaction booleans, and explicit
non-claims. After summary preflight
succeeds, failures must write a non-secret classification summary when possible:
`overall_status=fail`, `failure_phase`, `failure_class`, optional sanitized
`failure_message_class`, `secret_prompts_started`, `vault_operations_started`,
and `operations.<phase>.status=fail` where applicable. Pre-prompt failures must
make clear that secret prompts did not start; post-prompt failures may only
record that prompts started, never prompt values. It must not contain a root
token, unseal key, client token, Vault token, JWT-SVID payload, API key value,
private key, password, proof secret value, secret payload, raw exception string,
traceback, raw Vault output, raw HTTP headers, operator-entered prompt values,
or terminal transcript. P0q must not copy that summary back to Mac `.out`,
create an operator summary, run IM, or create a support bundle. The helper must
write through a temp file in the summary directory and atomically rename it only
after redaction checks pass; cleanup must remove temp summary files on failure
when possible.

P0q bootstrap configures expected Vault objects only. It must not run a
workload-auth check, reset, unseal, Infrastructure Manager refresh,
support-bundle collection, CP proof, runtime identity summary, runtime identity
generation, governed smoke, default readiness validation, post-unseal check, or
support-bundle collection. It must not claim workload-auth success,
runtime-profile readiness, submit readiness, Vault production readiness,
governed execution proof, IM authority, CP recovery authority, ES Vault token
brokerage, or Remote Alpha production/deployment/provisioning/reconciliation
architecture. The workload-auth check remains a separate post-bootstrap
command.

P0q validation remains fake/static only. Tests must cover helper help and
secret posture, secret CLI/env rejection, fake Vault API capture showing
bootstrap authority is not passed by argv/env/file, proof secret value redaction
from printed output and summary, expected fake Vault objects, exact Vault JWT
auth config validation-key/issuer shape, workload-auth check JWT claim alignment
with the bootstrap config labels, summary
writability preflight before prompts and Vault writes, config readability
preflight before prompts and Vault writes, summary schema and redaction scans,
redaction checks before final summary rename, no workload-auth
check/reset/unseal/IM/CP/runtime-identity commands, operator flag rejection,
fake summary-path preparation over only the bounded remote filesystem command,
fake config-readability preparation over only the bounded fixed-path ACL command,
preparation failing before helper staging and prompts when it cannot prepare,
combined preparation ordering before helper staging/execution, fake SSH/SCP
staging of exactly the bootstrap public/internal helper pair, `ssh -tt` only for
explicit `--interactive-tty`, public helper invocation only, cleanup attempts,
no transcript/`tee`/`script`, and no copy-back to Mac `.out`.

The P0r implementation/self-audit/merge-readiness slice may add exactly one
Mac-side recovery-session runtime identity evidence route:
`scripts/remote_alpha_operator.sh recovery-session runtime-identity-summary
--ssh-target <target> --interactive-tty`. This route is evidence/projection
only over the existing host-local runtime identity helper summary script. It
does not settle the reopened runtime-identity handoff seam and does not claim
runtime-profile readiness, submit readiness, retained-result readiness,
governed execution proof, CP proof, or production readiness.

P0r may stage only:

- `scripts/remote_alpha_runtime_identity_helper_summary.sh`

It must resolve that helper from `BASH_SOURCE[0]`, stage it to a
route-specific remote scratch path, invoke only the staged helper over
`ssh -tt`, and attempt remote staged-helper cleanup by default. It must not
stage `scripts/remote_alpha_operator.sh`, `scripts/internal/*`, reset/unseal
helpers, workload-auth helpers, workload-auth bootstrap helpers, service-user
helpers, config/TLS helpers, binary deployment helpers, bundles, unrelated
helpers, or a generic helper dispatcher. It must not source helper scripts,
construct helper paths from user input, use `tee`, run `script`, create
transcripts, capture stdout/stderr to files, create Mac `.out`, copy summaries
back to Mac, create an operator summary, call Infrastructure Manager, collect
support bundles, run CP proof, run reset/unseal, run workload-auth bootstrap or
check, or run runtime identity generation.

Allowed P0r route flags are only `--help`, `--ssh-target <target>`, and
`--interactive-tty`. The route must reject `--host-local`, `--dry-run`,
`--check-only`, `--apply`, `--execute-reset`, `--unseal-only`,
`--post-unseal-check`, `--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, `--prepare-spire-bundle-read`,
`--interactive-sudo`, `--governed-smoke-command`, helper override flags such as
`--output`, `--runtime-support-path`, `--spire-agent-socket-path`,
`--spire-server-socket-path`, `--workload-spiffe-id`, and `--audience`,
arbitrary commands, unknown flags, duplicate flags, extra positional arguments,
equals-form options, and all secret-like arguments including root tokens,
unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, private
keys, passwords, proof secrets, raw identity payloads, and secret payloads.

P0r keeps the canonical runtime identity helper summary on the remote host at
`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`.
The operator facade must not print full summary JSON and must not persist
JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private keys,
passwords, proof secrets, raw identity payloads, or secret material. After
remote success it may print only the canonical remote summary path, a reminder
that the summary is evidence/projection only and non-authoritative, and
printed-only next steps such as the local `recovery-session --evidence-check
--runtime-identity-summary <path>` command to use after separate evidence
collection makes the summary available locally.

P0r validation remains fake/static only. Tests must cover help/plan/inventory
wording and non-claims; `runtime-identity-summary --help`; missing
`--ssh-target`; missing `--interactive-tty`; forbidden host-local, dry-run,
check-only, reset/unseal, workload-auth bootstrap/check, preparation, helper
override, secret-like, unknown, duplicate, equals-form, and positional inputs;
fake SSH/SCP staging of exactly the one public runtime identity helper; use of
`ssh -tt` only for the explicit interactive route; public helper invocation
only with no helper override flags; cleanup attempts; no transcript/`tee`/`script`;
no `.out`, operator summary, support bundle, IM, CP proof, reset/unseal,
workload-auth bootstrap/check, runtime identity generation, generic helper
dispatch, or `scripts/internal/*`; and preservation of the existing
reset/workload-auth/readiness route boundaries.

The P0s implementation/self-audit/merge-readiness slice may add exactly one
bounded Remote Alpha internal ES service TLS helper pair and exactly two
Mac-side recovery-session routes for ARS/AGS/ES artifact-registry mTLS status
and renewal:
`scripts/remote_alpha_operator.sh recovery-session es-service-tls-status
--ssh-target <target> --interactive-tty` and
`scripts/remote_alpha_operator.sh recovery-session es-service-tls-renew
--ssh-target <target> --interactive-tty --execute-renew`. P0s may add the
public helper `scripts/remote_alpha_es_service_tls_renew.sh` and the internal
helper `scripts/internal/remote_alpha_es_service_tls_renew.sh`, plus static and
fake tests for that bounded route. P0s must not run live SSH, sudo, live remote
OpenSSL, Vault, reset/unseal, workload-auth bootstrap/check, runtime identity
summary, Infrastructure Manager refresh, support-bundle collection, CP proof,
SPIRE/Nomad mutation, or network-dependent integration tests.

P0s is an ES-owned Remote Alpha proof/support helper only. It is not generic TLS
deployment, provisioning, reconciliation, production readiness, IM authority,
CP authority, Vault lifecycle, SPIRE lifecycle, Nomad lifecycle, workload-auth
bootstrap/check, or runtime identity evidence. The route is bounded to the
internal ARS loopback artifact-registry mTLS path consumed by AGS and ES. The
fixed covered paths are:
`/etc/execution-substrate/ars-tls/runtime-ca.pem`,
`/etc/execution-substrate/ars-tls/ars-server-cert.pem`,
`/etc/execution-substrate/ars-tls/ars-server-key.pem`,
`/etc/execution-substrate/tls/ags-client-cert.pem`,
`/etc/execution-substrate/tls/ags-client-key.pem`,
`/etc/execution-substrate/tls/runtime-ca.pem`,
`/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`,
`/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`, and
`/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`.

P0s must inspect the current config topology before status or renewal. It may
proceed only when ARS, AGS, and ES config prove that ARS listens behind the
bounded loopback artifact-registry dependency and those fixed paths are the
paths in use for the ARS server/client-CA and AGS/ES artifact-registry client
identity/root-CA materials. It must inspect related service-facing TLS paths
for AGS, ES, EGS, and ARS-facing CAs. If AGS external server certs, ES external
server certs, EGS TLS/CAs, Vault, SPIRE, Nomad, or any broader topology share a
covered renewal path, the helper must stop with a non-secret topology blocker
instead of guessing or broadening the renewal. P0s intentionally does not cover
AGS external server certs, ES external server certs, EGS TLS/CAs, Vault, SPIRE,
Nomad, workload-zone Vault config, runtime identity material, or general
service deployment.

P0s status mode is non-mutating. It must report public certificate metadata
only: subject, issuer, SAN, EKU, notBefore, notAfter, expired/not-yet-valid
status, file SHA-256, public fingerprint, and public-key fingerprint. It must
confirm ARS/AGS/ES cert/key public-key matches without printing private keys;
verify AGS and ES client certificates against the ARS trusted runtime/client
CA; verify the ARS server certificate against the AGS and ES root CAs; and
write only an optional non-secret remote evidence/projection summary at
`/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`.

P0s renewal mode requires explicit `--execute-renew` and visible
`--interactive-tty`. The Mac-side facade must stage only the fixed public and
internal TLS renewal helper pair, invoke only `--execute-renew` over `ssh -tt`,
and pass no helper override flags. The helper may use OS sudo only through the
visible remote terminal when needed. It must create a backup directory with
non-secret metadata before replacing files, generate fresh short-lived Remote
Alpha internal CA/cert material with future notAfter dates, install with the
fixed ownership/mode policy `root:ars 0640` for ARS materials, `root:ags 0640`
for AGS materials, and `root:es 0640` for ES materials, and restart only the
bounded affected service set `ars.service`, `ags.service`, and `es.service`.
Post-renew verification must re-run the client/server certificate verification
checks and probe ARS `/health` over mTLS using the configured AGS and ES client
identities. Mac-side IM health refresh remains a separate later action.

P0s summaries are evidence/projection only. They may include schema, mode,
paths, byte counts, certificate file SHA-256, public fingerprints, validity
windows, verification statuses, backup metadata, restart statuses, mTLS probe
statuses, and explicit non-claims. They must not include private key PEM
bodies, full certificate PEM bodies, Vault tokens, root tokens, unseal keys,
client tokens, JWT-SVIDs, API keys, passwords, proof secrets, private-key
digests for backup material, raw secret-bearing command output, terminal
transcripts, support-bundle content, or Mac `.out` copy-back.

Allowed P0s route flags are only `--help`, `--ssh-target <target>`,
`--interactive-tty`, and `--execute-renew` for the renew route only. P0s must
reject `--host-local`, `--dry-run`, `--check-only`, `--status`, `--apply`,
`--execute-reset`, `--unseal-only`, `--post-unseal-check`,
`--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, `--prepare-spire-bundle-read`,
`--interactive-sudo`, `--governed-smoke-command`, helper override flags,
TLS/config path overrides, output/summary overrides, arbitrary commands,
unknown flags, duplicate flags, extra positional arguments, equals-form
options, and all secret-like arguments.

P0s validation remains fake/static only. Tests must cover status mode detecting
expired certificates and safe fields, status mode detecting valid
certificates, renew refusing without `--execute-renew`, renew refusing without
`--interactive-tty` and `--ssh-target`, secret-like argument rejection, fake
SSH/SCP staging of exactly the fixed TLS renewal public/internal helper pair,
private key PEM bodies not printed or persisted to summaries, ownership/mode
policy, backups before replacement, exact restart set, post-renew verification
of AGS/ES client certs against ARS CA and ARS server cert against AGS/ES root
CAs, and docs tests preserving non-authority and non-production claims.

The P0t implementation/self-audit/merge-readiness slice may extend the
existing bounded Remote Alpha internal ES service TLS helper pair with exactly
one additional fixed scope and exactly two Mac-side recovery-session routes for
the ES -> EGS execution-governance trust-model mTLS path:
`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-status
--ssh-target <target> --interactive-tty` and
`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-renew
--ssh-target <target> --interactive-tty --execute-renew`. P0t reuses only the
existing public helper `scripts/remote_alpha_es_service_tls_renew.sh` and the
existing internal helper `scripts/internal/remote_alpha_es_service_tls_renew.sh`
with a fixed `--scope execution-governance` helper invocation. It must not add
a new generic helper dispatcher, helper path override, or deployment
reconciliation surface. P0t validation remains fake/static only and must not
run live SSH, sudo, live remote OpenSSL, Vault, reset/unseal, workload-auth
bootstrap/check, runtime identity summary, Infrastructure Manager refresh,
support-bundle collection, CP proof, SPIRE/Nomad mutation, or
network-dependent integration tests.

P0t is an ES-owned Remote Alpha proof/support helper extension only. It is not
generic TLS deployment, provisioning, reconciliation, production readiness, IM
authority, CP authority, Vault lifecycle, SPIRE lifecycle, Nomad lifecycle,
workload-auth bootstrap/check, runtime identity evidence, or a redesign of EGS
trust-model semantics. The route is bounded to the internal EGS loopback
execution-governance mTLS path consumed by ES when ES fetches the current EGS
`GET /v1/trust-model` compatibility surface. The fixed covered paths are:
`/etc/execution-substrate/egs-tls/egs-server-cert.pem`,
`/etc/execution-substrate/egs-tls/egs-server-key.pem`,
`/etc/execution-substrate/egs-tls/runtime-ca.pem`,
`/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`,
`/etc/execution-substrate/es-tls/execution-governance-client-key.pem`, and
`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`.

P0t must inspect the current config topology before status or renewal. It may
proceed only when EGS config proves the server cert/key and client CA are the
fixed EGS-readable TLS paths above, ES config proves
`dependencies.execution_governance.base_url` is the bounded loopback EGS route
on port `8443`, ES config proves the fixed ES execution-governance client
identity/root-CA paths above plus `server_name` of
`server.execution-governance.internal`, and AGS config has no
execution-governance dependency. The current EGS trusted client CA is the same
runtime CA file at `/etc/execution-substrate/egs-tls/runtime-ca.pem`; the ES
execution-governance root CA is the ES-readable copy of that trust root at
`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`. Any AGS
client-to-EGS material is out of scope for P0t. If config shows AGS
client-to-EGS material, shared paths with ARS/AGS/ES external TLS, Vault,
SPIRE, Nomad, workload-zone Vault config, runtime identity material, or any
broader topology sharing a covered renewal path, the helper must stop with a
non-secret topology blocker instead of guessing or broadening the renewal.

P0t status mode is non-mutating. It must report public certificate metadata
only: subject, issuer, SAN, EKU, notBefore, notAfter, expired/not-yet-valid
status, file SHA-256, public fingerprint, and public-key fingerprint. It must
confirm ES execution-governance client cert/key and EGS server cert/key
public-key matches without printing private keys; verify the ES client
certificate against the EGS trusted runtime/client CA; verify the EGS server
certificate against the ES execution-governance root CA; and write only an
optional non-secret remote evidence/projection summary at
`/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json`.

P0t renewal mode requires explicit `--execute-renew` and visible
`--interactive-tty`. The Mac-side facade must stage only the fixed public and
internal TLS renewal helper pair, invoke only `--scope execution-governance`
plus `--execute-renew` over `ssh -tt`, and pass no helper override flags. The
helper may use OS sudo only through the visible remote terminal when needed. It
must create a backup directory with non-secret metadata before replacing files,
generate fresh short-lived Remote Alpha internal EGS runtime CA/cert material
with future notAfter dates, install with the fixed ownership/mode policy
`root:egs 0640` for EGS TLS material and `root:es 0640` for ES
execution-governance client/root material, and restart only the bounded
affected service set `egs.service` and `es.service`. Post-renew verification
must re-run the client/server certificate verification checks and probe EGS
`/v1/trust-model` over mTLS using the configured ES execution-governance
client identity. If safe in fake/static validation, the helper should also
record that `es.service` is active after restart. Mac-side IM health refresh
remains a separate later action.

P0t summaries are evidence/projection only. They may include schema, scope,
mode, paths, byte counts, certificate file SHA-256, public fingerprints,
validity windows, verification statuses, backup metadata, service restart
statuses, mTLS trust-model probe statuses, ES service active status, and
explicit non-claims. They must not include private key PEM bodies, full
certificate PEM bodies, Vault tokens, root tokens, unseal keys, client tokens,
JWT-SVIDs, API keys, passwords, proof secrets, private-key backup digests, raw
secret-bearing command output, terminal transcripts, support-bundle content, or
Mac `.out` copy-back.

Allowed P0t route flags are only `--help`, `--ssh-target <target>`,
`--interactive-tty`, and `--execute-renew` for the renew route only. P0t must
reject `--host-local`, `--dry-run`, `--check-only`, `--status`, `--scope`,
`--apply`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`,
`--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, `--prepare-spire-bundle-read`,
`--interactive-sudo`, `--governed-smoke-command`, helper override flags,
TLS/config path overrides, output/summary overrides, arbitrary commands,
unknown flags, duplicate flags, extra positional arguments, equals-form
options, and all secret-like arguments.

P0t validation remains fake/static only. Tests must cover status mode detecting
expired EGS/ES execution-governance certificates, status mode detecting valid
EGS/ES execution-governance certificates, renew refusing without
`--execute-renew`, renew refusing without `--interactive-tty` and
`--ssh-target`, secret-like argument rejection, fake SSH/SCP tests proving
exactly the fixed public/internal TLS renewal helper pair is staged, fake renew
tests proving private key PEM bodies are not printed or persisted to summaries,
fake renew tests proving owner/group/mode policy, fake renew tests proving
backups are made before replacement, fake renew tests proving services to
restart are exactly `egs.service` and `es.service`, fake post-renew
verification exercising the ES -> EGS trust-model TLS path, docs tests
preserving non-authority/non-production/non-IM/non-CP claims, and preservation
of existing P0s ARS/AGS/ES artifact-registry TLS tests.

P0t remains bounded ES Remote Alpha proof/support workflow glue only. It is
not generic TLS deployment, not Infrastructure Manager reconciliation, not
Control Plane authority, not Vault/SPIRE/Nomad authority, not EGS trust-model
redesign, not production readiness, and not Remote Alpha production,
deployment, provisioning, or reconciliation architecture.

The P0u implementation/self-audit/merge-readiness slice may add exactly one
bounded Remote Alpha host-local operator healthcheck client TLS helper pair and
exactly two Mac-side recovery-session routes:
`scripts/remote_alpha_operator.sh recovery-session
operator-healthcheck-tls-status --ssh-target <target> --interactive-tty` and
`scripts/remote_alpha_operator.sh recovery-session
operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty
--execute-renew`. P0u may add the public helper
`scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and the internal
helper `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`, plus
static and fake tests for that bounded route. P0u must not run live SSH, sudo,
live remote OpenSSL, Vault, reset/unseal, workload-auth bootstrap/check,
runtime identity summary, Infrastructure Manager refresh, support-bundle
collection, CP proof, SPIRE/Nomad mutation, service deployment, ES binary
deployment, ES service restart, or network-dependent integration tests.

P0u is an ES-owned Remote Alpha proof/support helper only. It is not generic
TLS deployment, provisioning, reconciliation, production readiness, IM
authority, CP authority, Vault lifecycle, SPIRE lifecycle, Nomad lifecycle,
workload-auth bootstrap/check, runtime identity evidence, ES service TLS
renewal, ES governance TLS renewal, or a change to CP workflow/run-control
authority. The route is bounded to the host-local operator healthcheck client
TLS material used by the Remote Alpha operator healthcheck environment. The
fixed covered paths are:
`/etc/execution-substrate/tls/operator-client-cert.pem` and
`/etc/execution-substrate/tls/operator-client-key.pem`.
The helper may read
`/etc/execution-substrate/tls/combined-service-ca-bundle.pem` only as the
healthcheck server trust bundle for safe mTLS probes, and may read ES config
only to identify the ES server client CA used to verify the operator client
certificate.

P0u must treat the previously observed operator identity
`spiffe://execution.internal/operator` as a legacy mismatch for the current ES
authorization semantics. The current ES/AGS allowlist accepts the repo-owned
operator path `spiffe://execution.internal/operator/local`, so any future
renewed operator healthcheck certificates must use subject `CN=client.operator` and SAN
`URI:spiffe://execution.internal/operator/local` plus the bounded DNS label
`client.operator`. The helper must detect and report the legacy
`spiffe://execution.internal/operator` SAN as a status failure that requires
renewal rather than renewing back into the old identity.

P0u status mode is non-mutating. It must report public certificate metadata
only: subject, issuer, SAN, EKU, notBefore, notAfter, expired/not-yet-valid
status, file SHA-256, public fingerprint, and public-key fingerprint. It must
confirm the operator cert/key public-key match without printing the private
key; verify the operator certificate against the ES server client CA bundle
when that topology is configured; detect the current `operator/local` URI;
detect the legacy `operator` URI; and write only an optional non-secret remote
evidence/projection summary at
`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`.
It may probe `/health` and `/v1/executions:contract` only with the configured
healthcheck env and only when the URLs are safe non-mutating local HTTPS
targets; probe response bodies must not be recorded.

P0u renewal mode requires explicit `--execute-renew` and visible
`--interactive-tty`. The Mac-side facade must stage only the fixed public and
internal operator healthcheck TLS helper pair, invoke only `--execute-renew`
over `ssh -tt`, and pass no helper override flags. The helper may use OS sudo
only through the visible remote terminal when needed. Current P0u renewal is
design-blocked because no authoritative Remote Alpha CA custody/signing
topology exists for this host-local operator client identity. The helper must
not assume a retained remote CA private key such as
`/etc/execution-substrate/tls/runtime-ca-key.pem`, must not accept ad hoc
signing material, and must fail closed with `failure_class` such as
`unsupported_signing_topology` before backup, install, service restart, or
post-renew probes. The summary must include explicit next-step text that
renewal requires a future documented CA custody/signing design. Client
certificate renewal must not restart ES unless a later documented code path
proves a restart is strictly necessary; P0u's bounded helper records ES
restart as not required.

P0u summaries are evidence/projection only. They may include schema, mode,
paths, byte counts, certificate file SHA-256, public fingerprints, validity
windows, configured identity classification, cert/key public-key match status,
verification statuses, unsupported-signing-topology failure classification,
next-step text, not-run backup/install/probe metadata, and explicit
non-claims. They must not include
private key PEM bodies, full certificate PEM bodies, Vault tokens, root
tokens, unseal keys, client tokens, JWT-SVIDs, API keys, passwords, proof
secrets, private-key backup digests, raw secret-bearing command output,
terminal transcripts, support-bundle content, raw retained bundles, raw
workspace contents, or Mac `.out` copy-back.

Allowed P0u route flags are only `--help`, `--ssh-target <target>`,
`--interactive-tty`, and `--execute-renew` for the renew route only. P0u must
reject `--host-local`, `--dry-run`, `--check-only`, `--status`, `--scope`,
`--apply`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`,
`--execute-bootstrap`, `--prepare-summary-path`,
`--prepare-config-readability`, `--prepare-spire-bundle-read`,
`--interactive-sudo`, `--governed-smoke-command`, helper override flags,
TLS/config/path overrides, output/summary overrides, arbitrary commands,
unknown flags, duplicate flags, extra positional arguments, equals-form
options, and all secret-like arguments.

P0u validation remains fake/static only. Tests must cover status detecting an
expired operator certificate, status detecting a valid operator certificate,
status detecting the legacy operator URI mismatch, renew refusing without
`--execute-renew`, renew refusing without `--interactive-tty` and
`--ssh-target`, secret-like argument rejection, fake SSH/SCP tests proving
exactly the fixed public/internal operator healthcheck TLS helper pair is
staged, fake renew tests proving private key PEM bodies are not printed or
persisted to summaries, renew failing closed with
`unsupported_signing_topology` before backup/install/service restart/probes,
renew not requiring a retained remote CA private key, docs tests preserving
non-authority/non-production/non-IM/non-CP claims, and preservation of existing
P0s/P0t service/governance TLS tests.

P0u remains bounded ES Remote Alpha proof/support workflow glue only. It is
not generic TLS deployment, not Infrastructure Manager reconciliation, not
Control Plane authority, not Vault/SPIRE/Nomad authority, not workload-auth or
runtime identity authority, not production readiness, and not Remote Alpha
production, deployment, provisioning, or reconciliation architecture.

The P0v design/static-test prep slice may define, but must not implement, a
future ES-owned noninteractive read-only operator-healthcheck TLS status route:
`scripts/remote_alpha_operator.sh recovery-session
operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format
json`. The design lives at
`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`.
P0v is a route-contract design extension over the P0u operator-healthcheck TLS
status surface, not renewal, not a signing-topology decision, not a profile
mutation path, and not a Maintenance Agent scheduling change. It must not run
live SSH, scp, BatchMode probes, sudo, remote helpers, live remote OpenSSL,
Vault, reset/unseal, workload-auth bootstrap/check, runtime identity summary,
Infrastructure Manager refresh, support-bundle collection, CP proof,
SPIRE/Nomad mutation, service deployment, ES submit, Docker/Nomad jobs,
certificate mutation, profile mutation, env/state mutation, proof generation,
or network-dependent integration tests.

P0v chooses a new route id instead of adding a mode flag to the current
interactive `operator-healthcheck-tls-status` route. The existing route remains
the foreground operator route with required `--interactive-tty`, local
stdin/stdout TTY preflight, `ssh -tt`, visible sudo/password prompt behavior,
fixed helper-pair staging, and remote summary retention. The proposed future
noninteractive route must require no local stdin/stdout TTY, allocate no
pseudo-TTY, use no-prompt SSH semantics if SSH is used, use no prompt-capable
sudo, fail closed when noninteractive auth is not ready, avoid password
storage/replay, avoid remote helper staging, avoid remote summary mutation, and
emit only bounded JSON evidence.

No fallback emitters are allowed for P0v. ES machine-readable route JSON is
promised only after declared route prerequisites pass. Missing local
runtime/validator dependencies are caller/integration preflight failures, not
ES route-output obligations. A later ES route implementation may assume
declared prerequisites or use a dedicated checked-in runtime/validator, but it
must not split one schema contract across a primary runtime plus shell fallback
JSON assembly. Until those prerequisites and the implementation audit land,
the script still has no active dispatch arm for
`operator-healthcheck-tls-status-noninteractive`; the existing P0u interactive
route remains the only implemented operator-healthcheck status route.

P0v's proposed status schema is
`execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`.
It may carry route id/version, generated time, live-contact-attempted status,
status availability, bounded failure class, numeric transport/helper exit
codes when safe, public certificate metadata, safe identity labels, safe trust
chain labels/digests, redaction flags, non-authority labels, owning-repo
contract labels, and profile-lineage hints only. It must not carry raw stdout,
raw stderr, helper or SSH transcripts, full certificate PEM bodies, private-key
PEM bodies, env values, endpoint secrets, remote paths, raw logs,
TLS/SPIFFE/Vault material, connector/workspace/org IDs, raw payloads, support
bundle contents, retained bundle contents, or unsafe local paths.

P0v status evidence remains evidence/projection only. CP may later consume it
as diagnostic evidence only after a CP docs/tests tranche; IM may later consume
it for readiness/profile/provenance only after an IM docs/tests tranche; MA may
run it only after ES implements and audits the route and a later MA tranche
updates route metadata to `supports_noninteractive=true` and
`scheduled_execution_allowed=true`. Until those later changes land, current MA
scheduled/background execution remains disallowed for
`operator-healthcheck-tls-status`, and `operator-healthcheck-tls-renew` remains
blocked/status-only with `unsupported_signing_topology`.

Bridge/MA/CP/IM consumers must not wrap missing ES prerequisites into ES status
truth. Bridge may record only Bridge-owned ChatGPT/Codex coordination preflight
evidence when ES prerequisites are not declared or the route is not invoked.
CP diagnose rerun and IM profile-lineage refresh remain future owning-repo
tranches; P0v does not renew, mutate cert/profile/key/trust/env/state, run live
proof, or widen any cross-repo authority boundary.

The operator-authorized operator-healthcheck TLS replacement design tranche is
also docs/static-test only. It records an ES-owned future replacement path in
`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`
and an IM-owned profile-lineage refresh counterpart in the Infrastructure
Manager repo. It is not a P0v route implementation, not renewal execution, not
Bridge or Maintenance Agent authority, not CP diagnose execution, and not
profile mutation. It preserves `operator-healthcheck-tls-renew` as
blocked/status-only with `unsupported_signing_topology` until ES documents the
signing topology, key custody, backup/rollback evidence, redaction, and
post-check semantics for the `spiffe://execution.internal/operator/local`
operator identity.

The Remote Alpha maintenance-monitor contract alignment slice is docs/static
contract work only. It may codify a future Mac-side maintenance project as a
scheduler, notifier, local-evidence summarizer, and allowlisted ES-command
invoker, but it must not implement that project or create a new repository in
this slice. ES keeps ownership of every Remote Alpha status, renewal, repair,
and route-contract semantic. External schedulers may invoke only documented
allowlisted ES commands and may not define their meaning, infer renewal
eligibility, broaden helper scope, or become ES runtime authority, IM
readiness/provenance authority, CP run-control authority, a hidden remote
reconciler, or broad provisioning automation. Remote Alpha remains bounded
proof/support posture only.

Remote Alpha maintenance route eligibility is fixed for this planning slice:
`es-service-tls-status`, `es-governance-tls-status`,
`operator-healthcheck-tls-status`, binary deployment check, workload-auth
check, and runtime identity summary are read-only monitor-eligible;
`es-service-tls-renew` and `es-governance-tls-renew` are operator-approved now
and future automatic-renewal candidates only after route-specific docs, tests,
audit, idempotence, backup-before-replace, post-verify, fail-closed behavior,
and no secrets in monitor-controlled surfaces are all present;
`operator-healthcheck-tls-renew` remains blocked/status-only until a signing
topology and operator/local identity renewal authority are documented; binary
deployment apply and workload-auth bootstrap are not monitor auto-renewal
routes.

## Current Remote Alpha Hardening Tranche

`Bounded slice rule`: the current Remote Supported-Host Alpha bounded hardening
posture is `AGS sealed + ARS de-root + EGS de-root + ES config/TLS prep
applied + ES stable writable-state prep applied + long-lived es.service de-root
applied`.

- AGS is already de-rooted and sealed in this tranche; preserve the landed
  `ags:ags` service posture and its existing host-local summary/evidence shape.
- ARS is already de-rooted in this tranche; preserve the landed `ars:ars`
  service posture, its dedicated TLS/state ownership model, and its existing
  host-local summary/evidence shape.
- EGS is already de-rooted in this tranche; preserve the landed `egs:egs`
  service posture and its existing host-local summary/evidence shape.
- ES config/TLS prep is applied and productized for the live host.
- ES writable-state roots are prepared under the documented stable `es:es`
  ownership model, and future writable-state readiness has passed.
- The current live long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`.
- Post-apply `/health`, `GET /v1/executions:contract`, and the current
  lowest-cost existing post-apply happy path all passed after the bounded live
  service-user change, and Infrastructure Manager readiness is accepted.
- The repo-local rollback rehearsal/check-only evidence set for that landed
  service-user slice now passes and remains non-mutating evidence only.
- This tranche does not claim full ES/runtime de-root.
- The root-start runtime helper, Nomad task `User: "0:0"`, helper-private
  SPIRE traversal, broad root selector posture, and Vault/workload-zone
  handoff remain bounded compatibility edges.
- The long-lived ES startup path keeps
  `execution.spire_workload_api_socket_path` as a config-shape and submit
  input only; operator/readiness tooling remains responsible for proving the
  host path is a real Unix socket, and runtime-helper failure to use that
  helper-private raw SPIRE path must remain explicit and fail closed.
- Future writable-state readiness and service-user migration check-only now
  require `execution.staging_root_dir` and `execution.results_root_dir` to
  resolve to one shared target owner UID:GID; mismatched stable-root owner
  models are honest blockers rather than compatibility noise.
- Old root-era staging/results roots remain preserved as rollback/debug/evidence
  state until a later explicit cleanup/archive action after the rollback window
  expires; they must not be recursively re-owned or deleted by inertia.
- Future cleanup/archive planning for those preserved roots is a repo-local,
  non-mutating evidence step only: consume local apply-summary artifacts,
  keep rollback-window status explicit, and do not SSH, use `sudo`,
  recursively re-owner preserved contents, archive live-host content, or
  delete anything by default.
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

`Current invariant`: the landed long-lived `es.service` service-user change is
already on the least-privilege side of this milestone baseline:
`User=es`, `Group=es`, `UMask=0027`, with post-apply `/health`,
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
| Nomad host client/server substrate | `blocker` | The current supported substrate still depends on a pre-managed non-dev Linux Nomad client/server. Upstream least-privilege guidance is to keep Nomad servers as narrow as feasible, but the Linux Nomad client remains a root-managed isolation boundary today and a rootless client is not the current supported/well-tested repo posture. | Supported-host qualification still requires a pre-managed non-dev Nomad baseline, `scripts/01_bringup.sh check` still treats Nomad readiness as an environment gate, and the landed ES happy paths still hand lifecycle authority to Nomad rather than replacing it. | Revisit only if a later separately documented substrate decision proves a supported client posture that does not depend on an unsupported rootless-client assumption while preserving Nomad as lifecycle authority. | Milestone 1 does not claim a rootless Nomad client or full Nomad least-privilege closeout. |
| SPIRE raw-socket traversal and selector posture | `accepted MVP compatibility edge` | The workload-visible contract is already narrowed to `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, but the helper-private raw SPIRE path and the broad root selector scope remain explicit compatibility edges rather than a finished least-privilege identity model. | Slice `1A`/`1B` proof, runtime-helper tests that keep the raw SPIRE path out of workload env, the remote runtime-identity helper summary, and the service-user migration check-only gate that validates helper-private runtime input without making `es:es` a raw-socket reader. | Revisit only through the later runtime-boundary redesign seam after a narrower helper principal or equivalent traversal model is documented and re-proved. | Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege. |
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

## Future ES Privilege-Boundary Design Track

`Reopened redesign seam`: full ES/runtime de-root beyond the now-landed
long-lived `es.service` user flip remains a future structural design track.

- This future track covers the long-lived ES service privilege model, Nomad
  task user model, runtime-helper/supervisor ownership, SPIRE selector posture,
  SPIRE socket traversal, staging/results ownership, retained-result
  materialization, and operator maintenance/rollback model as one boundary
  package rather than as implicit follow-on hardening.
- One bounded implementation slice on this seam is now landed: the repo-side
  binary-deployment helper, stable writable-state ownership helper, and
  long-lived `es.service` migration helper were all exercised in bounded
  sequence to reach the current live service-user posture.
- The current accepted Alpha posture now includes bounded long-lived ES
  service-user de-root: ES config/TLS prep is applied, stable writable-state
  roots are prepared, live `es.service` runs as `User=es`, `Group=es`,
  `UMask=0027`, post-apply lowest-cost happy path passed, and future
  writable-state readiness passed. Do not treat that bounded slice as proof
  that the full ES/runtime privilege boundary is solved.
- The current branch now carries design-only and branch-local readiness inputs
  for parts of Option B: the privileged-operation matrix, writable-state
  ownership model, runtime ownership-normalization contract, non-mutating
  writable-state readiness checker with `alpha-compat` and
  `future-non-root-required` modes, and repo-local normalized-run lifecycle
  tests covering success, failed, lost, canceled, invalid-marker,
  missing-marker Alpha compatibility, and future non-root-required preflight
  behavior.
- That repo-local readiness was necessary but not sufficient: the bounded live
  rollout also required host-side ES/runtime-helper binary parity, stable
  writable-state preparation, an explicit `future-non-root-required`
  readiness pass, and then the bounded long-lived service-user apply. Those
  helper flows are live-host evidence for their own bounded slices, not by
  themselves proof that the runtime/task/SPIRE boundary is fully de-rooted.
- The bounded rollout sequence that led to the current live posture was:
  resolve live ES/runtime-helper binary parity first, then prepare only the
  stable staging/results roots plus any bounded parent-traversal or
  legacy-artifact reconciliation needed to make those live roots future
  non-root-manageable, then rerun the explicit
  `future-non-root-required` writable-state gate, then use the long-lived
  `es.service` migration helper check-only path immediately before the
  bounded live service-user apply.
- Post-migration ES/runtime-helper binary refreshes now remain bounded to the
  current accepted live `User=es`, `Group=es`, `UMask=0027` host slice. The
  binary-deployment helper is no longer a root-like service-posture surface;
  any return to a root-era long-lived service identity must happen through a
  separate rollback/service-user action rather than through binary deployment.
- The helper-private raw SPIRE socket path remains a privileged runtime
  dependency and must stay operator-validated rather than being treated as a
  direct long-lived ES service-user read requirement.
- Design assessment for Remote Alpha -> Beta may compare alternative
  architectures, but implementation work must not proceed until the chosen
  boundary model and required evidence are documented explicitly.

## Explicit Deferred Post-Migration Actions

The current branch-level milestone for the completed long-lived `es.service`
service-user migration is now:

- ES config/TLS prep applied
- stable writable-state prep applied
- live `es.service` running as `User=es`, `Group=es`, `UMask=0027`
- post-apply `/health` and `GET /v1/executions:contract` passed
- post-apply lowest-cost existing happy path passed
- future writable-state readiness passed
- rollback rehearsal/check-only evidence passed
- old-root cleanup/archive planner present as a repo-local non-mutating
  planning surface only

`Current invariant`: that branch-level milestone does not claim full
ES/runtime de-root.

`Bounded slice rule`: old root-era cleanup/archive execution is explicitly
deferred.

- Any later implementation must be a separate live-mutating operator action,
  not a side effect of the writable-state or service-user helpers.
- Preconditions are explicit:
  - the rollback window is explicitly closed
  - preserved old-root evidence is archived elsewhere or explicitly deemed
    unnecessary
  - operator signoff is recorded
- If productized later, the surface should expose explicit `check-only` and
  `apply` modes.
- That later action must not recursively `chown` old roots and must not
  delete by default.

`Bounded slice rule`: an optional rollback execution helper is explicitly
deferred.

- It is not needed while the current `es:es` service posture is healthy.
- It must remain recovery-only rather than routine maintenance.
- Any future implementation must be bounded, must expose explicit
  `check-only` and `apply` modes, and must not run live rollback unless
  operationally necessary.

`Reopened redesign seam`: Option C runtime-boundary redesign remains a
separate architecture track, not a cleanup follow-on.

- Any future work on the root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, broad root selector posture, or
  Vault/workload-zone handoff must proceed only as that separately documented
  redesign track.

`Current invariant`: the completed branch-level milestone does not imply a
`master` merge.

- Merge remains a human milestone decision after review of the bounded
  evidence set and governance posture.

## Current Planning Objective

The repository is no longer in rewrite-by-default mode.

The current goal is to keep bounded platform work honest while making reopened seams explicit. Core contracts or boundaries should be re-derived only when `PLANS.md` names them as reopened; otherwise, current implementation, docs, and proof tooling should be treated as bounded platform work to harden rather than rewrite by default.

The current plan must prioritize:

- structural clarity
- Go-native boundaries
- explicit package-local ownership
- reduced dependence on the existing cross-service grammar
- reduced leakage of one service's DTO or fact model into another service's public shape

Current code remains the starting point for any reopened-seam work, not a compatibility promise. Historical references outside this repo, including the Monolith/Python repository, may inform migration context or bounded proof/bootstrap conventions only; they are not current architecture authority.

## Primary Program Orientation

Execution Substrate is the primary program in this repository.

The current ES work is foundational boundary and contract work, and that is real program delivery: it decides what governed execution can safely admit, run, project, retain, and expose to callers.

Control Plane is an important first non-operator consumer. It improves ergonomics and governance around ES, but it does not define ES core contracts. Control Plane documents may describe how CP consumes accepted ES surfaces; they must not widen ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness ownership.

Milestone 0 MVP claim freeze is recorded in `.docs/mvp.md`. That document is a
planning and documentation freeze only: it captures the current MVP claim,
surface classifications, and explicit non-claims without widening ES contracts
or promoting proof-harness behavior into architecture.

The next milestone package is **ES Admission And Runtime Boundary Realignment**.

That package is ES-owned. It should deliver a coherent ES milestone by:

- classifying stable ES semantic contracts, temporary compatibility edges, and implementation details/current slice constraints before implementation spreads outward
- completing only the Workstream A shared-kernel decisions needed to keep ES from inheriting accidental cross-service grammar
- completing only the Workstream B publication/storage/discoverability decisions needed to make ES input ownership explicit
- delivering Workstream C as the primary ES admission, submission, lifecycle-projection, retained-result, and runtime-boundary package
- preserving current CP compatibility for the governed execution path unless an explicit compatibility, drain, migration, or versioning plan is documented
- keeping the current `execution_substrate.runtime_profile` annotation and `control-plane-normal-shell/v1` profile as accepted bounded compatibility for the next milestone package

Stable semantic contracts for this next package:

- ES owns admission composition, submission handoff, Nomad-backed lifecycle projection, retained opaque result bundles, and runtime handoff boundaries.
- ES owns the public admission model, prepare model, submit model,
  Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- Nomad remains authoritative for submitted execution lifecycle; ES must not invent a parallel lifecycle store or scheduler authority.
- ES may expose a bounded lifecycle projection revision on status responses as an opaque same-run read-coordination fact derived from Nomad observation. Callers may compare equality/change for the same run only. They must not parse or order it, infer scheduler or backend state from it, use it as a write precondition for cancel/result/logs, or treat it as a Nomad identifier or index. It is not evidence of an ES-owned lifecycle store.
- ES may expose a bounded `authority_handoff` read surface on submission/status responses for non-secret runtime authority facts ES actually selected and handed off for a run: effective runtime profile, workload-visible identity endpoint handoff, workload-vault auth metadata, selected workload-zone Vault config reference, and bounded profile credential-location metadata. This surface is read-only evidence of the submitted runtime handoff, not live credential state, lease state, scheduler identity, policy approval state, or a Control Plane lifecycle record.
- ES must not bypass ARS artifact storage/discoverability, EGS runtime-trust publication, or configured runtime-config ownership to make admission easier.
- ES-owned retained results remain opaque output bundles and must not become Control Plane checkpoint, review, finalization, or orchestration state.
- ES-owned runtime identity and workload-credential handoff must remain platform-owned, non-secret, and non-brokering: workloads use the discovered endpoint and workload-Vault metadata; ES does not fetch, mint, store, rotate, parse, or validate Vault or Codex credential material.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
- Caller authentication and narrow SPIFFE allowlist authorization remain required on the governed execution path.

Temporary compatibility edges to preserve explicitly during this package:

- current CP compatibility for AGS publish plus ES prepare, submit, status, logs, result, and cancel over HTTPS+mTLS
- `GET /v1/executions:contract` as a narrow read-only producer compatibility declaration for the current governed-execution contract, including the mandatory outcome-evidence response surfaces
- `POST /v1/executions:prepare` as an active bounded preflight surface
- `invocation.annotations["execution_substrate.runtime_profile"]` and the bounded `control-plane-normal-shell/v1` profile
- the current `static-script` overlay behavior for that profile
- `/execution/staged`, `/execution/run`, `/execution/run/result`, and current runtime-identity path conventions
- the current `authority_handoff` field names and evidence-source labels while the ES request/runtime-profile and runtime-identity seams remain reopened
- the current additive `outcome_evidence` JSON field and successful logs/result outcome-evidence headers while lifecycle/status/result/log/cancel evidence vocabulary remains bounded to the current Nomad/retained-result slice
- retained `application/gzip` result bundles keyed by public `run_id`
- supported-local profile-image durability checks, including the Nomad Docker `docker.cleanup.image=false` guardrail for enabled local runtime-profile images
- the ES config/TLS ownership prep bridge where live `es.service` stays
  `root(default)` while dedicated `root:es` readable config/TLS material is
  staged for a later ES de-root slice

Implementation details and current slice constraints not to promote into stable architecture:

- host staging roots, bind-mount source paths, `.out/` proof workspaces, generated helper artifacts, and guest `/tmp` scratch
- the internal Nomad job naming rule `exec-<run_id>`
- the latest-allocation projection rule, stdout-only log retrieval, single task named `task`, async-only submit, and no-retry/no-reschedule slice, except that the status response may expose an opaque lifecycle projection revision without exposing the underlying selection rule or scheduler IDs
- proof-only Codex shim behavior and supported-local proof bootstrap details
- helper scripts and examples as client contracts; the HTTPS API and documented runtime handoff are the client-facing surfaces

## Current-State Facts To Preserve During Redesign

The following are useful current implementation facts and should remain visible to future agents while the redesign is underway:

- The repository currently implements five primary service boundaries: ARS, AGS, EGS, CGS, and ES.
- The current publication flow is `AGS -> ARS`.
- The current admission and execution flow is `request -> ES -> EGS / ARS -> Nomad -> Docker`.
- ES currently composes startup-owned runtime-config references, ARS, and EGS in its hot path. CGS exists but is not in the current ES hot path.
- The current primary artifact model crossing AGS, ARS, and ES is aggregate evidence plus payload, with manifest retained as supporting publication data.
- The repository now also carries a first parallel shared evidence kernel in `internal/contracts/evidence/v1` for the primary `AGS -> ARS -> ES` artifact path, and ES now requires that aggregate evidence on its first-class admission path.
- ARS currently exposes immutable blob reads plus a smaller runtime-facing discovery record for evidence and payload, while retaining descriptor/manifest support data as secondary publication discoverability.
- The repository now carries a small shared runtime-config surface in `internal/contracts/runtimeconfig/v1` for the named workload-zone Vault config reference and the current workload-zone Vault config blob schema.
- ES startup config currently carries the required workload-zone Vault config reference, while ARS remains the blob/discoverability owner for the corresponding runtime-config blob.
- CGS currently loads explicit subject policy records from startup `id.conf` input and returns bounded authorization decisions through `POST /v1/credential/authorize`.
- EGS currently publishes a signed runtime-trust payload with signer policy and artifact revocation policy, alongside separate EGS-owned publication metadata.
- ES currently exposes a narrow read-only producer compatibility declaration at `GET /v1/executions:contract`, a bounded preflight `POST /v1/executions:prepare`, a primary public execution handoff at `POST /v1/executions:submit`, and minimal Nomad-backed lifecycle endpoints whose current `run_id` lookup and projected-allocation rules are explicit ES-internal slice policy rather than public contract.
- ES status now includes a bounded lifecycle projection fact, `lifecycle_projection`, whose `source` is the current lifecycle authority and whose `revision` is an opaque same-run read-coordination token produced from implementation-private Nomad observation during the status read. Consumers may compare equality/change for the same run only. They must not parse or order it, infer scheduler or backend state from it, use it as a write guard, or treat it as a Nomad identifier or index. This is a read coordination surface for consumers, not a write coordination API or a durable ES run record.
- ES lifecycle/status/result/log/cancel surfaces now expose a smallest additive `outcome_evidence` descriptor family for facts ES can directly source today: status labels the Nomad observation family behind the projection and references the opaque lifecycle projection token, cancel labels the accepted Nomad stop request without claiming observed termination, logs label successful bodies as current Nomad task stdout, and result labels successful bodies as opaque ES-retained bundles. These descriptors are read-only current-slice evidence labels, not scheduler identifiers, write preconditions, policy truth, credential truth, or a global ES run revision.
- The producer compatibility declaration names the current governed-execution producer contract and the required status/cancel/logs/result outcome-evidence carriers without proving service health, submit readiness, run existence, credential possession, lifecycle write coordination, policy decisions, or scheduler internals.
- ES submit/status now include a bounded `authority_handoff` fact for new submissions. It is derived from ES-selected submit-time handoff facts and the submitted runtime spec, and it exposes only non-secret runtime authority facts: selected runtime profile, workload identity endpoint URI/env, workload-vault auth metadata, workload-zone Vault config digest, and the bounded Control Plane normal-shell Codex credential-location metadata when that profile is selected.
- ES now localizes submit-time payload staging, mount staging, result-directory staging, and runtime-ready package assembly behind one explicit internal execution-package layout; `/execution/staged` and `/execution/run` remain current bounded runtime conventions rather than diffuse helper assumptions.
- ES currently reserves `/execution/run/result` as the bounded workload-authored terminal output directory for the current `static-script` slice. That convention is active for the retained-result slice, but it remains part of the reopened execution-package/runtime-path surface rather than settled architecture.
- ES currently retains run-scoped host staging while the submitted workload may still depend on it, captures any terminal result files from the reserved result directory into a retained ES-owned bundle outside staging, then best-effort removes `execution.staging_root_dir/<run_id>` after ES observes terminal success; failed, canceled, lost, or otherwise ambiguous outcomes retain staging for operator debugging.
- ES now exposes `GET /v1/executions/{run_id}/result` as a bounded retained-result bundle retrieval surface. The bundle is opaque tar.gz data keyed by `run_id`, not a Control Plane checkpoint, orchestration decision, or ES-owned lifecycle-state record.
- The primary operator bring-up/check path now distinguishes service health, prepare-ready state, and full submit-ready state instead of treating ES `/health` alone as execution readiness.
- The current bounded operator hot path now uses the operator SPIFFE identity as the sole caller for AGS publish and ES execution/lifecycle entry surfaces; `service/deployment` no longer defines that current slice.
- The current shared execution/runtime contract in `internal/contracts/evidence/v1` is now limited to environment allowlist input, required runtime capabilities, `target_platform`, and `network_access`; non-runtime workload metadata no longer defines the live AGS -> ARS -> ES hot path.
- ES currently injects `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as its bounded workload-visible runtime identity handoff and internally backs the discovered endpoint with a run-scoped ES-owned runtime subtree.
- ES currently derives its workload-vault handoff from workload-zone vault runtime fields plus a bounded local default auth mode rather than from workload-attribute selector policy.
- When the workload-zone Vault runtime config carries a non-secret CA bundle, ES stages that trust material into the runtime platform directory, injects `VAULT_CACERT`, and also exposes a staged combined TLS bundle through `SSL_CERT_FILE` for the bounded Control Plane normal-shell Python runner path. This is a workload-facing TLS trust-material handoff, not Vault token brokerage or relaxed verification.
- ES now also supports one explicit runtime profile selection annotation for the bounded Control Plane normal-shell slice:
  - `invocation.annotations["execution_substrate.runtime_profile"] = "control-plane-normal-shell/v1"`
  - the selected profile is enabled only by explicit ES submit config under `execution.runtime_profiles.control_plane_normal_shell`
  - the profile remains a `static-script` execution-package overlay rather than a package-kind or lifecycle redesign
  - the profile requires network access, a dedicated configured runtime image, an absolute configured Codex CLI path inside that image, and a configured workload-vault secret path/field for Codex credential material
  - ES injects only non-secret metadata for that Codex material; the workload uses the existing platform-owned runtime identity endpoint and workload-vault auth env to fetch the material itself
  - ES does not fetch, mint, broker, store, rotate, parse, or validate Codex tokens
- The current slice-0 operator path now targets one Linux host/VM, runs ARS/EGS/AGS/ES as containers, keeps Nomad server/client and Docker on that same host, and treats Docker host networking as temporary compatibility scaffolding rather than final control-plane network architecture.
- The current slice-0 operator path now requires strict client-cert authentication at the hot-path TLS boundary, including `/health`, and ARS now rejects the configured bootstrap issuer on both read and write paths like the rest of the hot path.
- The current slice-0 operator path records the ES same-path staging proof at bring-up time, while slice `1A` and slice `1B` now separately prove the first bounded strong workload-identity handoff for runtime workloads.
- The current slice-0 operator path has been functionally proved on a real Linux VM through the real ES -> Nomad -> Docker execution path, and the current supported local reference profile on this Mac is Lima `qemu` + Ubuntu 24.04 arm64 with pre-managed non-`-dev` Nomad and positive natural `cpu.totalcompute`; the previously investigated VMware/aarch64 and Lima `vz` local profiles remain unsupported on this Mac because natural `cpu.totalcompute` stays `0`.
- The current AGS publish path now distinguishes artifact identity from payload identity: payload bytes remain content-addressed by `payload_digest`, while AGS derives `artifact_digest` from package-facing identity inputs only before registering the runtime-facing discovery record through ARS.
- The current shared authorization surface inside `internal/contracts/evidence/v1` is now limited to derivation request binding (`derivation_spec_digest`, `output_id`); workload-binding, policy-linkage, producer-trace, and derivation-constraint residue no longer define the active shared kernel.

These facts describe the current repository. They are not, by themselves, decisions that the reset must preserve.

## Explicit Supersession Of Prior Assumptions

The earlier planning assumptions below are now reopened and no longer count as fixed architectural endpoints:

- ARS is no longer treated as a frozen end-state storage and artifact-index boundary.
- AGS is no longer treated as a frozen end-state publication and fact-assembly boundary.
- EGS is no longer treated as a frozen end-state runtime-trust boundary.
- CGS is no longer treated as a frozen end-state authorization boundary.
- ES is no longer treated as a bounded-but-settled execution boundary.
- The old `contracts/signing/v2` kernel has now been excised from the active repo, and its former shared-kernel role is superseded by the evidence-native artifact path.
- The first controlled kernel-migration cut is allowed to add a parallel shared kernel and migrate one bounded path before broader service redesign lands.

More specifically, the redesign phase explicitly reopens or qualifies these previously locked assumptions:

- The current ARS registration, index, and read contract are reopened. The current runtime-facing discovery record, secondary descriptor support path, and discoverability shape remain implementation facts, not fixed architecture.
- The current AGS publish contract and fact assembly model are reopened. The existing manifest and signed-fact bundle are not presumed to be the enduring publication grammar.
- The current cross-service contract forms are reopened. Existing wire and package contracts survive only until they are explicitly retained, replaced, or wrapped as temporary compatibility edges.
- The historical `contracts/signing/v2` package no longer participates in any current code path. The repository now relies on `internal/contracts/evidence/v1` as the only active shared artifact kernel, while the long-term scope of that kernel remains under review.
- The current ES, ARS, CGS, and EGS interaction model is reopened. Existing call paths and non-call paths are current facts, not architectural endpoints.
- The current ES public execution and admission shape is reopened. This includes the `:prepare` and `:submit` split, current request and result DTOs, current scheduler receipt model, and current lifecycle projection model.
- The current runtime identity handoff conventions are reopened. The current path layout, `vault_identity_jwt` handoff shape, and reserved container paths are implementation choices that must now be justified or replaced.

Compatibility with any current contract is allowed only as a temporary and explicit transition tactic. If compatibility is retained, document:

- the reason
- the scope
- the removal condition

Do not describe compatibility edges as frozen architecture.

## Architecture-Defining Redesign Scope

### In Scope Now

The first redesign pass is explicitly about the architecture-defining core:

- shared contracts and any shared kernel
- service API shapes and DTO ownership
- data model boundaries between services
- artifact publication, storage, retrieval, verification, and execution flow
- policy model and trust model ownership
- authorization model ownership
- runtime identity and execution handoff
- package structure where it defines architectural meaning
- explicit clarification of what remains shared versus service-local

### Out Of Scope For The First Redesign Pass

The following are not primary redesign targets until the core surfaces stabilize:

- Docker scripts
- runbooks
- environment polish
- deployment helper glue
- superficial renames
- broad cleanup unrelated to core contract and boundary redesign
- generic refactors that do not reduce architectural ambiguity

## Redesign Workstreams

### Workstream A - Shared Contract And Kernel Reset

Purpose:

- Re-derive the minimum shared contract surface needed across services.
- Keep the shared artifact kernel narrow and evidence-owned after excising the historical signing kernel.
- Stop treating a shared package as the default home for cross-service meaning unless that meaning is truly stable and jointly owned.
- For the next milestone package, answer only the shared-kernel questions that ES needs to admit and execute governed artifacts without inheriting accidental AGS, ARS, or CP grammar.

Target files and packages:

- `internal/contracts/evidence/v1/`
- `ags/publish/`
- `es/admission/`
- `egs/model/`
- `ars/index/`

Success condition:

- A documented shared-kernel decision exists.
- The future shared surface is smaller and intentionally owned.
- Cross-service semantics that do not need to be shared are moved back toward service-local ownership.
- Future agents can tell which contracts are kernel-level versus service-level without inferring from package reuse.
- Future agents can tell which shared-kernel rules are stable ES admission semantics, which are temporary compatibility edges, and which are merely current slice implementation detail.

Current bounded decision status for Milestone 2A.1:

- The Workstream A shared-kernel decision is recorded in `.docs/system_overview/shared_kernel.md`.
- `internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel for the current `AGS -> ARS -> ES` path, but it is not a standalone service boundary.
- Kernel-level shared meaning stays limited to package identity, narrow derivation request-binding authorization, narrow execution/runtime claims ES actually enforces, and evidence canonicalization plus `seal` verification.
- AGS publication claims, ARS discoverability/index shapes, ES public execution/lifecycle grammar, and the long-term workload-zone Vault runtime-config owner remain service-owned or reopened elsewhere; Workstream A does not widen them into the kernel.
- `internal/contracts/evidence/v1` is not a cross-service semantic dumping ground. Fields, helper DTOs, proof outputs, generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts do not become shared-kernel authority by proximity to the shared evidence package.
- Workstream A0 preserves the current `execution_substrate.runtime_profile` annotation and bounded `control-plane-normal-shell/v1` compatibility edge. It does not change the runtime path, runtime-profile selection mechanism, or `static-script` overlay behavior.

Dependencies:

- No upstream workstream dependency beyond this `PLANS.md` reset.

### Workstream B - Artifact Storage And Publication Contract Reset

Purpose:

- Redesign the AGS and ARS contract around publication, runtime-facing discovery records, payload and evidence relationships, and visibility rules.
- Decide whether the current runtime-facing discovery shape, the secondary descriptor support path, and the current AGS artifact-identity derivation rule survive.
- Separate storage integrity concerns from publication grammar and from ES consumption needs.
- Keep the shared evidence grammar narrow: package identity remains separate, shared admission authorization is limited to derivation request binding, and execution/runtime claims remain distinct from non-shared publication or policy residue.
- For the next milestone package, treat AGS and ARS work as an ES-enabling input-boundary reset: AGS/ARS own publication and discoverability; ES consumes their designed outputs; CP examples or probes do not define that contract.

Target files and packages:

- `ags/api/`
- `ags/publish/`
- `ars/api/`
- `ars/index/`
- `ars/store/`

Success condition:

- The write and read contract between AGS and ARS is intentional and documented.
- The artifact discovery model is explicit about what is canonical, what is runtime-discoverable, and what is merely current secondary publication/support implementation detail.
- Payload versus artifact identity is no longer hidden in convenience assumptions.
- ES can later consume artifact data through a designed discoverability surface rather than through an inherited tuple shape.
- CP consumer compatibility can rely on the accepted API path, but CP-specific convenience expectations are not mistaken for AGS/ARS/ES core semantics.

Dependencies:

- Workstream A

Current bounded decision status for Milestone 2B.1:

- The Workstream B publication/storage/discoverability decision is recorded in
  `.docs/system_overview/artifact_publication_storage.md`.
- B0 is the docs and docs-contract-test gate for artifact publication,
  storage, discoverability, payload identity, artifact identity, and
  compatibility/support shapes. It makes no runtime implementation changes.
- B1 is the focused code-facing guardrail slice over the same B0 boundary. It
  adds tests for AGS publication output, ARS runtime-facing discovery, ES
  admission hot-path consumption, payload/artifact/package identity separation,
  CP proof/example non-authority, and `control-plane-normal-shell/v1`
  compatibility. It does not redesign AGS, ARS, or ES runtime behavior.
- AGS owns publish-time fact assembly, caller-bound publication semantics,
  aggregate evidence assembly, signing, payload/support upload, and
  registration into ARS.
- ARS owns blob storage, content-addressed integrity, artifact registration,
  runtime-facing discovery records, index behavior, descriptor/manifest support
  reads, and the ARS-owned read surfaces ES may later consume.
- The current ARS discovery record remains the canonical runtime-discoverable
  surface for the current slice. Descriptor/manifest support remains secondary
  publication detail, and the current index entry shape remains
  implementation-only/current-slice detail.
- `claims.package.identity` is the shared-kernel identity surface ES consumes;
  AGS-owned publication claims and ARS descriptor/manifest/index/support tuples
  do not become that identity surface.
- Payload identity and artifact identity remain separate:
  `payload_digest` identifies payload bytes or payload content identity, while
  `artifact_digest` identifies artifact/package identity as currently derived
  from `payload_digest`, `artifact_type`, and `intent_digest`.
- The current discovery/register JSON shapes are retained only as bounded
  slice rules, descriptor/manifest/index/support tuples are
  compatibility/support or implementation-only surfaces unless explicitly
  migrated, the secondary descriptor support path remains a temporary
  compatibility edge, and the long-term discovery/index/publication-support
  model remains reopened.
- ES must consume artifacts through a designed discoverability surface, not by
  inheriting ARS support tuple grammar as ES public grammar.
- CP examples and proof harness artifacts do not define AGS/ARS/ES core
  semantics; generated evidence, `.out`, support bundles, retained bundles,
  reports, traces, logs, summaries, and proof artifacts remain
  evidence/projection only.

### Workstream C - Execution And Admission Reset

Purpose:

- Redesign ES public admission and execution surfaces.
- Re-derive the preparation and submission boundary, scheduler handoff, and runtime package resolution from the Go codebase rather than from current inherited grammar.
- Decide what ES should own, what ES should compose, and what ES should stop carrying.
- Deliver the primary ES milestone package after the Workstream A and B input-boundary gates are explicit enough for ES not to inherit their ambiguities.
- Preserve the accepted CP governed-execution compatibility edge without letting CP orchestration, review, checkpoint, or finalization assumptions become ES-owned semantics.

Target files and packages:

- `es/api/`
- `es/admission/`
- `es/config/`
- `es/app/`
- `cmd/es/`

Success condition:

- ES has a clear public model for admission, submission, and lifecycle projection.
- ES no longer depends on the current inherited artifact and policy grammar by convenience.
- The remaining shared execution/runtime inputs are intentionally defined rather than passively inherited from upstream publication metadata.
- Scheduler handoff, payload resolution, and lifecycle projection are described as deliberate ES boundaries.
- The current CP path, `execution_substrate.runtime_profile`, and `control-plane-normal-shell/v1` remain compatible unless an explicit migration/versioning note says otherwise.
- Stable semantic contracts, temporary compatibility edges, and implementation details/current slice constraints are classified in `PLANS.md` and the adjacent system/lifecycle docs.

Dependencies:

- Workstream A, as the shared-kernel gate needed for ES admission ownership
- Workstream B, as the AGS/ARS input-boundary gate needed for ES payload and evidence ownership

Current bounded decision status for Milestone 2C.1:

- C0 is the docs and docs-contract-test gate for ES admission, prepare,
  submit, lifecycle projection, retained-result ownership, runtime-profile
  compatibility, runtime handoff, outcome evidence, runtime identity/workload
  credential handoff boundaries, and Control Plane compatibility.
- C0 makes no runtime implementation changes.
- Workstream C implementation must not start until C0 docs and docs-contract
  tests pass.
- C1 is the focused code-facing guardrail slice over the accepted C0 model.
  It adds or strengthens tests for bounded `:prepare` preflight non-effects,
  ARS discovery/evidence/payload/package-identity consumption, signed evidence
  and narrow execution/runtime claim enforcement, AGS/ARS support/CP grammar
  exclusion, payload-digest versus package-identity mismatch separation,
  current compatibility surfaces, and `authority_handoff`/`outcome_evidence`
  non-authority. It does not redesign runtime behavior.
- C2 is the focused tests/docs guardrail slice over the accepted submit and
  lifecycle-projection boundary. It pins `POST /v1/executions:submit` as the
  ES-owned async execution handoff through Nomad, keeps the submit receipt
  bounded and free of Control Plane attempt/review/checkpoint/finalization,
  intervention, approval, hold/resume/reject, Temporal, or workflow grammar,
  preserves `authority_handoff` as non-secret handoff evidence only, keeps
  `lifecycle_projection.source=nomad` with an opaque same-run
  read-coordination `revision`, preserves status/logs/result/cancel and
  `control-plane-normal-shell/v1` compatibility, and prevents generated
  evidence, reports, logs, support bundles, retained bundles, proof artifacts,
  and maintenance summaries from becoming authority. It does not redesign
  runtime behavior, retained results, runtime identity, Vault handoff, Nomad
  integration, or Control Plane behavior.
- C3 is the focused tests/docs guardrail slice for retained-result and
  `authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
  C3 pins that retained result bundles remain ES-owned opaque output artifacts
  and that CP may materialize, review, checkpoint, and finalize retained result
  contents semantically, but CP does not own the retained bundle as run-control
  state. Retained result references, paths, manifests, archives, `.out`
  copies, and materialized workspaces are evidence/projection or
  implementation detail, not orchestration authority.
  `GET /v1/executions/{run_id}/result` compatibility shape remains unchanged
  unless an explicit migration/versioning plan exists. `authority_handoff`
  remains bounded non-secret runtime handoff evidence only.
  `authority_handoff` never carries or implies live credentials, Vault tokens,
  Codex credentials, leases, approvals, operator authorization, CP workflow
  state, scheduler truth, or retained-result authority. Runtime identity/Vault
  handoff remains workload-side and non-secret; ES does not become a Vault
  token broker or Codex credential broker. `outcome_evidence` remains bounded
  evidence/projection; current labels remain compatibility surfaces.
  `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- C4 is the focused tests/docs guardrail slice for runtime identity and Vault
  handoff boundaries. C4 is guardrail work, not runtime redesign and not live
  helper execution. Runtime identity acquisition is workload-side or
  helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
  non-secret runtime identity and Vault configuration metadata, but ES must
  not mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES
  must not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies,
  private keys, API keys, proof secrets, root tokens, unseal keys, Vault client
  tokens, or secret payloads through public DTOs, lifecycle responses,
  retained-result metadata, summaries, logs, reports, `.out`, support bundles,
  or proof artifacts. `authority_handoff` may include non-secret
  credential-location and configuration metadata only. `authority_handoff`
  must not carry live credentials, leases, approvals, Vault tokens, Codex
  credentials, JWT-SVIDs, API keys, or scheduler truth. Workload-side Vault
  auth remains workload-side; Vault owns token, secret, and lease authority.
  SPIRE owns identity issuance and SVID material. ES must not expose raw SPIRE
  socket access to workloads as public ES grammar.
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the workload-facing identity
  endpoint contract rather than raw SPIRE socket access. Runtime identity and
  Vault handoff evidence remains non-authoritative and redacted. CP may
  consume runtime identity/Vault handoff evidence, but CP does not own
  credential acquisition, Vault tokens, SPIRE identity issuance, or ES runtime
  handoff boundaries. IM and Maintenance Agent may report
  diagnostics/readiness/status, but do not own runtime identity or Vault
  authority. `control-plane-normal-shell/v1` and
  `execution_substrate.runtime_profile` compatibility remain preserved unless
  an explicit migration/versioning plan exists. Existing workload-auth Remote
  Alpha helpers remain bounded operator/support surfaces, not ES token
  brokerage or production Vault readiness.
- C5 is the focused tests/docs guardrail slice for current
  status/logs/result/cancel compatibility and non-authority posture. C5 is
  guardrail work, not runtime redesign, live proof, or remote validation.
  Status remains Nomad-backed lifecycle projection and evidence, not CP
  workflow truth or ES lifecycle-store truth. Logs remain a bounded current
  compatibility/evidence surface, not final log architecture, CP run-control
  truth, or scheduler authority. Result remains opaque ES-retained output
  delivery, not CP checkpoint, finalization, or review state. Cancel remains a
  bounded ES/Nomad cancellation handoff, not CP intervention authority,
  operator approval authority, or Temporal workflow truth. Status/cancel JSON
  envelopes and successful logs/result headers must exclude CP run-control
  grammar and live credential/security fields; logs/result bodies remain
  payload/output surfaces governed by the existing compatibility contract and
  must not be newly sanitized, interpreted, or promoted into authority.
- C6 is the focused ES Admission Policy Layer v0 slice. It is a Workstream C
  admission extension, not the Workstream D CGS/EGS policy-language redesign.
  It adds a small ES-owned, replaceable policy-evaluation seam in the shared
  `:prepare`/`:submit` admission path and one built-in selected-pattern
  static-script content policy to prove the seam. ES remains the final
  admission-policy gate for ES-bound executions. Control Plane may later
  preflight or render ES policy decisions, but CP is not the final ES
  admission gate. IM remains readiness, provenance, and diagnostics only. C6
  may read bounded payload bytes during `:prepare` only when an enabled ES
  admission policy requires the ES-visible static-script text input class, and
  only through the explicit ARS payload digest relationship already discovered
  and cross-checked by ES admission. C6 must not add OPA/Rego, a DSL, customer
  regex configuration, CGS `id.conf` reuse, signed policy bundles, an external
  policy-decision service, durable policy-decision storage, CP prompt/workspace
  parsing, workspace archive decoding, binary payload inspection, retained
  bundle scanning, support-bundle scanning, or raw payload/matched-content
  disclosure.
- The C6 configurable-input follow-up is a bounded slice refinement of ES
  Admission Policy Layer v0. It may add ES deployment/admin configuration for
  inputs to built-in ES admission policies only. The follow-up adds the
  built-in
  `execution-substrate.admission.configured-static-script-literal-deny/v1`
  policy with reason code `configured_static_script_content_denied`, safe
  message `static script content denied by admission policy`, mode `disabled`
  or `enforce`, safe entry IDs, a bounded list of literal deny entries, and
  the fixed input class
  `static_script_payload_text`. These inputs are ES deployment/admin config
  only; CP does not define or supply them, IM remains readiness/provenance/
  diagnostics only, and request payloads cannot carry policy entries. This
  follow-up must not add evaluator injection, OPA/Rego, a DSL, arbitrary
  regex/glob/shell-expression config, customer-authored policy bundles, an
  external evaluator service, CGS `id.conf` reuse, user-defined reason codes,
  user-defined API messages, CP prompt/workspace parsing, workspace archive
  decoding, binary payload inspection, or raw configured-literal/matched-
  content disclosure. Denials remain redacted.
- The Workstream C ES public admission/execution model decision is recorded in
  `.docs/execution_lifecycle/es_execution_admission_model.md`.
- `GET /v1/executions:contract` and `POST /v1/executions:prepare` remain
  temporary compatibility edges for the current CP/IM consumer path, while
  `POST /v1/executions:submit` remains the real ES execution handoff surface.
- Nomad remains authoritative for submitted execution lifecycle. ES status,
  logs, and cancel remain bounded read-through projections, and result
  retrieval remains ES-owned opaque bundle access.
- ES admission composition remains limited to caller auth/allowlist plus ARS
  discovery/evidence/payload refs, narrow `internal/contracts/evidence/v1`
  execution claims, EGS runtime-trust output, the configured workload-zone
  Vault runtime-config reference/blob, and the ES-owned Admission Policy Layer
  v0 seam.
- `invocation.annotations["execution_substrate.runtime_profile"]`,
  `control-plane-normal-shell/v1`, the current `/execution/...` conventions,
  the current `authority_handoff` vocabulary, the current `outcome_evidence`
  vocabulary, and retained `application/gzip` result bundles keyed by `run_id`
  remain explicit compatibility edges rather than settled architecture.

### Workstream D - Policy And Authorization Reset

Purpose:

- Re-derive policy ownership across EGS and CGS.
- Decide what belongs to trust publication, what belongs to authorization, and what belongs nowhere in the long-term architecture.
- Reassess the current `id.conf` policy model, authorize DTO, and remaining policy/trust ownership seams.

Target files and packages:

- `egs/api/`
- `egs/model/`
- `egs/sign/`
- `cgs/api/`
- `cgs/policy/`
- `cgs/config/`
- `cgs/app/`

Success condition:

- Policy publication and authorization ownership are explicit.
- EGS and CGS no longer carry accidental compatibility behavior without documented ownership.
- The current `id.conf` and authorize shape are either intentionally retained, replaced, or explicitly downgraded to temporary compatibility edges.
- ES can consume policy and authorization outputs through designed contracts rather than through legacy compatibility DTOs.

Dependencies:

- Workstream A
- Workstream C

Current bounded planning direction:

- Treat the current `POST /v1/credential/authorize` request/response shape as a CGS v1 compatibility surface and the current `GET /v1/trust-model` route plus wrapper/payload shape as an EGS v1 compatibility surface.
- Do not semantically widen either current v1 surface in place. Semantic expansion requires explicit versioning before implementation.
- Treat `audit.policy_version` and EGS `publication.version` as service-owned audit/publication metadata, not transport/schema/API versioning.
- Treat `id.conf` as current-CGS-v1 compatibility/config residue rather than as final repo-wide policy language.
- Preserve ES CGS-independence in D1. If ES later consumes CGS output, it must do so through a separately versioned bounded authorization fact such as allow/deny plus opaque decision reference and expiry rather than by reusing the current CGS v1 shape or `id.conf`-derived subject grammar.
- D1b is an accepted docs/tests-only slice on that seam: keep the current `POST /v1/credential/authorize` route and wire shape as CGS v1 compatibility, define any future CGS v2 authorize contract only at design level, and require explicit versioning before any behavior change lands.
- In D1b, a future versioned CGS authorization fact may carry only allow/deny, an opaque decision reference, and expiry or another bounded freshness indicator if justified. Any audit/evaluation metadata on that fact remains non-authoritative outside CGS.
- That future D1b design must not carry runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler facts, ES lifecycle/admission facts, runtime-config refs, workload-zone Vault ownership facts, identity-handoff facts, or Control Plane review/approval/checkpoint/finalization semantics.
- D1b keeps `id.conf` as current-CGS-v1 compatibility/config residue, does not rewrite its grammar or evaluation, and does not expand EGS beyond signer/artifact runtime-trust publication.
- D1c is an accepted docs/tests-only slice on that seam: keep the current `GET /v1/trust-model` route plus wrapper/payload shape as EGS v1 compatibility, define any future EGS versioned runtime-trust wrapper only at design level, and require explicit wrapper/payload/versioning before any semantic expansion lands.
- D1c keeps EGS v1 publishing signed `runtime_trust` signer/artifact trust only. EGS publication metadata remains outside the signed runtime-trust payload, and `publication.version` remains service-owned publication metadata rather than trust-contract/schema/API versioning.
- In D1c, a future versioned EGS trust wrapper must distinguish signed runtime-trust payload facts, unsigned publication/discovery metadata, compatibility routing or API version, and non-authoritative service metadata.
- That future D1c wrapper design must not carry CGS authorization decisions, Control Plane review/approval/checkpoint/finalization semantics, runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler truth, ES lifecycle/admission truth, runtime-config refs, workload-zone Vault ownership facts, runtime identity handoff facts, or AGS/ARS artifact-publication authority.
- D1c keeps ES consuming EGS only for signer/artifact runtime trust, keeps ES consuming no CGS facts, does not reopen the accepted Workstream A/B/C decisions, does not change the Workstream B AGS/ARS artifact publication/storage/discoverability decision or the Workstream C ES admission/runtime public model, and does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.
- D1d is an accepted docs/tests-only slice on that seam: keep checked-in `cgs/policy/id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` as current-CGS-v1 compatibility/config residue only.
- In D1d, `id.conf` is not a shared policy language, not an ES admission policy input, not an EGS trust input, not a Control Plane review/approval/checkpoint/finalization policy input, and not an Infrastructure Manager readiness/profile/support-bundle authority input.
- D1d keeps the current CGS v1 subject grammar local to current CGS v1 evaluation, keeps the checked-in `cgs/policy/id.conf` baseline as implementation/config residue rather than future product policy architecture, and keeps `policy.id_conf_path` as a CGS-local current-v1 configuration pointer rather than a repo-wide policy registry.
- D1d must not move `id.conf` into runtime-config ownership before Workstream E or fold it into runtime-identity handoff before Workstream F.
- Future policy-input redesign requires explicit Workstream D follow-up and, if it changes CGS semantics, a versioned CGS contract. D1d does not change CGS v1 authorize behavior, does not implement CGS v2, and does not change EGS, ES admission, Workstream E runtime-config ownership, or Workstream F runtime-identity handoff.
- Workstream D checkpoint: D0-D1d completed the guardrail/design phase. Workstream D remains open; the long-term CGS authorize DTO, future CGS/EGS versioned contracts, and long-term `id.conf`/policy-input model remain reopened seams.
- Those remaining D seams are non-blocking follow-ups for Workstream E planning. No D2 behavior-changing slice is required before Workstream E planning.
- D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.

### Workstream E - Lookup And Config Indirection Reset

Purpose:

- Define and adopt an explicit replacement surface for the workload-zone Vault runtime-config reference and blob schema.
- Move the required workload-zone Vault config-reference guarantee into the replacement owner.
- Remove ACS from the live runtime path once the replacement surface is real.

Target files and packages:

- `internal/contracts/runtimeconfig/v1`
- `es/config/`
- `es/admission/`
- `es/app/`

Success condition:

- The named workload-zone Vault config reference and blob schema are explicit, shared, and no longer hidden in ES-local parsing.
- ES consumes the replacement surface directly without a transitional ACS lookup hop.
- Startup validation guarantees the required workload-zone Vault config reference exists before ES serves traffic.
- Future agents can tell that workload-zone Vault config semantics live in the runtime-config surface, ARS owns the blob, and ES remains only the consumer.

Dependencies:

- Workstream A
- Workstream B
- Workstream C
- Workstream D

Current docs/tests-only decision status for E0:

- The Workstream E runtime-config ownership decision is recorded in
  `.docs/system_overview/runtime_config_ownership.md`.
- E0 is docs/tests-only. It does not change runtime behavior, public DTOs,
  route handlers, wire shapes, ES admission behavior, runtime identity handoff,
  Control Plane compatibility, Infrastructure Manager inputs, or M6
  support-bundle input shapes.
- Runtime-config semantics are owned by the runtime-config contract surface.
  The current typed shared schema for workload-zone Vault runtime config is
  `internal/contracts/runtimeconfig/v1`.
- ARS owns blob storage and read by digest only. ARS does not own
  workload-zone Vault runtime-config semantics.
- ES is the current runtime-config consumer and lookup orchestrator during
  `:prepare` and `:submit`.
- ES startup config currently carries the required workload-zone Vault
  runtime-config reference. That placement is compatibility/config residue on
  a reopened ownership seam, not the declared final owner.
- The startup guarantee remains: the required typed runtime-config reference
  must be configured and validated before ES serves governed execution traffic.
  This is a reference-availability guarantee, not a new E0 guarantee that the
  ARS blob has been fetched before startup completes.
- The digest-only ref shape is active as a temporary compatibility edge and
  bounded current surface, not final runtime-config architecture.
- There is no ACS hop in the runtime-config path.
- Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff.
- Optional workload-zone Vault CA trust material remains standard non-secret
  TLS/env-based trust configuration only.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority or live credential truth.
- E0 preserves `GET /v1/executions:contract`,
  `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP
  compatibility, and M6 support-bundle inputs.
- E0 keeps CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, EGS `publication.version`, EGS unsigned publication
  metadata, AGS `policy_decisions`, ES retained bundles, ES
  `outcome_evidence`, ES `authority_handoff`, IM profiles, support bundles,
  logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state outside runtime-config
  authority.
- E0 does not settle Workstream F runtime-identity handoff, does not reopen
  Workstreams A/B/C, does not mark full Workstream D complete, and does not
  mark full Workstream E complete.

Workstream E guardrail status:

- E0 and E1 are sufficient guardrails before Workstream F planning.
- Full Workstream E remains open for long-term runtime-config owner,
  reference/versioning, and `workload_vault_auth.default_mode` follow-ups.
- Later Workstream E work must not drift into runtime identity handoff,
  helper behavior, SPIRE/Vault handoff implementation, or Workstream F
  reserved-path decisions.

### Workstream F - Runtime Identity Handoff Reset

Purpose:

- Redesign the ES-to-runtime identity boundary.
- Clarify ownership of runtime identity paths, Vault auth handoff, reserved interface conventions, and capability validation.
- Remove hidden coupling between ES submit behavior, policy surfaces, workload identity selection, and container path conventions.
- Prove platform-owned runtime identity delivery rather than workload-authored bridging.

Target files and packages:

- `es/admission/runtimeidentity.go`
- `es/admission/submit.go`
- `es/config/`
- `cgs/api/types.go`
- `cgs/config/`
- `.docs/system_overview/capability_probing.md`
- `.docs/execution_lifecycle/`

Success condition:

- Runtime identity handoff has explicit ownership and a documented contract.
- The current reserved paths survive only if intentionally retained.
- The handoff contract no longer depends on accidental coupling to current ES DTOs, current CGS authorize output, or current path names.
- Capability-sensitive validation remains behavior-based and local to validation boundaries.
- The workload-visible discovery contract remains explicit, but the implementation behind it is platform-owned.
- The final bounded slice does not depend on workload authors implementing their own identity-serving shim.

Current bounded planning direction:

- Preserve `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-visible discovery contract unless a later stop-condition justifies reopening it explicitly.
- Prefer a platform-owned runtime identity companion/bridge injected with the workload allocation over direct workload access to SPIRE internals or ES-owned runtime token minting.
- Treat the checked-in workload-authored runtime identity reference as example scaffolding only, not as an acceptable final ownership model.
- Treat the current slice-0 Linux schedulability caveat as an environment qualification issue that should remain explicit, not as a blocker to planning Workstream F.
- The bounded slice `1A` and slice `1B` implementation is now the same-container runtime helper launched by a platform-owned supervisor inside the workload task.
- Slice `1A` landed the runtime boundary before useful credential flow:
  - helper runs as `0:0`
  - workload runs as fixed `10000:10000`
  - workload gets no supplemental groups and no privilege-escalation path
  - the raw SPIRE Workload API socket remains helper-private under `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`
  - the workload-visible endpoint remains `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix:///run/es-runtime-identity/<run_id>/endpoint`
  - helper readiness is required before workload start and helper death is task-fatal in the first slice
- Slice `1B` keeps the public endpoint bounded:
  - support only a platform-defined JWT-SVID retrieval operation for the workload-vault target
  - reject arbitrary audience passthrough, raw SPIRE parameter passthrough, and X.509 delivery in this slice
- First-slice workload compatibility is intentionally narrowed:
  - no root workloads
  - no arbitrary image-user execution
  - no shared helper/workload UID
  - no supplemental groups that collapse the helper/workload boundary
- Useful credential flow is now proved on top of slice `1A` and slice `1B`:
  - the helper endpoint remains bounded to the workload-vault target
  - the workload performs the bounded Vault login flow itself as a client against a proof-scoped real Vault dev/test target
  - ES provides any workload-zone Vault CA trust material from the resolved runtime config as workload-visible CA files and standard TLS environment, without disabling verification
  - one secret read is proved through the real ES -> Nomad -> Docker path
  - the slice still avoids platform-owned Vault token brokerage
- The bounded `control-plane-normal-shell/v1` runtime profile builds on that same identity boundary:
  - ES selects the configured profile image for opt-in requests
  - the repo-owned reference image recipe provides Python, git, narrow shell utilities, and a configured Codex CLI realization at the configured path
  - the supported-local Nomad baseline disables Nomad Docker image cleanup for enabled local runtime-profile images so a local proof image is not removed merely because a prior successful allocation terminated
  - the supported-local proof realization uses the proof-only Codex shim at that path, seeds proof-scoped Codex credential material in Vault, proves workload-side credential acquisition through the existing identity endpoint, invokes the shim with stdin prompt input, creates a deterministic workspace mutation, renders a result diff that includes tracked changes and proof-created untracked files, and writes runner-style final-message, diff, stdout/stderr, and workspace-archive artifacts under `/execution/run/result`
  - the proof fetches and validates the retained ES result bundle for those artifacts
  - the proof intentionally does not prove real upstream Codex service behavior because this repo cannot own a non-sensitive production Codex credential or external Codex service availability
- The supported-host follow-through after that credential-flow proof is now landed in bounded form:
  - keep the current script-managed local Nomad path explicit as bounded fallback/troubleshooting
  - distinguish supported, bounded-fallback, and unsupported substrate states in operator output and runbooks
  - use Lima `qemu` + Ubuntu 24.04 arm64 as the current supported local reference host on this Mac
  - keep the previously investigated VMware/aarch64 and Lima `vz` local profiles explicit as unsupported on this Mac because natural `cpu.totalcompute` stays `0`
  - use the repo-owned `scripts/72_supported_local_setup.sh` helper plus `scripts/73_supported_local_proof.sh run` for the current supported local proof path instead of the earlier out-of-repo `/tmp` harnesses
  - keep the canonical supported-local proof workspace under `.out/es-proof-<id>/`, with guest `/tmp` only as internal Lima scratch when the repo mount is read-only
- That runtime narrowing is part of the claim-preserving slice boundary, not an accidental compatibility gap. If bounded implementation cannot preserve the helper-only SPIRE channel or the no-privilege-escalation workload launch model, stop and reopen only the runtime shape needed to keep ownership honest.

F0 - Runtime Identity Handoff Ownership Decision:

- F0 is docs/tests-only. It records the current runtime-identity handoff
  ownership model before any behavior-changing Workstream F implementation.
- The F0 decision is recorded in
  `.docs/system_overview/runtime_identity_handoff.md`.
- Runtime identity handoff is currently ES-selected and platform-delivered.
  ES owns handoff selection, env injection, reserved path layout, mounts, and
  Nomad job construction for the current slice.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract. It is not raw SPIRE socket exposure, Vault token brokerage,
  runtime-config authority, or a secret payload.
- The runtime supervisor/helper owns the in-task endpoint implementation,
  helper-private SPIRE traversal, readiness-before-workload, and
  root-to-workload privilege boundary for the current implementation.
- SPIRE owns JWT-SVID issuance. Vault owns token, secret, and lease issuance
  after workload-side login.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces
  are bounded or compatibility-heavy, not final generalized architecture.
- Capability validation remains behavior-based and local to validation
  boundaries, not based on accidental DTO/path coupling.
- F0 does not change runtime-config ownership from E0/E1, does not consume or
  promote D seams, does not change CP compatibility or
  `control-plane-normal-shell/v1`, and does not change M6 support-bundle
  inputs.
- F0 keeps CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, AGS
  `policy_decisions`, runtime-config refs, `authority_handoff.runtime_config_refs`,
  ARS blob mechanics, digest-only runtime-config refs,
  `workload_vault_auth.default_mode`, ES retained bundles,
  `outcome_evidence`, `authority_handoff`, IM profiles, support bundles,
  logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state outside runtime-identity and
  credential authority.
- F0 does not reopen Workstreams A/B/C, does not mark full Workstream D
  complete, does not mark full Workstream E complete, and does not mark full
  Workstream F complete.
- Full Workstream F remains open for long-term runtime-identity owner,
  helper/root/task-user, SPIRE selector/traversal, reserved-path, and
  workload-credential handoff follow-ups.
- F0 does not claim full ES/runtime de-root, rootless Nomad client,
  production readiness, production Vault readiness, or generalized remote
  deployment architecture.

Dependencies:

- Workstream C
- Workstream D
- Workstream E

## Ordered Execution Plan

Future agents should follow this order unless a later revision to `PLANS.md` changes it explicitly.

1. Reset planning authority in `PLANS.md`.
   This step is complete when the repo no longer treats the old frozen-slice plan as the operative design target.

2. Execute the next milestone as **ES Admission And Runtime Boundary Realignment**.
   This is a package made of Workstream A, Workstream B, and Workstream C, with ES as the primary delivery owner. Workstream A and Workstream B are gates that keep ES input contracts honest; Workstream C is the delivered ES milestone.

3. Complete the Workstream A gate first.
   The shared contract and kernel decision must be explicit enough that ES admission does not inherit accidental shared grammar. This gate is not permission to create a broad new shared kernel, and it is not CP-owned.

4. Complete the Workstream B gate second.
   AGS and ARS define the artifact publication and retrieval substrate that ES consumes. This gate must make the ES-consumed discovery and payload/evidence ownership explicit without letting CP examples or helper scripts become contract authority.

5. Deliver Workstream C third.
   ES admission, submission, lifecycle projection, retained-result behavior, runtime-profile handling, and runtime-boundary ownership are the primary next milestone delivery. Preserve the accepted CP governed-execution path as bounded compatibility while keeping ES-owned semantics in ES docs.

6. Execute Workstream D fourth.
   Policy and authorization surfaces should be re-derived once the ES execution shape is clear enough to say what policy inputs and outputs actually belong at runtime.

7. Execute Workstream E fifth.
   Lookup/config indirection should be reset only after artifact, execution, and policy contracts have been clarified, because the replacement owner depends on those decisions.

8. Execute Workstream F sixth.
   Runtime identity handoff should be redesigned after ES, policy, and runtime-config responsibilities are clear. Otherwise path conventions and auth-plan details will re-freeze around current incidental coupling.

9. Do scripts, runbooks, deployment glue, and peripheral cleanup only after the core contracts stabilize.
   Cleanup is valuable, but it should not happen while the architecture-defining surfaces are still moving.

This ordering is deliberate:

- use Workstream A and Workstream B as gates so ES does not inherit accidental shared or publication/storage grammar
- deliver Workstream C as the next ES-owned program milestone, not as a CP-shaped feature expansion
- preserve current CP compatibility as a bounded consumer edge while ES-owned contracts remain defined in this repo
- redesign execution before finalizing policy and lookup consumers
- redesign runtime identity only after the ES and policy boundaries are explicit

## Current Decision Rules

Future agents working in this phase must follow these rules:

- Redesign structure before renaming.
- Break core coupling before cleanup.
- Prefer package-local ownership over cross-service leakage.
- Do not preserve an old contract unless it is intentionally retained as a temporary compatibility edge.
- Document any new invariant in `PLANS.md` and the relevant `.docs/` pages before implementing against it.
- Do not introduce a new shared kernel casually. Shared code requires explicit ownership and a concrete cross-service reason.
- Use this repository as the planning authority. Treat the Monolith/Python repository as historical or bounded bootstrap reference only.
- Surface conflicts instead of working around them.
- Do not bypass governance, storage, trust, or scheduler boundaries as a shortcut during redesign.
- Keep capability-sensitive behavior validated by behavior or static resource checks, not by OS labels or fallback branching.
- Preserve current implementation behavior until a replacement contract is explicitly documented, tested, and implemented.
- Treat compatibility shims as temporary and track their removal conditions.
- Do not describe foundational ES boundary and contract work as secondary to the program; it is the current primary ES milestone.
- Do not let Control Plane documents, probes, or examples define ES core contracts. They may document consumption of accepted ES surfaces only.
- Preserve current CP compatibility for the governed execution path, including `execution_substrate.runtime_profile` and `control-plane-normal-shell/v1`, unless a coordinated compatibility, drain, migration, or versioning plan is documented first.

## Reopened-Seam Exit Criteria

The current reopened-seam plan is complete only when all of the following are true:

- The new shared kernel or contract layer is settled and explicitly documented.
- AGS and ARS no longer force the old artifact publication and retrieval choreography by default.
- ES no longer depends on the current inherited core grammar for its public admission and execution model.
- EGS and CGS have clearly defined policy and authorization ownership.
- The workload-zone Vault runtime-config reference and blob surface has a clearly justified long-term owner.
- Runtime identity and execution handoff have explicit ownership and no unresolved dependency on current incidental path conventions.
- Any retained compatibility edges are documented as temporary, with removal conditions.
- `PLANS.md`, `.docs/`, tests, and implemented code agree on the active architecture.
- Peripheral cleanup can proceed without architectural uncertainty.

Until those conditions are met, reopened seams must stay explicit in `PLANS.md`; outside those seams, treat the repository as bounded platform work rather than rewrite-by-default feature work.
