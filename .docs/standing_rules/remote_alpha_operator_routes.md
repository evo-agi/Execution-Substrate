# Remote Alpha Operator Route Standing Rules

These are the standing rules for the Remote Alpha operator facade routes P0i
to P0v. They moved here unreworded from the `PLANS.md` section
"Highest-Priority Backlog Entry" at `trunk_dev` commit
`8129b82d79b5700049621b6d4e95b6bf37ada7ac`, so that `PLANS.md` holds intent and
order.

The detailed route contracts are in
`.docs/system_overview/remote_supported_host_alpha.md`.

Edit a rule here in place when it changes. Do not add dated status entries:
say what a change did in its pull request description. Cite this file by
section heading, never by line number.

### Remote Alpha Vault unseal and disposable reset routes (P0i to P0m)

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
P0i/P0j unseal-existing, and recovery-session evidence/plan/inventory behavior.
The `readiness-session` and `es-writable-state-readiness-check` public names are
preserved only as fixed effect-free compatibility tombstones, not as helper or
readiness workflows.

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

### Remote Alpha Vault workload-auth bootstrap routes (P0o to P0q)

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

### Remote Alpha TLS status, renewal and diagnostic routes (P0s to P0v)

`Reopened redesign seam`: the P0s/P0t shared status-and-renewal helper is
re-derived as one dedicated status-only collector. This is a bounded Remote
Alpha evidence and repair-support refinement. The committed status/renewal
mode switch and the blocked protected-evidence supervisor are historical
implementation shapes, not architecture. Renewal is held; this tranche does
not implement it, production PKI, host provisioning, automatic renewal,
remote reconciliation, MA scheduling, IM or CP authority, governed-execution
proof, or service restoration. The P0q legacy writer, the separate P0u hold,
and P0v noninteractive route retain their own contracts.

`Temporary compatibility edge`: the Mac facade retains exactly
`es-service-tls-status` and `es-governance-tls-status` with `--ssh-target`
and visible `--interactive-tty`. They stage only
`scripts/internal/remote_alpha_es_tls_status.py` in one invocation directory
directly under `/tmp`, invoke one fixed source-controlled bootstrap with
`/usr/bin/python3 -I -B -c` through visible sudo, and select respectively the fixed `artifact-registry` or
`execution-governance` scope. The facade does not treat the TTY stream as
machine evidence and does not copy a summary to Mac `.out`. Both
`es-service-tls-renew` and `es-governance-tls-renew`, including
`--execute-renew`, refuse before staging, SSH, SCP, sudo, or host contact.
`--execute-renew` on a status route also refuses before contact. The public
renewal wrapper refuses locally without sourcing the committed internal
renewal helper. That internal file remains historical and undispatched.

The fixed remote wrapper is delivered as a bounded, single-quoted SSH remote
command derived only from source-controlled bytes and exact validated operands,
independently of SSH stdin. SSH stdin remains the operator's real local
terminal throughout the forced remote TTY invocation, including a
password-required sudo prompt. The route does not depend on cached sudo
credentials or NOPASSWD, and no sudo password is captured, relayed outside the
terminal, or retained. Target validation and worst-case command-size preflight
fail before host contact; the returned custody identity is validated before
the interactive invocation. No caller-supplied command fragment enters the
remote command.

`Bounded slice rule` failure-visibility refinement within this reopened seam:
the fixed root bootstrap is the sole owner of an optional, at-most-one,
source-bound P0s/P0t failure witness on its existing controlling terminal.
The verified collector selects only an invocation-local closed phase/reason;
it never writes a diagnostic itself. A witness is permitted only after the
applicable stage, child, temporary, status-directory and scope-lock closeout
is proved. Unresolved ownership or cleanup suppresses it. The output is one
fixed ASCII line of at most 512 bytes, with scope, bootstrap/collector origin,
verified/unverified source, the exact verified payload SHA-256 or `none`, and
a coupled fixed phase/reason. It is advisory operator text, never a protected
record, accepted TLS result, restoration or retry authority. No TTY input is
captured, no new wait or cleanup is added, and blocked or missing output cannot
change the status result. Successful completed pass and completed typed fail
publish silently through the existing final `os.replace` -> `os._exit(0)`
boundary. Post-contact facade failure says the remote phase is unproved;
it cannot infer a collector phase from SSH/sudo exit or witness absence.

For this bounded witness, each parent-owned descriptor or stream has its own
pending close obligation. Consume that obligation before an explicit close
attempt; a failed attempt leaves invocation-local disposition unproved even
when a stream reports itself closed or a later close of the same numeric value
would succeed. Do not retry that ambiguous resource. Still attempt the
separately owned resources that remain pending, including a newly opened
protected-ancestry child after its former parent's close fails. This narrow
close-accounting refinement does not change capability criteria, child/group
holds, scope-lock order, publication, or protected reader acceptance.
The fixed-input leaf and reverse ancestry chain, the scope lock then status
directory, and each acquired same-group member pidfd are finite ownership
groups. An ordinary failed close remains unproved while other applicable
pending obligations receive their own single attempts before the existing
incomplete outcome; a later successful close never clears that uncertainty.
For a fixed input, a missing final leaf is completed absence only after all
acquired input descriptors have received successful closeout. If any input
close fails, the primitive yields a controlled incomplete result after the
other pending close attempts, even when final-leaf `FileNotFoundError` was
already pending. A `FileNotFoundError` raised by close is not an absence
observation. Required or optional config, certificate, and key callers may
classify completed missing only after this proved input closeout.
`Bounded slice rule` input-origin refinement: the original no-follow stat of
the final component is the only operation that may provisionally observe a
missing fixed input. Only after ancestry revalidation and successful input
closeout does the primitive deliver a private, payload-free
`_VerifiedFinalLeafAbsent` marker. The config, certificate, and reached-key
callers classify completed missing only from that marker. A
`FileNotFoundError` from root/ancestor acquisition, metadata, a present-leaf
read or later identity recheck remains incomplete, never completed absence;
the private `fixed_input_read_unproved` literal maps to the existing
`fixed_input_unproved` collection witness reason when no narrower incomplete
classification applies. A settled operation failure may retain that advisory
witness after the ordinary lock/status closeout; failed input closeout still
suppresses it. This private interface changes no public code, schema, reader,
terminal grammar, publication boundary or retry authority.
After one member fault, later observed candidates still require their own
pidfd and exact group/start-time revalidation before signaling. Aggregate
member uncertainty enters the existing child-owner hold after that finite
scan, without changing its signal, reap, or lock authority.
`Bounded slice rule` process-identity refinement: every membership scan reads
the proc stat line of every process on the host, so the reader must not let a
process outside the fixed group decide its result. The reader parses that line
as bytes. The process name between the first `(` and the last `)` is chosen by
its own process and may hold any byte; it is never decoded, compared, or
otherwise interpreted. Only the kernel-written fields after the last `)`
supply the group ID and the start time. The stat file never proves that a
process is absent: while a thread other than the first thread of a live
process calls exec, the kernel can answer `ENOENT` or `ESRCH` at open,
`ESRCH` at read, or a line with a negative group ID. After such an answer a
listed process is absent only when `pidfd_open` confirms that no process has
its ID, by `ESRCH`, or by `EINVAL` from a kernel that answers so for a number
that no process leads. When a process still has the ID, the reader reads the
stat file again, four times at most, and an answer that stays unclear is
unproved, never absent. Every other open or read error is unproved, never
absent, and a missing `<pid> (` prefix, an oversized line, and a missing or
non-numeric field remain `process_identity_unproved`. The name or the exit of
an unrelated process therefore neither fails the capability probe nor prolongs
the unresolved-cleanup hold. This refinement adds no time limit to that hold,
never counts a visible zombie as absent, and changes no signal, reap, lock,
publication, or retry authority.
`Bounded slice rule` fixed-child containment refinement: the process-group
disposition above reaches only a process that stays in the fixed child's
process group and that one identity scan observes. A descendant that leaves
the group with `setsid` or `setpgid`, or that ignores TERM and replaces
itself with a new process between two scans, is outside both. Each fixed
OpenSSL command therefore runs in a PID namespace of its own, and the kernel,
not a scan, accounts for its processes. Immediately before the spawn the
collector proves from `/proc/self/ns/pid_for_children` that its children are
created in its own PID namespace, opens a new one with
`unshare(CLONE_NEWPID)`, and forks exactly one fixed internal anchor, which
becomes the first process of that namespace. The anchor first asks the
kernel with `prctl(PR_SET_PDEATHSIG)` to kill it when the collector's thread
that forked it ends. It then closes every inherited descriptor except its
standard streams, the read end of one control pipe, and the write end of one
ready pipe, including the status lock, and ends itself with a nonzero status
when one stays open. Only then does it write one byte to the ready pipe, and
the collector spawns nothing before it has read that byte, so no fixed child
exists while a death of the collector could leave the anchor alive. The
anchor reaps the orphans of the namespace, without which an orphan that ends
as a zombie in the fixed child's process group would stay visible to the
unchanged absence scan and hold it, and it ends with status zero when the
control pipe reports end of input. The fixed child is spawned exactly as
before, as the second process of the namespace and a direct child of the
collector. Directly after the spawn attempt, successful or not, the collector
sets its child namespace back with `setns` and proves the reset by the same
`pid_for_children` check. The cleanup owner, process-group disposition,
unresolved-cleanup hold, direct-child reap, and post-reap absence scan then
run unchanged, and on every path after the spawn the collector closes the
control pipe before the cleanup owner runs and sends the anchor, its own
unreaped child, one KILL, so that the namespace ends whatever a process of
the namespace does to the pipe or to the anchor. A descendant that left the
group can keep a child of its own in the fixed child's group and leave it
unreaped. Once that child has ended, it is a zombie that is not an orphan, so
the anchor cannot reap it, and no group signal can end it; the unchanged
cleanup would wait until the descendant ends by itself, which may be never.
With the namespace ended first, the kernel kills that descendant, the zombie
goes to the anchor, which reaps it, and the cleanup finds the fixed child
alone. The fixed command can also make a process whose parent is the
collector, with `clone` and `CLONE_PARENT`. Only the collector can reap such
a stray, and its zombie would hold the cleanup or the anchor. Before the
cleanup owner runs, the collector therefore waits without a time limit until
the fixed child is terminal and then reaps every stray: each child of the
collector, as `/proc/self/task/<tid>/children` lists them, that is outside
the collector's own PID namespace and is neither the anchor nor the fixed
child. It waits for a stray once it has ended and never signals it, and it
goes on until one list of its children holds no stray. Only the fixed child
and a stray can make a stray, so a list that holds none, read after the
fixed child was seen terminal, is final. A fixed child that still runs at a
timeout, an interruption, an output overflow, or a failed step after the
spawn, and any process that outlived the fixed child, is therefore killed by
the kernel without the grace period of TERM before KILL; on those paths the
command is incomplete, and after a normal end the result is already
complete, so nothing such a process could still write counts. When the
anchor ends, the kernel kills every process that is still in the namespace,
admits no new one, and lets the anchor become terminal only when no other
process of the namespace is left, an unreaped child of the collector
included. The collector waits for that with a nonblocking `waitpid` on the
anchor, reaping every ended stray in the same loop, sends the anchor one
KILL when it has not had one and is not terminal after the grace period or
when the pipe close failed, and reaps it exactly once. No fixed command
returns, with a result or incomplete, before its anchor is reaped. An anchor
that does not become terminal holds the invocation with lifecycle ownership
and the status lock retained, as the unresolved-cleanup hold does, and that
hold has no time limit. A collector that is killed takes its anchor with it
through the parent-death signal, so its fixed child and every descendant in
the namespace die with it.
No namespace, no anchor, or no ready byte means no spawn and an incomplete
command. An unproved reset, a failed control-pipe close, a failed KILL of the
anchor, a failed list of the collector's children or wait for a stray, an
anchor that ends in any way other than status zero or the collector's own
KILL, and an unproved anchor reap are incomplete after the complete cleanup,
through the private `child_namespace_unproved` literal, which maps to the
existing `openssl_child_unproved` collection witness reason. While the reset
stays unproved every later command refuses at its first check. No command
falls back to process-group disposition alone.
The invocation-boundary process-capability probe gains a second part, after
its first part succeeded and still before any status input is read: one probe
namespace with its anchor and one fixed internal member that never ends by
itself. After the control pipe closes, the member must become terminal by
the kernel's KILL, the anchor must not be terminal while the member is
unreaped, the ended member must be listed among the collector's children
outside its own PID namespace, as a stray is found, and the anchor must end
with status zero after the member's reap, without a KILL from the collector.
Both are reaped and every probe descriptor is closed on every path. A Python
without `os.unshare` or `os.setns`, a refused namespace, and any other
outcome are the existing `process_capability_unproved` reason, before any
status input is read and before any OpenSSL spawn. The decision is by
behavior, never by an OS label, a kernel version, or the caller's user ID.
Limits that this refinement states and does not remove: the fixed child still
runs as root, so a hostile child could ask a host service to start a process
outside its namespace, or write any root-writable file, and a root process of
the namespace that may trace the anchor could undo the anchor's parent-death
signal, so that a killed collector leaves that namespace alive; a process
that cannot die keeps the anchor or a stray from becoming terminal, and the
invocation holds; inside the namespace the fixed child has process ID 2 and
parent ID 0 while `/proc` stays the host's; and the namespace setting belongs
to the calling thread, which a kernel may refuse to a process with several
threads, so the collector keeps exactly one thread. Local and unprivileged
tests replace the namespace steps with a stand-in and prove nothing about the
kernel path; only a run as root on Linux does. This refinement changes no
process-group signal, hold, direct-child reap, lock, publication, public
code, schema, reader, or retry authority.

The facade uses one fixed remote Python stage-creation helper. It opens the
fixed `/tmp` parent, refuses an existing generated name, creates only that
name with mode `0700`, immediately opens it with
`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, and verifies directory type, current
caller UID/GID, mode, link rules, empty entry set, and matching parent-entry
and descriptor identity. It closes all descriptors and emits only two strict
unsigned decimal device/inode fields. Those fields are the
**custody-acquisition identity**, not a claim that POSIX atomically binds
`mkdir` to `open`. The supported operator route trusts its nonroot `ds`
account for this fixed helper; a concurrent malicious same-UID process before
custody acquisition is outside this operator-route trust boundary. After
acquisition, pathname ownership alone cannot authorize observation or
deletion: root still requires the measured identity and exact digest. A same-path replacement is refused after custody acquisition. Correct
payload bytes cannot authorize a different directory identity or scope.

After stage creation, the nonroot facade performs no destructive stage
cleanup. On SCP failure, sudo launch or authentication failure, transport
failure, bootstrap rejection, or any failure before root proves custody, it
returns nonzero, retains the stage as diagnostic residue, and emits only a
bounded non-sensitive cleanup disposition. The stage contains only the fixed
public collector payload and bounded metadata, never credential, host key,
certificate, private key, config, summary, or raw child output. The fixed
root bootstrap alone may delete a stage, after proving measured identity,
caller UID/GID, directory metadata and entry set, exact leaf, payload
identity, and digest. A substituted or unproved path remains residue.
Successful root removal is followed by no facade cleanup. No automatic
residue sweeper, wildcard cleanup, or historical-stage migration is added.
Residue is not accepted evidence, route success, host readiness, renewal
authority, or permission for later deletion. This bounded compatibility
rule deliberately retains an unproved object rather than deleting it.
Every facade setup and bootstrap stage check inspects the final staged
entry without following it before any blocking open. FIFO, socket, symlink,
directory, device, or other nonregular substitute is refused promptly and
retained as diagnostic residue. Only an observed regular entry may be opened
with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`; immediate `fstat` must match its
pre-open device, inode, type, owner, mode, and link count. An unproved or
failed cleanup is incomplete and preserves the previous generation.
The facade derives an expected SHA-256 internally from its exact fixed local
collector source; no caller supplies a digest. Its root bootstrap accepts only
the generated stage directory, fixed collector basename, derived 64-hex digest,
one fixed scope, and the two internally derived custody-acquisition device/inode operands.
It verifies stage and sudo caller, inspects the leaf without
following it, opens it with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, binds the descriptor
to the pre-open entry, reads a bounded complete payload, and verifies its digest
and stable identity. It transfers the exact stage to root custody, rechecks
identity before unlink, proves the directory empty, and removes it before
compiling and executing only the already-read bytes in memory. Root Python
never loads an operator-writable pathname. The collector receives a
source-visible internal bootstrap marker, latched-signal handoff, and synthetic source label; direct
pathname invocation refuses before status reads or publication. Substitution,
digest mismatch, and cleanup failure publish no fresh generation. There is no
post-publication stage cleanup.

`Bounded slice rule`: the root-run Python collector has only two immutable,
source-controlled scope tables and no renewal mode, path override, arbitrary
command, shell, backup, generation, install, restart, or post-renewal probe.
P0s observes the fixed ARS server, AGS client, and ES artifact-registry client
certificate/key/CA roles; checks ARS/AGS/ES fixed config bindings and the
loopback ARS dependency on port 8442; matches three cert/key pairs; and
verifies AGS/ES clients against ARS runtime CA and ARS server against the two
client trust copies. P0t observes fixed EGS server and ES governance client
certificate/key/CA roles; checks EGS/ES bindings, loopback EGS dependency on
port 8443, fixed server name `server.execution-governance.internal`, and AGS
execution-governance exclusion; matches two pairs and verifies the ES client
against EGS runtime CA and EGS server against the ES root copy. A topology,
certificate, key, or chain mismatch may be completed `fail` evidence. A
collector lifecycle failure is incomplete and publishes no generation.

`Bounded slice rule` audit repair: a related configuration used for a fixed
disjointness or exclusion check has a proved state. A safely absent optional
EGS config for P0s or ARS config for P0t gives its dedicated related-config
check `status=pass, code=absent`; affected disjointness checks may pass only
after that absence is proved. A safely read, valid config is checked for
overlap. A present malformed config yields completed typed
`related_config_malformed` on its related-config and affected
disjointness/exclusion checks, never an empty-object pass. A missing required
config yields `config_missing` on its required-config check and on related
disjointness/exclusion checks that depend on it. An unsafe, over-limit,
changing, or unexpectedly unreadable config is incomplete and emits no
completed unreadable code. These checks do not widen either scope or
repair authority.

Every required or present optional config uses strict JSON: duplicate keys,
non-finite constants (`NaN`, `Infinity`, `-Infinity`) and every parsed
non-finite numeric value (including `1e10000`, `-1e10000`, and nested
overflow in ignored fields), invalid UTF-8,
trailing data, and non-object top levels are malformed. Every strict-JSON
payload has `MAX_JSON_CONTAINER_DEPTH = 64`: a top-level
object or array is container depth 1, each nested object or array adds 1, and
scalars add none. Depth 64 is accepted subject to the existing schema and
byte-size limits; depth 65 is rejected as malformed for required and present
optional configurations. Required configurations retain `config_malformed`
and its dependent blocker relationship; present optional configurations retain
`related_config_malformed`, never absent/pass. An over-depth protected reader
summary is unaccepted evidence through the controlled reader failure API,
with no traceback or raw exception text. Decoder recursion exhaustion has the
same controlled structural rejection. The exact summary schema still governs
accepted-reader evidence independently of this depth ceiling.

`Bounded slice rule` prior-summary refinement: the pre-run canonical target
has three explicit private states: `ABSENT` only when the verified final leaf
is safely absent, `VALID(generation)` when a present protected leaf yields a
bounded generation snapshot, and `INVALID_OR_UNACCEPTED` when a present leaf
cannot yield that snapshot and is invalid/unaccepted. A present target is never
treated as absence.
Every strict-JSON or snapshot-shape rejection in a present target, including
depth, non-finite numbers, constants, duplicate keys, invalid UTF-8, trailing
data, non-object roots, decoder exhaustion, and mixed defects in either field
order, is
`INVALID_OR_UNACCEPTED` regardless of which defect is detected first.
The minimal pre-run snapshot requires the expected `schema_version`,
`collector_contract`, `finalized=true`, `scope`, and `route` for the selected
scope, plus a string `generation` of exactly 32 lowercase hexadecimal
characters. This is an identity snapshot, not full accepted-reader semantic
or freshness validation: a stale or completed-fail prior record with valid
snapshot identity may be replaced, but the new generation must differ.
After the one invocation-boundary process preflight and status-lock acquisition,
`INVALID_OR_UNACCEPTED` makes the current attempt incomplete before any status
collection, material read, OpenSSL spawn, or publication setup. No new
generation replaces the prior canonical bytes or metadata identity. Unsafe
type, identity, or read failure remains incomplete under the protected-leaf
rule. No raw exception text or new public evidence code is emitted.
Every configured
certificate, key, or CA path that participates in topology must be an
absolute lexical canonical POSIX material path. `/` is not material; NUL,
empty, `.`, or `..` components, repeated separators, and trailing separators
are rejected. A value must equal its own lexical normalization. A
noncanonical present config receives its governed malformed typed result;
expected-path and disjointness checks compare only accepted canonical
values, never raw aliases or host `realpath`.

The protected status contract is
`execution-substrate.remote-alpha.es-tls-status-evidence/v1`. Pre-existing
`/var/lib/execution-substrate-remote-alpha`, its `v1` child, and `v1/status`
must each be real root:root `0755` directories with no symlink, unsafe access,
or unresolved ACL/equivalent state. The collector never creates a missing
protected directory; host preparation is separate. It publishes only:

- `/var/lib/execution-substrate-remote-alpha/v1/status/es-service-tls-status-summary.json`
  with `execution-substrate.remote-alpha.es-service-tls-status-summary.v1`;
- `/var/lib/execution-substrate-remote-alpha/v1/status/es-governance-tls-status-summary.json`
  with `execution-substrate.remote-alpha.es-governance-tls-status-summary.v1`.

Existing targets must be root:root `0644`, regular, single-link, no-follow,
without unsafe access or unresolved extended access. Records are at most one
MiB. Separate persistent same-scope status locks in the verified status
directory are `.es-service-tls-status.lock` and
`.es-governance-tls-status.lock`, root:root `0600`, regular, single-link,
opened with `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC` and acquired by
`flock(LOCK_EX|LOCK_NB)`. Same-scope contention is incomplete; different
scopes may proceed. Status never creates or uses `private-backups`.

The collector contract identifier is
`execution-substrate.remote-alpha.es-tls-status-collector/v1`. Every
completed record has the exact scope schema, route, a random 128-bit
lowercase-hex generation, UTC `checked_at`, `finalized=true`, fixed role and
topology check arrays, typed blocker codes, consistent `result.status` and
`result.ok`, explicit false renewal/backup/generation/install/restart/probe
non-effect flags, and redaction flags. No raw config, OpenSSL output, private
key, private-key digest, environment value, arbitrary path, command string,
backup, or rollback metadata enters the record. Fixed public certificate
paths may appear only as part of the source-controlled scope contract.

Before status work, the root bootstrap verifies its exact one-file staged
invocation directory, owner/mode/type/link/descriptor identity and fixed `ds`
nonroot sudo caller,
transfers the verified directory to root custody, then unlinks that file
and removes that directory through verified handles.
Unprovable cleanup or a latched catchable signal aborts before any protected
status operation. It creates no later `/tmp` scratch. Fixed OpenSSL children
run one at a time with absolute argv, no shell, bounded concurrent pipe reads,
timeout, TERM-then-KILL, complete reap, typed parsing, no lock inheritance,
and no raw output in evidence. Each successfully spawned child enters a
cleanup owner immediately: selector construction/registration, nonblocking
setup, collection, parsing, timeout, signaling, wait/poll, and ordinary
exceptions all terminate and reap it before incomplete return. Signaling
errors require identity-safe same-group member disposition, never a
direct-child-only fallback; no live fixed child or process group may be left
by a returned attempt. After bootstrap stage removal and status-lock acquisition, before required
or optional status config, certificate, key, trust-anchor, or protected prior
summary reads and before any OpenSSL spawn, exactly one invocation-boundary
process-capability probe uses one fixed internal fork child to prove nonreaping
`waitid(P_PID, WEXITED|WNOHANG|WNOWAIT)`, subsequent exact reap, and
pidfd/proc member operations by behavior. The probe child closes inherited
descriptors, including the status lock, before waiting for its fixed release;
it is reaped on every
path; unavailable or indeterminate capability is incomplete before spawn.
A successful probe grants invocation-local capability state reused by every
fixed OpenSSL command. Each child command refuses without that state and never
forks another probe. A failed probe reads no status input, spawns no OpenSSL
child, publishes no generation, and leaves no probe descriptor or process.
In a second part the same probe proves the PID-namespace containment of the
fixed-child containment refinement with two further fixed internal fork
children, a probe anchor and one probe member, under the same rules.
On group signal failure it enumerates only members of the reserved
leader PGID, acquires pidfds, revalidates identity and membership, signals
members through pidfds, and repeats bounded scans until nonleader members are
proved gone. An individual member error does not skip other identity-proved
members in that scan. If group and member signaling remain unproved, it holds the leader
unreaped with lifecycle ownership and status lock retained and publishes no
generation. Every ordinary `Exception` from membership scanning, pidfd
acquisition, identity revalidation, signaling, polling, waiting, or
cleanup-state reporting is contained in the unresolved-cleanup hold. A
one-shot runtime fault is retried; a persistent fault retains the invocation
and status lock with bounded backoff. No outer retry may return or publish
until group absence and exactly one direct-child reap are proved, and no
fixed command returns before the anchor of its PID namespace is reaped. No
unrelated process is signaled. Group TERM and KILL
occur while the child remains unreaped and its PID reserved; cleanup never
signals a process group after reaping, when that PID could already have been
reused. Terminal detection uses nonreaping `waitid` with `WNOWAIT`, including
through the target's C runtime when Python does not expose it; the syscall and
group-disposition behavior must be proved, not inferred from an OS label.
The collector retains the leader's reserved PID through bounded TERM/KILL
disposition, even if its return code is known. After direct-child reap, only
a non-signaling identity-based proc group scan may run; no numeric process-group
signal occurs then. A zombie-only group may remain visible before reap; the
post-reap non-signaling absence check holds fail-closed until absence is proved
before a returned attempt. Post-exit wait/poll
or other lifecycle failure still disposes of descendants with the leader
reserved. An unavailable or indeterminate capability is incomplete and
publishes no new generation. It never switches to a weaker command or
process-cleanup mode. For each
fixed command, only
explicitly admitted C-locale whole responses (exit status, stdout, stderr)
can produce completed success or typed material failure. Extra or mixed
lines, unknown nonzero output, signal exit, output overflow, or runtime
OpenSSL grammar drift are incomplete.

`Bounded slice rule refinement` within the reopened P0s/P0t collector seam:
the fixed `x509 -in /dev/stdin -noout -text` success response admits exactly
two complete terminal signature tails. The existing tail has a
`    Signature Algorithm: <token>` line immediately followed by one or more
nine-space-indented lowercase hexadecimal rows. The additional tail has the
same algorithm line, exactly one `    Signature Value:` line, and one or more
eight-space-indented lowercase hexadecimal rows. Each alternative retains
the current token, colon, newline, prefix, CR/NUL, UTF-8, exit-zero,
empty-stderr, output-bound, and end-of-input rules. A heading-plus-nine,
no-heading-plus-eight, mixed-indentation, or unknown-heading hybrid is
incomplete. The earlier local synthetic text-tail response did not qualify the
target host's OpenSSL 3.0.13 binary or other fixed response families. A later
single nonroot synthetic observation of that target binary captured 55 complete
native tuples: 39 accepted by the unchanged consumer, 13 closed-grammar gaps,
and three downstream malformed-output controls unreachable at current call
sites. This is finite response evidence, not proof of production material,
root-context execution, complete P0t inventory, or service readiness.

`Bounded slice rule refinement` for those 13 gaps: the fixed certificate
metadata command admits exit 1, empty stdout, and exactly
`Could not read certificate from /dev/stdin\nUnable to load certificate\n`
as `certificate_malformed`; the fixed private-key-to-public-DER command admits
exit 1, empty stdout, and exactly
`Could not read key from /dev/stdin\n` as `key_malformed`. Their existing
LibreSSL alternatives remain. Later public-PEM, DER, and text malformed
outputs remain incomplete at their current call sites. No arbitrary nonzero
response becomes a typed failure. The same observation supports one closed
three-line `verify` stderr envelope and six coupled alternatives stated below;
other response families retain their previous acceptance sets.

Fixed config, certificate, and key inputs use verified no-follow ancestor and
leaf descriptors. The final entry is inspected without following it before
any blocking read open. FIFO, socket, symlink, directory, device, and every
other nonregular type are rejected without blocking. Only a prechecked regular
entry is opened with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, then immediately
`fstat`-matched on device, inode, type, owner, mode, link count, and governed
metadata before bounded reading. A swap to another regular file or unsupported
type fails closed. Only an absent final leaf beneath proved safe ancestry is
a completed missing result; unsafe ancestry, type, permission denial, metadata
failure, and race are incomplete. A bounded read
captures immutable bytes from the verified descriptor. Each OpenSSL metadata,
SAN/EKU, key, and verify operation consumes a fresh anonymous pipe carrying
those exact bytes, never the original mutable pathname. Transient key bytes
exist only to feed the fixed OpenSSL child; they and any key digest are never
published or retained after that check. The fixed public path is an evidence
label, while `/dev/stdin` is the leaf/key invocation operand and the selected
CA is a single inherited `/dev/fd/<n>` operand. Pipe setup or target descriptor
support failure is incomplete and creates no retained scratch.
Every P0s/P0t CA-role input is exactly one selected PEM `CERTIFICATE` block
with only bounded ASCII whitespace around it. Zero or multiple certificates,
another PEM block, or non-whitespace outside the block yields completed
`trust_anchor_count_mismatch` with null certificate metadata and
`certificate_unavailable` for dependent verification. The fixed `-trusted`
descriptor receives those same observed single-anchor bytes; a later anchor
in the file cannot rescue a wrong first anchor. This v1 status schema does
not call the selected input a bundle. Bundle support requires a separately
versioned trust-set and reader decision.

The exact client command is `/usr/bin/openssl verify -trusted <selected-ca-fd>
-purpose sslclient /dev/stdin`; the exact server command adds
`-purpose sslserver -verify_hostname <fixed-server-name> /dev/stdin` after
`-trusted <selected-ca-fd>`. Both use `shell=False`, one fixed minimal child
environment with `LC_ALL=C` and no inherited OpenSSL/trust/config overrides,
and no `-CAfile`, `-CApath`, `-CAstore`, or `-untrusted`. `-trusted` selects
only the scope's anchor; ambient default trust cannot rescue a wrong selected
anchor. Unsupported `-verify_hostname`, `/dev/fd`, or other exact-command
capability is incomplete. Positive target support belongs to later host
preflight, not this local repair.

The admitted `verify` response is an anchored whole tuple. Success is exit
zero, empty stderr, and exactly `/dev/stdin: OK\n` on stdout. A bounded
LibreSSL-shaped failure has exit 2 and empty stderr. For each of the four P0s
expiry fixtures, stdout is exactly three
repetitions of `CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup:certificate has expired\n`, then
`CN = <DNS token>\nerror 10 at 0 depth lookup:certificate has expired\n`,
then `/dev/stdin: verification failed: 10 (certificate has expired)\n`.
For the not-yet-valid server fixture, stdout is exactly
`CN = <DNS token>\nerror 9 at 0 depth lookup:certificate is not yet valid\n/dev/stdin: verification failed: 9 (certificate is not yet valid)\n`.
The bounded wrong-anchor failure has the same LibreSSL-shaped three-line
stdout grammar with code 20 and `unable to get local issuer certificate`.
The earlier compact OpenSSL-3-shaped failure remains: exit 2, empty stdout,
and stderr exactly
`CN=<DNS token>\nerror <code> at 0 depth lookup: <reason>\nerror /dev/stdin: verification failed\n`,
with its existing `(20, unable to get local issuer certificate)` and
`(62, hostname mismatch)` alternatives. Hostname mismatch requires the fixed
server hostname. The target OpenSSL 3.0.13 observation additionally admits
exit 2, empty stdout, and exactly
`CN = <subject>\nerror <code> at <depth> depth lookup: <reason>\nerror /dev/stdin: verification failed\n`.
The six coupled code/depth/reason/subject/context alternatives are: 20/0
`unable to get local issuer certificate`, 10/0 `certificate has expired`, and
9/0 `certificate is not yet valid`, each with a `[A-Za-z0-9.-]+` subject in
either purpose; 10/1 `certificate has expired` with subject exactly
`Remote Alpha Internal Runtime Root CA` in either purpose; 26/0
`unsuitable certificate purpose` with a bounded subject under `sslclient`
only; and 62/0 `hostname mismatch` with a bounded subject under `sslserver`
with its nonempty fixed hostname only. Each admitted negative tuple is the
existing completed `chain_failed`, including when certificate validity has
already failed. No code/reason/depth cross-product, arbitrary RDN, extra or
mixed stream, warning, CR/NUL, missing terminal LF, changed operand, unknown
exit, or unadmitted response can produce a completed result. These narrow
tuples are not a general certificate-error parser. Unknown grammar remains
incomplete and publishes no new generation; target scope remains finite.
Full positive target capability remains a separate host-preflight fact.

`Current invariant` evidence boundary: completed `pass` and typed completed
`fail` are both valid observations; interrupted, timed-out, overflowed,
uncertain, or internally failed collection publishes nothing new. The
collector finishes stage cleanup, children, encoding, size checks, temporary
write/fsync, mode/identity and existing-target checks before publication. It
latches HUP/INT/QUIT/TERM without asynchronous raise or I/O, blocks those
signals before final replacement, and refuses a latched or pending signal.
Every operation after successful exclusive temporary creation, including the
first `fstat`, is owned by pre-replacement cleanup. On failure the collector
closes the descriptor and unlinks only a revalidated invocation-owned
temporary; if ownership cannot be proved it leaves bounded protected
diagnostic residue. The previous canonical generation remains unchanged.
Successful `os.replace` through the verified status-directory handle is the
last evidence operation and is followed immediately by `os._exit(0)`. There
is no required cleanup, callback, directory fsync, verification, or machine
output after replacement. This gives atomic visible evidence, not crash
durability; after reboot or uncertain persistence a new observation is needed.
Collector exit zero means a completed record was published, not that TLS
passed. Route acknowledgment is separate from the record.

A reader accepts a record only after descriptor-first ancestry and canonical
file validation (root:root `0644`, regular, single-link, no symlink, bounded
size, no unresolved ACL), exact schema and collector id, `finalized=true`,
strict JSON decoding that rejects duplicate keys, non-finite constants,
and parsed non-finite numeric values,
matching route/scope, a 32-character lowercase-hex generation different from
the pre-run snapshot, UTC `checked_at` at most five minutes old and at most
thirty seconds in the future, exact fields/roles/cardinalities/enums,
consistent result and non-effect flags, and no unknown fields. A completed
`fail` is accepted failure evidence; an unchanged generation cannot satisfy a
new attempt. Route exit plus file presence is insufficient. No monitor or
scheduler gains authority here.
Publication existing-target checks, pre-run generation snapshots, and accepted
reader reads use one shared canonical-summary primitive. After verified
no-follow parent ancestry it inspects the final entry without following it,
rejects nonregular or unsafe metadata before a read-open, and opens only an
observed regular leaf with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`.
Immediate `fstat` must match inspected identity and governed metadata. The
bounded descriptor read must be complete and stable, with post-read descriptor
and pathname identity checks. FIFO and regular-to-FIFO, symlink, or
different-regular swaps refuse without blocking. Only a safely absent leaf
uses the governed absent behavior; incomplete checks publish no generation.

`Bounded slice rule` reader refinement: collector self-validation and a later
reader use the same exact semantic table. The actual certificate schema has
no `exists` field. A securely parsed certificate has valid UTC
`not_before`/`not_after` with `not_before <= not_after`, all five SHA-256
metadata fields, and role-appropriate SAN/EKU flags; a missing or malformed
certificate has null date, digest, and role-flag metadata. Unsafe or
unprovable certificate/key reads are incomplete and emit no completed
unreadable code.
One UTC `checked_at` is captured for the entire observation. `expired` is
exactly `checked_at > not_after`; `not_yet_valid` is exactly
`checked_at < not_before`; equality at either boundary is valid. Each
certificate status/code must agree with those predicates and its role flags.
Fixed role/path/label and key-pair/verification relationships, per-check code
vocabularies, nested field sets, and the exact blocker set must agree with
aggregate pass/fail and `ok`. Contradiction or unknown nested data is
incomplete before publication or reader acceptance.

Legacy `/var/tmp/execution-substrate-remote-alpha/*tls*summary*.json`, old
`*-renew-summary.json`, blocked-candidate protected summaries, and old backup
directories are historical only: no read as current status, migration, copy,
overwrite, symlink, fallback, renewal, or rollback authority. The blocked
candidate is design evidence and is not the implementation base. Validation
is local static/fake only; no live SSH, sudo, host certificate/key/config read,
service operation, Docker, Nomad, IM, CP, or host preparation is allowed.

`Bounded slice rule` diagnostic extension inside the reopened P0s/P0t seam:
`recovery-session es-governance-tls-grammar-diagnostic` is a third, separate
nonpublishing source-controlled route for **execution-governance only**. It identifies the
first newly observed rejection at one of the existing ten strict OpenSSL
grammar guards by fixed role, command kind, source predicate and bounded
response shape. It neither diagnoses the consumed attempt retrospectively nor
asserts TLS pass, readiness, restoration or P0t status acceptance. The two
publishing status routes remain exactly two and retain their existing
bootstrap, output and publication behavior. All renewal routes remain held.
This diagnostic must be reviewed for retirement or explicit re-justification
after the installed-response issue is resolved and a required status
observation can complete; it is not general privileged inspection authority.

`Temporary compatibility edge`: the new Mac facade form accepts only the
existing validated `--ssh-target` and visible `--interactive-tty` for live use,
plus a diagnostic-only local `--verify-only`. Verify-only checks the fixed local
source, stage/custody and worst-case command construction without SSH, SCP,
sudo, OpenSSL, installed material, lock or summary access; it grants no host
identity, sudo or lock-freedom claim. The live facade stages one exact
source-bound collector under the existing generated `/tmp/.es-tls-status-`
namespace (one `0700` directory, one `0600` regular leaf), with one stage SSH,
one SCP and one interactive SSH at most. It retains the existing bounded
single-quoted remote command, real operator stdin, visible foreground sudo,
source digest and measured stage device/inode. Root verifies both custody
identity and exact staged bytes, removes only its proved stage before loading
those bytes from memory, and uses a distinct diagnostic bootstrap marker and
synthetic non-`__main__` module name. It never fabricates the status marker or
emits the existing status failure witness. Failed/unproved stage custody
leaves residue; there is no nonroot cleanup, transcript capture, password
relay, NOPASSWD change, automatic retry, or status package copy-back.

The diagnostic parent enters only through that verified bootstrap. It opens
the existing root-owned protected status directory and acquires only the
pre-existing `.es-governance-tls-status.lock`: initial no-follow root:root
regular single-link `0600` size-zero metadata, then
`O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` without creation, truncate, write,
chmod, chown, or fsync. It checks the opened object's extended access and
full descriptor/path identity before and after nonblocking exclusive flock.
Missing, unsafe, changed, unproved or unavailable lock refuses before any
material read. A flock error is lock-acquisition-unproved, not proof of
contention. The lock is held through the unchanged one-time behavioral
process capability preflight, a fresh production prior-summary snapshot
requiring `ABSENT`, fixed topology/input observations and all child/input
closeout. The snapshot may read a present canonical leaf to refuse it, but
never alters it. The lock closes once after all child/input obligations;
the status directory receives its independent close attempt afterward.
Close failure is sticky and suppresses diagnostic output; no descriptor
rescue, forced unlock, broad scan or blanket parent timeout is permitted.
The shared protected-summary reader records a failed canonical-leaf close at
its one close boundary by setting the existing disposition-unproved marker
before re-raising the same exception, including close-raised interruptions
and `FileNotFoundError`. This is the explicit close-bookkeeping exception to
the original 53-function freeze; the other 52 original functions remain
unchanged. Successful close does not clear earlier uncertainty. Settled
read/metadata failure with successful close may still produce the existing
`incomplete_other` advisory after all other closeout succeeds; the diagnostic
does not suppress every prior-reader error or change status-reader acceptance.

The new diagnostic entrypoint follows existing four certificate, two key-pair
and two verification roles in source order, reusing exact fixed input,
selected-anchor, argv/environment, process/child/group and parser behavior.
It counts at most eighteen **attempted fixed OpenSSL calls**, including an
attempt that fails before spawn, but excluding the capability child. An
invocation-local context records at most one first direct grammar rejection,
then terminates native observations. The diagnostic graph does not call the
status `collect`, generation creation, `main`, `encode_document` or `publish`;
the unchanged capability child's required `os._exit` is allowed. Even an
all-success parser traversal creates no status generation, summary temp or
canonical replacement. Typed missing/malformed/expired input and dependency
skips remain distinct from accepted TLS health.

Only after verified stage/source, settled child/descriptor/lock/status closeout
and strict private validation may root make one best-effort nonblocking
output-only `/dev/tty` write: `ES_TLS_GRAMMAR_DIAGNOSTIC_V2 ` plus one closed
ASCII JSON body and LF, at most 2048 bytes. The body has one of
`first_grammar_rejection`, `no_grammar_rejection_reached`, or
`incomplete_other`, a verified source digest and bounded attempted-call count.
Role/operation/site/predicate, ordinal, exit class, stream structural facts
and closed verification token occur only for a first rejection. Exact types,
outcome/nullability, ordinal equality, role/site/operation/predicate/exit
coupling and stream count/flag consistency are enforced in code. A specific
`verify_success_stderr_nonempty` predicate requires the entire fixed ASCII
`/dev/stdin: OK` plus LF stdout shape: 15 bytes, one line, nonempty, valid
UTF-8, final LF, no CR and no NUL. The distinct
`verify_success_stdout_not_exact` predicate retains feasible opaque shapes,
including the same counts and flags; shape does not authenticate text.
Private `schema_version` and `scope` must have exact string types before
literal comparison, so equality-overloaded subclasses cannot pass. A specific
verification token requires exactly one complete supported LF-terminated
error-line occurrence wholly within one original stdout or stderr stream;
split fragments, repeated lines and multiple recognized lines remain
`other`. The private validator checks necessary LF/non-LF capacity. A specific
token reserves one of its two admitted ASCII literal lengths including LF in
one original stream; every other LF consumes a byte, any unterminated tail is
nonempty, and CR, NUL and invalid UTF-8 evidence each needs a distinct
non-LF byte outside the literal. If that literal is the only complete line
and there is no tail, its stream has exactly one admitted length and no
nonliteral flag or residual byte. These necessary shape checks do not claim
that counts authenticate native contents. A private
JSON Schema is reference/test data, not a runtime package or protected status
schema. No raw native stream, subject/SAN/serial, PEM/DER/key bytes, material
digest, path/PID, provider text or exception string is emitted. Unknown or
context-invalid grammar stays `other` or is refused. The optional line is
advisory; short/blocked/missing output, transport exit or `--verify-only`
cannot establish a usable measurement. A completed diagnostic can return
acknowledgment exit zero; incomplete/refusal uses nonzero with remote phase
uncertain. No follow-on scan, repair, status retry, IM/MA/CP authority or
service action follows.

`Bounded slice rule` verification-projection refinement: the current private
terminal body uses `es-p0t-openssl-grammar-diagnostic/v2` for all three outcomes
and all first-rejection sites. The consumed v1 advisory and its private schema
remain immutable historical evidence; neither is parsed as v2 or used for
protected status acceptance. Exactly at a first
`VERIFY_FAILURE_ENVELOPE_UNADMITTED` rejection, the source projects the
already returned stdout and stderr separately without another native call or
weakened `verify_chain` grammar. Complete LF-terminated lines keep order and
repetitions. Each receives one of six bounded categories: context-valid
`known` code/depth/closed reason; content-free
`context_invalid_unclassified`; bounded `unknown_numeric` code/depth;
`unclassified` error-like; exact `terminal`; or `opaque`. Unknown numeric
requires canonical ASCII code 1–999, depth 0–9, exact framing and 1–128
printable reason bytes, but exposes no reason. Unterminated tails are only
`error_like_unclassified` or `opaque`; no terminator is invented. Per-stream
counts include every bounded complete line, and `known_count` plus
`recognized_literal_count` retain multiplicity. At most eight complete lines
across both streams retain both ordered sequences; above eight both sequences
are empty with `cap_reached=true` and `sequence_complete=false`, while all
counts and tail kinds remain. The v2 gate checks exact types, legacy
token/predicate priority and identity where available, count and shape
coupling, classified-byte minimum/maximum capacity and nonliteral room for
CR/NUL/invalid-UTF-8 flags. These necessary checks do not authenticate native
text. The line remains ASCII, one LF and at most 2048 bytes including prefix;
over-limit output is refused without truncation or v1 fallback. The diagnostic
route and facade retain their retirement or explicit re-justification condition
after the response issue and required protected status observation can complete.

For exit two with both original streams nonempty, a single context-invalid
literal cannot form an admissible advisory. Placement keeps predicate priority,
and the unchanged producer's specific wrong-context token is refused by the
existing formatter. Replacing that token with `other` is also refused, including
when the global sequence cap hides order but retains the recognized counts.
This consistency rule does not change native grammar or predicate selection.

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

The P0v noninteractive TLS status implementation slice implements the
ES-owned noninteractive read-only operator-healthcheck TLS status route:
`scripts/remote_alpha_operator.sh recovery-session
operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format
json`. The design lives at
`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`.
P0v is a route-contract design extension over the P0u operator-healthcheck TLS
status surface, not renewal, not a signing-topology decision, not a profile
mutation path, and not a Maintenance Agent scheduling change. The
implementation is validated only through local/static/fake tests in this
tranche; no live SSH, sudo, remote OpenSSL, Vault, reset/unseal, workload-auth
bootstrap/check, runtime identity summary, Infrastructure Manager refresh,
support-bundle collection, CP proof, SPIRE/Nomad mutation, service deployment,
ES submit, Docker/Nomad jobs, certificate mutation, profile mutation,
env/state mutation, proof generation, or network-dependent integration test is
part of this slice.

P0v chooses a new route id instead of adding a mode flag to the current
interactive `operator-healthcheck-tls-status` route. The existing route remains
the foreground operator route with required `--interactive-tty`, local
stdin/stdout TTY preflight, `ssh -tt`, visible sudo/password prompt behavior,
fixed helper-pair staging, and remote summary retention. The implemented
noninteractive route requires no local stdin/stdout TTY, allocates no
pseudo-TTY, uses no-prompt SSH semantics, uses no prompt-capable sudo, fails
closed when noninteractive auth is not ready, avoids password storage/replay,
avoids remote helper staging, avoids remote summary mutation, and emits only
bounded JSON evidence.

No fallback emitters are allowed for P0v. ES machine-readable route JSON is
promised only after declared route prerequisites pass. Missing local
runtime/validator dependencies are caller/integration preflight failures, not
ES route-output obligations. The Bash facade parses/refuses route arguments,
performs contact-free prerequisite checks, constructs no JSON, performs no SSH
itself for P0v, and execs one dedicated checked-in local Python runtime. That
internal runtime source is not a supported executable command; the Bash facade
is the supported public entrypoint and invokes it through a resolved absolute
Python 3 executable with `-I -S -B`. That local runtime owns SSH construction,
bounded subprocess handling,
transport-versus-remote-protocol classification, final route-schema emission,
final schema validation, and redaction. The fixed checked-in remote Python
collector is streamed over SSH stdin, is not copied or retained on the remote
host, writes no remote file or summary, and emits only an internal protocol
document. Recognized local, transport, protocol, remote-status, and TLS
outcomes use one typed outcome path, one canonical builder, one explicit final
validator, and one emitter. Final-emitter invariant failures emit fixed stderr
and no route JSON because no fallback document is permitted. P0v v1 emits
`provenance.source_revision=null` and does not execute Git at runtime. There is
no shell fallback JSON assembly.

`Bounded slice rule` P0v descendant containment refinement: the remote
collector's process-group signals reach only a descendant that stays in the
fixed child's group, and only while the fixed child itself still runs at a
timeout, overflow, or error. A descendant that outlives a normal completion,
holds the output after the fixed child ended, or leaves the group was reached
by nothing. The remote collector therefore makes itself a child subreaper
before any status input is read, proves by a descendant capability probe that
an orphaned grandchild becomes its child and is killed and reaped until
`waitid` reports no child, and after every fixed command kills and reaps its
own children until the kernel reports none, within a two-second descendant
drain bound. An unproved drain is a runtime failure of that command, mapped
to the existing `remote_status_unavailable`, and refuses every later fixed
command of the invocation before its spawn; a failed probe emits the existing
`remote_status_unavailable` document before any fixed command. The decision is
by behavior, never by an OS label. Between its fork and its exec the fixed
child asks for `prctl(PR_SET_PDEATHSIG)`, proves that the collector is still
its parent, and sets its own `RLIMIT_NPROC` to `(0, 0)`, so that an
unprivileged fixed child can start no process or thread and dies with a
killed collector unless its program undoes that request itself. Stated
limits: root is not bound by that limit, and the exec of `sudo` clears the
parent-death request, so the root command of the fixed `sudo -n` path, and
every command when the SSH target is root, depend on the drain alone; a
changed binary can undo its own parent-death request and then outlives a
killed collector, as one process that the process limit still keeps from
starting any other; an unprivileged collector detects but cannot end a root
descendant of the fixed `sudo -n` path; descendants that only wait, such as a
long chain or a herd with a long children list, can outlast the drain's
bounded per-process kills, which then report a runtime failure and clear the
flag; and no root-side runner is added, because it would need a host sudo
grant for a general process launcher. The route schema, failure vocabulary, internal
protocol, sudo allowlist, and privilege posture do not change.

P0v's implemented status schema is
`execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`.
It carries route id/version/current status, generated time,
live-contact-attempted status, status availability, bounded failure class,
numeric transport/helper exit codes when safe, public certificate metadata,
safe identity labels, safe trust chain labels/digests, bounded public
key-pair-match evidence, redaction flags, non-authority labels,
owning-repo contract labels, and profile-lineage hints only. It must not carry
raw stdout, raw stderr, helper or SSH transcripts, full certificate PEM bodies,
private-key PEM bodies, env values, endpoint secrets, remote paths, raw logs,
TLS/SPIFFE/Vault material, connector/workspace/org IDs, raw payloads, support
bundle contents, retained bundle contents, or unsafe local paths.

P0v status evidence remains evidence/projection only. CP consumes nothing in
this tranche and may later consume it as diagnostic evidence only after a CP
docs/tests tranche; IM consumes nothing in this tranche and may later consume
it for readiness/profile/provenance only after an IM docs/tests tranche; MA
consumes, invokes, and schedules nothing in this tranche. Route metadata now
records `supports_noninteractive=true`, `requires_interactive_tty=false`, and
`current_status=implemented`, while `scheduled_execution_allowed=false`
remains the current ES status until a later separately audited ES/MA route
eligibility decision changes it. `operator-healthcheck-tls-renew` remains
blocked/status-only with `unsupported_signing_topology`.

Bridge/MA/CP/IM consumers must not wrap missing ES prerequisites into ES status
truth. Bridge may record only Bridge-owned ChatGPT/Codex coordination preflight
evidence when ES prerequisites are not declared or the route is not invoked.
CP diagnose rerun and IM profile-lineage refresh remain future owning-repo
tranches; P0v does not renew, mutate cert/profile/key/trust/env/state, run live
proof, or widen any cross-repo authority boundary.
