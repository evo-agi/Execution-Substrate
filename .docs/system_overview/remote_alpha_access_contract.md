# Remote Alpha Access Contract v1

## 1. Authority, scope, and status

This document freezes an ES-owned Remote Alpha access contract at the
documentation and repository-contract-test level. Tranche A does not implement
a profile validator, access-status emitter, live route, local profile store,
host provisioning, scheduled check, or restoration step. The schemas below
are target contracts, not outputs currently emitted by ES.

Authority follows the repository order:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, and boundaries
4. `.docs/execution_lifecycle/*` for lifecycle guidance
5. current Go code and tests for factual implemented behavior

`Reopened redesign seam`: `PLANS.md` opens the absent ES access-profile and
access-status surface for this contract-only decision. Tranche A fixes the v1
schema envelope, field ownership, role separation, fail-closed safety intent,
fixed identity-check boundary, status state matrix, redaction, non-authority,
and scheduling prohibition. The exact static SSH parser and filesystem
acceptance boundary are reopened Tranche B implementation-contract decisions;
implementation, host acceptance, and later scheduled eligibility are separate
decisions. No existing route is re-derived by this contract.

`Current invariant`: ES owns its Remote Alpha route and transport semantics;
Infrastructure Manager (IM) currently owns host profile, readiness,
provenance, and diagnostics; Maintenance Agent (MA) does not define ES route
meaning or own credentials. Access evidence is a bounded projection and
cannot become ES runtime, IM readiness, or governed-execution authority.

`Bounded slice rule`: committed P0t
`recovery-session es-governance-tls-status` and
`recovery-session es-governance-tls-renew` use the fixed ES service TLS
helper pair and the fixed `execution-governance` scope. They require
`--ssh-target` and `--interactive-tty`, stage the pair, use a remote
`ssh -tt` session, and may request remote sudo. P0t status avoids
certificate/service mutation but staging, cleanup, and an optional remote
summary are filesystem effects. P0t is not a write-free access check.
Committed P0v `operator-healthcheck-tls-status-noninteractive` is a
TLS-specific bounded status route; its `ssh -F /dev/null` construction does
not use the operator's confirmed alias configuration. Its
`scheduled_execution_allowed=false` constraint remains intact. Neither
P0t nor P0v supplies this access contract or is generalized by it.

`Temporary compatibility edge`: the operator-owned
`host_to_remote_linux_m75q` alias and existing `--ssh-target` operator
route arguments stay unchanged until a separate documented migration.
This contract neither renames the alias nor rewrites those routes.

User/Codex-reported foreground BatchMode and strict-host-key sessions reached
a nonroot account through that alias. The inspected user-config block had one
explicit IdentityFile and `IdentitiesOnly=yes`. Those observations do not
prove the actual signer, agent or Keychain participation, certificate use,
effective system SSH config, known-hosts source, post-logout availability,
service health, or TLS state. They are evidence, not repository contract.

## 2. Versioned profile and ownership

The exact local input schema is `es.remote-alpha.access-profile/v1`.
One operator-owned local store may contain separately selected profiles:

| Field | v1 meaning |
| --- | --- |
| `schema` | Exact profile schema name above. |
| `profile_id` | Opaque, non-secret, stable selector; never a path, endpoint, or credential. |
| `role` | Exactly `operator` or `monitor`. |
| `ssh_config_ref` | Absolute reference to operator-owned SSH configuration in a bounded local user-owned area. |
| `ssh_alias` | Exact alias selected inside that configuration, with one unambiguous effective binding. |
| `expected_account` | Exact expected nonroot remote account label. |
| `expected_uid` | Expected nonzero effective remote UID. |
| `host_identity_label` | Opaque logical identity binding for the intended host, distinct from endpoint resolution. |
| `configuration_generation` | Operator-assigned, non-sensitive change label for one intended local profile generation; it is not a digest or proof of local file state. |
| `scheduled_use_policy` | Declared intent only; it cannot override the producer-owned v1 scheduling prohibition. |
| `known_hosts_ref` | Absolute operator-owned known-hosts reference; a dedicated reference is required for `monitor`. |

The suggested default store
`~/.config/execution-substrate/remote-alpha/access-profiles.v1.json` is an
implementation detail, not an immutable public protocol. The store and
referenced private configuration must be owner-controlled; the planned
validator requires regular file type, owner, restrictive mode, path
confinement, and safe symlink posture. The exact supported local areas and
mode checks must be fixed and fake-tested in Tranche B before any file is
accepted. A profile can refer to one identity through its bounded SSH
configuration; it carries no key bytes or key digest.

`configuration_generation` has type string and length 1 through 64 ASCII
characters. Its lexical grammar is `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`:
ASCII letters, digits, period, underscore, and hyphen only, beginning with an
alphanumeric character. It contains no whitespace, path separator, or shell
metacharacter. It must not contain endpoint material, usernames, filenames,
or credential material, and must not be derived from or equal to a private-key
digest, host-key digest, endpoint, raw path, configuration content, or any
other secret-bearing value. It is not signer identity, key identity, host
identity, or freshness evidence. A future validator must reject an invalid or
unprovably non-sensitive label as `profile_invalid` before emitting status
evidence; it must never echo the rejected value. Lexical checks alone do not
prove non-derivation, so Tranche B must document and fake-test a safe
acceptance rule or fail closed.

Local endpoint, identity, known-hosts, signer, and credential details remain
operator-owned state. Private endpoint values, private-key material, host-key
material, credentials, and secret values are never repository content. The
existing operator alias remains a compatibility input, not an assertion that
its current config already passes the future validator.

An independent `monitor` alias/profile and distinct, minimally capable
nonroot identity are introduced only after scheduled remote checks are
approved and provisioned. Key generation, host-key pinning, remote
`authorized_keys` restrictions, and account/forced-command provisioning are
future sensitive effects. No profile ID itself grants SSH or sudo authority.

## 3. Contact-free static validation target

The future validator accepts only a supported static SSH configuration
subset. It does not run `ssh -G`, contact a host, execute `Match exec`, query
an agent or Keychain, or treat a platform name as proof of a capability. At
the local validation boundary it must:

1. validate exact schema/version, role, field types, nonempty opaque labels,
   expected nonroot account, and expected nonzero UID;
2. validate owner, regular-file type, restrictive mode, path confinement, and
   symlink posture for the profile store and every referenced configuration,
   identity, and known-hosts resource it is allowed to inspect;
3. resolve only a bounded, safe Include closure and prove one exact,
   unambiguous alias binding and one unambiguous identity selection;
4. prove the selected user and a deterministic existing-host-key binding,
   including a dedicated known-hosts reference for monitor use;
5. prove the required no-prompt, public-key-only, strict-host-key,
   no-host-key-update, no-forwarding, no-multiplexing, and no-TTY policy;
6. fail explicitly when any required effective value cannot be proven
   within the supported static subset.

Ambiguous or wildcard alias matches affecting the selected profile,
unresolved/unsafe Includes, `Match exec`, `ProxyCommand`,
`LocalCommand`, `KnownHostsCommand`, unreviewed `ProxyJump` or
equivalent paths, executable/dynamic config, forwarding, ambient monitor-agent
dependence, and implicit SSH-certificate lifecycle must ultimately fail
closed. No alternate endpoint, identity, account, config parser, host-key
source, or weaker verification path is tried. Tranche A freezes these rejection
categories and safety obligations, not an exact parser boundary.

`Reopened redesign seam`: the exact supported OpenSSH directive grammar;
Include closure, ordering, and precedence; effective interaction with system
SSH configuration; accepted operator-local filesystem roots; exact file and
directory modes; component-by-component symlink policy; Apple Keychain,
agent, certificate, and platform-specific interpretation; and exact handling
of otherwise safe optional SSH directives are reopened Tranche B
implementation-contract decisions. Tranche B must freeze each decision in
governing documentation and fake/static contract tests before implementing a
validator. Until that freeze and implementation exist, no repository behavior
may claim that a local profile conforms to the full v1 static subset. The
present operator alias remains a compatibility edge and is not silently
declared v1-conformant. No live route, validator, profile store, or scheduled
monitor is delivered by this tranche.

Tranche B's runtime must force safety options that local configuration cannot
weaken: `BatchMode=yes`, `StrictHostKeyChecking=yes`,
`UpdateHostKeys=no`, public-key-only authentication, disabled password and
keyboard-interactive fallback, `IdentitiesOnly=yes`, no agent/X11/local/
remote/dynamic forwarding, no local command, no ControlMaster multiplexing,
and `-T` without an interactive shell. These are required semantics, not
permission to run the live route in Tranche A. Runtime capability validation
must follow `.docs/system_overview/capability_probing.md`: prove by behavior
or static resource checks at validation boundaries, fail fast, and do not
branch on OS labels or silently fall back.

Contact-free validation does **not** prove live authentication, the physical
machine behind an endpoint, SSH signer identity or custody, agent/Keychain
availability after logout or reboot, host reachability, service health, TLS
validity, sudo readiness, installed-state correctness, or governed execution.

## 4. Fixed live-check target and compatibility

A future public ES check-only route selects one validated profile with
`--access-profile <profile_id>`. It accepts no arbitrary `--ssh-config`
escape hatch, remote command, SSH option, endpoint, identity override, helper
path, or output path. Its sole remote observations are fixed effective UID and
account checks. It must reject UID zero, require the expected nonroot UID and
account, use no sudo, TTY, remote write, service operation, TLS probe, or
renewal, and retain no raw SSH stdout/stderr. A remote failure ends the
check without fallback.

Current `--ssh-target` routes keep their existing bounded behavior as a
temporary compatibility edge. A later migration must document each route's
removal or versioning condition before it changes. The new access-status
route does not depend on P0t or P0v implementation or TLS semantics.

## 5. Access-status evidence contract

The exact evidence schema is `es.remote-alpha.access-status/v1`.
Top-level `outcome` is exactly `ready`, `unavailable`, or `unknown`.
`unavailable` means a reviewed, bounded signal proved a specific blocking
condition in the required validation or fixed check. `unknown` means access
readiness cannot be established and no permitted, proven unavailable cause
applies. A specific reason requires its row's bounded evidence; raw SSH
diagnostics alone never establish a precise reason. The `reason` field is
always present: its exact JSON value is `null` for `ready`, and a string from
the complete matrix below for every non-ready state.

### Normative state matrix

The rows below are the complete permitted source, outcome, and reason
relationships. `producer` rows describe status emitted by ES. `consumer`
rows describe an effective interpretation of otherwise valid evidence; they
do not mutate the producer document or introduce a third `evidence_source`
value. In consumer rows, `local_validation or live_check` means the preserved
originating field is one of those two exact values. Each row's explicit
non-claim applies even when its required evidence is present.

| Evaluation | Evidence source | Outcome | Reason | Required evidence | Explicit non-claim |
| --- | --- | --- | --- | --- | --- |
| producer | `local_validation` | `unavailable` | `profile_invalid` | A bounded schema, field, or local-resource validation failure with a safe generation label. | No live access was checked. |
| producer | `local_validation` | `unavailable` | `unsupported_dynamic_config` | A bounded finding of unsupported, executable, dynamic, or ambiguous configuration. | No alternate parser or fallback is authorized. |
| producer | `local_validation` | `unknown` | `live_check_not_performed` | Contact-free validation passed for the selected profile and generation; no remote check ran. | Local validation is not live readiness. |
| producer | `local_validation` | `unknown` | `configuration_changed` | Before/after observation found a change in the selected profile or supported local resource closure. | No ready evidence may be emitted. |
| producer | `local_validation` | `unknown` | `unclassified` | Validation could not prove a more specific permitted reason. | No precise cause is asserted. |
| producer | `live_check` | `ready` | `null` | Static validation passed for the same profile and generation; strict existing-host-key verification succeeded; the fixed remote account and effective UID matched the expected nonroot values; UID was nonzero; evidence is fresh; no configuration change was observed. | Ready does not permit scheduling, sudo, service readiness, TLS correctness, or governed execution. |
| producer | `live_check` | `unavailable` | `host_identity_unverified` | A bounded existing-host-key verification failure. | No physical host identity is proved. |
| producer | `live_check` | `unavailable` | `authentication_unavailable` | A bounded public-key authentication failure. | No signer identity or custody is inferred. |
| producer | `live_check` | `unavailable` | `transport_unavailable` | A bounded transport failure. | No service or TLS state is inferred. |
| producer | `live_check` | `unavailable` | `remote_identity_mismatch` | The fixed observation returned a nonzero UID or account that differs from the expected nonroot values. | No arbitrary remote-shell authority is granted. |
| producer | `live_check` | `unavailable` | `root_login_blocked` | The fixed observation returned effective UID 0; the check stopped immediately. | Root login is neither authorized nor normalized. |
| producer | `live_check` | `unavailable` | `check_failed` | A bounded failure of the fixed UID/account check after transport and authentication. | No repair or retry fallback is authorized. |
| producer | `live_check` | `unknown` | `configuration_changed` | Before/after observation found a change in the selected profile or supported local resource closure. | No ready evidence may be emitted. |
| producer | `live_check` | `unknown` | `unclassified` | No bounded signal proves a more specific permitted reason. | Raw SSH diagnostics do not establish a precise cause. |
| consumer | `local_validation or live_check` | `unknown` | `stale_evidence` | Evidence age exceeds the versioned freshness window. | A prior ready result is not preserved. |
| consumer | `local_validation or live_check` | `unknown` | `configuration_changed` | The profile ID or generation differs from the current selected profile. | A prior ready result is not preserved. |

The profile requires a nonroot account, yet endpoint, account, server, or
configuration drift can make the fixed server-side observation return UID 0.
That observation must stop the check and use `unavailable /
root_login_blocked`; it does not authorize or normalize root login. A
`local_validation` producer must never emit `ready`: a successful static
validation yields `unknown / live_check_not_performed` and only makes the
profile eligible for a separately authorized live check. A `live_check`
producer may emit `ready` only with every condition in its matrix row. A
missing or unproved condition fails closed to a permitted non-ready row.

One validation or live check is bound to one profile ID and one
`configuration_generation`. The future producer must establish a before/after
consistency observation for that profile and every local resource in the
supported Tranche B closure. The exact safe consistency mechanism is a
reopened Tranche B implementation-contract decision. If a relevant resource
changes during the observation, the producer must emit `unknown /
configuration_changed`, never `ready`. Neither a sensitive digest, raw path,
key identity, nor host-key value may enter status evidence. An invalid or
unprovably non-sensitive generation label is rejected before status emission;
the raw candidate value must not be echoed into a `profile_invalid` result.

Required safe fields are schema name/version; implementation/source revision
(nullable when not established); `profile_id`; `role`;
`configuration_generation`; UTC observation time; `evidence_source` exactly
`local_validation` or `live_check`; bounded numeric command status or null
when no command ran; freshness window or computed age; outcome and reason;
`scheduled_execution_allowed=false`; and explicit non-authority labels.
The future implementation may include only bounded parsed UID/account values
after validation. A generation label is not proof that local files stayed
unchanged, and a recent timestamp is not independent proof of readiness.
Before any producer or consumer can treat evidence as fresh, the route's
positive freshness window must be fixed in a versioned contract and enforced;
the exact duration remains a Tranche B implementation-contract decision.
Absent or invalid freshness information never preserves `ready`.

Evidence is applicable only to the same profile ID and generation. A
consumer first checks that binding: a mismatch produces effective `unknown /
configuration_changed`. It then checks the versioned freshness window:
expiry produces effective `unknown / stale_evidence`. If both apply,
`configuration_changed` takes precedence. Neither the generation label nor a
recent timestamp can independently preserve `ready`. A consumer may not
promote `local_validation` evidence to `ready`.

The evidence has no authority to establish SSH signer identity/custody,
application or service readiness, TLS correctness, sudo readiness,
installed-state correctness, ES execution readiness, governed execution,
incident acceptance, or repair authority. It is not permission to start,
restart, renew, reconcile, or provision anything.

Safe output must never include an endpoint, resolved IP or hostname, identity
path/content/digest, host-key value/fingerprint, agent identity, raw SSH
stdout/stderr, raw SSH config, credential, or command transcript containing
sensitive values. Diagnostic parsing must not leak those values through
errors, logs, summaries, reports, tests, or MA/IM handoff.

### V1 scheduling gate

`scheduled_execution_allowed=false` is a producer-owned constant in every v1
status, including `ready`. It is not supplied or overridden by the local
profile, inferred from `ready`, enabled by MA configuration or IM readiness,
or enabled by successful foreground SSH or the current operator alias. The
local `scheduled_use_policy` value cannot turn it on. Changing eligibility
requires a separately documented ES route-eligibility decision, MA
consumer/scheduler decision, scheduled-context acceptance in login, logout,
reboot, and agent-unavailable contexts, a versioned contract change, and
separate implementation, host provisioning, validation, and audit. Until
then MA may summarize existing safe evidence locally, but may not schedule
this unimplemented check. `ready` never implies scheduled execution permission.

## 6. Service and privilege boundaries

ES owns the future access validator, SSH transport construction, fixed check,
and versioned safe access evidence. MA may later consume and notify over that
evidence, but owns no SSH credential generation/custody, raw SSH diagnostic
interpretation, arbitrary remote shell, sudo password, or ES route semantics.
IM currently owns Remote Alpha profile, doctor, readiness, provenance, and
diagnostic outputs. Its direct SSH access interpretation is a migration
compatibility edge: an IM-owning tranche must consume or migrate to the ES
evidence, preserve IM's current ownership, and correct source/freshness
provenance before retiring any direct SSH path. Tranche A edits neither repo.

Public-key SSH does not solve sudo authentication. Current P0t status/renew
routes retain operator-interactive sudo when needed. Future noninteractive
privileged status would require a separately reviewed exact NOPASSWD rule
for fixed root-owned code or a root-owned systemd operation producing a
sanitized status projection. Neither is authorized by access-status v1.
Reject `NOPASSWD: ALL`, passwordless sudo for a staged or user-writable
helper, unattended arbitrary shell, MA custody/replay of a sudo password,
and widening fixed status into renewal or repair authority.

## 7. Future work and restoration boundary

Tranche B must first freeze the reopened static grammar, filesystem,
platform-interpretation, consistency, and freshness-window decisions in
governing documentation and fake/static contract tests; it may then
implement and fake-test the contact-free validator and fixed check-only
route. Tranche C may provision operator-owned profile state,
dedicated monitor material, and host restrictions under separate
sensitive-effect authority. Tranche D is an MA-owned evidence/scheduling and
notification decision; Tranche E is an IM-owned compatibility migration.
None is implemented here, and cross-repository consumers receive no new
current execution permission from this document.

The contained ES-to-EGS certificate-validity failure remains a separate
restoration problem. Access-status evidence does not inspect its TLS topology,
repair certificates, complete P0t role inventory, restart ES, or prove
governed execution. P0t inventory and any later renewal need their own
authorization, privilege path, evidence, and audit.
