# Runtime Identity Handoff Ownership Decision

## 1. Purpose and scope

This document records the docs/tests-only F0 Workstream F runtime-identity
handoff ownership decision.

F0 documents the current ownership model before any behavior-changing
Workstream F implementation. It does not change runtime behavior, public DTOs,
route handlers, wire shapes, ES admission behavior, runtime-config behavior,
SPIRE/Vault handoff implementation, runtime helper behavior, Nomad/Docker
placement behavior, Control Plane compatibility, Infrastructure Manager
inputs, or support-bundle input shapes.

Workstream F continues only once this document matches current code and tests
on implemented behavior.

## 2. Decision summary

- Runtime identity handoff is currently ES-selected and platform-delivered.
- ES owns handoff selection, environment injection, reserved path layout,
  mounts, and Nomad job construction for the current slice.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery
  contract.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` is not raw SPIRE socket exposure, not Vault
  token brokerage, not runtime-config authority, and not a secret payload.
- The runtime supervisor/helper owns the in-task endpoint implementation,
  helper-private SPIRE traversal, readiness-before-workload, and the
  root-to-workload privilege boundary for the current implementation.
- SPIRE owns JWT-SVID issuance.
- Vault owns token, secret, and lease issuance after workload-side login.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces
  are bounded or compatibility-heavy. They are not final generalized
  architecture.
- Capability validation remains behavior-based and local to validation
  boundaries, not based on accidental DTO or path coupling.
- Workload-visible discovery is explicit while implementation remains
  platform-owned.
- F0 does not change runtime-config ownership from E0/E1, consume or promote
  D seams, or widen CP, IM, support-bundle, report, trace, retained-bundle,
  profile, log, or `.out` authority.
- F0 preserves ES public execution DTOs, `GET /v1/executions:contract`,
  `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP
  compatibility, and M6 support-bundle inputs.
- F0 does not claim full ES/runtime de-root, rootless Nomad client, production
  readiness, production Vault readiness, or generalized remote deployment
  architecture.
- F0 does not reopen Workstream A, Workstream B, or Workstream C. It does not
  mark full Workstream D complete, does not mark full Workstream E complete,
  and does not mark full Workstream F complete.

## 3. Surface classes used here

| Class | Meaning for F0 |
| --- | --- |
| `Current invariant` | Active ownership or behavior that current code and docs rely on and that must not change silently. |
| `Bounded slice rule` | Active behavior that is real today but intentionally narrow and not automatically long-term architecture. |
| `Temporary compatibility edge` | Active shape retained for continuity and explicitly not preserved by inertia. |
| `Compatibility/config residue` | Current config or helper placement retained from earlier forms; it must not become the final owner by accident. |
| `Non-authority evidence/projection` | Readable evidence, report, trace, profile, bundle, or handoff data that may describe facts but cannot own runtime identity or credentials. |
| `Security-sensitive secret-bearing surface` | Runtime material that can carry JWT-SVIDs, Vault tokens, secrets, leases, or credential payloads and must not leak into evidence or authority docs. |
| `Reopened redesign seam` | Active architecture-defining ownership that `PLANS.md` keeps open for re-derivation. |
| `Workstream F stop line` | Runtime identity, helper, SPIRE, Vault, task-user, or reserved-path behavior F0 must document without changing. |

## 4. Classified current runtime-identity surfaces

| Surface | Class | Current rule |
| --- | --- | --- |
| Runtime identity handoff overall | `Current invariant`, `Bounded slice rule` | The current handoff is ES-selected and platform-delivered. ES chooses and injects the workload-visible discovery endpoint; the platform helper implements the endpoint in the task. |
| ES handoff selection, env injection, reserved path layout, mounts, and Nomad job construction | `Current invariant`, `Bounded slice rule` | ES owns these current submit-time handoff mechanics for the bounded slice. This does not make current path names final architecture. |
| `EXEC_WORKLOAD_IDENTITY_ENDPOINT` | `Current invariant`, `Bounded slice rule` | The env var is the current bounded workload-visible discovery contract. It names the platform-owned endpoint URI. |
| Raw SPIRE Workload API socket | `Security-sensitive secret-bearing surface`, `Temporary compatibility edge` | Raw SPIRE access is helper-private and must not be exposed to workload env, workload mounts, workload-authored code, `authority_handoff`, logs, reports, support bundles, or `.out` artifacts. |
| Runtime supervisor/helper endpoint implementation | `Bounded slice rule`, `Implementation detail`, `Workstream F stop line` | The supervisor/helper owns in-task endpoint serving, helper-private SPIRE traversal, readiness-before-workload, helper death task-fatal behavior, and root-to-workload boundary enforcement today. |
| Helper start as `0:0`, Nomad task `User: "0:0"`, fixed workload `10000:10000`, no supplemental groups | `Temporary compatibility edge`, `Bounded slice rule` | These are current compatibility-heavy runtime boundaries needed by the landed slice. They are not a claim of rootless helper startup, rootless Nomad client, arbitrary image-user execution, or final runtime de-root. |
| `/run/es-runtime-identity/<run_id>/endpoint` and helper-private `internal/spire-agent.sock` | `Temporary compatibility edge`, `Reopened redesign seam` | Current reserved path conventions are active and protected, but the path layout remains reopened. |
| `/execution/staged`, `/execution/run`, `/execution/run/result`, `/execution/run/platform`, and `/execution/run/work` | `Temporary compatibility edge`, `Reopened redesign seam` | Current runtime package and reserved-path conventions are active today and must be intentionally retained or replaced later. |
| SPIRE JWT-SVID issuance | `Current invariant`, `Security-sensitive secret-bearing surface` | SPIRE owns JWT-SVID issuance. ES does not mint, sign, broker, validate, store, or expose JWT-SVID payloads. |
| Vault token, secret, and lease issuance | `Current invariant`, `Security-sensitive secret-bearing surface` | Vault owns token, secret, and lease issuance after workload-side login. ES does not broker or store those materials. |
| Workload-side Vault login and secret read | `Bounded slice rule`, `Security-sensitive secret-bearing surface` | The workload is the Vault client in the current useful credential flow. ES provides only non-secret metadata and CA trust material needed for standard TLS verification. |
| Workload-zone Vault CA trust files and TLS env | `Bounded slice rule` | Non-secret TLS trust material may be staged for workload-side verification. It is not credential truth, token truth, runtime-config authority, or relaxed verification. |
| Runtime-config refs, digest-only refs, and `workload_vault_auth.default_mode` | `Compatibility/config residue`, `Workstream F stop line` | These remain Workstream E surfaces and current ES config residue. F0 does not turn them into runtime-identity or credential authority. |
| `authority_handoff` and `authority_handoff.runtime_config_refs` | `Non-authority evidence/projection` | These are bounded non-secret handoff evidence only. They are not live credential truth, runtime-config authority, or proof that the workload obtained a JWT-SVID, Vault token, secret, or lease. |
| `outcome_evidence`, retained bundles, support bundles, reports, traces, logs, profiles, and `.out` artifacts | `Non-authority evidence/projection` | These surfaces may record bounded observations or proof evidence. They do not own runtime identity or credential semantics. |
| Capability-sensitive validation | `Current invariant` | Validation must remain behavior-based and local to validation boundaries, following `capability_probing.md`. No OS-label branching or hidden fallback behavior should be introduced. |

## 5. Ownership and non-ownership

**Current ownership**

- ES owns the current submit-time handoff selection, environment injection,
  reserved path layout, runtime mount assembly, and Nomad job construction.
- The runtime supervisor/helper owns the in-task endpoint implementation,
  helper-private SPIRE traversal, helper readiness before workload start,
  helper death handling, and the current root-to-workload privilege boundary.
- SPIRE owns JWT-SVID issuance.
- Vault owns Vault token, secret, and lease issuance after workload-side login.
- The workload owns use of the discovered endpoint and workload-vault metadata
  as a client inside the container.

**Explicit non-ownership**

- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` does not expose the raw SPIRE Workload API
  socket and does not make ES a Vault token broker.
- Runtime-config refs, digest-only runtime-config refs,
  `authority_handoff.runtime_config_refs`, ARS blob storage/read mechanics,
  `workload_vault_auth.default_mode`, E0/E1 runtime-config docs, and E1
  startup-guarantee tests do not own runtime identity or credentials.
- CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS `publication.version`,
  EGS unsigned publication metadata, and AGS `policy_decisions` do not own
  runtime identity or credentials.
- ES retained bundles, `outcome_evidence`, `authority_handoff`, IM profiles,
  support bundles, logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state are evidence/projection only.

## 6. Required D exclusions

None of the following are runtime-identity or credential authority:

- CGS authorize output
- `id.conf`
- `policy.id_conf_path`
- `audit.policy_version`
- CGS v1/v2 design docs
- EGS `publication.version`
- EGS unsigned publication metadata
- AGS `policy_decisions`

These exclusions preserve the accepted D0-D1d guardrails. They do not mark full
Workstream D complete and do not close the remaining D seams.

## 7. Required E exclusions

None of the following are runtime-identity or credential authority:

- runtime-config refs
- `authority_handoff.runtime_config_refs`
- ARS blob storage/read mechanics
- digest-only runtime-config refs
- `workload_vault_auth.default_mode`
- runtime-config ownership docs/tests
- E0/E1 startup-guarantee tests

These exclusions preserve the accepted E0/E1 guardrails. They do not mark full
Workstream E complete and do not close the remaining E seams.

## 8. Required evidence exclusions

None of the following are runtime-identity or credential authority:

- ES retained bundles
- `outcome_evidence`
- `authority_handoff`
- IM profiles
- support bundles
- logs
- traces
- reports
- `.out` artifacts
- CP review/approval/checkpoint/finalization state

These surfaces may be useful evidence, diagnostics, compatibility projections,
or proof outputs. They must remain non-authoritative and non-secret.

## 9. Workstream F stop lines

F0 must stop and report instead of widening into behavior change if a change
would touch:

- public DTOs, route handlers, or wire shapes
- `GET /v1/executions:contract`
- `POST /v1/executions:prepare`
- submit, status, log, result, or cancel behavior
- runtime-config schema/source files or ownership
- ARS blob APIs
- CGS or EGS behavior
- `id.conf` grammar or policy evaluation
- ES-to-CGS dependency
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` behavior
- SPIRE/Vault handoff implementation
- reserved runtime paths
- runtime helper behavior
- Nomad task user, workload UID/GID, Vault JWT login, token, secret, or lease
  semantics
- M6 support-bundle inputs or IM-facing evidence shapes
- Control Plane or Infrastructure Manager repositories

F0 does not decide whether the current runtime-identity delivery model is
final. It records the current ownership split so later Workstream F slices can
change it honestly.

## 10. Remaining Workstream F seams

F0 intentionally leaves these Workstream F seams open for F1/F2:

- whether the long-term workload-visible discovery contract remains
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- whether the current run-scoped `/run/es-runtime-identity/...` path layout
  survives, changes, or receives explicit versioning
- whether the runtime helper remains same-container or moves to another
  platform-owned companion shape
- whether helper startup can be narrowed from root while preserving
  helper-private SPIRE traversal and fixed non-root workload launch semantics
- whether Nomad task `User: "0:0"` can be replaced without weakening the
  current helper/workload boundary
- how SPIRE selector posture and helper principal narrowing are re-proved
- how future Vault posture hardening preserves workload-side login and the
  no-ES-token-brokerage rule
- how any replacement preserves ES public execution DTOs,
  `GET /v1/executions:contract`, `POST /v1/executions:prepare`,
  `control-plane-normal-shell/v1`, CP compatibility, and M6 support-bundle
  input shapes

The next behavior-changing Workstream F slice must update `PLANS.md` and the
authoritative `.docs/` pages before changing runtime source files.

Section 11 records that slice, F1. It settles the SPIRE selector posture, the
Vault posture of workload identities, and the layout of workload SPIFFE IDs
under `workload/`. The other seams in this section stay open.

## 11. F1 decision: named workload identities and workload grants

F1 is the next behavior-changing Workstream F slice. The project owner
approved its design; the pull requests in section 11.10 implement it. Until
the pull request that lands a part merges, sections 1 to 10 and the other
`.docs/` pages describe current behavior for that part, and this section is
the target it implements. Each of those pull requests moves the matching
current-behavior text to the new rule in the same change.

### 11.1 What F1 changes and why

Today:

- every workload run receives the same SPIFFE ID,
  `spiffe://execution.internal/workload`, and logs in to Vault with one
  shared role, so any workload can read any other workload's secrets;
- the SPIRE registration for that ID matches any root process on the host
  (`unix:uid:0` plus `unix:gid:0`), inside a container or not;
- the publisher's signed `network_access` alone decides whether a run gets a
  network.

F1 replaces this with:

- one identity per named workload, such as `codex-agent`, each with its own
  SPIRE registration, Vault role and Vault policy;
- names assigned by owner grant rules in ES deployment configuration, not
  requested by publishers;
- network access that needs both the publisher's signed request and an owner
  grant.

### 11.2 Names and the SPIFFE ID layout

- A workload identity name is a single SPIFFE path segment of 1 to 63
  characters from `a-z`, `0-9` and `-`, starting with a letter or a digit.
- A named identity is `spiffe://execution.internal/workload/<name>`.
- `spiffe://execution.internal/workload/<name>/run/<run_id>` is reserved for
  per-run identities. F1 registers none. Every other path under `workload/`
  is reserved and unused.
- The shared ID `spiffe://execution.internal/workload` is retired when the
  identity part of F1 lands.
- Workload identities are never callers. The caller authentication contract
  refuses every caller whose path is `workload` or starts with `workload/`
  (`.docs/system_overview/contracts.md`, section 3A), for ARS, AGS, EGS, CGS
  and ES alike, including the reserved per-run paths. A later design that
  lets a workload call a service must change that rule explicitly.

### 11.3 Who picks the name

- ES admission picks the name from an owner grant rule in ES deployment
  configuration, `admission_policy.workload_grants`
  (`.docs/execution_lifecycle/contracts.md`, section 5B).
- A rule matches exactly on four facts: the publisher principal
  (`claims.package.publication.invoker.principal`, which AGS takes from its
  authenticated caller), the evidence signer key ID (`seal.key_id`), the
  artifact type, and the effective runtime profile name.
- Publishers do not request a name. F1 adds no identity claim to signed
  evidence: Workstream A removed `workload_identity_id` from the shared
  execution claims, and F1 keeps it removed.
- ES does not create SPIRE entries, Vault roles or Vault policies, and holds
  no SPIRE or Vault administrative access. It can pick only names the owner
  registered with the repository's setup scripts. ES startup refuses a grant
  that names an identity missing from the configured list.

### 11.4 Realization: one place translates names

- Admission produces scheduler-neutral results only: an identity name or
  none, and an egress lane name or none. Grant rules, policy decisions and
  the abstract parts of durable formats name only these.
- Runtime realization alone turns a name into the expected SPIFFE ID string,
  the container label `execution-substrate.workload-identity=<name>`, the
  Vault role `workload-<name>`, and the environment the helper and the
  workload receive. It is the only code that maps grants to Nomad or Docker
  terms.
- A guard test fails if grant or admission-policy code names Nomad, Docker or
  the container label.
- F1 adds no scheduler plug-in interface. Nomad remains the lifecycle
  authority, and the Docker driver remains the only driver.

### 11.5 Runs without an identity

- A run whose matching rule names no identity, or that matches no rule, gets
  no identity handoff: no runtime helper endpoint, no
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, no helper-private SPIRE socket mount, no
  runtime-identity tmpfs, and no workload-zone Vault environment. The
  supervisor still starts the workload as fixed `10000:10000`.
- A runtime profile that needs a credential, today
  `control-plane-normal-shell/v1`, is refused at admission with
  `403 workload_identity_not_granted` when no identity is granted.
- An identity is handed off only when the run's egress lane reaches the
  workload-zone Vault. ES startup refuses a rule that pairs an identity with a
  lane that does not.

### 11.6 The helper checks the identity it serves

- ES passes the runtime helper the expected SPIFFE ID string of the run.
- The helper refuses to serve the endpoint unless the JWT-SVID that SPIRE
  returns names exactly that ID. A mismatch is task-fatal before the workload
  starts.
- A per-run identity later changes only that string.

### 11.7 SPIRE and Vault posture

- The setup scripts register one SPIRE entry per configured name, with the
  selectors `docker:label:execution-substrate.workload-identity:<name>` and
  `unix:uid:0`. Only the root runtime helper inside a container that carries
  that label matches it: a root process outside any container, an unlabelled
  container, and the fixed `10000:10000` workload process do not.
- The broad entry that gives `spiffe://execution.internal/workload` to every
  root process is removed in the same change. Readiness refuses
  `submit-ready` while any `workload` entry uses only `unix` selectors, lacks
  the label selector, or names an identity that ES configuration does not
  list.
- The SPIRE agent enables the Docker workload attestor. That attestor reads
  container labels through the Docker API, which is root-equivalent access.
  How the agent gets that access, and how it is limited, is decided and
  red-teamed in the identity pull request.
- Each name gets a Vault JWT role and a Vault policy, both named
  `workload-<name>`, with `bound_subject` set to the name's exact SPIFFE ID
  and explicit `token_ttl`, `token_max_ttl` and `token_bound_cidrs`. The
  defaults are those of the current shared role: `15m`, `30m`, and the
  workload bridge subnet.
- A name's secrets live under `<name>/shared/` in the workload secret mount.
  `<name>/runs/` stays free for later per-run secrets.
- The workload-zone Vault runtime config moves to a version 2 blob without a
  single `auth_role`, because the role follows from the name. This is a
  Workstream E surface (`.docs/system_overview/runtime_config_ownership.md`)
  and changes only the field set, not its owner.

### 11.8 Adding per-run identities later

F1 keeps a path to per-run identities that adds pieces and removes no code:

- a small dedicated service, neither ES nor EGS, that creates a run's SPIRE
  entry before submit and lets it expire after, called from realization;
- a SPIRE access policy that limits that service to
  `workload/<name>/run/*` entries;
- replay-safe entry creation in reliable submit;
- for each name switched to per-run, a Vault role that binds the subject by
  glob (`bound_claims` with `bound_claims_type=glob`), and the retirement of
  that name's static entry with one setup-script command.

The ID layout of section 11.2, the realization seam of section 11.4, the
expected-ID string of section 11.6, the realized ID string in durable formats
(section 11.10, WI-5) and the `<name>/shared/` folder are what keep that path
open.

### 11.9 What F1 does not change

- `EXEC_WORKLOAD_IDENTITY_ENDPOINT` stays the workload-visible discovery
  contract, and the raw SPIRE socket stays helper-private.
- The helper still starts as `0:0`, the Nomad task user is still `0:0`, and
  the workload still runs as fixed `10000:10000` with no supplemental groups.
- SPIRE issues JWT-SVIDs and Vault issues tokens, secrets and leases. ES
  brokers none of them.
- The ES public execution request and response DTOs,
  `GET /v1/executions:contract`, `outcome_evidence`, CP compatibility, and M6
  support-bundle inputs keep their shapes. Admission gains two refusal reason
  codes, `network_access_not_granted` and `workload_identity_not_granted`, in
  the existing redacted error envelope.
- `authority_handoff` stays non-secret evidence. For a run with an identity
  it keeps every current field, `workload_vault.auth_role` names that name's
  `workload-<name>` role, and `identity_handoff` gains the non-secret fields
  `workload_identity` (the name) and `spiffe_id` (the expected ID string). For
  a run without an identity, `identity_handoff.mode` is `none`, and the fields
  that describe an endpoint or a Vault login are absent. The identity pull
  request records the exact shape, including `authority_path`, in
  `.docs/execution_lifecycle/contracts.md` before it changes code. A
  `control-plane-normal-shell/v1` run always has an identity, so every field
  CP reads today stays present.

### 11.10 Delivery

| Pull request | What it lands | Gate |
| --- | --- | --- |
| WI-1 | This decision in `PLANS.md` and `.docs/`, with doc-contract tests. No behavior change. | Audit and the merge gate |
| WI-2 | Network grants: `admission_policy.workload_grants` with exact-match rules, the lane value `unrestricted` only, `403 network_access_not_granted` on `:prepare` and `:submit`, startup validation, setup scripts that write grants for today's flows, and the readiness report `workload_egress_unrestricted=true` | Audit, red-team and the merge gate |
| WI-3a | The caller authentication contract refuses `workload` caller paths | Audit and the merge gate |
| WI-3 | Named identities: sections 11.2 to 11.7, the rewrite of the tests that pin the shared identity, and CI integration tests with real SPIRE, Vault and Docker | Audit, red-team, a box run with scripted rollback, and the merge gate |
| WI-4 | Egress lanes: Docker `internal` networks whose only exit is a pinned filtering proxy, `network_mode` chosen by lane, the removal of `unrestricted`, and readiness checks. It starts with a box measurement of the hosts the Codex CLI contacts. | Audit, red-team, a box run, and the merge gate |
| WI-5 | Durable replay and operational formats carry the identity name, the realized SPIFFE ID string and the lane name, with the runtime catalogue's vendor-neutral credential slot | Audit, red-team and the merge gate, before D3 makes those formats live state |
