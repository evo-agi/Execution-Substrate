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
