# Runtime-Config Ownership Decision

## 1. Purpose and authority

This document records the docs/tests-only E0 Workstream E runtime-config
ownership decision.

E0 documents the current ownership model before any behavior-changing
Workstream E implementation. It does not change runtime behavior, public DTOs,
route handlers, wire shapes, ES admission behavior, runtime identity handoff,
Control Plane compatibility, Infrastructure Manager inputs, or support-bundle
input shapes.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
the code and tests win and this document must be realigned before Workstream E
continues.

## 2. Decision summary

- Runtime-config semantics are owned by the runtime-config contract surface,
  not by ARS blob mechanics, ES startup placement, CGS, EGS publication
  metadata, IM profiles, support bundles, or CP orchestration.
- The current typed shared schema for workload-zone Vault runtime config is
  `internal/contracts/runtimeconfig/v1`.
- ARS owns blob storage and blob read by digest. ARS does not own
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
- The digest-only reference shape is active today as a temporary compatibility
  edge and bounded current surface. It must not be silently promoted to final
  runtime-config architecture.
- There is no ACS hop in the runtime-config path.
- Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff.
- Optional workload-zone Vault CA trust material remains standard non-secret
  TLS/env-based trust configuration only. It is not runtime-config authority,
  token truth, or relaxed verification.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior. It is not a generalized runtime-auth-plan contract.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only.
  It is not runtime-config authority, live credential truth, or a source of
  workload-zone Vault semantics.
- E0 preserves ES public execution DTOs, `GET /v1/executions:contract`,
  `POST /v1/executions:prepare`, and `control-plane-normal-shell/v1`.
- E0 does not settle Workstream F runtime-identity handoff.
- E0 does not widen CP, IM, support-bundle, report, trace, retained-bundle,
  profile, log, or `.out` artifact authority.
- E0 does not reopen Workstream A, Workstream B, or Workstream C. It does not
  mark full Workstream D complete and does not mark full Workstream E complete.

## 3. Surface classes used here

| Class | Meaning for E0 |
| --- | --- |
| `Current invariant` | Active behavior or ownership that current code and docs rely on and that must not change silently. |
| `Bounded slice rule` | Active behavior that is real today but intentionally narrow and not automatically long-term architecture. |
| `Temporary compatibility edge` | Active shape retained for continuity and explicitly not preserved by inertia. |
| `Compatibility/config residue` | Current config placement or verifier shape retained from earlier forms; it must not become the final owner by accident. |
| `Non-authority evidence/projection` | Readable evidence, report, trace, profile, bundle, or handoff data that may describe facts but cannot own runtime-config semantics. |
| `Reopened redesign seam` | Active architecture-defining ownership that `PLANS.md` keeps open for re-derivation. |
| `Workstream F stop line` | Runtime-identity or credential-handoff behavior that E0 must not settle or change. |

## 4. Classified current runtime-config surfaces

| Surface | Class | Current rule |
| --- | --- | --- |
| Workload-zone Vault runtime-config semantics | `Current invariant` | Semantics live in the runtime-config contract surface. Today that typed surface is `internal/contracts/runtimeconfig/v1`. |
| `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef` | `Current invariant` | The required ref is a named typed ref, not an anonymous string. |
| `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob` and `WorkloadZoneVaultConfig` | `Current invariant` | The typed schema carries Vault HTTPS address, JWT auth mount, auth role, JWT audience, and optional non-secret `ca_bundle_pem` trust material. |
| ARS blob storage and read by digest | `Current invariant` | ARS owns storing and reading the referenced blob by digest. ARS does not own runtime-config semantics. |
| ES prepare/submit lookup orchestration | `Current invariant` | ES is the current consumer and lookup orchestrator: it reads the validated startup ref, fetches the blob from ARS, decodes it through `internal/contracts/runtimeconfig/v1`, and derives local workload-vault handoff metadata. |
| ES startup-config placement of `runtime_config.workload_zone_vault_config_ref` | `Compatibility/config residue`, `Reopened redesign seam` | ES startup config currently carries the required ref and validates it before ES serves governed execution traffic. The placement is not the final runtime-config owner unless a later Workstream E slice explicitly decides that. |
| Digest-only ref shape | `Temporary compatibility edge`, `Bounded slice rule` | The current ref points to the blob by digest. This is active today and must be preserved for compatibility until a documented Workstream E replacement exists. |
| No ACS runtime-config lookup hop | `Current invariant` | The live runtime-config path is ES startup config ref -> ARS blob read -> typed runtime-config decode. There is no ACS hop. |
| Optional `ca_bundle_pem` | `Bounded slice rule` | Optional CA material is non-secret TLS trust material staged and exposed through standard TLS env conventions. ES bounds the enclosing workload-zone runtime-config JSON response to 256 KiB before strict decode and the normalized Vault CA to 256 KiB before owned-material freeze. The selected normalized system CA is independently bounded to 256 KiB and the combined workload bundle to 524,289 bytes. Each input is normalized once; combined-bundle assembly consumes the normalized inputs directly, so the 168,820,737-byte peak ledger includes one temporary system-CA input and no redundant normalized copies. These explicit consumer compatibility/security limits do not transfer runtime-config semantic ownership to ES and do not make the CA secret material, credential truth, or runtime-config authority beyond the typed field meaning. |
| `workload_vault_auth.default_mode` | `Compatibility/config residue`, `Bounded slice rule` | ES currently combines the typed workload-zone Vault config with a local default auth mode. This is not generalized runtime-auth-plan architecture. |
| `authority_handoff.runtime_config_refs` | `Non-authority evidence/projection` | The field records the selected workload-zone Vault config digest in non-secret handoff evidence. It does not own semantics and does not prove live credential state. |
| Runtime identity handoff, `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, SPIRE/Vault helper behavior, reserved runtime paths, workload UID/GID, token, and lease semantics | `Workstream F stop line` | These remain Workstream F territory and must not be changed, settled, or reclassified by E0. |

## 5. Ownership and non-ownership

**Current ownership**

- `internal/contracts/runtimeconfig/v1` owns the current typed shared schema for
  workload-zone Vault runtime-config semantics.
- ARS owns blob storage, integrity, and read by digest after a digest is known.
- ES owns the current consumer-side lookup orchestration during `:prepare` and
  `:submit`.
- ES startup validation currently guarantees the typed
  `runtime_config.workload_zone_vault_config_ref` is present and valid before
  ES serves governed execution traffic.

**Explicit non-ownership**

- ARS blob mechanics do not own workload-zone Vault runtime-config semantics.
- ES startup config placement does not become the final runtime-config owner by
  inertia.
- CGS authorize output, CGS policy input, and EGS publication metadata do not
  own runtime-config semantics.
- IM profiles, support bundles, reports, traces, logs, retained bundles, and
  `.out` artifacts do not own runtime-config semantics.
- `authority_handoff.runtime_config_refs` is evidence only, not authority.
- Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff.

## 6. Required D exclusions

None of the following are runtime-config authority:

- CGS authorize output
- `id.conf`
- `policy.id_conf_path`
- `audit.policy_version`
- EGS `publication.version`
- EGS unsigned publication metadata
- AGS `policy_decisions`
- ES retained bundles
- ES `outcome_evidence`
- ES `authority_handoff`
- IM profiles
- support bundles
- logs, traces, reports, and `.out` artifacts
- CP review/approval/checkpoint/finalization state

These exclusions preserve the accepted D0-D1d guardrails. They do not mark full
Workstream D complete and do not close the remaining D seams.

## 7. Workstream F stop lines

E0 must stop and report instead of widening into Workstream F if a change would
touch:

- runtime identity handoff ownership
- `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- SPIRE or Vault handoff implementation
- raw SPIRE socket traversal
- reserved runtime paths
- runtime helper behavior
- workload UID/GID or task-user semantics
- Vault JWT login protocol
- token, lease, or credential lifecycle semantics
- `authority_handoff` vocabulary beyond the non-authority evidence note above

E0 does not decide whether the current runtime-identity delivery model is final.
That remains Workstream F.

## 8. Remaining Workstream E seams

E0 intentionally leaves these Workstream E seams open for E1/E2:

- whether the long-term runtime-config owner remains a shared contract surface
  plus ES startup placement or moves behind a different narrow owner
- whether the startup guarantee moves out of ES config placement once a
  replacement owner exists
- whether the digest-only reference shape remains the long-term lookup form
- whether `workload_vault_auth.default_mode` is replaced, reduced, or
  absorbed into a documented runtime-config owner
- how to migrate any replacement without changing ES public execution DTOs,
  `GET /v1/executions:contract`, `POST /v1/executions:prepare`,
  `control-plane-normal-shell/v1`, CP compatibility, or M6 support-bundle
  input shapes

The next behavior-changing Workstream E slice must update `PLANS.md` and the
authoritative `.docs/` pages before changing runtime source files.
