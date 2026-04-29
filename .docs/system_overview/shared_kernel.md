# Shared Contract And Kernel Decision

## 1. Purpose and authority

This document records the bounded Workstream A shared-contract and shared-kernel
decision for Milestone 2A.1.

It answers only the questions needed to keep ES admission ownership explicit for
the current `AGS -> ARS -> ES` governed artifact path. It does not settle the
broader Workstream B publication/discoverability redesign, the Workstream C ES
public execution redesign, the Workstream E runtime-config ownership redesign,
or the Workstream F runtime-identity redesign.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
the code and tests win and this document must be realigned.

## 2. Decision summary

- `internal/contracts/evidence/v1` is the only active shared artifact evidence
  kernel for the current `AGS -> ARS -> ES` path.
- `internal/contracts/evidence/v1` is not a standalone service boundary and is
  not permission to grow a broad new shared grammar.
- The kernel must remain narrow and evidence-owned. Kernel-level shared meaning
  is currently limited to:
  - package identity
  - narrow derivation request-binding authorization
  - narrow execution/runtime claims ES actually enforces
  - canonicalization plus `seal` verification
- AGS owns publish-time fact assembly and signing into ARS.
- ARS owns blob storage, integrity, artifact registration, and runtime-facing
  discoverability.
- ES owns admission composition and verifies/consumes designed ARS, EGS, and
  runtime-config outputs. ES must not inherit AGS publication grammar, ARS
  tuple/index grammar, or CP example expectations as public ES grammar.
- Payload identity and artifact identity remain separate. ES consumes payload
  discoverability through ARS and cross-checks it against evidence claims; it
  does not assume `artifact_digest == payload_digest`.
- The current runtime-profile compatibility key is
  `execution_substrate.runtime_profile`, and the current bounded opt-in profile
  name is `control-plane-normal-shell/v1`. Both remain outside the shared
  kernel and retain only temporary compatibility status.
- AGS publication claims, ARS discoverability/index shapes, ES public
  execution/lifecycle grammar, and the long-term workload-zone Vault
  runtime-config owner remain service-owned or reopened elsewhere.
- Control Plane orchestration, review, checkpoint, finalization,
  task-attempt/proof-harness expectations, `.out` workspaces, reports, support
  bundles, and semantic interpretation of retained-result contents remain
  outside the shared kernel and outside ES run authority.

## 3. Surface classes used here

| Class | Meaning for Workstream A |
| --- | --- |
| `kernel-level shared contract` | Cross-service meaning that more than one service depends on semantically today and that must stay narrow and jointly explicit. |
| `service-owned contract` | An active surface that may cross boundaries, but whose meaning is authoritative to one service rather than to the shared kernel. |
| `temporary compatibility edge` | An active compatibility shape retained for continuity; it is real today but must not be preserved by inertia. |
| `implementation-only/current-slice detail` | Current code-path, proof, or storage detail that must not be mistaken for a shared or public cross-service contract. |
| `reopened seam` | An active architecture-defining surface that remains intentionally open in `PLANS.md` and is not settled by this decision. |

## 4. Classified current surfaces

### 4A. Kernel-level shared contract

| Surface | Class | Current rule | Guardrail |
| --- | --- | --- | --- |
| `internal/contracts/evidence/v1.ArtifactEvidence` envelope, canonicalization, and `seal` verification | `kernel-level shared contract` | AGS signs canonical aggregate evidence bytes; ES reconstructs those bytes and verifies `schema_version`, `algorithm`, `key_id`, `content_digest`, and detached signature before admission succeeds. | Keep the shared kernel evidence-owned. Do not let storage/discoverability, proof harnesses, or CP runtime expectations expand this envelope by convenience. |
| `claims.package.identity` | `kernel-level shared contract` | `artifact_digest`, `payload_digest`, `artifact_type`, and `intent_digest` are the current shared package-identity facts. ARS discoverability and ES admission cross-check them today. | Preserve visible separation between artifact identity and payload identity. Do not collapse payload reference into package identity or vice versa by shortcut. |
| `claims.admission.authorization.derivation` | `kernel-level shared contract` | Shared derivation authorization is intentionally limited to `derivation_spec_digest` and `output_id`. ES compares only those request-binding facts from the evidence record when admitting a request. | Do not add workload binding, policy linkage, producer traces, derivation constraints, or CP task-attempt grammar here without a separate documented redesign. |
| `claims.admission.execution` | `kernel-level shared contract` | The live shared execution/runtime contract is intentionally limited to runtime environment allowlist, required capabilities, `target_platform`, and `network_access`. ES uses those claims when preparing and selecting runtime behavior. | Do not absorb CP orchestration, review, checkpoint, finalization, task-attempt, proof-harness, or retained-result semantics into shared execution/runtime claims. |

### 4B. Service-owned contracts

| Surface | Class | Current owner | Current rule |
| --- | --- | --- | --- |
| `claims.package.publication` | `service-owned contract` | `AGS` | `builder_service`, caller-derived `invoker`, `policy_decisions`, and `build_log_digest` remain AGS-owned publish-time facts carried inside the signed evidence record. ES verifies the signed record but must not treat publication claims as public ES admission grammar. |
| `POST /v1/artifacts:publish` request grammar and AGS manifest/support-data assembly | `service-owned contract` | `AGS` | AGS accepts the publish request, derives artifact identity, builds aggregate evidence, signs it, uploads payload/evidence/supporting blobs, and registers the artifact through ARS. |
| ARS blob, registration, discovery, descriptor, and manifest routes | `service-owned contract` | `ARS` | ARS owns blob storage, integrity enforcement, artifact registration, and runtime-facing discoverability. ES consumes ARS outputs; ARS route/index shape is not itself the shared kernel. |
| EGS runtime-trust payload and signed response wrapper | `service-owned contract` | `EGS` | EGS owns signer/artifact trust policy publication. ES consumes that trust output but the EGS payload does not become part of the shared artifact kernel. |
| ES public execution request, lifecycle, result, and `authority_handoff` surfaces | `service-owned contract` | `ES` | ES owns admission composition, runtime-profile handling, scheduler handoff, lifecycle projection, retained-result exposure, and runtime handoff evidence. ES must not let AGS/ARS or CP consumer assumptions define those public ES semantics. |

### 4C. Temporary compatibility edges

| Surface | Reason | Scope | Removal condition |
| --- | --- | --- | --- |
| Current CP governed execution consumer path | Preserve the first repo-owned non-operator governed execution path while Workstream C remains open. | AGS publish plus ES `:prepare`, `:submit`, `status`, `logs`, `result`, and `cancel` over HTTPS+mTLS for the current CP consumer path only. | Remove or change only with an explicit compatibility, drain, migration, or versioning plan that documents the replacement consumer path first. |
| `invocation.annotations["execution_substrate.runtime_profile"]` plus `control-plane-normal-shell/v1` | Preserve the accepted CP normal-shell runtime selection path without widening it into the shared kernel. | Annotation-selected ES runtime-profile choice and the bounded `static-script` overlay behavior for the current CP normal-shell attempt slice only. | Remove or change only after an ES-owned replacement runtime-profile/package-selection contract and a coordinated compatibility/versioning plan are documented. |
| ES evidence verification reuses the AGS artifact-signer trust settings already configured for provenance verification | Keep the current verifier setup coherent while the long-term evidence-verifier split remains under review. | Current `key_id` and algorithm reuse for ES evidence verification only. It does not merge AGS publication ownership with ES admission ownership. | Remove when a separate documented evidence-verifier contract or config split is adopted and migrated. |

### 4D. Implementation-only/current-slice details

| Surface | Class | Why it is not shared-kernel authority |
| --- | --- | --- |
| `ars/index.Entry` plus `KindDiscovery`, `KindDescriptor`, `KindEvidence`, and `KindManifest` | `implementation-only/current-slice detail` | These are current ARS indexing/persistence mechanics. They do not define the minimum cross-service kernel ES should inherit. |
| `es/admission.Manifest`, `preparedArtifact`, and `manifestFromEvidence` | `implementation-only/current-slice detail` | These are ES-local projections and helpers derived from shared/kernel and service-owned inputs. They are not themselves shared contracts. |
| Example callers, proof harnesses, `.out` workspaces, reports, support bundles, and semantic interpretation of logs or retained-result bundle contents | `implementation-only/current-slice detail` | These may prove or inspect the current slice, but they do not define shared-kernel meaning and must not become ES run authority. |

### 4E. Reopened seams

| Surface | Class | What remains open |
| --- | --- | --- |
| Long-term scope of `internal/contracts/evidence/v1` | `reopened seam` | Workstream A settles the current minimum kernel only. Whether publication facts stay in this package, shrink further, or move behind a different boundary remains open. |
| ARS registration/discoverability/index shape and precise artifact-identity publication model | `reopened seam` | Workstream B must decide the long-term discoverability surface, optional support-data role, and whether the current artifact-identity derivation/publication model survives unchanged. |
| ES public execution request shape, lifecycle model, runtime-profile selection surface, and runtime-identity handoff | `reopened seam` | Workstream C and Workstream F must settle these ES-owned surfaces. Workstream A does not grant permission to import upstream or CP grammar into them. |
| Workload-zone Vault runtime-config owner | `reopened seam` | The current `internal/contracts/runtimeconfig/v1` surface is active and adjacent, but Workstream E remains the place to decide the long-term owner and replacement boundary. |

## 5. Guardrails for future edits

- Do not add new shared-kernel meaning just because a field already exists in a
  shared package.
- Do not widen `claims.admission.authorization` beyond
  `derivation_spec_digest` and `output_id` without a separate documented
  redesign decision.
- Do not widen `claims.admission.execution` with CP orchestration,
  review/checkpoint/finalization semantics, task-attempt state, proof-harness
  expectations, or retained-result meaning.
- Do not treat ARS discoverability/index shapes as ES public grammar just
  because ES currently consumes them.
- Do not let CP examples, reports, support artifacts, `.out` artifacts, or
  proof harnesses become ES admission or run authority.
- Do not use Workstream A to widen the workload-zone Vault runtime-config
  surface. That surface is active and adjacent, but its long-term owner remains
  a separate reopened seam.
