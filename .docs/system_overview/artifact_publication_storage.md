# Artifact Publication, Storage, And Discoverability Decision

## 1. Purpose and authority

This document records the bounded Workstream B artifact
publication/storage/discoverability decision for Milestone 2B.1.

It answers only the questions needed to keep AGS publication ownership, ARS
storage/discoverability ownership, payload-versus-artifact identity, and ES
consumer boundaries explicit for the current `AGS -> ARS -> ES` governed
artifact path. It does not settle:

- Workstream C ES public execution/admission redesign
- Workstream D policy/authorization redesign
- Workstream E runtime-config ownership redesign
- Workstream F runtime-identity redesign
- Control Plane orchestration, review, checkpoint, or finalization semantics

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
the code and tests win and this document must be realigned.

## 2. Decision summary

- `AGS` owns publish-time fact assembly, caller-bound publication semantics,
  aggregate evidence assembly, signing, payload/support blob upload, and
  artifact registration into `ARS`.
- `AGS` does not own blob storage, post-publication runtime discoverability,
  runtime execution, lifecycle state, ES admission, semantic interpretation of
  workload outputs, or Control Plane orchestration semantics.
- `ARS` owns content-addressed blob storage, read/write integrity enforcement,
  artifact registration, runtime-facing discovery records, and the read
  surfaces by which ES may later discover payload/evidence relationships.
- `ARS` does not own publish-time fact assembly, trust evaluation, policy
  evaluation, runtime execution, lifecycle state, or Control Plane
  orchestration semantics.
- Payload identity and artifact identity remain separate. `payload_digest`
  addresses payload bytes. `artifact_digest` is package-facing identity derived
  from `payload_digest`, `artifact_type`, and `intent_digest`.
- The current ARS discovery record is the canonical runtime-discoverable
  surface for the current slice. Descriptor/manifest support remains secondary
  publication detail and does not define ES public grammar.
- The current discovery JSON shape and `POST /v1/artifacts:register` write
  grammar are retained only as bounded current-slice rules. The long-term
  discoverability/index model remains reopened.
- ES later consumes designed ARS discovery outputs, explicit
  evidence/payload relationships, and explicit cross-checks. ES must not
  inherit AGS publish DTOs, ARS descriptor/index tuples, or Control Plane
  examples/probes as public execution grammar.
- Control Plane examples, probes, scripts, proof harnesses, `.out` artifacts,
  retained result bundles, reports, logs, support bundles, and consumer
  convenience expectations remain outside AGS/ARS/ES core semantics.

## 3. Surface classes used here

| Class | Meaning for Workstream B |
| --- | --- |
| `Current invariant` | Active ownership or relationship rule that the current `AGS -> ARS -> ES` path relies on and that must not change silently. |
| `Bounded slice rule` | Active behavior or contract retained intentionally for the current slice, but not declared as frozen long-term architecture. |
| `Temporary compatibility edge` | Active compatibility/support behavior retained for continuity; it must stay explicitly labeled as temporary. |
| `Implementation-only/current-slice detail` | Current storage, indexing, support-data, or helper shape that must not be mistaken for shared or public architecture. |
| `Reopened redesign seam` | An active architecture-defining surface that `PLANS.md` explicitly keeps open for re-derivation. |

Role labels used in the classification tables below:

- `canonical runtime-discoverable surface`
- `support/secondary publication detail`
- `storage/discoverability mechanic`

## 4. Classified current surfaces

### 4A. Ownership split

| Surface | Class | Current rule |
| --- | --- | --- |
| AGS publish-time ownership | `Current invariant` | AGS owns publish-time fact assembly, caller binding, aggregate evidence assembly, signing, payload/support upload, and registration into ARS. |
| ARS post-publication ownership | `Current invariant` | ARS owns blob storage, integrity, registration, runtime-facing discovery, and post-publication read authority. |
| ES consumer boundary | `Current invariant` | ES consumes designed ARS discoverability outputs plus explicit evidence/payload relationships. ES public grammar must not inherit AGS publish DTOs, ARS descriptor/index tuples, or Control Plane examples/probes. |

### 4B. Publication, storage, and discoverability surfaces

| Surface | Role | Class | Current rule |
| --- | --- | --- | --- |
| Aggregate artifact evidence blob (`internal/contracts/evidence/v1.ArtifactEvidence`) | canonical signed publication fact record; runtime-discoverable through ARS discovery | `Current invariant` | AGS assembles and signs this record, ARS stores it by digest, and ES later verifies it after following the ARS discovery record. Descriptor/manifest support data do not replace it as the authoritative publish-time fact record. |
| Payload blob referenced by `payload_digest` | canonical runtime-consumable payload bytes | `Current invariant` | Payload bytes remain content-addressed by `payload_digest`. ARS stores and re-verifies those bytes by digest, and ES later consumes payload bytes only through an explicit payload reference and cross-check. |
| ARS discovery record (`GET /v1/artifacts/{artifact_digest}/discovery`, `ars/api.ArtifactDiscovery`) | canonical runtime-discoverable surface | `Bounded slice rule` | The current record repeats package-facing artifact identity and points to aggregate evidence and payload digests. ES consumes this runtime-facing role today, but the exact JSON/route shape is not frozen beyond the current slice. |
| AGS -> ARS registration write contract (`POST /v1/artifacts:register` with required `discovery_digest` and optional `descriptor_digest`) | storage registration contract | `Bounded slice rule` | Discovery-centered registration is the intentional current write contract. ARS validates the discovery record, optionally validates secondary descriptor support data, and validates referenced blobs before the artifact becomes discoverable. The long-term write grammar remains open. |
| Current artifact identity derivation rule | package-facing artifact identity rule | `Bounded slice rule` | `artifact_digest` is derived from `payload_digest`, `artifact_type`, and `intent_digest`. It is not hidden payload equality and is not derived from admission/runtime claim material. Any future change requires explicit migration/versioning and coordinated evidence/discovery updates. |
| Artifact descriptor plus `/descriptor` read surface | support/secondary publication detail | `Temporary compatibility edge` | Descriptor support data remains optional and secondary. It is retained for publication/support reads, not as the canonical runtime-discoverable surface, and ES must not require descriptor presence for current admission. |
| Manifest support path plus `/manifest` read surface | support/secondary publication detail | `Temporary compatibility edge` | ARS resolves manifest reads only through secondary descriptor support data when present, specifically the current descriptor `package.supporting[name=manifest]` reference. The current ES hot path does not require manifest reads; manifest support remains compatibility scaffolding for publication/support consumers. |
| Current AGS manifest JSON contents | support-only projection of the current runtime interface | `Implementation-only/current-slice detail` | AGS emits the current manifest blob today, but ES reconstructs its local manifest from aggregate evidence rather than treating the published manifest as the authoritative hot-path input. |
| `ars/index.Entry` plus `KindDiscovery`, `KindDescriptor`, `KindEvidence`, and `KindManifest` | storage/discoverability mechanic | `Implementation-only/current-slice detail` | These are the current persistence/index helpers that make the ARS slice work. They do not define shared-kernel meaning, canonical runtime discoverability by themselves, or ES public grammar. |
| Long-term ARS discovery/index/publication-support model | architecture-defining contract seam | `Reopened redesign seam` | Workstream B settles the current guardrails only. The long-term discovery/index/publication-support model may be re-derived later, but only with explicit documentation and compatibility/migration planning first. |

### 4C. Temporary compatibility edge metadata

| Edge | Reason | Scope | Affected contract or boundary | Visibility | Removal condition |
| --- | --- | --- | --- | --- | --- |
| Descriptor read/support path (`GET /v1/artifacts/{artifact_digest}/descriptor`, optional `descriptor_digest`) | Preserve current publication/support descriptor reads while the ARS discovery record remains the canonical runtime-discoverable surface for ES and other runtime-facing consumers. | Descriptor blob registration, storage, and support-only reads for publication/support consumers only. It remains outside the ES hot path and outside ES public grammar. | ARS storage/discoverability contract and ARS boundary, with AGS writing the optional secondary support blob into ARS. | `system-visible` | Remove or change only after a replacement publication/support read surface, deprecation path, or explicit versioning/migration plan is documented first. |
| Manifest read/support path (`GET /v1/artifacts/{artifact_digest}/manifest` through descriptor `package.supporting[name=manifest]`) | Preserve current publication/support manifest reads without promoting the manifest projection into canonical runtime discoverability or ES admission semantics. | Manifest blob storage plus the current descriptor-carried `package.supporting[name=manifest]` reference for publication/support consumers only. It remains secondary support data, not ES hot-path discoverability or ES public grammar. | ARS storage/discoverability contract and ARS boundary, plus the AGS publication-support blob layout that currently feeds that read path. | `system-visible` | Remove or change only after a replacement support-read surface, descriptor-layout migration, or explicit versioning/deprecation plan is documented first. |

The current discovery/register JSON shape is a `Bounded slice rule`, not a
temporary compatibility edge.

`ars/index.Entry` plus `KindDiscovery`, `KindDescriptor`, `KindEvidence`, and
`KindManifest` remain `Implementation-only/current-slice detail`, not
compatibility surfaces.

### 4D. Current relationship map

1. AGS accepts payload bytes plus publish-time `artifact`, `publication`, and
   `admission` inputs from the caller.
2. AGS computes `payload_digest` from the payload bytes.
3. AGS derives package-facing artifact identity from `payload_digest`,
   `artifact_type`, and `intent_digest`.
4. AGS assembles the aggregate artifact evidence record and signs it.
5. AGS writes payload, aggregate evidence, discovery, descriptor, and manifest
   blobs to ARS, then registers the artifact with `discovery_digest` and
   optional `descriptor_digest`.
6. ARS makes the artifact discoverable by `artifact_digest` through the
   registered discovery record. Evidence and payload are the canonical
   runtime-facing references. Descriptor/manifest support stays secondary.
7. ES reads the ARS discovery record, follows the evidence reference, verifies
   the signed evidence, cross-checks payload/artifact identity facts, and later
   resolves payload bytes through the designed ARS discoverability surface.

## 5. Guardrails for future edits

- Do not collapse `artifact_digest` and `payload_digest` into a hidden equality
  assumption.
- Do not let descriptor, manifest, index, or support-data tuples become ES
  public admission grammar by reuse.
- Do not widen `internal/contracts/evidence/v1` beyond the Workstream A
  shared-kernel decision just because AGS and ARS currently exchange adjacent
  publication or storage data.
- Do not let Control Plane examples, probes, `.out` artifacts, proof harnesses,
  retained result bundles, reports, logs, or support bundles become AGS/ARS/ES
  core semantics.
- Do not treat ARS as trust, policy, runtime, lifecycle, or output-semantic
  authority.
- If the current discovery/registration grammar changes, document the
  compatibility, drain, migration, or versioning plan before changing the
  active contract.
- If the current artifact identity derivation inputs change, update the
  authoritative docs, tests, evidence validation, ARS discoverability
  cross-checks, and ES consumer checks together.
