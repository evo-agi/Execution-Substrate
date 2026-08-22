# Remote Alpha Operator-Healthcheck TLS Signing/Custody Resolution Criteria

## 0. Purpose, Authority, And Status

This document defines the evidence gate for moving Remote Alpha
operator-healthcheck TLS signing/custody from unresolved/fail-closed to
operator-authorized replacement design-ready.

Status:

- `Design/static-test prep only`: this document does not execute replacement,
  renewal, route execution, profile refresh, CP diagnose, IM refresh, remote
  contact, live proof, certificate generation, CSR generation, key generation,
  trust-bundle mutation, profile mutation, or authorization artifact creation.
- `Current invariant`: `operator-healthcheck-tls-renew` remains blocked with
  `unsupported_signing_topology`.
- `Bounded slice rule`: at the time this resolution criteria record was first
  recorded, the existing interactive `operator-healthcheck-tls-status` route
  was the only implemented operator-healthcheck TLS status route. A later P0v
  tranche now implements only read-only noninteractive status evidence.
- `Reopened redesign seam`: signer authority, signer custody, key custody,
  key reuse, key rotation, and CSR/cert material flow remain unresolved for the
  host-local operator-healthcheck client identity until ES documents
  source-grounded evidence and tests the exact owner path.

This criteria document is separate from
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md` because that
document records the custody design and stop conditions, while this document is
the checklist for resolving those stop conditions. It is also separate from
`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`
because replacement sequencing must not be treated as signer authority. The
signer/custody decision record lives in
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`
because options comparison and selection status must not be confused with
resolution criteria.

The no-signer/no-replacement conclusion here continues to govern reusable P0u
`operator-healthcheck-tls-renew`. The separate single-use external-family
incident in
`.docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md`
does not unblock or widen P0u and provides no reusable signer or route;
`unsupported_signing_topology` remains the reusable-route result.

Authority follows the repository hierarchy in `AGENTS.md`: `PLANS.md`,
`.docs/system_overview/*`, route-specific `.docs/` records, and then current
code/tests for factual implemented behavior. IM, CP, Maintenance Agent, and
Bridge documents are references for non-ES owner boundaries only; they do not
create ES signing authority.

Current reusable P0u resolution verdict: blocked. No current ES source satisfies
the signer authority and custody evidence gate below, so no reusable replacement, renewal,
profile-lineage refresh, CP diagnose rerun, MA execution, Bridge projection, or
live proof may proceed by inference.

## 1. Resolution Gate Purpose

The resolution gate exists only to define what evidence must be present before
operator-authorized replacement execution design can proceed.

It does not:

- authorize certificate replacement;
- enable renewal;
- make `unsupported_signing_topology` safe;
- authorize or consume the later read-only noninteractive status route;
- schedule the later read-only noninteractive status route;
- update MA route metadata;
- authorize MA scheduling or auto-renew;
- run CP diagnose;
- refresh IM profile lineage;
- create a biometric lease;
- prove Remote Alpha live readiness.

Passing this gate later would mean only that ES has enough documented,
source-grounded signer/custody evidence to design an operator-authorized
replacement execution path. It would still not execute that path.

## 2. Acceptable Signer Evidence

Acceptable signer authority must be source-grounded in ES-owned docs/tests or
in an owning-repo contract that ES explicitly adopts without widening that
repo's authority.

Required signer evidence:

- documented ES-owned signing authority for the
  operator-healthcheck client TLS scope, or documented host-local signer
  authority explicitly adopted by ES for that scope;
- documented host-local signer custody for signer private material, with safe
  audit labels and no private-material exposure;
- documented CA/trust ownership for the issuing authority and the trust bundle
  that validates the operator-healthcheck client identity;
- documented issuer/trust-chain metadata expected by CP profile diagnostics,
  limited to safe labels, timestamps, and owner-allowed digests;
- documented separation from `es-service-tls-renew` and
  `es-governance-tls-renew` signers unless an ES contract explicitly proves a
  shared signing authority for this exact scope;
- documented subject/SAN/SPIFFE identity requirements for
  `client.operator` and `spiffe://execution.internal/operator/local`;
- documented signer audit evidence, rotation policy, and failure class for
  missing or mismatched signer evidence;
- explicit non-authority labels for CP, IM, Maintenance Agent, and Bridge.

Evidence that is not acceptable:

- assumption that a retained runtime CA private key exists;
- ad hoc signing material supplied through CLI args, env files, reports,
  support bundles, retained bundles, proof artifacts, Bridge evidence, MA
  plans, CP diagnostics, or IM profile lineage;
- authority inferred from service TLS, governance TLS, profile refresh,
  CP diagnostics, Bridge preflight, or a biometric lease;
- authority inferred from the current helper implementation.

No current ES source satisfies this list. Until a later ES doc/test tranche
does, resolution remains blocked and the renewal failure class remains
`unsupported_signing_topology`.

## 3. Key Custody Evidence

Before replacement execution design can proceed, ES must document all key
custody facts below.

| Custody fact | Required evidence | Current state |
| --- | --- | --- |
| Current key custody owner | Owner label for the host-local operator-healthcheck client key, process label allowed to use it, and non-owner labels for CP, IM, Maintenance Agent, Bridge, support, retained, proof, and report tooling. | Unresolved stop condition. |
| Key reuse policy | Explicit allow/prohibit decision for reusing the existing host-local key, including signer compatibility and key-pair match proof. | Unresolved stop condition. |
| Key rotation policy | Explicit allow/require/prohibit decision for host-local key rotation, including owner, mode/ownership policy, rollback model, and no-exposure proof. | Unresolved stop condition. |
| CSR author | If CSR flow is used, the ES-owned host-local process that may generate the CSR and the exact public metadata allowed to leave host-local custody. | Unresolved stop condition. |
| Key-pair match owner | The ES-owned host-local process that may prove public certificate/public key match without exporting, printing, copying, hashing for evidence, or retaining private key material. | Unresolved stop condition. |
| Public metadata artifacts | Owner-approved labels, timestamps, byte counts when allowed, issuer/trust labels, public fingerprints, and safe digests. | Allowed only after owner contract. |
| Never-private artifacts | Reports, support bundles, retained bundles, proof artifacts, CP diagnostics, IM lineage, MA plans, Bridge evidence, docs, and tests must never contain private keys. | Current invariant. |

If current key custody owner, key reuse, key rotation, CSR author, or key-pair
match ownership cannot be documented without exposing private key material,
reusable P0u replacement remains blocked.

## 4. CSR, Cert-Only, Key-Reuse, And Key-Rotation Criteria

Each option must be selected explicitly. None is enabled today.

| Option | Required evidence | Prohibited actions | Redaction requirements | Stop conditions | Owner |
| --- | --- | --- | --- | --- | --- |
| CSR flow | ES-documented signer authority, CSR author, key action classification, public-key binding, CSR storage/cleanup labels, signer audit label, issuer/trust labels. | Generate CSR in this tranche, expose private key, accept ad hoc signer input, emit raw CSR body without owner contract, mutate profile material. | Only safe CSR labels, byte counts when allowed, public-key fingerprints, and owner-allowed digests. No raw CSR body unless a later ES contract explicitly allows it. | CSR author unclear, key custody unclear, signer authority unclear, redaction unavailable, hidden SSH/provisioning required. | ES for TLS/key flow; signer owner as documented by ES. |
| Cert-only replacement | ES-documented signer authority, cert delivery path, existing-key reuse approval, trust-chain labels, key-pair match without key exposure, backup/rollback labels. | Replace cert in this tranche, expose key, accept raw cert bodies in reports, install before backup, infer trust from service/governance TLS. | Public cert metadata only: subject/issuer/SAN labels, timestamps, public fingerprints, safe trust labels/digests. | Key reuse not approved, key-pair match unavailable, trust-chain mismatch, signer custody unclear, rollback unavailable. | ES. |
| Key reuse | Explicit reuse approval, current key custody owner, existing-key health evidence, cert-only or CSR binding evidence, rollback labels. | Reuse by inertia, hash private key for evidence, export or copy private key, allow non-ES repos to inspect key. | Public-key fingerprint derived locally; private key never leaves custody and is never represented by a private-key digest. | Reuse policy absent, key ownership unclear, key-pair match cannot be proven safely. | ES host-local custody. |
| Key rotation | Explicit rotation approval or requirement, host-local key-generation owner, ownership/mode policy, rollback/recovery plan, public metadata for new key only. | Generate key in this tranche, import/export/escrow key, route key material through Bridge/MA/CP/IM, leave rollback unspecified. | Public-key fingerprint and ownership labels only; no private key, no private-key digest, no raw key material. | Rotation owner unclear, rollback unavailable, signer cannot bind new public key, redaction unavailable. | ES host-local custody. |

Service TLS and governance TLS renewal criteria do not substitute for any
operator-healthcheck TLS option above unless ES later documents an explicit
shared scope and updates tests.

## 5. Backup And Rollback Proof Model

Before any future replacement execution, ES must define safe proof/evidence for:

- pre-replacement public operator client certificate metadata;
- trust-bundle metadata;
- profile material metadata received from or destined for IM-owned profile
  contracts;
- safe public-material digests or fingerprints only where the owner contract
  allows them;
- rollback labels and rollback target labels;
- owner confirmation labels for ES TLS material and IM profile/provenance
  material;
- redaction status and final deny-scan status;
- post-rollback check labels.

Rollback evidence is not authority until the owning path confirms it:

- ES owner confirmation is required before restored TLS material is treated as
  restored;
- IM owner confirmation is required before refreshed or restored profile
  lineage is treated as current;
- CP owner diagnostics are required before profile acceptance can be claimed;
- no rollback label is a live proof, CP acceptance, IM readiness, Bridge truth,
  MA approval, or renewed TLS success.

If backup evidence, rollback labels, owner confirmation, redaction status, or
post-rollback checks are unavailable before mutation, replacement stops before
mutation.

## 6. Redaction Gate

Before any future replacement execution design may proceed, every planned
evidence surface must pass this pre-execution redaction checklist.

Forbidden material:

- private keys;
- PEM bodies;
- raw certificate bodies;
- raw CSR bodies unless explicitly allowed by a later ES owner contract;
- env values;
- endpoint secrets;
- TLS/SPIFFE/SPIRE/Vault material beyond safe labels and owner-allowed
  digests;
- raw logs;
- raw helper, SSH, shell, CP, IM, MA, or Bridge transcripts;
- raw payloads;
- unsafe local paths;
- unsafe remote paths;
- support-bundle payloads;
- retained-bundle payloads;
- proof payloads;
- connector ids, tunnel ids, workspace ids, or org ids.

Required redaction evidence:

- redaction policy label;
- deny-scan status;
- list of allowed safe fields;
- owner label for each evidence surface;
- non-authority labels;
- failure class if redaction cannot be guaranteed.

If redaction cannot be proven before evidence is emitted, replacement,
reporting, profile refresh, CP diagnose planning, MA planning, and Bridge
projection stop.

## 7. Post-Check Evidence Gates

A future replacement may not be claimed successful until all post-check evidence
exists and remains owner-scoped.

Required gates:

- cert metadata freshness: public `not_before`/`not_after` metadata is fresh
  and not expired or not-yet-valid;
- identity/SAN/SPIFFE match: safe labels match
  `spiffe://execution.internal/operator/local` and `client.operator`;
- trust-chain match: issuer/trust labels and safe digests match the documented
  ES signing topology;
- key-pair match without key exposure: certificate public-key fingerprint
  matches the host-local key-derived public fingerprint without printing,
  exporting, copying, or retaining private key material;
- CP diagnose-remote-profile pass: CP reruns its contact-free profile
  diagnostic over refreshed profile material and owns the result;
- IM profile lineage refreshed: IM refreshes profile/provenance/readiness
  lineage from owner-approved public metadata and owns the output;
- redaction pass: all emitted evidence passes the redaction gate and final
  deny scan;
- no authority widening: CP, IM, Maintenance Agent, and Bridge remain
  non-signers and non-mutators for ES TLS material;
- no live proof claim: replacement success does not claim ES submit, Temporal,
  workers, validation driver, golden capture, retained-result proof, or Remote
  Alpha live proof.

Any failed or unavailable gate leaves the replacement unclaimed and blocks
Remote Alpha proof resumption.

## 8. Route Metadata Transition Criteria

All route metadata transitions are blocked today.

Before `operator-healthcheck-tls-renew` can move from blocked to
operator-approved renewal, ES docs/tests and route metadata must prove:

- source-grounded signing authority;
- signer custody;
- key custody and selected key action;
- CSR or cert-only material flow;
- backup-before-replace and rollback model;
- redaction gate and final deny scan;
- exact foreground operator-approved invocation semantics;
- no fallback emitters, hidden SSH, hidden reconciler, helper override, or
  profile mutation by ES;
- CP and IM post-check ownership;
- service/governance TLS separation;
- `unsupported_signing_topology` is no longer active for the selected path.

Before the implemented read-only noninteractive status route can be consumed by
MA:

- ES must complete independent audit of the route in a later tranche;
- ES route metadata already declares `supports_noninteractive=true`,
  `requires_interactive_tty=false`, `current_status=implemented`, and
  `scheduled_execution_allowed=false`;
- ES schema and redaction validation must be available before JSON output is
  promised;
- the route must not stage helpers, prompt for auth, mutate remote summaries,
  renew, replace, or emit fallback JSON;
- MA must update its own route metadata/docs/tests before consumption;
- CP and IM must document any later consumption in their owning repos.

Before auto-renew eligibility can be discussed:

- a noninteractive renewal route must be separately documented, implemented,
  audited, and tested;
- no-prompt auth, route idempotence, safe scheduling metadata, backup/rollback
  automation, post-check automation, redaction, owner-bound evidence, and MA
  route metadata must exist;
- a future lease or approval model must bind only an exact plan digest after
  route eligibility exists;
- no monitor, scheduler, lease, Bridge preflight, CP diagnostic, or IM refresh
  may create renewal eligibility.

Current state remains:

- `operator-healthcheck-tls-renew`: blocked/status-only with
  `unsupported_signing_topology`;
- `operator-healthcheck-tls-status-noninteractive`: implemented read-only
  status only, not renewal, not signer/custody resolution, not scheduled, not
  MA-consumable until later MA-owned metadata/docs/tests and audit;
- auto-renew: not eligible and not discussable as executable design.

## 9. Relationship To Biometric Leases

A future biometric lease may approve only the exact canonical plan digest for a
future owner-repo replacement plan after signer/custody evidence is resolved.

A lease cannot:

- create signer authority;
- create signer custody;
- create key custody;
- choose key reuse or rotation;
- generate CSR/cert/key/trust material;
- override route eligibility;
- make an interactive route noninteractive;
- bypass CP profile diagnostics ownership;
- bypass IM profile lineage ownership;
- bypass ES TLS/material ownership;
- make `unsupported_signing_topology` safe;
- authorize scheduled execution or auto-renew by itself.

If the route is blocked, the plan digest mismatches, the lease is invalid,
expired, consumed, or outside route eligibility, or CP/IM ownership would be
bypassed, replacement stops before action.

## 10. Owner Boundaries

ES owns:

- operator-healthcheck TLS route/material semantics;
- signing topology resolution;
- key custody and key action classification;
- replacement and rollback semantics for ES TLS material;
- ES status evidence and redaction rules.

IM owns:

- Remote Alpha profile/provenance/readiness emission;
- profile-lineage refresh artifacts;
- IM redaction and support-bundle packaging if later authorized.

CP owns:

- `diagnose-remote-profile`;
- profile acceptance;
- workflow/run-control;
- Temporal/proof semantics;
- proof-profile lineage creation.

Maintenance Agent owns:

- its own route metadata;
- scheduler/notification behavior;
- proposal, plan digest, and lease records after owning-repo contracts exist.

Bridge owns:

- local coordination/preflight evidence only.

CP, IM, Maintenance Agent, and Bridge must not act as ES signing authorities,
must not mutate ES TLS material, and must not wrap missing ES prerequisites
into ES status truth.

## 11. Static-Test Expectations

Docs-contract tests should preserve that:

- this resolution criteria doc exists;
- the gate is docs/static only;
- no replacement execution is enabled;
- no renewal is enabled;
- `unsupported_signing_topology` remains blocked today;
- signer evidence remains unresolved unless explicitly documented by ES;
- key custody evidence is required;
- CSR/cert-only, key reuse, and key rotation criteria are present;
- backup/rollback proof model is present;
- redaction gates are present;
- post-check evidence gates are present;
- route metadata transition criteria are present and keep renewal,
  noninteractive MA consumption, and auto-renew blocked today;
- biometric leases approve only exact plan digests after owner evidence exists
  and cannot create signer authority or key custody;
- raw PEM/key/cert material is absent from docs;
- CP, IM, Maintenance Agent, and Bridge boundaries remain preserved.

Allowed validation is limited to docs/static tests and safe local checks.
Disallowed validation includes remote contact, SSH, scp, BatchMode probes,
ES status or renewal route execution, certificate or CSR generation,
cert/key/trust/profile/env/state/support/retained/proof mutation, CP diagnose
execution, IM refresh, service startup, ES submit, Temporal, workers,
validation drivers, golden capture, and live proof.
