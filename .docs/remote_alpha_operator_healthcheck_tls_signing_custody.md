# Remote Alpha Operator-Healthcheck TLS Signing And Custody Design

## 0. Purpose, Authority, And Status

This document hardens the ES-owned signing topology, private-key custody,
public-material flow, backup/rollback, redaction, and post-check requirements
for a future operator-authorized Remote Alpha operator-healthcheck TLS
replacement.

Status:

- `Design/static-test prep only`: this document does not execute replacement,
  renewal, route execution, profile refresh, CP diagnose, remote contact, live
  proof, certificate generation, CSR generation, key generation, trust-bundle
  mutation, or profile mutation.
- `Current invariant`: `operator-healthcheck-tls-renew` remains blocked with
  `unsupported_signing_topology`.
- `Bounded slice rule`: the existing interactive
  `operator-healthcheck-tls-status` route remains the only implemented
  operator-healthcheck TLS status route.
- `Reopened redesign seam`: signing authority and private-key custody for this
  host-local operator client identity remain unresolved until ES documents and
  tests the exact owner path.

This is a companion to
`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`.
The companion is separate because the replacement document records the
end-to-end owner sequence, while this document records the stricter custody and
material-flow gates that decide whether any future replacement path is allowed
to proceed. The resolution criteria and evidence checklist live in
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`;
that document is separate so checklist completion cannot be confused with
replacement execution or renewal authorization. The signer/custody decision
record lives in
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`; it
compares candidate signer/custody options and records that no option is
selected today.

Authority follows the repository hierarchy in `AGENTS.md`: `PLANS.md`,
`.docs/system_overview/*`, route-specific `.docs/` design records, and then
current code/tests for factual implemented behavior. Related IM, CP,
Maintenance Agent, and Bridge docs are references for non-ES owner boundaries
only; they do not create ES signing authority.

## 1. Signing Authority

Current answer: unresolved. No ES-owned or host-local authority is currently
documented as allowed to sign replacement operator-healthcheck client
certificates for this scope.

Therefore no replacement may proceed today. The current renew route must
continue to fail closed with `unsupported_signing_topology` before backup,
install, service restart, post-renew probes, CP diagnose rerun, IM refresh, or
live proof.

Before replacement can proceed, ES must document and test all of this evidence:

- allowed signer owner label, scoped to ES-owned or host-local
  operator-healthcheck client TLS only;
- public issuer/trust labels and safe digests for the signing authority;
- signer custody label and audit evidence for the signing key, without
  exposing signer private material;
- explicit statement that CP, IM, Maintenance Agent, and Bridge are not signing
  authorities;
- route/action label and exact operator-approved plan digest label;
- whether the plan is cert-only replacement, host-local key rotation, or a
  different documented owner path;
- CSR or cert-only material-flow decision;
- public certificate identity requirements for
  `spiffe://execution.internal/operator/local` and `client.operator`;
- backup and rollback evidence labels;
- redaction status and final deny-scan status;
- post-check ownership labels for ES, IM, and CP;
- route metadata showing renewal has moved only to the documented
  operator-approved mode, if that later change is made.

The future design must not assume a retained runtime CA private-key topology,
must not accept ad hoc signing material, must not infer authority from service
or governance TLS routes, and must not let a biometric lease, Bridge preflight,
CP diagnostic, or IM profile refresh become the signer.

## 2. Key Custody

The operator-healthcheck client private key belongs only in the P0u documented
fixed host-local operator-healthcheck client-key location on the Remote Alpha
host. This document intentionally refers to that owner-documented location by
label instead of restating raw path material.

Only an ES-owned host-local process running under the documented operator
healthcheck TLS route/custody model may read or use the key. CP, IM,
Maintenance Agent, Bridge, support-bundle tooling, retained-result tooling,
proof tooling, reports, profile lineage, profile diagnostics, and maintenance
summaries must never read, copy, retain, print, parse, summarize, hash, or
expose private key material.

Key action classification:

| Key action | Current classification | Requirement |
| --- | --- | --- |
| Reuse existing host-local key for cert-only replacement | `unresolved stop condition` | Allowed only after ES documents the signer, key custody, CSR/cert flow, key-pair match, backup/rollback, and redaction checks. |
| Replace or rotate the key through host-local generation | `unresolved stop condition` | Allowed only after ES documents the host-local key-generation owner, ownership/mode policy, rollback model, key-pair match, and no-exposure evidence. |
| Import, export, copy, escrow, print, hash for evidence, or pass private key material outside host-local ES custody | `prohibited` | Replacement stops before action. |
| Any key reuse, replacement, rotation, or generation in this tranche | `prohibited` | This tranche is docs/static-test only. |

If private-key exposure outside the documented custody boundary is needed, if
key custody is unclear, or if key-pair match cannot be proven without exposing
the key, replacement stops.

## 3. CSR And Certificate Material Flow

This section is design-only. No CSR or certificate material is generated here.

CSR flow, if selected later:

- the CSR must be created by an ES-owned host-local process inside the
  documented custody boundary;
- the CSR may bind either the existing host-local public key or a newly
  generated host-local key only after the key action has been explicitly
  classified by ES docs/tests;
- any CSR file must remain in an owner-documented temporary or evidence path
  with redaction and cleanup rules;
- reports may record only safe CSR labels, byte counts when allowed, public-key
  fingerprints, and SHA-256 digests when the owner contract allows them;
- raw CSR bodies must not appear in reports, support bundles, retained
  bundles, proof artifacts, Bridge evidence, Maintenance Agent plans, CP
  diagnostics, or IM profile-lineage outputs unless a later ES owner contract
  explicitly allows that public-material emission.

Cert-only replacement, if selected later:

- the signer returns only a public replacement certificate through an
  owner-documented path;
- the host-local ES process checks that the replacement certificate public key
  matches the host-local private key by comparing public-key fingerprints
  derived locally from the certificate and key;
- the private key is never printed, copied, exported, or included in evidence;
- the host-local ES process checks safe identity labels, validity metadata,
  trust-chain labels, and issuer/trust digests before any install;
- public material emission is limited to owner-documented safe metadata paths.

Any flow that requires hidden SSH, hidden provisioning, helper-path overrides,
fallback emitters, raw helper transcripts, or profile mutation by ES stops
before mutation.

## 4. Backup And Rollback

Before any future replacement, the owning ES path must record safe backup
evidence for:

- current public operator client certificate metadata;
- current trust-bundle metadata;
- current profile material metadata received from or destined for the owning IM
  profile contract;
- safe public-material digests and fingerprints where the owner contract
  allows them;
- ownership and mode labels, not raw private-key material;
- redaction status and final deny-scan status;
- rollback target labels;
- replacement plan digest label;
- replacement evidence digest label.

The evidence must not contain private keys, PEM bodies, raw certificate bodies,
raw profile payloads, env values, endpoint secrets, TLS/SPIFFE/SPIRE/Vault
secret material, raw logs, raw helper transcripts, support-bundle payloads,
retained-bundle payloads, proof payloads, unsafe local paths, or unsafe remote
paths.

Rollback after a failed replacement remains an owner-path action, not authority
widening. ES owns restoration of ES TLS material. IM owns restoration or
refresh of profile/provenance/readiness material. CP owns only the later
diagnostic interpretation of refreshed profile material.

Rollback evidence may record what public material and profile metadata should
be restored, who owns restoration, safe digests, redaction status, and failure
classes. Until the owning repo confirms a successful restore or refresh,
rollback evidence is evidence/projection only and must not be treated as CP
acceptance, IM readiness, live proof, or renewed TLS success.

If backup or rollback evidence is unavailable before mutation, replacement
stops.

## 5. Redaction Requirements

Forbidden in all reports, bundles, docs, tests, plans, summaries, diagnostics,
lineage artifacts, support artifacts, retained artifacts, proof artifacts, and
Bridge or Maintenance Agent evidence:

- private keys;
- PEM bodies;
- raw certificate bodies;
- env values;
- endpoint secrets;
- TLS/SPIFFE/SPIRE/Vault material beyond safe labels or owner-allowed digests;
- raw logs;
- raw helper transcripts;
- raw SSH transcripts;
- support-bundle payloads;
- retained-bundle payloads;
- proof payloads;
- unsafe local paths;
- unsafe remote paths;
- connector ids, workspace ids, org ids, or tunnel ids.

Allowed safe fields, when the owning repo contract allows them:

- safe identity label;
- certificate `not_before` and `not_after`;
- expired or not-yet-valid flag;
- issuer label;
- trust label;
- safe issuer/trust digest;
- public certificate fingerprint;
- public-key fingerprint;
- plan digest label;
- profile lineage labels;
- profile digest labels;
- ownership label;
- rollback label;
- redaction status;
- final deny-scan status;
- owner/non-authority labels.

If redaction cannot be guaranteed before evidence is emitted, replacement and
reporting stop.

## 6. Post-Check Semantics

Required post-checks for a future replacement:

| Post-check | Owner | Required result |
| --- | --- | --- |
| Cert metadata freshness | ES | Public certificate metadata has fresh `not_before`/`not_after` values and is not expired or not-yet-valid. |
| Safe identity/SAN/SPIFFE match | ES | Safe labels match `spiffe://execution.internal/operator/local` and `client.operator`. |
| Trust-chain match | ES | Issuer/trust labels and safe digests match the documented ES signing topology. |
| Key-pair match without exposing key | ES | Public-key fingerprint derived from the certificate matches the host-local key-derived public fingerprint without printing or exporting private key material. |
| Backup/rollback evidence present | ES with IM labels where applicable | Safe backup, rollback, ownership, and redaction labels exist before mutation is considered complete. |
| CP `diagnose-remote-profile` pass | CP | CP reruns its contact-free profile diagnostic over refreshed profile material and owns the result. |
| IM profile lineage refresh | IM | IM refreshes profile/provenance/readiness lineage from owner-approved public metadata and owns the output. |
| Optional ES read-only status evidence | ES | Evidence is owner-approved, redacted, and non-authoritative. |
| Optional IM read-only status/provenance evidence | IM | Evidence is owner-approved, redacted, and non-authoritative. |
| Live proof claim | CP with ES/IM prerequisites | No live proof claim is allowed until the later Milestone 3 path actually runs. |

Post-checks do not create signing authority, renewal eligibility, CP
run-control truth, IM readiness authority, Bridge authority, Maintenance Agent
authority, production readiness, or Remote Alpha live proof by themselves.

## 7. Relationship To `operator-healthcheck-tls-renew`

`operator-healthcheck-tls-renew` still blocks because ES has not documented an
allowed signer, signer custody, key custody, CSR/cert flow, backup/rollback
model, redaction model, route eligibility change, and post-check set for this
host-local operator client identity. That absence is exactly the
`unsupported_signing_topology` failure.

Before the renew route could move from blocked to operator-approved renewal,
all of these must be true in ES docs/tests and route metadata:

- signing authority is documented and source-grounded;
- signer custody is documented without private-material exposure;
- key custody and key action classification are documented;
- CSR/cert material flow is documented;
- backup-before-replace and rollback evidence are documented;
- redaction and final deny-scan requirements are documented;
- route invocation is still explicit operator-approved foreground behavior;
- no hidden SSH, hidden reconciler, fallback emitter, or helper-path override
  is introduced;
- post-checks and owner boundaries are documented;
- CP and IM owning-repo follow-up requirements are documented;
- service/governance TLS routes remain separate scopes.

Before auto-renew eligibility could even be discussed, a later tranche would
also need documented noninteractive route support, route-specific idempotence,
safe scheduling metadata, MA route metadata changes, audit evidence,
operator-approved or lease-gated plan-digest semantics, no prompt-capable auth,
no secret monitor-controlled surfaces, fail-closed redaction, backup and
rollback automation through owner paths, post-check automation through owner
paths, and explicit scheduled-execution permission. None of those are enabled
here.

## 8. Relationship To Service And Governance TLS Routes

`es-service-tls-renew` and `es-governance-tls-renew` are separate scopes.

The service TLS route is bounded to the ARS/AGS/ES artifact-registry mTLS
scope. The governance TLS route is bounded to the ES to EGS
execution-governance trust-model mTLS scope. Operator-healthcheck TLS is the
separate host-local operator client identity used by the operator healthcheck
and profile path.

Service or governance TLS renewal cannot repair operator-healthcheck TLS by
inference, cannot refresh operator-healthcheck profile certificate metadata,
cannot clear CP `cert_metadata_expired` blockers for the operator-healthcheck
client material, and cannot establish the missing signing/custody topology.

## 9. Relationship To Biometric Leases

A future biometric lease may approve only the exact canonical plan digest for a
future owner-repo action.

It cannot create signing authority, signer custody, key custody, CSR flow,
profile lineage, CP diagnose ownership, renewal eligibility, ES authority, IM
authority, CP authority, Bridge authority, Maintenance Agent authority,
noninteractive route support, scheduled execution, or Remote Alpha proof.

If a future lease is invalid, expired, consumed, mismatched, out of route
eligibility, or bound to a different plan digest, replacement stops before
action.

## 10. Stop Conditions

Replacement stops when any of these are true:

- signing authority is unclear;
- signer custody is unclear;
- key custody is unclear;
- CSR flow is unclear;
- cert-only flow is unclear;
- key-pair match cannot be proven without private-key exposure;
- backup evidence is unavailable;
- rollback evidence is unavailable;
- redaction cannot be guaranteed;
- CP diagnose expected input is unclear;
- IM profile lineage owner is unclear;
- hidden SSH, hidden provisioning, hidden helper staging, or hidden reconciler
  behavior would be required;
- fallback emitter behavior would be required;
- route eligibility would be widened by implication;
- service or governance TLS renewal is offered as a substitute for
  operator-healthcheck TLS;
- plan digest mismatches;
- future biometric lease gating is invalid, expired, consumed, mismatched, or
  outside route eligibility;
- raw secrets, PEM bodies, raw certificate bodies, env values, endpoint
  secrets, raw logs, raw transcripts, support payloads, retained payloads,
  proof payloads, or unsafe paths would be exposed;
- CP, IM, Maintenance Agent, or Bridge would need to act as ES signing
  authority;
- replacement evidence would be treated as live proof, production readiness,
  CP run-control truth, IM readiness authority, Bridge authority, Maintenance
  Agent authority, or remote reconciliation truth.

## 11. Static-Test Expectations

Static docs-contract tests should preserve that:

- signing authority and key custody are explicit unresolved stop conditions;
- no renewal is enabled by this design;
- `unsupported_signing_topology` remains the current renewal blocker;
- service and governance TLS scopes remain separate;
- raw PEM, private-key, and raw certificate bodies are absent from the design
  docs;
- route eligibility is not widened;
- P0v noninteractive status remains unimplemented and no fallback emitter is
  introduced;
- CP, IM, Maintenance Agent, and Bridge authority boundaries remain preserved;
- biometric leases remain exact-plan-digest approval only and not authority.

Allowed validation for this design tranche is limited to docs/static tests and
safe local checks. Disallowed validation includes remote contact, SSH, scp,
BatchMode probes, ES status or renewal route execution, certificate or CSR
generation, cert/key/trust/profile/env/state/support/retained/proof mutation,
CP diagnose execution, IM refresh, service startup, ES submit, Temporal,
workers, validation drivers, golden capture, and live proof.
