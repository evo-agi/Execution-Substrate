# Remote Alpha Operator-Authorized Operator-Healthcheck TLS Replacement Design

## 0. Purpose, Authority, And Status

This document defines a design-only, ES-owned path for a future
operator-authorized replacement of Remote Alpha operator-healthcheck TLS public
material, followed by owner-repo profile/provenance refresh and Control Plane
profile diagnostics.

The signing, private-key custody, CSR/cert flow, backup/rollback, redaction,
and post-check gates for that future path are hardened in the companion design
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`. The evidence
checklist for resolving those stop conditions is recorded separately in
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`.
The signer/custody decision record is
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`.
The companions are separate so this document can remain the end-to-end
replacement sequence. The signing/custody companion records the stricter
material-custody stop conditions, while custody requirements and resolution
criteria remain explicit non-execution gates, and the decision record records
that no signer/custody option is selected today.

Status:

- `Design/static-test prep only`: this document does not implement renewal,
  replacement, profile refresh, CP diagnose, route execution, lease creation,
  or remote contact.
- `Current invariant`: `operator-healthcheck-tls-renew` remains blocked with
  `unsupported_signing_topology`.
- `Bounded slice rule`: at the time this replacement design was first recorded,
  the existing interactive `operator-healthcheck-tls-status` route was the only
  implemented operator-healthcheck TLS status route. A later P0v tranche now
  implements only read-only noninteractive status evidence.
- `Reopened redesign seam`: signing authority and private-key custody for this
  host-local operator client identity remain unresolved until ES documents and
  tests the exact owner path.
- This is an operator-authorized replacement design. It is not generic TLS
  deployment, broad repair automation, a hidden reconciler, or proof that
  Remote Alpha is live-ready.

Authority follows the repository hierarchy in `AGENTS.md`: `PLANS.md`,
`.docs/system_overview/*`, route-specific `.docs/` design records, and then
current code/tests for factual implemented behavior.

## 1. Current Source-Grounded Use

Operator-healthcheck TLS is the host-local operator client TLS scope used by
the Remote Alpha operator healthcheck path. Current ES docs and tests describe
the implemented status route as a non-mutating evidence route over the
operator healthcheck client certificate, key-public match, expected identity,
trust verification, and safe local HTTPS healthcheck probes when configured.

The CP `diagnose-remote-profile` command consumes
`control-plane.remote-supported-host-profile.v1` profile metadata and reports
contact-free profile diagnostics such as `cert_metadata_expired`. That
diagnostic is not a live remote TLS handshake, ES route execution, CP proof,
Temporal proof, ES submit, or Remote Alpha live proof.

Infrastructure Manager owns Remote Alpha profile/provenance/readiness emission.
The refreshed profile and proof-profile lineage artifacts are evidence and
provenance only. ES status evidence may indicate that a profile refresh is
needed, but it does not mutate profile lineage or establish CP acceptance.

## 2. Blocked Identity

Source-supported safe labels:

- expected current operator identity:
  `spiffe://execution.internal/operator/local`
- legacy mismatch identity:
  `spiffe://execution.internal/operator`
- expected future subject label: `client.operator`

Any future replacement certificate for this scope must use the current
`operator/local` URI label. Legacy-only identity remains a status failure that
requires replacement through a documented owner path. This document does not
print PEM bodies, raw certificate bodies, private key material, profile
payloads, endpoint values, or unsafe path material.

## 3. Signing And Authorization Topology

ES must define signing authority for this TLS scope before replacement can run.
The required ES-owned decisions are:

- which signing authority may issue the operator healthcheck client
  certificate;
- where signing authority and audit evidence are held;
- whether the client key is preserved, rotated, or regenerated;
- how backup, install, post-check, rollback, and failure evidence are
  recorded without exposing secret material;
- how route eligibility changes from `unsupported_signing_topology` to a
  specific replacement path.

Current signing topology is undocumented for this scope. That is why
`operator-healthcheck-tls-renew` still fails closed with
`unsupported_signing_topology` before backup, install, service restart, or
post-renew probes. Existing ES tests also preserve that the helper must not
assume a retained runtime CA private-key topology or accept ad hoc signing
material.

The companion signing/custody design currently records no allowed signer for
this scope. Replacement can proceed only after ES documents source-grounded
evidence for the allowed signer owner label, signer custody label, public
issuer/trust labels or digests, key custody, CSR/cert flow, backup/rollback
evidence, redaction, route eligibility, and post-check ownership. CP, IM,
Maintenance Agent, and Bridge are explicitly not signing authorities.

A future Maintenance Agent biometric lease may approve only an exact canonical
plan digest. The lease cannot define signing topology, create signing
authority, choose key custody, make the blocked route eligible, make an
interactive route noninteractive, approve CP diagnose success, or create IM
profile lineage.

## 4. Key Custody Principles

Private keys remain inside ES-owned or host-local custody, or another
explicitly documented owning-repo custody path. Bridge, Maintenance Agent,
Control Plane, Infrastructure Manager reports, support bundles, readiness
reports, and profile lineage artifacts must never retain, print, copy, expose,
parse, or summarize private keys.

If replacement requires private-key exposure outside the documented custody
boundary, the replacement stops. If custody is unresolved, replacement stops.
If backup or rollback cannot be described without private-key material in
evidence, replacement stops.

Key reuse, key replacement, and key rotation are not enabled by this design.
The companion signing/custody design classifies reuse of the existing
host-local key and host-local key rotation as unresolved stop conditions until
ES documents the exact key action, owner process, custody boundary,
backup/rollback model, and no-exposure key-pair match. Importing, exporting,
copying, escrowing, printing, or passing private key material outside
host-local ES custody is prohibited.

## 5. Public Material And Profile Emission Ownership

Ownership boundaries:

- ES owns TLS route/material semantics, signing topology, replacement
  semantics, route failure classes, key custody requirements, and ES-owned
  status evidence.
- IM owns Remote Alpha profile, provenance, readiness, support-bundle, and
  profile-lineage refresh emission.
- CP owns remote-supported-host profile parsing, profile diagnostics,
  profile acceptance, workflow/run-control, Temporal, review, checkpoint, and
  proof semantics.
- Bridge and Maintenance Agent may summarize, propose, or record evidence only
  within their own contracts. They must not mutate TLS material or profiles.

Public certificate/profile material may appear only as safe metadata allowed by
the owning repo contract: labels, timestamps, expiry, issuer/subject labels,
SAN expectation labels, byte counts when safe, SHA-256 digests, public
fingerprints, redaction booleans, failure classes, and non-authority labels.

## 6. Backup And Rollback Evidence Requirements

Before any future operator-authorized replacement, the owning repo path must
record safe backup and rollback evidence for:

- existing public operator client certificate metadata;
- existing trust/profile material metadata;
- public-material digests where the owning repo contract allows them;
- profile lineage metadata and source-profile digest compatibility state;
- redaction status and final deny-scan status where applicable;
- rollback labels and rollback target labels;
- replacement plan digest and replacement evidence digest labels.

Forbidden backup/evidence material:

- private keys;
- PEM bodies;
- raw certificate bodies;
- raw profile payloads;
- env values;
- endpoint secrets;
- TLS/SPIFFE/SPIRE/Vault secret material;
- raw logs, raw command output, terminal transcripts, support-bundle payloads,
  retained-bundle payloads, proof payloads, unsafe local paths, or unsafe
  remote paths.

Rollback is not authority widening. A rollback label only identifies the
documented ES/IM owner path to restore prior public material and profile
metadata if post-checks fail. If rollback evidence is unavailable, replacement
stops before mutation.

## 7. Operator-Authorized Replacement Phases

Each phase is design-only here. No phase is executed by this document.

| Phase | Owner | Allowed actions | Prohibited actions | Evidence | Stop conditions | Authority non-claims |
| --- | --- | --- | --- | --- | --- | --- |
| Source-of-truth confirmation | ES with CP/IM references | Confirm current ES docs, IM profile docs, and CP diagnostics contracts. | Remote contact, route execution, renewal, profile mutation. | Doc refs, route labels, blocker labels. | Owner conflict, doc/code drift, missing CP or IM contract. | Not CP acceptance, not IM readiness, not ES status truth. |
| Backup and safe inventory | ES | Define inventory fields and backup metadata for public cert/trust/profile references. | Copy private keys into evidence, print PEM/cert bodies, mutate material. | Safe labels, byte counts, digests, redaction booleans. | Secret exposure required, rollback evidence unavailable. | Not replacement, not proof, not profile acceptance. |
| Signing and custody confirmation | ES | Document signer, signer custody, key custody, audit, idempotence, and failure classes. | Retained runtime CA assumption, ad hoc signer input, key disclosure. | Signing-topology label, custody label, blocker status. | Signing topology unclear, key custody unclear. | Not lease authority, not Bridge/MA authority. |
| Plan digest generation | MA future, using ES/IM/CP owner contracts | Build exact canonical plan digest for the future owner-repo action. | Route execution, lease minting by background scheduler, hidden shell/SSH. | Plan digest label, route/action labels, stop-condition set. | Digest mismatch, forbidden material in plan, route blocked. | Digest is not permission by itself. |
| Operator authorization lease approval | MA future only | Foreground operator approves the exact plan digest after owner contracts exist. | macOS API implementation in this tranche, broad shell approval, signing authority by lease. | Lease label, digest match label, TTL/attempt labels. | Lease invalid, expired, consumed, route not eligible. | Lease does not sign, renew, replace, or refresh profiles. |
| Public cert/profile replacement by owning path | ES for TLS material, IM for profile emission inputs | Replace only through documented ES-owned TLS/material semantics after all gates pass. | Bridge/MA/CP mutation, hidden SSH/provisioning, fallback emitters, undocumented signing. | Replacement summary, backup/rollback labels, redaction status. | Custody/signing ambiguity, rollback missing, redaction cannot be guaranteed. | Not Remote Alpha proof, not CP acceptance. |
| IM profile/provenance refresh | IM | Regenerate or refresh Remote Alpha profile/provenance artifacts from owner-approved public material. | Define ES signing, mutate ES TLS material, claim CP diagnose pass. | Refreshed profile digest, provenance labels, lineage status. | Profile lineage owner unclear, stale or incompatible source digest. | Not ES TLS authority, not CP run-control. |
| CP diagnose rerun | CP | Rerun contact-free profile diagnostics over refreshed profile material. | CP behavior change, ES route execution, live proof, Temporal start. | `control-plane.remote-profile-diagnostic.v1`, blocker/warning labels. | Expected CP input unclear, diagnostics still blocked. | Not live ES status, not governed proof. |
| Optional ES/IM read-only status evidence | ES and IM | Collect only owner-approved read-only status/provenance evidence when route prerequisites allow, including the later implemented P0v read-only status route where available. | Treat P0v as replacement authorization, post-replacement acceptance by itself, signer/custody resolution, scheduled execution, fallback emitters, support-bundle mutation as authority, or consumer authority widening. | Safe status JSON or profile/readiness refs. | Prerequisites missing, redaction unavailable, P0v missing/failed/blocked, owner contract unknown, or evidence unavailable. | Evidence/projection only. |
| Remote Alpha proof resumption gate | CP with ES/IM prerequisites | Decide whether a separate Milestone 3/live proof path may resume after diagnostics pass. | Claim proof from replacement, start workers, run ES submit, run golden capture in this tranche. | Gate decision label and required proof plan refs. | CP diagnose not passing, IM lineage stale, ES status blocked. | No live proof claim until the proof path runs. |

## 8. Post-Checks

Required post-checks for a future replacement:

- public certificate metadata is fresh;
- identity/SAN/SPIFFE labels match `spiffe://execution.internal/operator/local`;
- trust chain metadata matches the documented ES signing topology;
- key-pair match is checked without printing key material;
- backup and rollback evidence labels are present before mutation is considered
  complete;
- CP `diagnose-remote-profile` passes on refreshed profile material;
- IM profile lineage/provenance is refreshed and digest-compatible;
- redaction confirms no raw secret, PEM, cert body, env, endpoint, raw log,
  support-bundle payload, retained-bundle payload, or proof payload exposure;
- route eligibility and authority labels are not widened;
- no live proof, ES submit, Temporal proof, retained-result proof, or golden
  capture is claimed until a later proof path actually runs.

## 9. Why Service And Governance TLS Routes Are Insufficient

`es-service-tls-renew` is bounded to the ARS/AGS/ES artifact-registry mTLS
scope. `es-governance-tls-renew` is bounded to the ES to EGS
execution-governance trust-model mTLS scope. Operator-healthcheck TLS is the
separate host-local operator client identity scope used by the operator
healthcheck/profile path.

Renewing service or governance TLS does not refresh the operator-healthcheck
client certificate, does not refresh the Remote Alpha profile certificate
metadata, and does not remove a CP profile `cert_metadata_expired` blocker
unless ES docs later prove a shared scope and route contract. Current docs do
not prove that shared scope.

## 10. Relationship To P0v Noninteractive Status

This replacement design is separate from P0v. At the time this replacement
design was recorded, P0v was design/static-test prep only for a future
read-only noninteractive status route. A later P0v tranche now implements only
the read-only
`operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format
json` observation route.

That later status route does not implement renewal or replacement, resolve
signer/custody, add fallback emitters, widen route eligibility, change MA
scheduled metadata, convert caller preflight blockers into ES status truth, or
create a route from status evidence to renewal permission. Renewal and
replacement remain blocked; signer/custody remains unresolved; no MA/IM/CP,
Bridge, or Coordinator authority changes.

Missing local runtime/schema/redaction prerequisites remain integration or
caller preflight blockers. The implemented P0v route uses a dedicated local
runtime and a streamed fixed collector with no fallback emitter, no staging,
and no remote summary.

P0v evidence may be used only as optional read-only evidence in a later
owner-approved replacement flow. P0v is not replacement authorization, is not
post-replacement acceptance by itself, never resolves signing or custody, does
not change `scheduled_execution_allowed=false`, and does not create MA, IM, CP,
Bridge, or Coordinator authority. Missing, failed, or blocked P0v evidence
remains a blocker or unknown according to the owner contract rather than a
reason to infer success.

## 11. Relationship To Maintenance Agent Biometric Leases

A future biometric lease may approve only the exact canonical plan digest for a
future owner-repo replacement plan. It does not:

- sign certificates;
- renew or replace TLS material;
- define signing topology or key custody;
- mutate profiles or profile lineage;
- run CP diagnose;
- approve CP acceptance;
- define IM lineage;
- make `unsupported_signing_topology` safe;
- make interactive routes scheduled or noninteractive.

If a lease is invalid, expired, consumed, mismatched, or outside route
eligibility, replacement stops before action.

## 12. Relationship To Bridge

Bridge preflight evidence is local-only and non-authoritative. Bridge does not
invoke ES, mutate certs/profiles, approve replacement, prove CP diagnostics,
refresh IM lineage, start/control ES/CP/IM/MA, or convert missing ES
prerequisites into ES status truth.

## 13. Relationship To CP And IM

CP owns the `diagnose-remote-profile` rerun and profile acceptance semantics.
The rerun happens only after refreshed owner-repo profile material exists.
CP does not become ES TLS signing authority.

IM owns Remote Alpha profile/provenance/readiness emission and profile-lineage
refresh artifacts. IM does not become ES TLS signing authority and must not
infer ES renewal eligibility from copied evidence.

Neither CP nor IM becomes ES signing authority unless an owning ES document
explicitly says so.

## 14. Stop Conditions

Replacement must stop when any of these are true:

- signing topology is unclear;
- signing authority is unclear;
- signer custody is unclear;
- key custody is unclear;
- CSR flow is unclear;
- key-pair match cannot be proven without exposing private key material;
- backup evidence is unavailable;
- owner is unclear;
- any private key, PEM body, raw certificate body, raw profile payload, raw
  env value, endpoint secret, unsafe path, raw log, support-bundle payload,
  retained-bundle payload, or proof payload would need exposure;
- profile lineage owner is unclear;
- CP diagnose expected input is unclear;
- replacement would require hidden SSH, provisioning, helper staging, or
  reconciler behavior outside the owner contract;
- rollback evidence is unavailable;
- redaction cannot be guaranteed;
- the exact plan digest does not match;
- a future biometric lease is invalid, expired, consumed, or mismatched;
- service/governance TLS renewal is being used as a substitute for
  operator-healthcheck TLS without ES docs proving a shared scope;
- hidden SSH, provisioning, helper staging, or reconciler behavior would be
  required outside the owner contract;
- a consumer attempts to treat replacement evidence as live proof, production
  readiness, CP run-control truth, IM authority, Bridge authority, or MA
  authority.

## 15. Validation Plan

Allowed validation for this design tranche:

- docs/static tests that this document exists and preserves owner boundaries;
- tests that no raw PEM/key/cert material is added to docs/examples;
- tests that `unsupported_signing_topology` remains the current
  operator-healthcheck renewal blocker;
- tests that service and governance TLS routes remain separate scopes;
- tests that Bridge and Maintenance Agent non-authority are preserved;
- tests that CP diagnose and IM lineage ownership remain in their repos;
- tests that no route eligibility, scheduled execution, lease, or macOS API
  implementation is added.

Disallowed validation in this tranche:

- remote contact;
- SSH, scp, BatchMode probes, sudo, or remote helpers;
- ES status/renewal routes;
- cert/key/trust/profile/env/state/support/retained/proof mutation;
- CP diagnose execution;
- IM live refresh or support-bundle collection;
- ES submit, Temporal, worker startup, validation driver, golden capture, or
  live proof.
