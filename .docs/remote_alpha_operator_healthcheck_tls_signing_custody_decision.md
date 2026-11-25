# Remote Alpha Operator-Healthcheck TLS Signer/Custody Decision Record

## 0. Purpose And Status

This decision record compares signer-authority and private-key custody models
for future Remote Alpha operator-healthcheck client TLS replacement.

Decision status for reusable P0u: blocked.

Decision question:

"What signer authority and private-key custody model may be used for operator-healthcheck client TLS replacement?"

Status:

- `Design/static-test prep only`: this record does not execute replacement,
  renewal, route execution, profile refresh, CP diagnose, IM refresh, remote
  contact, live proof, certificate generation, CSR generation, key generation,
  trust-bundle mutation, profile mutation, biometric lease creation, or
  authorization artifact creation.
- `Current invariant`: `operator-healthcheck-tls-renew` remains blocked with
  `unsupported_signing_topology`.
- `Bounded slice rule`: at the time this decision record was first recorded,
  the existing interactive `operator-healthcheck-tls-status` route was the only
  implemented operator-healthcheck TLS status route. A later P0v tranche now
  implements only read-only noninteractive status evidence.
- `Reopened redesign seam`: signer authority, signer custody, key custody,
  key reuse, key rotation, and CSR/cert material flow remain unresolved for the
  host-local operator-healthcheck client identity until ES documents
  source-grounded evidence and audits the exact owner path.

This record is separate from
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`
because the resolution document defines gates and required evidence, while this
record compares candidate signer/custody options and records that no option is
selected. It is also separate from
`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`, which records
the material-custody boundaries and stop conditions, and from
`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`,
which records the future replacement sequence.

The no-signer/no-replacement conclusion here continues to govern reusable P0u
`operator-healthcheck-tls-renew`. The separate single-use external-family
incident in
`.docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md`
does not unblock or widen P0u and provides no reusable signer or route;
`unsupported_signing_topology` remains the reusable-route result.

Related IM, CP, Maintenance Agent, and Bridge docs are references for non-ES
owner boundaries only; they do not create ES signing authority.

## 1. Decision Outcome

No option is selected for reusable P0u.

Reusable P0u replacement remains blocked. `operator-healthcheck-tls-renew` remains blocked
by `unsupported_signing_topology`. Service and governance TLS signers cannot be
reused by inference. CP, IM, Maintenance Agent, Bridge, biometric leases,
profile diagnostics, profile lineage, preflight evidence, support bundles,
retained bundles, proof artifacts, and reports cannot create ES signer
authority or key custody.

Future work must source-ground signer authority, signer custody, CA/trust
ownership, key custody, key action classification, CSR/cert flow,
backup/rollback, redaction, and post-check ownership before replacement
execution design can proceed.

## 2. Options Compared

### Option A: Reuse Service TLS Signer/CA

- Current source evidence: ES documents service TLS renewal as a separate
  ARS/AGS/ES artifact-registry mTLS scope. Current ES sources do not document
  service TLS as the signer for operator-healthcheck client TLS.
- Required missing evidence: explicit ES shared-scope contract for
  operator-healthcheck client TLS, signer owner, signer custody, CA/trust
  ownership, CP-expected issuer/trust metadata, key action policy, redaction,
  backup/rollback, route eligibility, and service-scope separation proof.
- Authority owner: none for operator-healthcheck today. If later selected, ES
  would need to document the shared signer owner and the exact scope.
- Custody implications: service signer private material must not be assumed,
  copied, exposed, or reused for operator-healthcheck by path similarity.
- Redaction implications: only safe labels, timestamps, public fingerprints,
  owner-allowed digests, redaction status, and non-authority labels may appear.
- CP/IM handoff implications: service TLS evidence cannot refresh
  operator-healthcheck profile metadata or clear CP profile blockers unless ES,
  CP, and IM later document that shared scope.
- Backup/rollback implications: service TLS backup/rollback evidence does not
  cover operator-healthcheck client TLS.
- Disposition: rejected by inference; blocked and not selected.
- Stop conditions: shared scope absent, signer custody unclear, CA/trust owner
  unclear, key custody unclear, CP/IM expected metadata unclear, or redaction
  unavailable.

### Option B: Reuse Governance TLS Signer/CA

- Current source evidence: ES documents governance TLS renewal as a separate
  ES to EGS execution-governance trust-model mTLS scope. Current ES sources do
  not document governance TLS as the signer for operator-healthcheck client
  TLS.
- Required missing evidence: explicit ES shared-scope contract for
  operator-healthcheck client TLS, signer owner, signer custody, CA/trust
  ownership, CP-expected issuer/trust metadata, key action policy, redaction,
  backup/rollback, route eligibility, and governance-scope separation proof.
- Authority owner: none for operator-healthcheck today. If later selected, ES
  would need to document the shared signer owner and exact cross-scope limits.
- Custody implications: governance signer private material must not be assumed,
  copied, exposed, or reused for operator-healthcheck by trust-model proximity.
- Redaction implications: only safe labels, timestamps, public fingerprints,
  owner-allowed digests, redaction status, and non-authority labels may appear.
- CP/IM handoff implications: governance TLS evidence cannot refresh
  operator-healthcheck profile metadata or clear CP profile blockers unless ES,
  CP, and IM later document that shared scope.
- Backup/rollback implications: governance TLS backup/rollback evidence does
  not cover operator-healthcheck client TLS.
- Disposition: rejected by inference; blocked and not selected.
- Stop conditions: shared scope absent, signer custody unclear, CA/trust owner
  unclear, key custody unclear, CP/IM expected metadata unclear, or redaction
  unavailable.

### Option C: Define A Dedicated ES-Owned Operator-Healthcheck Signer/CA

- Current source evidence: no current ES source defines a dedicated ES-owned
  operator-healthcheck signer, CA, issuer, trust chain, or signer custody.
- Required missing evidence: ES signer owner, signer private-material custody,
  CA/trust ownership, issuer/trust-chain metadata expected by CP, signer audit
  labels, rotation policy, failure classes, route eligibility, and
  service/governance separation.
- Authority owner: ES, only after a later ES doc/test/audit tranche selects
  this model.
- Custody implications: signer material and client key custody must remain
  explicitly owner-bound; CP, IM, Maintenance Agent, and Bridge remain
  non-custodians.
- Redaction implications: signer private material, private keys, PEM bodies,
  raw cert bodies, raw CSR bodies unless later allowed, env values, endpoint
  secrets, raw logs, support payloads, retained payloads, and proof payloads
  remain forbidden.
- CP/IM handoff implications: CP may diagnose only refreshed profile material
  after CP documents expected issuer/trust metadata; IM may refresh lineage
  only from owner-approved public metadata.
- Backup/rollback implications: ES must define backup-before-replace,
  rollback labels, owner confirmation labels, redaction status, and
  post-rollback checks before mutation.
- Disposition: deferred candidate; blocked and not selected.
- Stop conditions: signer owner absent, signer custody absent, CA/trust owner
  absent, CP expected metadata absent, key action unresolved, or redaction
  unavailable.

### Option D: Define A Host-Local Operator-Healthcheck Signer

- Current source evidence: no current ES source defines a host-local signer
  authority or host-local signer custody for operator-healthcheck client TLS.
- Required missing evidence: host-local signer owner, signer custody, signing
  audit labels, CA/trust ownership, issuer/trust metadata, signer rotation,
  client-key custody, route eligibility, and failure classes.
- Authority owner: host-local signer owner adopted by ES, only after ES
  documents and audits the exact owner path.
- Custody implications: signer material and client key material would stay
  host-local and owner-bound; private material must not be routed through CP,
  IM, Maintenance Agent, Bridge, reports, support bundles, retained bundles, or
  proof artifacts.
- Redaction implications: evidence may contain only safe labels, timestamps,
  public fingerprints, owner-allowed digests, redaction status, and
  non-authority labels.
- CP/IM handoff implications: CP expected issuer/trust labels and IM profile
  lineage inputs must be documented before refreshed profile material can be
  treated as current.
- Backup/rollback implications: host-local backup and rollback owner labels,
  safe public metadata, rollback targets, and post-rollback checks must exist
  before mutation.
- Disposition: deferred candidate; blocked and not selected.
- Stop conditions: host-local signer owner unclear, signer custody unclear,
  CA/trust owner unclear, client-key custody unclear, CP/IM metadata unclear,
  or hidden provisioning would be required.

### Option E: External/Manual Operator-Provided Public Cert Only

- Current source evidence: current ES docs allow future public-material
  metadata only after an owner contract. They do not authorize accepting a
  manually supplied public certificate as replacement authority.
- Required missing evidence: external signer owner, signer provenance, ES
  adoption decision, CA/trust ownership, expected issuer/trust metadata, public
  certificate delivery path, existing-key reuse approval, key-pair match method,
  backup/rollback, redaction, and failure classes.
- Authority owner: external signer owner plus ES verification/adoption, only if
  a later ES decision selects and audits that model.
- Custody implications: this option must remain public-cert-only. It cannot
  import, export, copy, escrow, print, hash for evidence, or expose the
  host-local private key.
- Redaction implications: reports may use public cert metadata labels and
  public fingerprints only; raw certificate bodies and PEM bodies remain
  forbidden unless a later ES contract explicitly allows a public-material
  channel.
- CP/IM handoff implications: CP and IM cannot accept the replacement by
  manual assertion; they require owner-approved public metadata and their own
  documented follow-up contracts.
- Backup/rollback implications: pre-replacement public metadata, rollback
  labels, owner confirmation, and post-rollback checks are required before any
  install.
- Disposition: blocked; not selected. Manual public cert input cannot be
  accepted as ad hoc signer authority.
- Stop conditions: signer provenance unclear, ES adoption absent, key reuse
  absent, key-pair match unavailable, trust metadata unclear, or redaction
  unavailable.

### Option F: CSR Flow From Host-Local Key To Future ES-Approved Signer

- Current source evidence: ES resolution criteria describe CSR flow as a future
  option, but no current source selects it or identifies the signer, CSR
  author, or custody owner.
- Required missing evidence: ES-approved signer, signer custody, CA/trust
  owner, CSR author, key action classification, CSR storage/cleanup labels,
  public-key binding, issuer/trust metadata, backup/rollback, redaction, and
  CP/IM handoff contracts.
- Authority owner: ES for the host-local CSR/key flow plus the signer owner
  selected by a later ES decision.
- Custody implications: CSR generation must occur inside host-local ES custody;
  private key material must never leave custody or appear in evidence.
- Redaction implications: only safe CSR labels, byte counts when allowed,
  public-key fingerprints, owner-allowed digests, redaction status, and
  non-authority labels may appear.
- CP/IM handoff implications: CP expected issuer/trust metadata and IM
  refreshed profile inputs must be documented before profile diagnostics or
  profile lineage can be updated.
- Backup/rollback implications: CSR flow still requires pre-replacement public
  metadata, backup labels, rollback target labels, redaction status, and
  post-rollback checks before mutation.
- Disposition: deferred candidate; blocked and not selected.
- Stop conditions: signer missing, CSR author unclear, key custody unclear,
  key action unresolved, raw CSR body required without owner contract, or
  redaction unavailable.

### Option G: Cert-Only Replacement Against Existing Host-Local Key

- Current source evidence: ES resolution criteria describe cert-only
  replacement as a future option, but no current source selects it, approves
  key reuse, or identifies an approved signer.
- Required missing evidence: ES-approved signer, signer custody, CA/trust
  owner, existing-key reuse decision, key custody owner, key-pair match method,
  public certificate delivery path, issuer/trust metadata, backup/rollback,
  redaction, and CP/IM handoff contracts.
- Authority owner: ES for cert install and host-local key custody plus the
  signer owner selected by a later ES decision.
- Custody implications: existing key reuse must be explicitly approved; the
  private key must not be copied, exported, escrowed, printed, hashed for
  evidence, or exposed.
- Redaction implications: only public certificate metadata, public-key
  fingerprint, issuer/trust labels, owner-allowed digests, redaction status,
  and non-authority labels may appear.
- CP/IM handoff implications: CP diagnostics and IM lineage can follow only
  after refreshed profile material is emitted through owner-approved public
  metadata contracts.
- Backup/rollback implications: cert-only still requires backup-before-replace,
  rollback labels, owner confirmation, redaction status, and post-rollback
  checks before mutation.
- Disposition: deferred candidate; blocked and not selected.
- Stop conditions: signer missing, key reuse not approved, key custody owner
  unclear, key-pair match unavailable, trust metadata unclear, rollback absent,
  or redaction unavailable.

## 3. External Evidence Requirements

Before this decision can move from blocked to selected, ES must document and
audit all of the following evidence:

- signer owner;
- signer custody;
- CA/trust ownership;
- issuer/trust metadata expected by CP;
- key custody owner;
- reuse vs rotation decision;
- CSR vs cert-only decision;
- key-pair match method that does not expose private-key material;
- backup/rollback owner and evidence labels;
- redaction proof;
- CP diagnose input contract;
- IM lineage refresh input contract.

Evidence must be source-grounded in ES-owned docs/tests or in an owning-repo
contract that ES explicitly adopts without widening that repo's authority.
Operator-provided or external material must include signer provenance,
trust/issuer metadata, owner labels, and redaction proof before ES can treat it
as candidate evidence.

## 4. Decision Consequences

Until a selected signer/custody model exists and is audited:

- no replacement execution;
- no renewal;
- no route eligibility widening;
- no noninteractive renewal route;
- no MA scheduled execution;
- no biometric lease approval path for renewal;
- no CP diagnose rerun;
- no IM refresh execution;
- no Remote Alpha proof resumption;
- no Bridge projection or preflight may become ES status truth;
- no service/governance TLS signer may be reused by inference.

The current helper and route behavior remains fail-closed. A future tranche may
change that only after this decision record is updated from blocked to selected
with source-grounded evidence and docs-contract coverage.

## 5. Relationship To Existing Docs

ES docs:

- `.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md` records
  custody boundaries and stop conditions.
- `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`
  records the evidence gate and exact criteria for resolving the stop
  conditions.
- `.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`
  records the future replacement sequence and keeps it separate from signer
  authority.
- `.docs/remote_alpha_operator_healthcheck_noninteractive_status.md` now
  records P0v as an implemented no-fallback read-only status route, not
  renewal or signer authority. At the time of this decision record, P0v was a
  design/static-only proposal.
- Historical status alignment: P0v was design/static only at the time of this
  decision record. A later P0v tranche implements read-only status only with no
  fallback emitter, no remote summary, no renewal, no signer/custody
  resolution, no scheduled execution, and no route from status to renewal
  permission.
- `.docs/system_overview/remote_supported_host_alpha.md` records the Remote
  Alpha route matrix and keeps `operator-healthcheck-tls-renew` blocked.

Related owner-boundary docs:

- IM `remote-alpha-operator-healthcheck-profile-lineage-refresh.md` records
  IM profile-lineage refresh as future owner-repo work over safe ES metadata
  only.
- CP `diagnose-remote-profile` owns contact-free profile diagnostics and
  profile acceptance; it does not create ES signer authority.
- MA `macos-biometric-maintenance-authorization.md`,
  `canonical-maintenance-plan-digest.md`, `biometric-lease-verifier-design.md`,
  and `route-eligibility.md` record leases and route metadata as approval and
  scheduling evidence only, not signing authority.
- Bridge `es-operator-healthcheck-preflight-design.md` records local-only,
  non-authoritative preflight evidence and must not be promoted to ES route
  truth.

## 6. Static-Test Expectations

Docs-contract tests should preserve that:

- this decision record exists;
- decision status is blocked, not selected;
- the decision question is present;
- options A through G are enumerated;
- no option is selected today;
- service/governance TLS reuse is not selected by inference;
- replacement remains blocked;
- `operator-healthcheck-tls-renew` remains blocked by
  `unsupported_signing_topology`;
- route eligibility is not widened;
- P0v was design/static-only at the time of this decision record. A later P0v
  tranche now implements read-only status only with no fallback emitter, no
  remote summary, no renewal, no signer/custody resolution, no scheduled
  execution, and no route from status to renewal permission;
- P0v was design/static-only at the time of this record, and the later
  implementation remains read-only with no fallback emitter;
- external evidence requirements are documented;
- no raw PEM/key/cert material is present;
- CP, IM, Maintenance Agent, Bridge, and biometric leases cannot provide ES
  signer authority;
- no route execution, renewal, CP diagnose, IM refresh, MA scheduled
  execution, Bridge control, or live proof is enabled.

Allowed validation is limited to docs/static tests and safe local checks.
Disallowed validation includes remote contact, SSH, scp, BatchMode probes,
ES status or renewal route execution, certificate or CSR generation,
cert/key/trust/profile/env/state/support/retained/proof mutation, CP diagnose
execution, IM refresh, service startup, ES submit, Temporal, workers,
validation drivers, golden capture, and live proof.
