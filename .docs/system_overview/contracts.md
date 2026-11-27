# Cross-Service Contracts

## 1. Purpose And Scope

This document inventories the current cross-service contracts in the Go repository.

A system contract, for this document, is any rule, DTO, route, shared payload, or ownership boundary that crosses service or runtime boundaries and that another component can rely on.

This document describes the repo's active cross-service behavior in the current bounded platform phase. A contract may be active today without being treated as a permanent endpoint.

## 2. How To Read This Document

This file uses four status labels.

| Label | Meaning |
| --- | --- |
| `Observed current contract` | A behavior, surface, or payload shape enforced by the current Go code and tests. |
| `Current invariant` | An active cross-service rule that other components currently depend on and that must not change silently during redesign. |
| `Temporary compatibility edge` | An active field, shape, or behavior retained for continuity or consumer compatibility, but not treated as a long-term architectural endpoint. |
| `Reopened redesign seam` | A currently active surface that `PLANS.md` explicitly reopens for redesign. Its present shape must not be mistaken for settled architecture. |

The labels are intentionally different:

- `Observed current contract` says what exists now.
- `Current invariant` says what must remain explicit and aligned while redesign is underway.
- `Temporary compatibility edge` says the system still uses it, but future work must not preserve it by inertia.
- `Reopened redesign seam` says the surface is live today and also explicitly under architectural review.

## 3. Shared Cross-Service Kernel

### Purpose

Describe the current shared kernel that multiple services use directly today.

The authoritative Workstream A classification of kernel-level shared contract,
service-owned contract, temporary compatibility edge,
implementation-only/current-slice detail, and reopened seam lives in
`shared_kernel.md`.

The shared kernel is not a standalone service boundary and not a cross-service
semantic dumping ground. A contract becomes kernel-level only when the
Workstream A decision explicitly classifies it that way.

### Current producers / consumers

- `AGS` produces aggregate artifact evidence using `internal/contracts/evidence/v1` for the publish path.
- `ES` treats the `internal/contracts/evidence/v1` artifact record as the canonical admission input.
- `ARS` stores and serves the evidence record as the first-class artifact representation, and ARS does not interpret signing semantics.
- `EGS` does not use either package; it has its own runtime-trust signing surface.

### Public surface

`Observed current contract`

- The repo now has one active shared artifact evidence kernel:
  - `internal/contracts/evidence/v1`
- `internal/contracts/evidence/v1` defines one aggregate `ArtifactEvidence` record with these top-level sections:
  - `claims`
  - `seal`
- The `claims` section currently carries:
  - `schema_version`
  - `package`
  - `admission`
- The `package` section currently carries:
  - `identity`
  - `publication`
- The aggregate evidence claims carry explicit `artifact_digest` and `payload_digest` fields inside `claims.package.identity`.
- `claims.package.identity` is the current kernel-level shared package-identity surface for the `AGS -> ARS -> ES` path.
- `claims.package.identity` is the shared-kernel identity surface ES consumes.
  `payload_digest` identifies payload bytes or payload content identity, while
  `artifact_digest` identifies artifact/package identity as currently derived
  and documented.
- `claims.package.publication` remains AGS-owned publish-time meaning carried inside the signed record; ES must not treat those publication claims as ES public admission grammar. From WI-2, workload grants (`.docs/execution_lifecycle/contracts.md`, section 5B) read one of them, `claims.package.publication.invoker.principal`, as an exact-match fact against ES configuration; that read adds nothing to ES request or response grammar, and no other publication claim reaches ES admission.
- `claims.admission.authorization` is intentionally limited to `derivation_spec_digest` and `output_id`.
- `claims.admission.execution` is intentionally limited to runtime env allowlist, required capabilities, `target_platform`, and `network_access`.

### Current invariants

`Current invariant`

- AGS signs canonical aggregate evidence bytes and ES reconstructs those bytes before verifying the evidence `seal`.
- When ES uses `internal/contracts/evidence/v1`, it verifies:
  - `claims.schema_version == "v1"`
  - expected `algorithm`
  - expected `key_id`
  - recomputed `content_digest`
  - signature over canonical aggregate bytes
- The aggregate evidence canonicalization is typed and normalizes current set-like collections such as:
  - publication `policy_decisions`
  - runtime allowlists and capability lists
- `artifact_digest` and `payload_digest` remain separate facts. ES cross-checks payload discoverability against evidence claims; it does not assume package identity and payload identity are the same thing.
- EGS runtime-trust signing is a separate contract and must not be conflated with either artifact kernel.

### Ownership boundary

- `AGS` owns aggregate evidence production.
- `ES` owns verification of the aggregate evidence record that now drives its first-class admission path.
- `ARS` owns storage and retrieval, not signature semantics.
- Shared packages are transport for explicitly classified shared contract logic,
  not owners of broader system policy, publication semantics, discovery
  semantics, ES lifecycle grammar, CP orchestration semantics, or generated
  evidence/projection outputs.
- Generated evidence, `.out` workspaces, support bundles, retained bundles,
  reports, traces, logs, summaries, and proof artifacts are not shared-kernel
  authority.

### Temporary compatibility edges

- The current ES evidence verification path reuses the AGS artifact signer trust settings already configured for provenance verification. That reuse is a first-cut compatibility choice, not a statement that the two verifier surfaces are permanently identical.

### Reopened seams

`Reopened redesign seam`

- The shared-kernel role of `internal/contracts/evidence/v1` remains explicitly reopened by `PLANS.md`.
- The new aggregate evidence record is active today, but it is still a first migration cut rather than the declared end-state kernel.

## 3A. Caller Authentication Contract

### Purpose

Define once what "authenticated SPIFFE caller identity" means for every
current service boundary: ARS, AGS, EGS, CGS, and ES. Authentication answers
who is calling. Authorization, which authenticated callers may use which
route, stays with each service and is described in that service's section.

### Current producers / consumers

- Callers present an X.509 client certificate on a mutual-TLS connection.
  Each service's TLS listener requires a client certificate that verifies
  against that service's configured client CA bundle, including on `/health`.
- ARS, AGS, EGS, CGS, and ES authenticate the caller of every route that
  checks a caller with the one shared package `internal/callerauth`. No
  service keeps its own copy of these rules.

### Public surface

`Observed current contract`

- `401` plain text `Authenticated caller identity required` when the
  request carries no acceptable caller identity.
- `403` plain text
  `Bootstrap PKI callers are not accepted; use a SPIRE-issued identity`
  when the client certificate was issued by the configured bootstrap issuer.
- Neither response says which rule refused the request.

### Current invariants

`Current invariant`

- The caller identity is read from the leaf certificate of the first verified
  client certificate chain. A request without a verified chain, or whose
  first chain has no leaf, has no caller identity.
- The verified chain must still be within its validity period at the time of
  each request, not only at the TLS handshake. A request has a caller
  identity only if at least one verified chain that starts with the leaf has
  every certificate between its `notBefore` and `notAfter` at the time the
  request is authenticated. Go's TLS server checks the chain once per
  connection, so without this rule a client that keeps its connection busy
  would stay authenticated after its certificate expired, which defeats
  short-lived certificates as the way to cut a caller off.
- The leaf must be an end-entity certificate. A leaf whose basic constraints
  mark it as a CA, or whose key usage includes `keyCertSign` or `cRLSign`,
  has no caller identity: the SPIFFE X.509-SVID standard requires every
  validator to refuse such a leaf, and a CA certificate that carries an ES
  identity would otherwise authenticate as that caller. The
  `digitalSignature` key usage is an issuer rule and is not checked.
- The leaf must carry exactly one URI SAN. A certificate with no URI SAN has
  no caller identity. A certificate with more than one URI SAN is refused
  even when one of them would be acceptable: the SPIFFE X.509-SVID standard
  allows exactly one URI SAN, and no service picks one of several.
  DNS-name, IP-address, and e-mail SANs are not read.
- That URI must be a SPIFFE ID in the trust domain `execution.internal`,
  written as `spiffe://execution.internal/<segment>[/<segment>...]`, where
  every segment is one or more of `A-Z`, `a-z`, `0-9`, `.`, `-`, and `_` and
  is not `.` or `..`. These are the SPIFFE ID rules of the SPIFFE standard,
  plus the requirement of a path, because the trust domain's own ID names no
  workload.
- Therefore refused: any other trust domain (including names that contain
  `execution.internal`), user information, a port, upper-case letters in the
  trust domain, a query, a fragment, percent encoding, an empty segment, a
  trailing slash, `.` and `..` segments, and an ID without a path.
- A caller whose path starts with the segment `workload`, in any letter
  case, has no caller identity, at every service. That covers the shared
  workload ID `spiffe://execution.internal/workload`, the named workload
  identities `spiffe://execution.internal/workload/<name>`, and the per-run
  identities reserved below them (`runtime_identity_handoff.md`, section
  11.2). Workload identities exist so that workloads can log in to the
  workload-zone Vault; they are never callers, and a later design that lets a
  workload call a service must change this rule explicitly. A path that only
  contains the word later, such as `service/workload`, or whose first segment
  is longer, such as `workloads`, is not affected. The comparison ignores
  letter case on purpose, so no configuration can name a workload identity
  in another letter case. It closes letter-case variants only: a different
  word, such as `workloads/x` or `work-load/x`, is a different SPIFFE ID and
  stays a valid path.
- The rule applies to the URI as Go's certificate parser hands it over. That
  parser lower-cases the URI scheme and drops an empty fragment (a trailing
  `#`), so such a SAN names the same ID as without them. go-spiffe's
  `x509svid.IDFromCert` reads a certificate the same way.
- Identity failures return `401` before the bootstrap-issuer rule runs. A
  caller whose leaf certificate names the configured bootstrap issuer common
  name (`security.bootstrap_issuer_common_name`, compared exactly after
  trimming surrounding white space from the configured value) gets `403`.
- Every service's startup configuration refuses an empty bootstrap issuer
  common name. A service whose authenticator has none refuses every request
  with `401`.
- AGS and ES also apply namespace issuer bindings, configured in
  `security.namespace_issuers`. Each binding names a path namespace
  (`path_prefix`, the path of a SPIFFE ID that this section accepts, without
  its leading slash, such as `user`) and one CA certificate of the service's
  client CA bundle by the SHA-256 of its DER encoding
  (`issuer_certificate_sha256`, 64 lower-case hexadecimal characters). The
  binding holds in both directions. A CA bound to a namespace vouches for no
  path outside it, and a path in a bound namespace needs that namespace's CA:
  a caller gets `401` when a verified chain of its certificate that starts
  with the leaf ends at a bound CA while its path is neither that namespace
  nor a path continuing it after a `/`, and when its path is in a bound
  namespace while any such chain ends at another certificate. So a CA bound
  to `user` can never vouch for `operator/local`, and no other CA can vouch
  for `user/claude`. The rule runs after the bootstrap-issuer rule. Without
  bindings it changes nothing. An X.509 URI name constraint cannot do this:
  it can hold a CA to the trust domain but not to a path inside it.
- Startup refuses a malformed binding, a binding of a `workload` namespace
  (workload identities are never callers, so no CA vouches for one), two
  bindings of one CA, and two bindings whose namespaces are equal or one
  lies within the other, and names the entry. Startup does not check that a bound CA is in the client
  CA bundle: a binding whose CA is absent leaves its namespace with no CA
  that can vouch for it. ARS, EGS, and CGS have no such field and their
  client CA bundles must not hold a bound CA. On the Remote Alpha box,
  `scripts/remote_alpha_user_identity.sh` writes the one binding, `user` to
  the user CA, with every `allow`, and removes it with `revoke --remove-ca`
  (`.docs/system_overview/remote_supported_host_alpha.md`, section "Remote
  Alpha User Caller Identities").
- After authentication, services authorize the canonical identity only: the
  path after `spiffe://execution.internal/` for path-prefix and exact-path
  allowlists, and the full canonical SPIFFE ID where a service compares
  whole identities (AGS publication caller binding, CGS caller/workload
  match). A path that is not in canonical form never reaches authorization.
- ARS, AGS, and ES check and match their path-prefix allowlists with the one
  shared package `internal/callerallowlist`. A configured prefix must be the
  path of a SPIFFE ID that this section accepts, without its leading slash,
  and must have at least two segments. Each of those services refuses any
  other prefix at startup: no authenticated caller could ever match it, or a
  one-segment prefix such as `service` would grant every identity below it. A
  prefix matches the caller path that equals it and every caller path that
  continues it after a `/`, so `operator/local` matches `operator/local/a` but
  not `operator/local-evil`. A prefix that fails the rule matches nothing.
- A configured prefix whose first segment is `workload`, in any letter case,
  is refused at startup like any other prefix no caller could match, with
  its own message, and `id.conf` loading refuses a workload identity as a
  principal the same way.

### Ownership boundary

- `internal/callerauth` owns caller authentication only, including the
  namespace issuer rule. It does not own any allowlist, route, policy
  decision, or service grammar, nor which bindings a service configures.
- `internal/callerallowlist` owns only the shape of a valid path prefix and
  the prefix match that ARS, AGS, and ES share. It owns no allowlist content
  and no route: which prefixes each of those services configures, and which
  routes they open, stay with that service.
- Each service owns its authorization: ARS read prefixes and its writer
  path, AGS and ES configured prefixes, EGS's fixed caller list, and CGS's
  caller/workload match plus `id.conf`.

### Temporary compatibility edges

- The bootstrap issuer is recognized by the issuer common name string in the
  leaf certificate, not by the issuing key. The rule lives in one place so a
  stronger rule can replace it in one change.

### Reopened seams

`Reopened redesign seam`

- One trust domain is accepted. Federation with other trust domains is not
  designed; adding it requires an explicit contract change, not a list in
  configuration.
- The inert outside-observer protocol
  (`.docs/execution_lifecycle/outside_observer_protocol.md`) names fixed
  SPIFFE ID values in the trust domain `governed-execution.local`. They are
  message field values, not callers of any service today. If that observer
  ever authenticates to an ES service over mutual TLS, this contract refuses
  it until the trust-domain rule is changed explicitly.

## 3B. Known Signing Key Contract

### Purpose

Define once which Ed25519 signing keys no service may sign or verify with,
because anyone can know their private halves or sign for them without one.
AGS evidence signatures and EGS runtime-trust signatures are the only proof
ES has of who published an artifact and which signers are allowed; a key
whose private half is public, or that needs none, proves nothing.

### Current producers / consumers

- AGS refuses such a key as `signer` at startup, EGS refuses one as `signer`
  at startup, and ES refuses one as any `verification` key at startup, all
  through the one shared package `internal/knownkeys`. No service keeps its
  own copy of the rule.
- `scripts/internal/signingkeygen` generates each host's own AGS and EGS
  keys, and `scripts/72_supported_local_setup.sh` uses it for every
  supported-local install (`configuration.md`, "Signing keys").

### Public surface

`Observed current contract`

- A refused key stops the service before it listens, with an error that
  names the configuration field, says which family the key is in (the
  repeated byte of a known key, or a point of small order), and says that the
  host needs its own key. No network response carries the rule.

### Current invariants

`Current invariant`

- A known key is an Ed25519 key whose 32-byte private seed is one byte
  repeated: 256 keys. The family includes the two keys of the repository's
  example configurations and of every supported-local install made before
  setup generated its own: seed `0x11` repeated (AGS, public key
  `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737`) and seed
  `0x33` repeated (EGS, public key
  `17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce`).
- A public key that needs no private key is refused the same way: one of the
  14 values that `crypto/ed25519` decodes to a point of small order (the
  eight such points, the two whose x is 0 also written with the sign bit set,
  and the four written with y = p or y = p + 1, each with either sign bit).
  Anyone can make a signature
  that verifies under such a key. 32 zero bytes is one of them, so a
  placeholder of zeros is refused like a known key. A test derives the eight
  points from the curve and checks the list against every encoding of them
  under which a signature made without a key verifies.
- AGS and EGS refuse a 64-byte `signer.private_key_hex` whose second half is
  not the public key of its first half. Its signatures verify under no key,
  and they would give the seed away once the same bytes were signed again
  under the right public key.
- AGS and EGS refuse a configuration file that other users can read or
  write, or that is not a regular file, since it holds the private key: the
  check is on the opened file.
- AGS and EGS check the public key derived from `signer.private_key_hex`
  (a 32-byte seed, or a 64-byte private key, whose seed and public half are
  both checked) and `signer.public_key_hex`. ES checks the `public_key_hex`
  of `verification.trust_model`, `verification.provenance`,
  `verification.derivation_attestation` and
  `verification.workload_identity_binding`.
- The check is part of each service's configuration loading, so every tool
  that loads a configuration the way the service does refuses the same keys;
  `scripts/internal/esconfigcheck` is one. A host still on known keys is
  stopped by AGS, EGS and ES refusing to start on binaries that have the
  check, whichever path installed them.
- Outside Go test files, every value given to a signer or verification key
  field (`private_key_hex`, `public_key_hex`) in the repository is a known
  key, so no configuration it ships or a script writes can give a real
  install a key a service accepts. A test in `internal/knownkeys` scans the
  repository for values given to those fields, and another loads each
  example configuration: refused as it is, with exactly the known-key error,
  and accepted with fresh keys. A key held in some other form, such as an
  unlabelled constant, is not something the scan sees.

### Ownership boundary

- `internal/knownkeys` owns only the definition of a known key, the list of
  points of small order, and the check. It owns no key, no key ID, no allow
  list, and no trust decision.
- Each service owns which keys it configures; EGS owns which AGS key IDs it
  allows; ES owns which keys it verifies with.

### Temporary compatibility edges

- None. The rule refuses; it keeps no old key working.

### Reopened seams

`Reopened redesign seam`

- Private signer keys are held inline in the AGS and EGS configuration
  files, protected by the file's owner and mode. A separate key file or
  key-custody service with its own checks, and key rotation as a service
  operation rather than a configuration change, are not designed.

## 4. Workload-Zone Vault Runtime-Config Contract

### Purpose

Define the shared reference and blob schema ES uses to resolve workload-zone Vault runtime settings.

The authoritative E0 runtime-config ownership decision lives in
`runtime_config_ownership.md`.

### Current producers / consumers

- Startup config installs the required `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`.
- `ES` consumes that reference directly from its validated startup config.
- `ARS` serves the blob addressed by the reference digest.
- There is no ACS hop in the runtime-config path.

### Public surface

`Observed current contract`

- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigRef`
- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`
- `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfig`

### Current invariants

`Current invariant`

- The workload-zone Vault config reference is explicit and typed rather than being an anonymous digest string.
- The workload-zone Vault blob schema is defined by `internal/contracts/runtimeconfig/v1.WorkloadZoneVaultConfigBlob`.
- The current blob schema carries the Vault HTTPS address, JWT auth mount, auth role, JWT audience, and optional non-secret `ca_bundle_pem` trust material for Vault TLS verification.
- ES consumes the typed `WorkloadZoneVaultConfig` derived from that blob rather than owning ad hoc local parsing of the blob shape.
- ARS remains the blob storage and read authority after the digest is known.
- Runtime-config semantics are owned by the runtime-config contract surface,
  not by ARS blob mechanics, ES startup placement, CGS, EGS publication
  metadata, IM profiles, support bundles, or CP orchestration.
- Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads,
  leases, Codex credential material, or runtime identity handoff.
- Optional `ca_bundle_pem` remains non-secret TLS trust material for standard
  TLS/env-based verification, not token truth or relaxed verification.

### Ownership boundary

- `internal/contracts/runtimeconfig/v1` owns the shared schema surface for the reference and blob meaning.
- ES startup validation currently owns the guarantee that a workload-zone Vault config reference has been installed before ES serves traffic. This is a reference-availability guarantee, not a startup blob-fetch guarantee.
- ES is the current runtime-config consumer and lookup orchestrator during `:prepare` and `:submit`.
- ARS owns blob storage and retrieval by digest only. ARS does not own workload-zone Vault runtime-config semantics.

### Temporary compatibility edges

`Temporary compatibility edge`

- The current reference still identifies the blob by digest. That is an active bounded choice, not a statement that all future runtime-config discovery must remain digest-only.
- ES startup-config placement of `runtime_config.workload_zone_vault_config_ref`
  is compatibility/config residue on a reopened ownership seam unless a later
  Workstream E slice explicitly decides otherwise.
- `workload_vault_auth.default_mode` is current ES config residue and bounded
  current behavior, not a generalized runtime-auth-plan contract.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority or live credential truth.

### Reopened seams

`Reopened redesign seam`

- The long-term owner of the workload-zone Vault runtime-config surface remains explicitly reopened in `PLANS.md`.
- The current startup-configured replacement surface is active today, but it is not yet the declared end-state config ownership model.
- The digest-only ref shape remains active but not final runtime-config
  architecture.

## 5. AGS Publication Contract

### Purpose

Accept bounded publication input, assemble the canonical aggregate evidence record, and publish the resulting artifact package through ARS.

The authoritative Workstream B classification of AGS publish-time ownership,
ARS storage/discoverability authority, canonical runtime-discoverable
surfaces, secondary publication/support detail, and reopened seams lives in
`artifact_publication_storage.md`.

### Current producers / consumers

- `AGS` consumes the ARS write boundary.
- `ES` later consumes AGS output indirectly through ARS reads.

### Public surface

`Observed current contract`

- `POST /v1/artifacts:publish`

Current request shape:

- `artifact_payload_b64`
- `artifact`
- `publication`
- `admission`

Current response shape:

- `published`
- `artifact_digest`
- `discovery_digest`
- `descriptor_digest`
- `evidence_digest`
- `manifest_digest`
- `payload_digest`

### Current invariants

`Current invariant`

- AGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A.
- AGS authorizes publish callers by configured SPIFFE path prefixes from `authorization.allowed_spiffe_path_prefixes`, checked at startup and matched under the allowlist-prefix rule in section 3A.
- The current repo-owned runbooks, proofs, and generated helper configs keep that AGS caller allowlist operator-only:
  - `spiffe://execution.internal/operator/local`
- The first repo-owned non-operator AGS caller activation path is Control Plane at:
  - `spiffe://execution.internal/service/control-plane`
- AGS computes `payload_digest` from payload bytes.
- AGS derives `artifact_digest` separately from deterministic package identity inputs: `payload_digest`, `artifact_type`, and `intent_digest`. Artifact identity is no longer equal to payload identity by shortcut, and it is no longer derived from admission/runtime claim material.
- AGS now also assembles and signs one aggregate `internal/contracts/evidence/v1` record whose `claims` section is deliberately split between:
  - `claims.package` for publication/discoverability-facing meaning
  - `claims.admission.authorization` for derivation request-binding meaning only
  - `claims.admission.execution` for the smaller shared runtime contract ES currently consumes:
    - runtime env allowlist
    - required runtime capabilities
    - `target_platform`
    - `network_access`
- AGS assembles and uploads:
  - payload bytes
  - aggregate artifact evidence
  - manifest
  - runtime-facing artifact discovery record
  - artifact descriptor as secondary publication/support data
- AGS signs aggregate artifact evidence using `internal/contracts/evidence/v1`.
- AGS derives publication caller binding directly from the authenticated caller SPIFFE identity, records the caller path as `claims.package.publication.invoker.service`, and always emits `claims.package.publication.builder_service = "artifact-governance"` in aggregate evidence.
- AGS now rejects non-docker `admission.workload.target_platform` values at publish time because the active shared runtime contract only admits empty or `docker` target platforms.
- AGS publish requests currently carry execution access at `admission.access.network_access`; that runtime-facing input is emitted into `claims.admission.execution.access` rather than into shared authorization claims.
- Non-runtime workload metadata such as `artifact_class`, `workload_type`, `service_name`, `workload_identity_id`, and `description` no longer live inside the shared execution/runtime evidence claims.
- `policy_decisions` are caller-supplied and are normalized structurally for signing, but AGS does not semantically evaluate them.
- AGS publishes only through ARS:
  - `PUT /v1/blobs/{digest}`
  - `POST /v1/artifacts:register`
  - registration is now discovery-centered rather than tuple-centered, with optional secondary descriptor support

### Ownership boundary

- AGS owns artifact-fact assembly, signing, upload, and registration.
- AGS does not own EGS runtime-trust publication, runtime admission, scheduler behavior, or runtime credential delivery.

### Temporary compatibility edges

`Temporary compatibility edge`

- None on the current AGS publish path.

### Reopened seams

`Reopened redesign seam`

- The AGS publish contract and fact-assembly model are explicitly reopened in `PLANS.md`.
- The current runtime-facing discovery record, secondary descriptor support data, and caller-binding model are live today, but they are not automatically the target end-state.

## 6. ARS Storage And Discoverability Contract

### Purpose

Provide content-addressed blob storage, integrity enforcement, artifact registration, and runtime-facing artifact discoverability.

### Current producers / consumers

- `AGS` is the fixed writer for the current ARS write boundary.
- `ES` consumes ARS for runtime-facing discovery, evidence and payload blob
  reads, and workload-zone vault blob reads.
- Descriptor/manifest support data remain ARS-owned secondary publication
  detail for publication/support reads; they are not required ES admission
  inputs on the current hot path.
- Other read callers may access ARS if their SPIFFE path matches configured allowed prefixes. ARS checks those prefixes at startup and matches them under the allowlist-prefix rule in section 3A.

### Public surface

`Observed current contract`

Write surface:

- `PUT /v1/blobs/{digest}`
- `POST /v1/artifacts:register`

Read surface:

- `HEAD /v1/blobs/{digest}`
- `GET /v1/blobs/{digest}:bytes`
- `GET /v1/blobs/{digest}:json`
- `GET /v1/artifacts/{artifact_digest}/discovery`
- `GET /v1/artifacts/{artifact_digest}/descriptor`
- `GET /v1/artifacts/{artifact_digest}/evidence`
- `GET /v1/artifacts/{artifact_digest}/manifest`

Current registration record is discovery-centered:

- `artifact_digest`
- `discovery_digest`
- `descriptor_digest`
- discovery `artifact` identity
- discovery references for evidence and payload
- optional secondary descriptor support data for publication-only reads such as manifest

### Current invariants

`Current invariant`

- ARS is the only current publication and retrieval boundary for published artifacts.
- ARS authenticates every read and write caller under the caller authentication contract in section 3A, including the bootstrap-issuer refusal on both paths.
- Write access is limited to SPIFFE caller path `service/artifact-governance`.
- `PUT /v1/blobs/{digest}` recomputes the digest from received bytes.
- Upload is idempotent for identical content.
- `HEAD /v1/blobs/{digest}` is an integrity check, not a mere presence check.
- `GET /v1/blobs/{digest}:bytes` and `GET /v1/blobs/{digest}:json` both re-read and re-verify blob integrity on the read path.
- `GET /v1/blobs/{digest}:json` additionally requires the blob bytes to be valid JSON.
- Artifact reads become visible only after successful registration.
- ARS serves the registered discovery record as the first-class artifact discoverability surface at `/v1/artifacts/{artifact_digest}/discovery`.
- ARS requires `discovery_digest` for artifact registration.
- `descriptor_digest` is optional secondary support data for descriptor and manifest reads.
- Descriptor/manifest/index/support tuples are compatibility/support or
  implementation-only surfaces unless explicitly migrated.
- ARS resolves `/evidence` reads through the registered discovery record and `/manifest` reads through the secondary descriptor support path when present, using the current descriptor `package.supporting[name=manifest]` reference.
- Registration validates every referenced digest by:
  - checking digest syntax
  - validating discovery structure and identity fields
  - reading the referenced blob through the storage layer
  - rejecting missing or corrupted blobs
  - requiring JSON validity for the discovery, evidence, and any secondary descriptor/manifest blobs the registration includes
- Registration is idempotent for the same discovery/descriptor tuple and a conflict for a different tuple under the same `artifact_digest`.
- ARS read paths treat referenced blob corruption as a storage failure, not as valid discoverability.

### Ownership boundary

- ARS owns storage correctness, read integrity, and discoverability.
- ARS does not own signature verification, trust enforcement, or policy evaluation.

### Temporary compatibility edges

`Temporary compatibility edge`

- Descriptor read/support path (`GET /v1/artifacts/{artifact_digest}/descriptor`, optional `descriptor_digest`) is a system-visible compatibility edge retained so publication/support consumers can keep the current secondary descriptor read while the ARS discovery record stays canonical for runtime discoverability. Scope: support-only descriptor registration and reads, not ES hot-path admission or ES public grammar. Removal condition: replace only with a documented support-surface migration, deprecation path, or explicit versioning plan first. See `artifact_publication_storage.md` for the full Workstream B metadata.
- Manifest read/support path (`GET /v1/artifacts/{artifact_digest}/manifest` through descriptor `package.supporting[name=manifest]`) is a system-visible compatibility edge retained so current publication/support consumers can keep manifest reads without treating manifest as canonical runtime discoverability. Scope: secondary manifest support data only, not ES hot-path admission or ES public grammar. Removal condition: replace only with a documented support-surface or descriptor-layout migration, deprecation path, or explicit versioning plan first. See `artifact_publication_storage.md` for the full Workstream B metadata.

### Reopened seams

`Reopened redesign seam`

- The ARS registration and index model are explicitly reopened in `PLANS.md`.
- The current runtime-facing discovery record and secondary descriptor support shape are active, but must not be assumed long-term solely because ES currently consumes them.

## 7. ES Admission And Execution Contract

### Purpose

Compose startup-owned runtime-config references, ARS, and EGS into governed admission and one bounded execution submit path, then project lifecycle state from Nomad.

The authoritative Workstream C classification of ES public execution surfaces,
admission composition, scheduler handoff, runtime-package resolution,
retained-result ownership, runtime-profile handling, and compatibility edges
lives in `.docs/execution_lifecycle/es_execution_admission_model.md`.

### Current producers / consumers

- ES consumes:
  - the configured workload-zone Vault config reference
  - ARS discovery, artifact evidence, and payload/blob reads on the current
    hot path
  - ARS descriptor/manifest support data only as secondary
    publication/support detail, not as required ES admission inputs
  - EGS runtime-trust publication
  - Nomad job and allocation APIs

### Next milestone classification

`Current invariant`

Stable semantic contracts for the ES Admission And Runtime Boundary Realignment package:

- C0 is the docs and docs-contract-test gate for ES admission, prepare,
  submit, lifecycle projection, retained-result ownership, runtime-profile
  compatibility, runtime handoff, outcome evidence, runtime identity/workload
  credential handoff boundaries, and Control Plane compatibility. C0 makes no
  runtime implementation changes, and Workstream C implementation must not
  start until C0 docs and docs-contract tests pass.
- C2 is the tests/docs guardrail slice for submit and lifecycle projection. It
  keeps `POST /v1/executions:submit` as the ES-owned async execution handoff
  through Nomad, keeps the submit receipt bounded and free of Control Plane
  attempt/review/checkpoint/finalization/intervention, approval,
  hold/resume/reject, Temporal, or workflow grammar, keeps
  `lifecycle_projection.source=nomad` with an opaque same-run
  read-coordination `revision`, preserves status/logs/result/cancel and
  `control-plane-normal-shell/v1` compatibility, and does not redesign
  runtime behavior.
- C3 is the focused tests/docs guardrail slice for retained-result and
  `authority_handoff` boundaries. C3 is guardrail work, not runtime redesign.
  C3 pins that retained result bundles remain ES-owned opaque output artifacts
  and that CP may materialize, review, checkpoint, and finalize retained result
  contents semantically, but CP does not own the retained bundle as run-control
  state. Retained result references, paths, manifests, archives, `.out`
  copies, and materialized workspaces are evidence/projection or
  implementation detail, not orchestration authority.
  `GET /v1/executions/{run_id}/result` compatibility shape remains unchanged
  unless an explicit migration/versioning plan exists. `authority_handoff`
  remains bounded non-secret runtime handoff evidence only.
  `authority_handoff` never carries or implies live credentials, Vault tokens,
  Codex credentials, leases, approvals, operator authorization, CP workflow
  state, scheduler truth, or retained-result authority. Runtime identity/Vault
  handoff remains workload-side and non-secret; ES does not become a Vault
  token broker or Codex credential broker. `outcome_evidence` remains bounded
  evidence/projection; current labels remain compatibility surfaces.
  `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- C4 is the focused tests/docs guardrail slice for runtime identity and Vault
  handoff boundaries. C4 is guardrail work, not runtime redesign and not live
  helper execution. Runtime identity acquisition is workload-side or
  helper-mediated at runtime, not CP-owned and not IM-owned. ES may stage
  non-secret runtime identity and Vault configuration metadata, but ES must
  not mint, fetch, broker, parse, store, rotate, or validate Vault tokens. ES
  must not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies,
  private keys, API keys, proof secrets, root tokens, unseal keys, Vault client
  tokens, or secret payloads through public DTOs, lifecycle responses,
  retained-result metadata, summaries, logs, reports, `.out`, support bundles,
  or proof artifacts. `authority_handoff` may include non-secret
  credential-location and configuration metadata only. `authority_handoff`
  must not carry live credentials, leases, approvals, Vault tokens, Codex
  credentials, JWT-SVIDs, API keys, or scheduler truth. Workload-side Vault
  auth remains workload-side; Vault owns token, secret, and lease authority.
  SPIRE owns identity issuance and SVID material. ES must not expose raw SPIRE
  socket access to workloads as public ES grammar.
  `EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the workload-facing identity
  endpoint contract rather than raw SPIRE socket access. Runtime identity and
  Vault handoff evidence remains non-authoritative and redacted. CP may
  consume runtime identity/Vault handoff evidence, but CP does not own
  credential acquisition, Vault tokens, SPIRE identity issuance, or ES runtime
  handoff boundaries. IM and Maintenance Agent may report
  diagnostics/readiness/status, but do not own runtime identity or Vault
  authority. `control-plane-normal-shell/v1` and
  `execution_substrate.runtime_profile` compatibility remain preserved unless
  an explicit migration/versioning plan exists. Existing workload-auth Remote
  Alpha helpers remain bounded operator/support surfaces, not ES token
  brokerage or production Vault readiness.
- C5 is the focused tests/docs guardrail slice for current
  status/logs/result/cancel compatibility and non-authority posture. C5 is
  guardrail work, not runtime redesign, live proof, or remote validation.
  Status remains Nomad-backed lifecycle projection and evidence, not CP
  workflow truth or ES lifecycle-store truth. Logs remain a bounded current
  compatibility/evidence surface, not final log architecture, CP run-control
  truth, or scheduler authority. Result remains opaque ES-retained output
  delivery, not CP checkpoint, finalization, or review state. Cancel remains a
  bounded ES/Nomad cancellation handoff, not CP intervention authority,
  operator approval authority, or Temporal workflow truth. Status/cancel JSON
  envelopes and successful logs/result headers must exclude CP run-control
  grammar and live credential/security fields, while logs/result bodies remain
  payload/output surfaces under the existing compatibility contract and are
  not newly sanitized, interpreted, or promoted into authority.
- ES owns governed admission composition, submission handoff, Nomad-backed lifecycle projection, retained opaque result-bundle ownership, and runtime handoff boundary enforcement.
- ES owns the public admission model, prepare model, submit model,
  Nomad-backed lifecycle projection, retained opaque result bundles,
  runtime-profile compatibility, runtime-boundary handoff semantics, and
  bounded runtime identity/workload credential handoff boundaries.
- ES owns final admission policy for ES-bound executions. ES Admission Policy
  Layer v0 is a small local policy-evaluation seam in the shared
  `:prepare`/`:submit` admission path, not a CGS/EGS policy-language
  redesign, OPA/Rego surface, DSL, customer regex configuration, signed
  policy-bundle system, external policy service, or durable policy-decision
  store.
- ES does not own artifact publication, artifact storage, runtime-trust publication, scheduler state, Control Plane orchestration, checkpoint, review, finalization, Vault token brokerage, or Codex token brokerage.
- Control Plane owns orchestration, Temporal workflow state, review,
  checkpoint, finalization, intervention, and operator-facing control
  semantics. CP consumes accepted ES surfaces but does not define ES core
  contracts.
- IM readiness/profile/support-bundle/provenance artifacts remain
  evidence/projection/diagnostics only; they do not become ES or CP authority.
- Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs
  only and do not define ES route semantics.
- Nomad remains authoritative for submitted execution lifecycle; ES exposes a bounded projection and must not synthesize a parallel lifecycle authority.
- ES status exposes a bounded `lifecycle_projection` read-coordination fact derived from Nomad observation. Its `revision` is an opaque same-run read-coordination token for status reads; callers may compare equality/change for the same run only. It is not parseable or orderable scheduler state, a scheduler ID, a write precondition, or an ES-owned lifecycle record. It is not a Control Plane workflow version or revision, result-reference id, or Nomad allocation id, and not proof of global freshness outside the documented same-run status read model.
- `lifecycle_projection` remains a Nomad-backed projection with `source=nomad`
  and an opaque read-coordination revision; it is not a Nomad scheduler id, ES
  lifecycle store, or write guard.
- ES lifecycle/status/result/log/cancel surfaces may expose additive `outcome_evidence` descriptors for evidence ES directly observed or retained: Nomad-backed status projection depth, accepted Nomad stop requests, Nomad task stdout, and opaque ES-retained result bundles. These descriptors are read-only evidence labels, not lifecycle ownership, scheduler identifiers, policy truth, credential truth, or write preconditions.
- `outcome_evidence` remains bounded evidence/projection; current labels are
  compatibility surfaces, not final scheduler/result/log/cancel vocabulary.
- Status/cancel JSON envelopes and successful logs/result headers must not
  expose Control Plane run-control grammar, Temporal workflow truth, operator
  approval authority, backend scheduler IDs as public authority, or live
  credential/security material. Logs and result bodies remain payload/output
  surfaces; their raw content is not an ES-owned authority source.
- ES submit/status expose a bounded `authority_handoff` read fact for submitted runs when ES can recover the submitted runtime handoff. It contains only non-secret facts ES selected or derived during admission/runtime handoff: runtime profile, workload identity endpoint handoff, workload-vault auth plan metadata, selected workload-zone Vault config digest, and bounded profile credential-location metadata. It is not live credential, lease, token-expiry, approval, scheduler-ID, or lifecycle-store state.
- `authority_handoff` remains bounded non-secret runtime handoff evidence; it
  never becomes a live credential, lease, approval, or scheduler truth.
- ES-retained result bundles are opaque output material. They are not logs wrappers, CP checkpoints, review decisions, finalization records, or ES-owned orchestration state.
- ES-retained result bundles remain opaque output artifacts owned by ES; CP
  may materialize, review, and finalize their contents semantically, but CP
  does not own the retained bundle as run-control state.
- The workload credential handoff is non-secret and workload-side: ES injects identity and credential-location metadata, while the workload uses the discovered endpoint and workload-Vault metadata to acquire material itself.
- Runtime identity and workload credential handoff remain non-secret and
  workload-side; ES must not become a Vault token broker or Codex credential
  broker.
- Caller identity and narrow configured SPIFFE allowlist authorization remain required on the governed execution path.

`Temporary compatibility edge`

Compatibility edges to preserve during the next package unless a coordinated migration/versioning note says otherwise:

- current CP compatibility for AGS publish plus ES prepare, submit, status, logs, result, and cancel
- `GET /v1/executions:contract` as a narrow read-only producer compatibility declaration for the current governed-execution contract and mandatory outcome-evidence surfaces
- `GET /v1/executions:contract` remains a narrow producer compatibility
  declaration, not health, submit readiness, run authority, or a general
  capability registry.
- `POST /v1/executions:prepare` as an active bounded preflight surface
- `POST /v1/executions:prepare` remains bounded preflight and creates no run
  object or scheduler handoff.
- `POST /v1/executions:submit` remains the MVP execution handoff surface:
  async, bounded receipt, and Nomad submission through ES.
- `invocation.annotations["execution_substrate.runtime_profile"]` and the bounded `control-plane-normal-shell/v1` profile
- `control-plane-normal-shell/v1` and `execution_substrate.runtime_profile`
  compatibility remain preserved unless an explicit migration/versioning plan
  exists.
- `/execution/staged`, `/execution/run`, `/execution/run/result`, and current runtime-identity path conventions
- the exact `authority_handoff` field names, evidence-source labels, and current workload-visible env/path vocabulary while the request, runtime-profile, and runtime-identity seams remain reopened
- the additive `outcome_evidence` JSON field and successful logs/result evidence headers while the status/result/log/cancel descriptor vocabulary remains bounded to the current Nomad/retained-result slice
- retained `application/gzip` result bundles keyed by public `run_id`

`Observed current contract`

Implementation details and current slice constraints must not be promoted into stable cross-service semantics merely because they appear in code, helpers, or CP proof harnesses:

- host staging roots, bind-mount source paths, local proof workspaces, guest scratch, and generated helper artifacts
- internal Nomad job IDs such as `exec-<run_id>`
- latest-allocation projection, stdout-only log retrieval, one task named `task`, async-only submit, and no-retry/no-reschedule behavior
- proof-only Codex shim behavior and supported-local proof bootstrap details
- shell helpers and examples as client contracts

### Public surface

`Observed current contract`

- `POST /v1/executions:prepare`
- `GET /v1/executions:contract`
- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- `GET /v1/executions/{run_id}/result`
- `POST /v1/executions/{run_id}:cancel`

### Current integration-facing note

`Observed current contract`

- The current programmatic governed-execution surface is the HTTPS API boundary, not the shell helpers:
  - `POST /v1/artifacts:publish` through AGS
  - the ES execution, retained-result, and lifecycle endpoints above
- `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, `scripts/50_lifecycle.sh`, and `scripts/60_execute_loop.sh` are operator/proof helpers over those APIs; they are not a separate client contract.
- Host staging paths, current bind-mount sources, and the helper-private SPIRE source attachment are ES/operator deployment implementation details, not part of the client-facing execution contract.
- A future infra manager may satisfy those internal attachment needs with named volumes or other managed attachment semantics without changing the current HTTPS API, `run_id` lifecycle lookup contract, or workload-visible endpoint discovery contract.
- The current client-authorization shape is still operator-centric:
  - AGS publish and ES execution/lifecycle authorization now come from configured SPIFFE path-prefix allowlists
  - the current repo-owned runbooks, proofs, and generated helper configs still keep those allowlists operator-only:
    - `spiffe://execution.internal/operator/local`
  - the first repo-owned non-operator governed-execution caller activation path is Control Plane at:
    - `spiffe://execution.internal/service/control-plane`
  - the current prefix-based allowlist model is sufficient for that activation when configured narrowly with `service/control-plane`; a broad `service/` allowlist is not required
  - the current repo-owned activation path for that caller is the direct API example at `.examples/control_plane_static_script/run.sh`, paired with `.examples/config/ags.operator_and_control_plane.json` and `.examples/config/es.operator_and_control_plane.json`
  - the current governed sequencing for that caller is producer contract compatibility check, AGS publish, ES `:prepare`, ES `:submit`, and then status/logs/result/cancel only for submitted runs
  - the current direct API helper remains a lower-level compatibility helper: it still performs publish and submit directly by default, and submit reuses ES admission internally. The helper does not define CP policy ownership and does not imply submit can bypass prepare/admission.
  - when that direct API example waits for terminal status outside explicit cancel mode, it now fails fast if ES reports a terminal nonzero workload exit instead of printing a false success marker
  - on this Mac, the supported-local guest path is the grounded positive verification path for that bounded `logs` step
  - `es/app/control_plane_integration_path_test.go` remains the repo-owned verification layer for that same direct API path, including disallowed-caller failures, while staying bounded to publish, submit, status, and cancel coverage in the host-local harness
  - the focused AGS/ES app integration harness still exists as verification for that path, but it is no longer the only repo-owned activation surface

Current prepare request shape:

- `schema_version`
- `invocation`
- `mode`
- `timeout_seconds`
- `resources`

Current invocation shape:

- `schema_version`
- `artifact_digest`
- `derivation_spec_digest`
- `output_id`
- `argv`
- `env`
- `mounts`
- `annotations`

The invocation strings that ES places in the Nomad job (`output_id`, each
`argv` element, each `env` key and value, and each mount `target_path`) must
not contain `${`, `%{` or a NUL byte, which Nomad would not pass to the
workload as written. Each `argv` element and each mount `target_path` must
also be in Unicode Normalization Form C, hold only code points assigned in
the Unicode version of ES's normalization tables and not begin with a byte
order mark, because Nomad's client would pass it on in another form
(`.docs/execution_lifecycle/contracts.md`).

Current runtime-profile annotation:

- `execution_substrate.runtime_profile`
  - omitted or empty: the current default `static-script` runtime behavior
  - `control-plane-normal-shell/v1`: opt in to the bounded Control Plane normal-shell runtime profile

Current lifecycle lookup policy:

- `run_id` must match `run-[0-9a-f]{16}`
- ES owns one explicit internal execution-locator policy for lifecycle lookup
- the current locator resolves `nomad_job_id = exec-<run_id>`

Current successful response shapes:

- `:contract`
  - `schema_version`
  - `service`
  - `governed_execution`
    - `contract`
    - `enabled`
    - optional `disabled_reason`
    - `runtime_profiles`
    - `outcome_evidence`
  - `non_authority`
- `:prepare`
  - `success`
- `:submit`
  - `success`
  - `submitted`
  - `run_id`
  - `status`
  - `authority_handoff`
- `status`
  - `success`
  - `run_id`
  - `status`
  - `lifecycle_projection`
    - `source`
    - `revision`
  - `outcome_evidence`
  - optional `authority_handoff`
  - optional `exit_code`
  - `terminal`
- `cancel`
  - `success`
  - `run_id`
  - `status`
  - `outcome_evidence`

### Current invariants

`Current invariant`

- ES requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A.
- ES authorizes execution and lifecycle callers by configured SPIFFE path prefixes from `authorization.allowed_spiffe_path_prefixes`.
- ES prefix matching is exact-or-subpath: the authenticated caller path must
  equal a configured prefix or start with that prefix followed by `/`.
- ES startup config validation rejects broad or malformed prefixes under the
  allowlist-prefix rule in section 3A, which ARS and AGS share. Accepted
  prefixes are relative SPIFFE path prefixes with at least two non-empty path
  segments, no leading or trailing slash, no `.` or `..` segment, and no
  first segment `workload` in any letter case, and every segment uses only
  `A-Z`, `a-z`, `0-9`, `.`, `-`, and `_`. A single-segment prefix such as
  `service` or `operator` is invalid, and so is a workload prefix such as
  `workload/codex-agent`.
- `GET /v1/executions:contract` uses that same caller authorization and returns only non-secret, non-run-specific producer compatibility metadata.
- The current repo-owned runbooks, proofs, and generated helper configs keep that ES caller allowlist operator-only:
  - `spiffe://execution.internal/operator/local`
- The first repo-owned non-operator ES caller activation path is Control Plane at:
  - `spiffe://execution.internal/service/control-plane`
- `:prepare` validates request shape, fetches the artifact discovery record from ARS, follows that record to aggregate evidence and payload references, verifies the evidence record with `internal/contracts/evidence/v1`, enforces the current EGS runtime-trust payload against the evidence signer key, reads the configured workload-zone Vault blob from ARS through `internal/contracts/runtimeconfig/v1`, derives the bounded workload-vault handoff directly from that runtime config plus ES `workload_vault_auth.default_mode` and optional Vault CA trust material, and returns bounded preflight success only.
- `:prepare` evaluates ES Admission Policy Layer v0 before success. When an
  enabled ES admission policy requires payload inspection, `:prepare` may read
  bounded static-script payload text through the explicit ARS payload digest
  already discovered and cross-checked by ES admission.
- ES must consume artifacts through a designed discoverability surface, not by
  inheriting ARS support tuple grammar as ES public grammar.
- `:prepare` and `:submit` make ES the current runtime-config consumer and
  lookup orchestrator only. Runtime-config semantics live in
  `internal/contracts/runtimeconfig/v1`, ARS owns blob read by digest, and no
  ACS lookup hop exists on this path.
- ES startup-config placement of the workload-zone Vault config ref is
  compatibility/config residue on a reopened Workstream E ownership seam, even
  though startup validation must still guarantee the typed ref exists before ES
  serves governed execution traffic.
- `:prepare` does not create run IDs, scheduler metadata, durable execution state, or public composition detail.
- ES verifies and consumes these current ARS artifact surfaces:
  - artifact discovery record at `/v1/artifacts/{artifact_digest}/discovery`
  - aggregate evidence blob referenced by that discovery record
  - payload bytes at `/v1/blobs/{payload_digest}:bytes`
- ES currently interprets EGS `runtime_trust.signer_policy.allowed_signers` as artifact publication evidence signer key IDs.
- ES verifies and enforces only the signed EGS runtime-trust payload and does not surface EGS publication metadata in `:prepare` results.
- `:submit` reuses the full `:prepare` path first.
- `:submit` cannot bypass the ES Admission Policy Layer v0 path used by
  `:prepare`; policy denial happens before run ID creation, payload staging,
  and Nomad submission.
- `:submit` is async-only in the current execution slice.
- `:submit` currently supports only:
  - `static-script` artifacts
  - Docker target platform when a target platform is present
  - no required runtime capabilities
- The bounded `control-plane-normal-shell/v1` runtime profile is an explicit prepare/submit-time opt-in using `invocation.annotations["execution_substrate.runtime_profile"]`.
- The `control-plane-normal-shell/v1` profile:
  - still requires a `static-script` artifact and Docker target platform
  - requires `network_access=true`
  - requires explicit ES config under `execution.runtime_profiles.control_plane_normal_shell`
  - uses the configured profile image instead of `execution.base_image`
  - keeps any profile-image tool contents, supported-local image checks, and proof-only shims outside the ES public execution contract; those remain current-slice runtime support and proof scaffolding only
  - for the repo-owned supported-local runtime surface, requires the configured local profile image to remain available across repeated client runs by disabling Nomad Docker image cleanup in the supported single-node Nomad baseline and by refusing submit-ready when that guardrail is absent
  - injects `EXEC_CODEX_CLI_PATH`, `EXEC_CODEX_CREDENTIAL_SOURCE`, `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH`, and `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD` as non-secret runtime metadata
  - relies on the existing `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, `VAULT_ADDR`, `EXEC_WORKLOAD_VAULT_AUTH_*`, and workload-zone Vault CA trust handoff for workload-side Vault login and credential-material reads
- ES does not read the configured Codex credential secret, return it through an API, or broker Vault or Codex tokens for this profile.
- Successful submit returns the bounded `authority_handoff` read fact assembled from the same selected runtime profile, runtime identity handoff, workload-vault plan, workload-zone Vault config reference, and profile credential-location metadata ES hands to the submitted runtime.
- `authority_handoff.runtime_config_refs` is non-secret handoff evidence only,
  not runtime-config authority or live credential truth.
- Status returns `authority_handoff` when ES can recover those non-secret facts from the submitted runtime spec. This recovery does not create a run store and does not expose Nomad job IDs, allocation IDs, or task-state detail.
- The supported-local proof image may realize the configured Codex CLI path with a deterministic proof-only shim. That proves the ES runtime contract for the CP normal-shell path without claiming real upstream Codex service behavior.
- The producer contract declaration lets clients verify before submission that this ES instance declares `governed-execution-producer/v1`, whether submit is enabled, whether `control-plane-normal-shell/v1` is enabled in config, and that status/cancel JSON plus successful logs/result responses require the current outcome-evidence carriers.
- The current producer declaration disabled-reason vocabulary distinguishes absent submit configuration with `submit_not_configured` from a configured producer whose optional runtime profile is off with `profile_not_enabled` on that profile entry.
- The current producer declaration `non_authority` classifications include `not_run_existence_proof` so clients do not mistake static compatibility metadata for live lifecycle observation.
- The producer contract declaration is not service health, submit readiness, artifact-specific admission proof, run authority, lifecycle truth, credential truth, policy truth, lifecycle write coordination, or scheduler API.
- ES must not absorb CP attempt/review/checkpoint/finalization semantics.
- ES must not become a Vault token broker, Codex credential broker, IM
  readiness authority, CP run-control authority, or maintenance-agent
  authority.
- Generated evidence, `.out`, reports, traces, logs, summaries, support
  bundles, retained bundles, proof artifacts, and maintenance summaries remain
  non-authoritative evidence/projection.
- `:submit` is the primary public execution handoff in the current slice and its successful receipt is centered on `run_id`, not backend-specific scheduler IDs.
- ES currently fetches payload bytes via the explicit payload reference carried in the ARS discovery record and cross-checks that reference against aggregate evidence.
- ES now localizes submit-time payload staging, mount staging, and runtime-ready package assembly behind one internal execution-package layout rather than letting that contract drift across submit, mount, and handoff helpers.
- ES reserves `/execution/run/result` as the current bounded workload-authored terminal result directory for the `static-script` slice, then stores non-empty terminal result contents as an opaque tar.gz bundle under `execution.results_root_dir`.
- ES serves retained opaque result bundles without interpreting checkpoint, review, finalization, or other Control Plane state semantics from their contents. The current result route is not a logs wrapper, checkpoint API, or Control Plane state surface.
- ES result retention is independent of staging retention. Publication success,
  absence, conflict, or failure never authorizes staging mutation. The current
  paired-root and authenticated final/record eligibility rules are owned by
  `.docs/execution_lifecycle/contracts.md`. Pair proof is a prerequisite for
  permitted result operations, not existing-object repair or deletion authority.
  New unpublished result objects may receive initial owner/mode; existing
  directories, finals, and normalization evidence are checked without repair or
  adoption. Uncertain leaves and startup probe fixtures remain retained; no
  whole-root reclamation authority is selected.
- B2 preserves every public route, HTTP status, existing error code, DTO shape,
  field name, precedence rule, and successful response while replacing only
  selected operational-cause text. The exact fixed messages are
  `workload-zone vault configuration is invalid`,
  `derive execution host context failed`,
  `stage workload vault trust material failed`,
  `derive execution platform state owner failed`, and
  `execution submission failed`. Public errors remain
  `{success:false,error:<safe message>,code:<existing code>}`; no cause or
  diagnostic field is added.
- The three governed result-retention failures use only
  `es result retention failed run_id=%s` and the validated public run ID. This
  is a finite call-site contract, not process-wide log noninterference.
- Nomad Submit registration, projected-allocation list, and allocation-detail
  JSON are limited to 256 KiB and exactly one compatible JSON document. Unknown
  provider fields remain accepted. Known oversized bodies are refused before
  reading, unknown/chunked bodies use a limit-plus-one read, exact equality is
  accepted, and non-success bodies are not consumed as diagnostics.
- Nomad job lookup remains explicitly unbounded but one-document because
  admitted caller-environment aggregates are currently unbounded and the job
  summary echoes `Task.Env`. Successful authenticated public Logs likewise
  remain unbounded byte-identical opaque workload output. B2 does not select a
  universal control-response or workload-output size policy.
- `preparedAdmission` is a private fixed-redacted aggregate under ordinary
  formatting and formatted standard-library logging and remains `{}` under
  ordinary JSON. This bounded structural defense does not cover reflection,
  `unsafe`, malicious same-package code, arbitrary serializers, secure erasure,
  or authorize logging the aggregate.
- The complete `control-plane-normal-shell/v1` direct literal submitted-job and
  authority-handoff golden is ES profile-coverage evidence only. It is
  source-distinct from the B1 default golden and is neither current CP request
  bytes nor CP authority over ES semantics.
- B2's finite assurance is source-bounded and reviewable, not a general
  analyzer. Reliable keyed-submit runtime remains unwired, and native Linux
  runtime validation of the combined candidate remains pending.
- Runtime network mode is derived directly from signed execution access claims:
  - `network_access=false -> network_mode=none`
  - `network_access=true -> network_mode=bridge`
  Workstream F slice F1 changes this mapping
  (`.docs/execution_lifecycle/contracts.md`, section 5B). From WI-2, a run
  that requests the network also needs an owner grant in ES configuration and
  is otherwise refused with `network_access_not_granted`. From WI-4, a granted
  run joins its egress lane's network instead of `bridge`.
- Caller runtime mounts are currently limited to governed artifact-backed mounts that are:
  - read-only
  - absolute
  - already cleaned
  - under `/execution/mounts`
  - non-overlapping
- Each runtime mount artifact is revalidated through ARS and runtime-trust enforcement before staging.
- Once ES exclusively creates `execution.staging_root_dir/<run_id>/`, every
  post-claim outcome retains that visible root: failed or partial Submit,
  ambiguous or accepted registration, terminal success or failure,
  cancellation, loss, unknown evidence, and every result-publication outcome.
- ES does not adopt, reopen, quarantine, scan, or recursively delete a run
  root. Automatic whole-root reclamation is not implemented; governed staging
  reclamation is an ES-owned reopened seam.
- If Submit never successfully claims a run root, there is no claimed run tree
  for Submit to reclaim; startup root provisioning and capability probes are
  separate effects.
- After successful exclusive claim, the isolated candidate retains
  `execution.staging_root_dir/<run_id>/` on materialization error, Nomad
  registration failure or ambiguity, terminal success/failure/cancel/loss, and
  result-publication failure. Closing held descriptors does not delete it.
- Authenticated result capture is separate from retained staging. Retention
  increases disk use and sensitive-material residence; no TTL, garbage
  collector, operator deletion authority, or reclamation policy is selected.
- Lifecycle is Nomad-backed only:
  - ES does not persist run state
  - ES resolves status, logs, result readiness when no retained bundle exists, and cancel through Nomad
  - ES derives the minimal public lifecycle `status` value from Nomad-backed state as `submitted`, `running`, or `terminal`
  - ES includes `lifecycle_projection.source = "nomad"` and an opaque `lifecycle_projection.revision` in status responses so consumers can compare status observations without inferring Nomad IDs or ES-owned run persistence
  - ES includes additive `outcome_evidence` on status and cancel JSON responses and successful logs/result headers to label the bounded observation or retained output source without exposing scheduler IDs, staging paths, or payload contents
  - ES may include `authority_handoff` in status from submitted runtime handoff metadata/environment, but that fact remains read-only runtime handoff evidence and is not lifecycle state
  - logs are stdout-only for task `task`
  - result bundles are retained opaque output artifacts keyed by `run_id`, not lifecycle-state records
  - ES uses one explicit projected-allocation policy that currently chooses the latest allocation in the current no-retry, no-reschedule slice

### Ownership boundary

- ES owns request validation, cross-service composition, Nomad submission, and Nomad-backed lifecycle projection.
- ES owns retained opaque terminal result bundles for the current bounded slice.
- ES does not own:
  - trust policy
  - artifact publication
  - storage semantics
  - scheduler state
  - durable lifecycle state
  - Control Plane orchestration, checkpoint, review, or terminal decision semantics

### Temporary compatibility edges

`Temporary compatibility edge`

- `POST /v1/executions:prepare` is an active milestone surface, not a declared long-term public execution API.
- `GET /v1/executions:contract` is a current compatibility-gate declaration for CP/IM consumers; it is not a broad capability registry or replacement for readiness checks.
- The current container path conventions under `/execution/...` and the current runtime environment variable names are active today, but should not be treated as permanent by default.
- The current `/execution/run/result` convention and retained tar.gz bundle shape are active for the bounded terminal-result slice, but should not be treated as a general runtime-output platform by default.
- The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and retained `application/gzip` bundle retrieval shape are the active CP-consumed compatibility path for the bounded terminal-result slice.
- The current internal execution-locator policy (`run_id -> exec-<run_id>`) and projected-allocation model are current slice mechanics, not a general scheduler abstraction.
- The current `authority_handoff` JSON field layout, evidence-source labels, and current endpoint/path/env names are compatibility-heavy read vocabulary on reopened request/runtime-identity seams.
- The current `outcome_evidence` JSON field layout, successful logs/result evidence headers, and observation labels are current-slice read vocabulary, not durable scheduler, log, result, or cancellation architecture.
- `control-plane-normal-shell/v1` is a bounded compatibility-heavy runtime contract for one CP-owned normal-shell attempt path. It should not be generalized into an arbitrary image/toolchain marketplace or used to absorb CP orchestration semantics into ES.

### Reopened seams

`Reopened redesign seam`

- The ES public request model is explicitly reopened in `PLANS.md`.
- The current prepare/submit split, payload-resolution path, runtime mount model, and scheduler handoff shape are live today but not treated as settled architecture.
- Whether runtime profiles remain annotation-selected overlays or become part of a later re-derived ES admission model remains reopened.

## 8. EGS Policy Contract

### Purpose

Publish the signed runtime-trust payload that ES enforces at admission time for
signer/artifact trust only.

### Current producers / consumers

- `EGS` publishes the runtime-trust payload plus separate publication metadata.
- Current allowed callers are:
  - `spiffe://execution.internal/service/execution`
  - `spiffe://execution.internal/operator/local`
- `ES` is the current runtime consumer.

### Public surface

`Observed current contract`

- `GET /v1/trust-model`

Current response shape:

- `runtime_trust`
- `algorithm`
- `key_id`
- `payload_digest`
- `signature`
- `publication`

Current `runtime_trust` payload shape:

- `signer_policy.allowed_signers`
- `signer_policy.revoked_signers`
- `artifact_policy.revoked_artifacts`

Current `publication` metadata shape:

- `version`
- `update_revision`

### Current invariants

`Current invariant`

- EGS authenticates `GET /v1/trust-model` callers under the caller authentication contract in section 3A, then accepts exactly the caller paths `service/execution` and `operator/local`.
- EGS signs the canonical runtime-trust payload, not artifact facts.
- The signed `runtime_trust` payload is intentionally limited to signer and
  artifact trust policy. It does not carry authorization decisions, runtime
  auth-plan material, or ES runtime handoff facts.
- D1b does not expand this EGS surface. EGS remains signer/artifact
  runtime-trust publication plus separate EGS-owned publication metadata only.
- D1c is design-only and docs/tests-only. It does not implement EGS v2 or
  change the current `GET /v1/trust-model` route, wrapper, signed
  `runtime_trust` payload shape, or signing behavior.
- The current `GET /v1/trust-model` route plus wrapper/payload shape therefore
  remains the live EGS v1 compatibility surface until an explicitly versioned
  replacement exists.
- Current canonical runtime-trust signing covers:
  - `signer_policy`
  - `artifact_policy`
- Runtime-trust list fields are normalized deterministically before digest and signature generation.
- `payload_digest` and `signature` are the authoritative trust signals in the current contract.
- EGS publication metadata remains outside the signed `runtime_trust` payload.
  `publication.version` and `publication.update_revision` are EGS-owned
  metadata, not signed runtime-trust facts.
- `publication.version` and `publication.update_revision` are EGS-owned
  publication metadata. They are not trust-contract, schema, or API
  versioning for the current EGS surface.
- Future EGS semantic expansion requires explicit wrapper/payload/versioning
  before implementation.
- If a future EGS versioned trust wrapper is implemented, it must distinguish:
  - signed runtime-trust payload facts
  - unsigned publication/discovery metadata
  - compatibility routing or API version
  - non-authoritative service metadata
- That future wrapper must not carry:
  - CGS authorization decisions
  - Control Plane review/approval/checkpoint/finalization semantics
  - runtime auth plans
  - Vault token material
  - JWT-SVIDs
  - credential payloads
  - scheduler truth
  - ES lifecycle/admission truth
  - runtime-config refs
  - workload-zone Vault ownership facts
  - runtime identity handoff facts
  - AGS/ARS artifact-publication authority
- ES verifies the EGS signature and then enforces:
  - provenance signer allow-list
  - provenance signer revocation
  - artifact revocation

### Ownership boundary

- EGS owns runtime-trust publication and signing only.
- EGS-owned publication metadata remains outside the signed runtime-trust
  payload.
- EGS does not own artifact signing, artifact retrieval, runtime execution, or lifecycle state.

### Temporary compatibility edges

`Temporary compatibility edge`

- The route remains `GET /v1/trust-model` even though the shared runtime contract is now the narrower `runtime_trust` payload plus separate EGS-owned publication metadata.
- The current route plus wrapper/payload shape are the live EGS v1 compatibility surface.
- Semantic expansion of the EGS trust surface requires explicit wrapper/payload versioning before implementation; do not widen the current v1 surface in place.

### Reopened seams

`Reopened redesign seam`

- The current runtime-trust form and response wrapper are explicitly reopened in `PLANS.md`.
- The current EGS surface is live, but its exact payload and wrapper shape must not be treated as frozen architecture.

## 9. CGS Authorization Contract

### Purpose

Provide a direct authorize-only decision boundary for credential-related
access.

### Current producers / consumers

- Callers invoke CGS directly with their own authenticated SPIFFE identity.
- The caller identity must match `workload.workload_identity_id`.
- ES is not a current CGS consumer in the active ES hot path.

### Public surface

`Observed current contract`

- `POST /v1/credential/authorize`

Current request shape:

- `workload`
- `requested_capabilities`

Current response shape:

- `allowed`
- `request_id`
- `decision_id`
- `decision` on allow
- `audit`
- optional `reason` on deny

### Current invariants

`Current invariant`

- CGS exposes only `POST /v1/credential/authorize` in the current Go contract.
- CGS requires authenticated SPIFFE caller identity and rejects bootstrap-PKI callers under the caller authentication contract in section 3A. A caller identity from any trust domain other than `execution.internal` is refused with `401` before policy evaluation.
- The authenticated caller identity must equal `workload.workload_identity_id`.
- CGS is a direct authorize-only boundary. The current request/response surface
  does not carry runtime auth-plan fields, credential material, Vault token
  material, JWT-SVID material, or ES runtime handoff facts.
- CGS currently depends only on:
  - `workload.type`
  - `workload.workload_identity_id`
- Removed location-convenience fields such as `module_path`, `file_path`, and `service_name` are not part of the active request contract.
- `requested_capabilities` currently allows only `vault:read`.
- `id.conf` is loaded at startup, parsed into explicit subject records, and used to:
  - validate workload principals
  - derive subject IDs from explicit policy records
  - evaluate allow or deny decisions
- The current supported `id.conf` grammar is:
  - `subject "<id>" {`
  - `type: "service" | "script"`
  - `principal: "spiffe://..."`
  - `role: "<role>"`
  - `}`
- A `principal` must be a SPIFFE ID that the caller authentication contract
  in section 3A accepts, written exactly in that form. `id.conf` loading
  refuses any other principal, because no authenticated caller could ever
  match it.
- The repo now carries a minimal checked-in baseline at `cgs/policy/id.conf`.
  - It is grounded in current Go-repo tests/examples only.
  - It must not be mistaken for a complete production policy file or final long-term policy grammar.
- `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path`
  remain local to current CGS v1 evaluation only. They are not a shared
  policy language, not ES admission policy truth, not EGS trust truth, not
  Control Plane review/approval/checkpoint/finalization policy truth, and not
  Infrastructure Manager readiness/profile/support-bundle authority truth.
- `policy.id_conf_path` remains a CGS-local configuration pointer for current
  v1 only. It is not a repo-wide policy registry.
- `id.conf` must not move into runtime-config ownership before Workstream E
  and must not fold into runtime-identity handoff before Workstream F.
- Allow and deny both return `200` in the current boundary.
- Allow responses currently return:
  - `role`
  - optional decision constraints
- Current authorize responses include no secret material and no runtime auth-plan payload.
- `audit.policy_version` inside `audit` is CGS audit/evaluation metadata. It
  is not transport, schema, or API versioning for the current authorize
  surface.

### Ownership boundary

- CGS owns the current direct authorize-only decision surface only.
- CGS does not own artifact publication, EGS runtime-trust publication, scheduler state, or the current ES admission path.

### Temporary compatibility edges

`Temporary compatibility edge`

- The current request/response shape is the live CGS v1 compatibility surface.
- `audit.policy_version` is audit/evaluation metadata, not transport/schema/API versioning.
- `id.conf` remains current-CGS-v1 compatibility/config residue even while it is active today.
- `id.conf` is an active local policy input and current authorize-shape
  dependency, but it should not be mistaken for a permanent repo-wide policy
  architecture just because it is currently in use.
- The checked-in `cgs/policy/id.conf` baseline is implementation/config
  residue, not future product policy architecture.
- Semantic expansion of the CGS authorize surface requires explicit versioning before implementation; do not widen the current v1 surface in place.

### D1b design-only future versioned boundary

- D1b is design-only and docs/tests-only. It does not implement CGS v2 or
  change the current `POST /v1/credential/authorize` route, DTO, wire shape,
  or `id.conf` evaluation behavior.
- The current `POST /v1/credential/authorize` request/response shape therefore
  remains the live CGS v1 compatibility surface until an explicitly versioned
  replacement exists.
- If a future CGS v2 authorize contract is implemented, it must be explicitly
  versioned before behavior changes land.
- The allowed design-level shape of a future CGS v2 authorization fact is
  limited to:
  - allow/deny result
  - opaque decision reference
  - expiry or another bounded freshness indicator if justified
  - audit/evaluation metadata that remains non-authoritative outside CGS
- That future versioned fact must not carry:
  - runtime auth plans
  - Vault token material
  - JWT-SVIDs
  - credential payloads
  - scheduler facts
  - ES lifecycle/admission facts
  - runtime-config refs
  - workload-zone Vault ownership facts
  - identity-handoff facts
  - Control Plane review/approval/checkpoint/finalization semantics
- ES remains a non-consumer in D1b. Any later ES consumption of a CGS fact
  remains hypothetical and must be version-gated separately.
- D1b does not expand EGS beyond signer/artifact runtime-trust publication and
  does not settle Workstream E runtime-config ownership or Workstream F
  runtime-identity handoff.

### D1d design-only policy-input seam

- D1d is design-only and docs/tests-only. It does not change current
  `POST /v1/credential/authorize` behavior, does not implement CGS v2, and
  does not change the current `id.conf` grammar, `policy.id_conf_path`, or
  checked-in `cgs/policy/id.conf` baseline.
- `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path`
  remain current-CGS-v1 compatibility/config residue local to current CGS v1
  evaluation only.
- They are not a shared policy language, not ES admission policy truth, not
  EGS trust truth, not Control Plane
  review/approval/checkpoint/finalization policy truth, and not
  Infrastructure Manager readiness/profile/support-bundle authority truth.
- `policy.id_conf_path` remains a CGS-local current-v1 configuration pointer,
  not a repo-wide policy registry.
- `id.conf` must not be moved into runtime-config ownership before Workstream
  E or folded into runtime-identity handoff before Workstream F.
- Future policy-input redesign requires explicit Workstream D follow-up and,
  if it changes CGS semantics, a versioned CGS contract.

### Reopened seams

`Reopened redesign seam`

- The CGS authorize DTO and `id.conf` policy-input model are explicitly reopened in `PLANS.md`.
- CGS remains live today, but its current wire and policy-input shape must not
  be treated as the final core authorization contract or final policy
  architecture.

## 10. Runtime Identity Handoff Contract

### Purpose

Describe the current ES-to-runtime identity boundary used during submission and execution.

The authoritative F0 runtime-identity handoff ownership decision lives in
`runtime_identity_handoff.md`.

The next slice, F1, is decided and recorded in section 11 of
`runtime_identity_handoff.md`: one identity per named workload, at
`spiffe://execution.internal/workload/<name>`, picked by owner grant rules in
ES configuration and checked by the helper against the expected ID string ES
passes it; no identity handoff for a run without an identity grant; one SPIRE
entry per name with a Docker label selector instead of the entry that matches
every root process; and one Vault role and policy per name. It lands with
WI-3. Until then this section describes current behavior.

### Current producers / consumers

- `ES` selects the handoff and provisions the backing runtime-identity
  workspace, environment marker, reserved path layout, mounts, and Nomad job
  construction at submit time for the current slice.
- The platform-owned runtime supervisor/helper implements the endpoint inside
  the task.
- The workload container consumes the discovered endpoint and the resulting non-secret runtime inputs.
- SPIRE owns JWT-SVID issuance.
- Vault owns token, secret, and lease issuance after workload-side login.
- Nomad and Docker carry the task and mounts, but they do not own the handoff semantics.

### Public surface

`Observed current contract`

Current workload-visible handoff:

- canonical `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://<ES-owned run-scoped endpoint>`
- non-secret workload-vault environment inputs derived from the resolved workload-vault auth plan
  - `VAULT_ADDR`
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`
- when the resolved workload-zone Vault config includes CA material, ES stages:
  - `VAULT_CACERT=/execution/run/platform/workload-vault-ca.pem`
  - `SSL_CERT_FILE=/execution/run/platform/workload-ca-bundle.pem`
- for `control-plane-normal-shell/v1` only, non-secret Codex credential-location environment inputs:
  - `EXEC_CODEX_CLI_PATH`
  - `EXEC_CODEX_CREDENTIAL_SOURCE=workload_vault`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH`
  - `EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD`

Current ES read handoff surface:

- `authority_handoff.authority_path = "workload_identity_endpoint/workload_vault"`
- `authority_handoff.runtime_profile.name`
- `authority_handoff.identity_handoff`
  - `mode = "workload_identity_endpoint"`
  - `endpoint_env`
  - `endpoint_uri`
  - `jwt_svid_target = "workload_vault"`
- `authority_handoff.workload_vault`
  - `auth_mode`
  - `address`
  - `auth_mount`
  - `auth_role`
  - `jwt_audience`
  - optional CA trust file env/path labels when CA trust material was staged
- `authority_handoff.runtime_config_refs.workload_zone_vault_config.digest`
- for `control-plane-normal-shell/v1` only, `authority_handoff.codex_credential_location`
  - `cli_path`
  - `credential_source = "workload_vault"`
  - `vault_secret_path`
  - `vault_secret_field`
- `authority_handoff.evidence` labels whether each fact came from the submitted runtime spec, submitted runtime environment, or submitted runtime metadata.

This surface is intentionally non-secret and read-only. It does not state that a workload successfully contacted the endpoint, obtained a JWT-SVID, logged into Vault, holds a Vault token, read a Codex token, or has a live lease.

F0 classifies `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the bounded
workload-visible discovery contract only. It is not raw SPIRE socket exposure,
Vault token brokerage, runtime-config authority, or a secret payload.

Current ES-owned implementation details behind that handoff:

- ES currently backs the discovered endpoint with a writable tmpfs workspace under a run-scoped subtree rooted at `/run/es-runtime-identity/`
- ES currently protects the workspace subtree and the endpoint path from caller mount overlap
- the bounded slice-1 implementation target stages platform-owned runtime support assets under `/execution/run/platform/` and keeps workload content under `/execution/run/work`

Current runtime rules:

- ES adds exactly one writable tmpfs-backed workspace to back the discovered runtime-identity endpoint.
- The backing workspace is not caller-controlled.
- Caller mounts must not overlap the ES-owned runtime subtree that backs the discovered endpoint.
- ES also injects non-secret Vault auth metadata through environment variables.
- ES injects non-secret Codex credential-location metadata only when the bounded Control Plane normal-shell profile is selected.
- ES does not apply per-workload selector overrides when shaping that Vault auth metadata in the current slice.
- the slice-1 first implementation slice narrows workload runtime compatibility to platform-controlled non-root workloads:
  - helper runs as `0:0`
  - workload runs as fixed `10000:10000`
  - workload receives no supplemental groups and no privilege-escalation path
- the helper-private SPIRE channel is bounded to `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`
- the public workload-visible endpoint remains `EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix:///run/es-runtime-identity/<run_id>/endpoint`
- the public endpoint is platform-bounded and must not become a raw SPIRE passthrough

### Current invariants

`Current invariant`

- Runtime identity handoff is currently ES-selected and platform-delivered.
- ES owns handoff selection, env injection, reserved path layout, mounts, and
  Nomad job construction for the current slice.
- ES reserves the runtime-identity workspace and validates that caller mount targets do not overlap it.
- The workspace backing the discovered runtime-identity endpoint is tmpfs-backed, writable, and not persisted into host staging.
- ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases,
  Codex credential material, or credential payloads.
- ES derives the workload-vault auth plan from workload-zone vault runtime fields plus the locally configured default auth mode.
- ES does not treat endpoint creation failure, workload identity failure, or Vault auth failure as ES lifecycle state.
- ES exposes only bounded non-secret authority handoff facts and their evidence sources; it does not expose live credential possession, lease state, token expiry, policy approval state, or backend scheduler identifiers through that surface.
- Capability-sensitive behavior in this area must not rely on OS-based branching or fallback behavior.
- The first platform-owned runtime-identity slice must fail closed unless the workload can be launched as fixed non-root `10000:10000` with no supplemental groups and no privilege-escalation path.
- The raw SPIRE channel must remain helper-private and must not be exposed to workload env, workload mounts, or workload-authored code.
- Runtime-config refs, `authority_handoff.runtime_config_refs`, ARS blob
  storage/read mechanics, digest-only runtime-config refs, and
  `workload_vault_auth.default_mode` are not runtime-identity or credential
  authority.
- CGS authorize output, `id.conf`, `policy.id_conf_path`,
  `audit.policy_version`, CGS v1/v2 design docs, EGS
  `publication.version`, EGS unsigned publication metadata, and AGS
  `policy_decisions` are not runtime-identity or credential authority.
- Retained bundles, `outcome_evidence`, `authority_handoff`, IM profiles,
  support bundles, logs, traces, reports, `.out` artifacts, and CP
  review/approval/checkpoint/finalization state remain evidence/projection,
  not runtime-identity or credential authority.

### Ownership boundary

- ES owns current handoff selection, env injection, workspace reservation,
  boundary enforcement, reserved path layout, mounts, and Nomad job
  construction.
- The workload owns use of the discovered endpoint inside the container and remains only a client of that endpoint.
- The checked-in workload-authored reference bridge is example scaffolding only and does not define final ownership of runtime identity delivery.
- The platform-owned runtime helper owns:
  - raw SPIRE access
  - endpoint serving
  - JWT-SVID retrieval and refresh
  - readiness-before-workload
  - root-to-workload privilege boundary enforcement
  - endpoint-local runtime failure
- SPIRE owns JWT-SVID issuance.
- Vault owns token, secret, and lease issuance after workload-side login.
- ES does not own:
  - Vault token minting or brokerage
  - JWT-SVID payload brokerage
  - Vault token storage
  - Vault secret or lease storage
  - credential payload delivery
  - post-submit identity lifecycle

### Temporary compatibility edges

`Temporary compatibility edge`

- The endpoint URI is ES-chosen and run-scoped rather than a fixed `/execution/runtime-identity/endpoint` contract.
- The `/run/es-runtime-identity/...` backing layout is current ES implementation, not a broader workload contract.
- Helper start as `0:0`, Nomad task `User: "0:0"`, fixed workload
  `10000:10000`, helper-private SPIRE traversal, and current reserved runtime
  paths are bounded or compatibility-heavy first-slice surfaces. They are not
  final generalized runtime architecture, rootless Nomad client proof, or full
  ES/runtime de-root.

### Reopened seams

`Reopened redesign seam`

- The runtime identity handoff surface is explicitly reopened in `PLANS.md`.
- The current reserved paths, env var, and ES/runtime division of responsibility are active now, but must not be preserved automatically.
- The current bounded planning target is to keep the workload-visible discovery contract explicit while moving the implementation behind it into a platform-owned injected runtime companion/bridge rather than a workload-authored shim.
- The accepted bounded runtime shape for slice `1A` and `1B` is now the same-container helper launched by a platform-owned supervisor; reconsider sidecar/task only if that shape cannot keep the raw SPIRE channel helper-private or cannot enforce the non-root workload boundary without compromise.
- F0 records current ownership only. It does not settle the long-term
  runtime-identity owner, helper/root/task-user model, SPIRE selector posture,
  Vault posture, or reserved-path architecture.

## 11. Temporary Compatibility Edges

The following active edges are compatibility-heavy enough to keep in one place:

- `ES` currently uses `/v1/executions:prepare` as an active milestone surface rather than a declared long-term public execution API.
- `internal/contracts/evidence/v1` now separates signed `claims` content from the `seal` envelope, but the package still remains the active shared artifact kernel and therefore still concentrates substantial cross-service meaning.
- `ES` currently uses `/execution/staged`, `/execution/run`, `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, and the current ES-owned runtime-identity backing layout as active runtime conventions.
- `ES` currently supports `control-plane-normal-shell/v1` as one bounded annotation-selected runtime-profile overlay for a CP-owned normal-shell attempt path, not as a general runtime-profile framework.
- `CGS` currently uses `id.conf` as a local policy input format.

## 12. Reopened Redesign Seams

The following cross-service seams are active today and explicitly not fixed architectural endpoints:

- The shared-kernel role of `internal/contracts/evidence/v1`.
- The ARS registration and index model.
- The workload-zone Vault runtime-config ownership surface.
- The AGS publish grammar and fact-assembly model.
- The ES request model, payload-resolution path, and scheduler handoff shape.
- The EGS runtime-trust form and response wrapper.
- The CGS authorize DTO and `id.conf` policy-input model.
- The ES/runtime identity handoff surface, including reserved path conventions.
- The runtime-profile selection vocabulary and whether it remains annotation based.
- Signing-key custody: AGS and EGS hold their private keys inline in their configuration files, and rotating a key is a configuration change (section 3B).

This section is not a proposal for replacements. It exists to prevent future readers from preserving the current choreography by accident.

## 13. Decision Rules For Future Edits

Future edits to cross-service contracts must follow these rules:

- Structural coupling must be documented before being preserved.
- Compatibility-only edges must be labeled as such.
- A shared kernel must not grow casually.
- No contract becomes "fixed" merely because it is already implemented.
- No contract becomes "fixed" unless it is named explicitly as such in `PLANS.md` and aligned docs.
- If cross-service behavior changes, update `PLANS.md`, the relevant `.docs/` pages, and tests before treating the change as complete.
