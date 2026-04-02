# System Contracts

## Purpose

This document defines the system-wide contracts that span multiple services. These are not local implementation details. They are cross-service rules that must remain aligned across publication, storage, trust, admission, execution, and lifecycle.

## AGS -> ES Canonicalization Contract

AGS and ES are bound by a fixed producer/consumer contract for signed artifact facts:

- provenance
- derivation attestation
- workload identity binding

AGS must emit the exact canonical payloads ES verifies.

ES must verify those facts using the frozen canonicalization rules and must not silently accept semantically equivalent but differently canonicalized payloads.

Any change to those canonicalization rules must update:

- AGS production
- ES verification
- fixtures and integration tests
- authoritative Go documentation

in one explicit contract change.

## ARS Write / Read Contract

ARS is the only storage boundary for published artifacts.

### Write Contract

AGS publishes through the authoritative ARS write boundary only:

- `PUT /v1/blobs/{digest}`
- `POST /v1/artifacts:register`

ARS must:

- verify uploaded blob bytes against the requested digest
- validate registration at the storage level only
- make artifacts visible only after successful atomic registration

ARS must not:

- perform governance validation
- verify artifact signatures
- enforce trust policy

### Read Contract

ES reads artifacts and payloads through ARS only.

ARS must:

- verify blob integrity on read paths
- serve artifact-fact indirection only after registration

ES must not:

- bypass ARS for payload or fact retrieval
- treat registration alone as proof of integrity without ARS read verification

## EGS Trust Model Contract

EGS publishes the external TrustModel that ES enforces.

EGS must:

- sign the canonical TrustModel payload
- publish trust policy separately from artifact facts

ES must:

- verify the EGS signature
- treat only `payload_digest` and `signature` as authoritative in EGS v1
- treat `trust_model.signer_policy.allowed_signers` as artifact provenance signer key IDs

ES must not:

- define trust policy locally
- treat the EGS signing key as the artifact provenance signer set
- use `source_digest` for trust decisions in EGS v1

## CGS Isolation Contract

CGS is a separate compatibility authorization boundary.

CGS is not part of the current ES admission or execution hot path.

ES must:

- reject `cgs_proof_legacy` locally in the current slice

ES must not:

- call CGS during the current bounded admission or execution path
- absorb CGS decision ownership into ES

Any future reintroduction of CGS into the ES path requires an explicit contract change.

## ES Composition Contract

ES is a composition boundary, not an ownership boundary.

ES must:

- validate execution requests
- retrieve immutable facts from ARS
- resolve workload-zone Vault metadata through ACS
- enforce the EGS TrustModel
- submit one bounded class of execution to Nomad
- derive lifecycle status, logs, and cancellation from Nomad only

ES must not:

- own trust policy
- own storage semantics
- own artifact publication
- own scheduler state
- own execution lifecycle state
- broaden bounded lifecycle projection into a private scheduler abstraction

## Lifecycle Contract

For submitted execution lifecycle:

- Nomad is authoritative
- ES is stateless
- lifecycle is derived from Nomad only

ES must not:

- cache lifecycle state
- reconstruct lifecycle state from local artifacts
- synthesize private lifecycle phases
- aggregate allocations into a synthetic execution model

## Reference vs Authority

The Go rewrite is authoritative.

Authoritative sources are:

- `PLANS.md`
- `.docs/system_overview/`
- `.docs/execution_lifecycle/`
- current Go code and tests

The Python repository is historical reference only and must not override Go documentation, Go contracts, or Go implementation decisions.
