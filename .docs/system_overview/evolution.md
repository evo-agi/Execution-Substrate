# System Evolution Rules

## 1. Change Discipline

Changes to system-defining contracts must be documented before or alongside implementation. Code must not be the first place a contract change appears.

Any change to:

- canonicalization
- execution lifecycle behavior
- ARS write or read contract
- EGS trust-model semantics
- AGS publish authorization rules

must:

- update `PLANS.md`
- update the relevant `.docs/` pages
- update or add tests that lock the changed behavior

before implementation is treated as complete.

For these contract classes, the required order of operations is:

1. define the change in `PLANS.md`
2. update the authoritative Go docs
3. update the tests that express the new contract
4. implement code to match

Silent contract drift is forbidden.

## 2. Temporary Exceptions

Temporary deviations are allowed only when they are explicit and bounded.

Every temporary exception must be documented with:

- reason
- scope
- removal condition

The documentation must say exactly:

- what contract is being deviated from
- which component is affected
- whether the deviation is test-only, local-runtime-only, or system-visible
- what event or milestone ends the exception

Temporary exceptions must not silently modify system contracts. If a temporary deviation affects externally visible behavior, that behavior must still be documented explicitly as temporary rather than treated as an unannounced contract change.

## 3. Slice Constraints vs System Invariants

The system distinguishes between invariants and slice constraints.

### System Invariants

These must not change silently:

- Nomad is the source of truth for submitted execution lifecycle state
- ES lifecycle remains stateless
- ARS remains the storage and integrity boundary
- the `AGS -> ES` canonicalization contract remains explicit and enforced

Changing an invariant requires an explicit contract revision across code, tests, `PLANS.md`, and the authoritative docs.

### Slice Constraints

These are bounded slice choices and may evolve later through explicit planning:

- `static-script` only
- network access only through the signed `constraints.network_access` toggle
- no host networking, port publishing, or custom networks
- runtime mounts only through bounded artifact-backed read-only mounts under `/monolith/mounts/`
- no host-path, writable, identity, or secret mounts
- one reserved ES-owned Unix-socket workload-identity endpoint mount at a fixed in-container path
- no retries or reschedule

These constraints are still contractual for the current slice, but they are not system invariants. They may be extended later only through explicit design updates, not by convenience changes in code.

## 4. AGS Trust Boundary

AGS is a trusted control-plane boundary.

AGS must be callable only by trusted control-plane identities authorized to publish artifacts into the governed system.

AGS must not become a signing oracle.

That means:

- AGS must not sign arbitrary caller-supplied facts without bounded publication rules
- AGS must not be exposed as a general-purpose signing service
- AGS caller trust is a system-level responsibility, not an implementation detail inside one request handler
- AGS caller-to-provenance bindings, builder derivation, and publish-time conflict checks are contract-bound and must not drift silently

The trustworthiness of AGS inputs is part of the system boundary. If caller trust assumptions change, that is a system contract change and must be documented explicitly.

## 5. Evolution Rules

The system evolves by extending slices, not by silently rewriting existing contracts.

Allowed evolution pattern:

- define the next bounded slice
- document its scope and boundaries
- lock behavior with tests
- implement the slice

Disallowed evolution pattern:

- broaden an existing contract without updating `PLANS.md`
- rely on undocumented behavior
- let tests, code, and docs disagree about authoritative semantics

The governing rule is simple:

- extend slices explicitly
- do not modify existing contracts silently

## 6. Contract Violations

If a contract violation is discovered:

- stop further feature work
- identify the violated contract (invariant or slice constraint)
- classify the violation:
  - unintended drift
  - temporary exception
  - deliberate contract change
- apply one of:
  - revert the change
  - document as a temporary exception
  - update PLANS.md and docs as a formal contract revision

The system must be realigned before continuing development.

Unresolved contract violations must not accumulate.
