# Capability Probing

## Purpose

This document defines how the system handles environment and runtime capabilities.

Capability probing exists to keep contract enforcement explicit without introducing OS-specific behavior, hidden fallback paths, or service-to-service probing frameworks.

## Core Principle

Use capability-based validation, not OS-based branching.

Services must not use `runtime.GOOS`, OS-version checks, or runtime-label checks to change behavior for capability-sensitive slices.

Capability must be validated by behavior or by local static validation of the configured resource, not by assuming what a named platform should support.

## Model

The system uses two types of checks.

### 1. Static Validation

Static validation covers local checks such as:

- path validity
- file or socket type
- configuration shape
- required names or formats

Static validation is used at:

- startup
- submit, when submit-time drift revalidation is required by contract

### 2. Runtime Capability Probe

Runtime capability probing is behavior-based validation.

It exists for cases where a slice depends on the execution substrate behaving a certain way and local static checks are not enough.

Examples include:

- proving that a topology-specific runtime interface is actually usable inside a workload container

Runtime capability probes are used at:

- startup only

They are not used on every request or submit unless the contract is explicitly widened later.

## Placement Rules

Capability checks must run only at validation boundaries:

- startup
- submit for static validation only

Capability checks must never run inside:

- execution paths after validation has completed
- lifecycle handlers
- ordinary business logic

The system must not add:

- background probing
- polling loops
- implicit health workers for capability validation

## Failure Behavior

If a required capability is not met, the owning service must fail explicitly.

The system must not:

- silently omit capability-dependent behavior
- degrade silently
- switch to fallback behavior
- branch on OS or version labels

Capability failure is a contract-validation failure, not a runtime optimization hint.

## Implementation Rules

Capability probing must remain:

- small
- local to the owning service
- stateless

Allowed:

- small reusable validation and probing functions local to the owning service

Forbidden:

- global capability manager
- cross-service probing framework
- hidden shared state
- centralized runtime capability registry

## Contract Alignment

Capability requirements must be documented in:

- `PLANS.md`
- `.docs/system_overview/`
- `.docs/execution_lifecycle/` when lifecycle semantics are implicated

Probes enforce the documented contract.

Probes do not define new behavior on their own and must not silently widen a service boundary.

## Producer Contract Declarations

Read-only producer contract declarations, such as ES `GET /v1/executions:contract`, are not runtime capability probes.

They may declare static compatibility facts owned by the producer, such as the current governed-execution producer contract, config-enabled runtime-profile names, and mandatory response-evidence carriers. They must not perform background probing, call runtime dependencies, create run state, or replace health/readiness checks.

Consumers may use such declarations as early compatibility gates, but runtime readiness still belongs to the documented validation and readiness boundaries.

## Example: Runtime Identity

For the bounded slice-1 runtime-identity delivery slice:

- static validation must prove:
  - caller mounts do not overlap the reserved runtime-identity workspace and paths
  - the configured runtime-support binary path is absolute and readable
  - the configured SPIRE Workload API socket path is absolute in config
- startup-only runtime capability probes may prove:
  - the platform-owned helper can bind and serve the public endpoint inside the reserved runtime workspace
  - operator/readiness tooling can still prove the configured host SPIRE Workload API path refers to a local Unix socket before submit-ready or service-user apply is claimed
  - the actual runtime mount form in use can carry the helper-private SPIRE source directory into the container so the helper can reach the mounted unix socket
  - the helper-private SPIRE socket remains reachable to the helper and not workload-readable after the runtime boundary is established
  - the workload launch model can drop to the fixed non-root UID/GID with no supplemental groups and no privilege-escalation path
- long-lived ES startup does not need direct read/traverse authority on the raw host SPIRE socket; it only needs the configured path string so submit can build the helper-private mount model
- these checks must still fail closed instead of degrading to workload-owned SPIRE access

This keeps the slice behavior-based, deterministic, and consistent across environments without introducing OS-based branching.

## Test Harness Use

`es/app` integration tests that exercise submitted Nomad/Docker allocations through the current runtime-identity helper path use the same behavior-based capability shape as a test-harness gate.

The gate proves the local test substrate can run Docker/Nomad allocations and can carry the SPIRE Workload API socket source directory into the workload container so the helper can reach the mounted Unix socket. Unsupported hosts skip those allocation-dependent tests with an explicit runtime-identity capability reason instead of letting expected substrate limitations appear as noisy workload failures.

This is test hygiene only. It does not change ES public contracts, readiness semantics, startup validation, runtime identity ownership, or runtime failure semantics. Tests that cover prepare-only behavior, caller authorization, static submit/job-spec shape, or submit-time validation without requiring helper socket reachability do not use this gate.

`es/admission` unit tests that intentionally exercise chmod-backed filesystem denial use test-local behavior probes before asserting permission-sensitive fail-closed behavior.

The probe must create or mark a temporary fixture with the restrictive mode needed by the test, attempt the same class of operation the assertion depends on, and continue only when the current process receives a permission-denied error. If the current process can bypass the fixture permissions, the test skips with a specific `skipping permission-denied fixture: ...` reason.

This is also test hygiene only. It does not change ES public contracts, lifecycle cleanup semantics, retained-result semantics, readiness boundaries, or production capability probing placement.
