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

## Example: Runtime Identity

For the bounded runtime-identity plumbing slice:

- static validation proves that caller mounts do not overlap the reserved runtime-identity workspace and paths
- no dedicated runtime capability probe is required in the current slice because ES no longer depends on topology-specific host plumbing
- if a future plumbing slice adds topology-specific behavior again, it must probe the reserved runtime interface by behavior rather than branch on OS labels

This keeps the slice behavior-based, deterministic, and consistent across environments without introducing OS-based branching.
