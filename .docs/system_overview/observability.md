# System Observability Model

## Purpose

This document defines the bounded observability model for the Go rewrite.

It exists to make observability explicit without introducing hidden state, cross-service trace reconstruction, or lifecycle drift.

This is a system-level contract document, not a service-local implementation note.

## 1. Trace Model

The system uses W3C `traceparent` only for cross-service trace propagation.

The bounded trace model contains only:

- `trace_id`
- `request_id`

`trace_id` is the cross-service correlation identifier.

`request_id` is the local hop identifier for one service handling one request.

Trace ownership is bounded:

- the first internal service that receives a request without a valid `traceparent` generates the root `trace_id`
- downstream internal services must continue that trace
- downstream internal services must not create a new root trace when a valid upstream `traceparent` is present

`request_id` semantics are also bounded:

- `request_id` is unique per service hop
- a new `request_id` is generated for each inbound request handled by a service
- a new `request_id` is also generated for each outbound dependency call emitted as a separate boundary event in this slice

The system does not define:

- span trees
- in-process trace graphs
- function-level tracing
- cross-service trace reconstruction
- a trace ingestion pipeline

Observability in this slice is correlation-oriented, not distributed-tracing-platform-oriented.

## 2. Propagation

### Inbound HTTP

For inbound HTTP requests:

- if a valid `traceparent` header is present, the service continues that trace
- if no valid `traceparent` is present, the service creates a new trace
- the service generates a new local `request_id` for the current hop

The current request's `trace_id` and `request_id` must remain request-scoped.

### Outbound HTTP

For outbound HTTP requests:

- the caller propagates `traceparent`
- the outbound `traceparent` must be derived from the current inbound request context
- `traceparent` must propagate across internal service-to-service calls
- `traceparent` must not be propagated to external systems unless that propagation is explicitly allowed by contract

Services must not invent parallel propagation formats or service-specific trace headers for primary correlation.

Retry semantics are undefined in this slice.

The current observability model does not define a retry-aware trace contract or any guaranteed correlation model across retries.

## 3. Logging

Logging is bounded to service-edge observability.

Primary logging points are:

- inbound request completion
- outbound dependency calls

Structured logs for those events should include only the minimal correlation and operational fields needed to understand boundary behavior:

- `trace_id`
- `request_id`
- `service`
- `route` or operation
- `dependency` for outbound calls
- `status`
- `duration`

Additional bounded fields may be included only if they remain operational and non-sensitive.

The minimal status classification for observability events is:

- `success`
- `client_error`
- `server_error`
- `timeout`
- `dependency_failure`

This classification is intentionally minimal. It exists to support bounded operational visibility, not to define a broader execution-state model.

Services must not use this observability model as a reason to add broad business-logic logging.

The following are explicitly forbidden in this model:

- logging inside business logic purely for tracing purposes
- logging sensitive data
- logging secrets
- logging raw payloads
- logging artifact bytes
- logging policy blobs
- logging full request or response bodies by default

Observability logs must remain boundary-focused and safe.

## 4. ES Constraint

ES has an additional observability constraint because execution lifecycle is Nomad-backed.

ES must not:

- use logs to reconstruct lifecycle state
- use trace data to reconstruct lifecycle state
- synthesize lifecycle phases from observability signals
- treat observability output as a secondary lifecycle store

Nomad remains the only source of truth for submitted execution lifecycle state.

Observability may describe what ES did at submission time or when serving lifecycle endpoints, but it must not become an alternative execution-state system.

## 5. Metrics

Metrics are optional and deferred in the current system slice.

If metrics are introduced later, they must remain bounded and explicit.

The current system does not adopt:

- decorator-based metric systems
- dynamic metric-definition systems
- background collectors
- process-wide observability frameworks that hide state or behavior

Any future metrics slice must be added explicitly through `PLANS.md`, authoritative docs, and tests before implementation.

## 6. Boundaries

The observability model must preserve the existing system invariants.

The following are explicitly forbidden:

- hidden global state for trace or request correlation
- runtime context stores that act as ambient observability state
- trace ingestion pipelines
- cross-service trace reconstruction systems
- background observability workers that change service behavior
- observability layers that bypass service boundaries

Correlation data must remain explicit and request-scoped.

Observability must not:

- introduce new ownership boundaries
- weaken existing service contracts
- create an implicit execution-state model
- become a substitute for ARS, EGS, Nomad, or any other authoritative boundary

## 7. Change Discipline

Because observability can easily create hidden coupling, changes to this model must follow the same contract discipline as other system-wide behaviors.

Any change to:

- trace propagation rules
- required log fields
- observability ownership boundaries
- any future metrics contract

must update:

- `PLANS.md` when system scope changes
- `.docs/system_overview/`
- `.docs/execution_lifecycle/` if lifecycle behavior is implicated
- tests when implementation is added

Observability must evolve as an explicit bounded slice, not as incidental framework drift.
