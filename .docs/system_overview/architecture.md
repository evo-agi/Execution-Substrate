# System Architecture

## Overview

The current system is a governed artifact and execution system composed of these boundaries:

- ACS: digest lookup for governed configuration indirection
- ARS: content-addressed blob storage, integrity verification, and artifact-fact retrieval
- AGS: artifact-fact producer and publisher
- EGS: TrustModel publication
- CGS: separate compatibility authorization boundary
- ES: governed admission, bounded execution submit, and bounded Nomad-backed lifecycle projection
- Nomad: scheduler and execution-state authority
- Docker: task runtime under Nomad

The system is intentionally decomposed so that no single service owns all trust, storage, execution, and lifecycle responsibilities.

## Primary Data Flows

### Publication Flow

Artifact publication flows through:

`AGS -> ARS`

AGS:

- computes digests
- constructs manifest and signed artifact facts
- signs the fact types ES later verifies
- uploads blobs through the ARS write boundary
- registers the artifact so it becomes visible

ARS is the only publication and retrieval boundary for published artifacts. ES must not bypass it.

### Admission and Execution Flow

Governed execution flows through:

`request -> ES -> EGS / ACS / ARS -> Nomad -> Docker`

ES:

- validates the request
- reads immutable artifact facts from ARS
- resolves workload-zone Vault metadata through ACS
- enforces the EGS TrustModel
- stages the payload locally
- submits one bounded Nomad batch job

Nomad schedules the work. Docker runs the task container. ES does not become a scheduler or runtime state owner in this flow.

### Lifecycle Flow

Execution lifecycle flows through:

`request -> ES -> Nomad`

Lifecycle endpoints are Nomad-backed only:

- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- `POST /v1/executions/{run_id}:cancel`

ES derives the Nomad job identifier from `run_id` and projects or forwards Nomad state. ES does not maintain a separate lifecycle store.

## Service Roles

### ACS

ACS is a lookup boundary only. It maps fixed assignment keys to digests and exposes no storage or trust-policy behavior.

### ARS

ARS is the storage and integrity boundary. It accepts content-addressed publication from AGS, verifies blobs by digest, makes artifacts discoverable only after registration, and re-verifies integrity on read paths.

### AGS

AGS is the producer boundary. It publishes immutable facts and payloads that ES later consumes. AGS is a write-time component, not a runtime dependency for execution.

### EGS

EGS publishes the external TrustModel that ES enforces. EGS signs constitutional policy, not artifacts.

### CGS

CGS is a separate compatibility authorization boundary. It is not part of the current ES hot path.

### ES

ES is the composition boundary. It does not own trust policy, storage, or scheduler state. It admits requests against governed facts, submits one bounded class of execution to Nomad, and exposes Nomad-backed lifecycle endpoints without persisting run state.

### Nomad

Nomad is the scheduler and lifecycle authority for submitted executions.

### Docker

Docker is the task runtime used by the current bounded execution slice under Nomad.

## Boundaries

The system is intentionally split across write-time, read-time, trust, authorization, and execution concerns:

- AGS owns artifact production
- ARS owns artifact storage and integrity
- EGS owns trust policy publication
- CGS owns separate compatibility authorization
- ES owns governed composition and bounded execution submit
- Nomad owns scheduling and submitted execution state

These boundaries exist to prevent hidden coupling and duplicate state.

## Reference vs Authority

This repository is the authoritative source of truth for system behavior and design:

- `/Users/ds/Repositories/Execution-Platform/PLANS.md`
- `/Users/ds/Repositories/Execution-Platform/.docs/system_overview/`
- `/Users/ds/Repositories/Execution-Platform/.docs/execution_lifecycle/`
- current Go code and tests
