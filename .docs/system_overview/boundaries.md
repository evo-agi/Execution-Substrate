# Service Boundaries

## ACS

ACS owns:

- governed digest lookup
- assignment-to-digest mapping

ACS must not:

- store blobs
- publish artifacts
- enforce trust policy
- own runtime execution logic

## ARS

ARS owns:

- content-addressed blob storage
- storage-level write validation
- storage-level read integrity verification
- artifact discoverability through registration

ARS must not:

- enforce governance policy
- verify artifact trust semantics
- publish TrustModel policy
- own execution or lifecycle state

## AGS

AGS owns:

- artifact-fact production
- artifact-fact signing
- artifact publication through ARS
- bounded publish authorization checks for trusted control-plane callers

AGS must not:

- bypass ARS
- act as a runtime dependency for ES execution
- own runtime admission
- enforce TrustModel policy at execution time
- own scheduler or lifecycle behavior
- act as a general-purpose signing service
- sign caller identity claims without binding them to the authenticated caller
- trust caller-supplied `builder_service`
- semantically validate `policy_decisions` in this slice

## EGS

EGS owns:

- TrustModel publication
- TrustModel signing

EGS must not:

- sign artifacts
- validate artifact execution requests
- own execution lifecycle
- fetch or publish runtime state

## CGS

CGS owns:

- separate compatibility authorization decisions

CGS must not:

- become part of the current ES hot path by drift
- own artifact publication
- own trust policy publication
- own scheduler or lifecycle state

## ES

ES owns:

- governed request validation
- composition across ACS, ARS, and EGS
- bounded Nomad submission
- bounded Nomad-backed lifecycle projection
- bounded runtime identity plumbing through one reserved generic workload-identity endpoint mount plus non-secret Vault auth metadata
- startup-only validation that the configured identity endpoint path is valid and that the configured execution substrate can expose that mounted endpoint inside the workload container

ES must not:

- own trust policy
- own artifact storage
- own artifact publication
- own lifecycle state
- cache run data
- synthesize lifecycle state
- enforce policy that belongs to upstream boundaries
- fetch or mint identity material
- fetch or store Vault tokens
- rotate credentials
- treat identity endpoint or auth failures as ES lifecycle state
- background-poll identity plumbing capability
- branch behavior on OS or runtime family instead of proving capability by behavior

## Nomad

Nomad owns:

- job submission target
- allocation state
- submitted execution lifecycle state

Nomad must not be shadowed by an ES-owned lifecycle model.

## Docker

Docker owns:

- task container runtime under Nomad

Docker must not be treated as an independent scheduler or lifecycle authority.

## System Rules

The system must preserve these ownership rules:

- ES must not own lifecycle state
- ARS must not enforce policy
- AGS must not be a runtime dependency
- EGS must not become an artifact signer
- CGS must remain isolated from the current ES hot path

If any of these boundaries need to change, the change must be documented explicitly before implementation.
