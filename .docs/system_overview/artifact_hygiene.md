# Generated Artifact Hygiene

## 1. Purpose and authority

This document classifies generated, binary-ish, proof, and local-output
artifacts in the current source baseline. Its purpose is to keep the repository
reproducible and honest without promoting generated evidence into runtime or
architecture authority.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on factual tracked-file
state, code and tests win and this document must be realigned.

## 2. Current invariant

Generated or proof artifacts are evidence/projection/diagnostics only. They are
not hidden runtime authority, scheduler authority, admission authority, policy
truth, credential truth, Control Plane orchestration state, or architecture
source of truth.

This applies to `.out/`, proof workspaces, reports, logs, retained bundles,
example package archives, local build directories, Python bytecode caches, OS
metadata files, and ad hoc packaging output.

Remote Alpha helper summaries under `/var/tmp/execution-substrate-remote-alpha`
are remote-host evidence/projection only unless an authoritative doc explicitly
promotes a specific file. The P0s ES service TLS status/renew summary
`/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`
with schema
`execution-substrate.remote-alpha.es-service-tls-renew-summary.v1` is a
non-secret helper summary only. It may include paths, byte counts, certificate
file SHA-256 digests, public fingerprints, validity windows, cert/key
public-key match status, backup metadata, service restart statuses, mTLS probe
statuses, verification statuses, and explicit non-claim labels. It must not be
copied back to Mac `.out` by the operator facade, must not become an IM input
or CP proof artifact, and must not contain private key PEM bodies, full
certificate PEM bodies, private-key backup digests, Vault tokens, root tokens,
unseal keys, client tokens, JWT-SVID payloads, API keys, passwords, proof
secrets, terminal transcripts, support-bundle content, or raw secret-bearing
command output.

## 3. Tracked generated-artifact allowlist

The source tree intentionally keeps only these generated/binary-ish artifacts
tracked:

| Path | Class | Why it remains tracked | Regeneration or drift guard |
| --- | --- | --- | --- |
| `.examples/execution_loop/artifacts/static-script-success.tar.gz` | non-authoritative fixture | Default static-script example payload used by `.examples/execution_loop/static_script_success.input.json` and the direct Control Plane static-script example default. | Regenerate with `.examples/execution_loop/artifacts/package_static_script_success.sh`. |
| `.examples/control_plane_normal_shell_runtime/dist/control_plane_normal_shell_runtime.tar.gz` | non-authoritative fixture | Bounded Control Plane normal-shell runtime-contract example payload referenced by `.examples/execution_loop/control_plane_normal_shell_runtime.input.json` and supported-local proof scripts. | Regenerate with `.examples/control_plane_normal_shell_runtime/package.sh`. |
| `.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz` | non-authoritative fixture | Legacy runtime-identity reference example payload retained for example continuity, not for the current platform-owned runtime identity proof path. | Regenerate with `.examples/runtime_identity_reference/package.sh`. |
| `.out/Dockerfile` | temporary compatibility edge; generated projection | Current bring-up scripts use a checked-in default service-image Dockerfile projection while retaining `scripts/generate_control_plane_dockerfile.sh` as the source-of-truth generator. | `es/app` generator coverage fails if `.out/Dockerfile` drifts from fresh generator output. |

The example archives contain only an `entrypoint` file. They are current
fixtures for examples and proofs, not authority over ES admission, lifecycle,
runtime-profile, runtime-identity, retained-result, or readiness contracts.

## 4. Disallowed tracked byproducts

The following must not be tracked unless this document is updated with an
explicit classification, reason, scope, and removal condition:

- `__pycache__/` and `*.pyc`
- `.DS_Store` and AppleDouble `._*` files
- unclassified `*.tar.gz` or `*.zip` archives
- unclassified `*.egg-info/`, `build/`, or `dist/` package output
- unclassified `.out/*` files

The tracked artifact hygiene test enforces this rule with the allowlist above.

## 5. Removal conditions

The example archive fixtures can be removed after the consuming example inputs
or proof scripts are changed to build them deterministically before use, or
after the corresponding example is explicitly retired.

The tracked `.out/Dockerfile` projection can be removed after the default
bring-up path consumes a generated temporary Dockerfile or the generator output
directly, and after the integration drift check no longer needs a checked-in
projection.
