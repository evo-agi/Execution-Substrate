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
truth, credential truth, shared-kernel authority, Control Plane orchestration
state, or architecture source of truth.

CP examples and proof harness artifacts do not define AGS/ARS/ES core
semantics. Generated evidence, `.out`, support bundles, retained bundles,
reports, traces, logs, summaries, and proof artifacts remain
evidence/projection only.

Generated evidence, `.out`, reports, traces, logs, summaries, support bundles,
retained bundles, proof artifacts, and maintenance summaries remain
non-authoritative evidence/projection.

Runtime identity and Vault handoff evidence in summaries, outcome evidence,
retained result metadata, support bundles, logs, reports, `.out`, and proof
artifacts remains non-authoritative and redacted.

Status/logs/result/cancel evidence, generated `.out` files, reports, traces,
raw logs, summaries, support bundles, retained bundles, proof artifacts,
Remote Alpha summaries, and Maintenance Agent summaries remain
non-authoritative evidence/projection. They must not become CP run-control
truth, ES lifecycle-store truth, scheduler authority, operator approval
authority, credential authority, or the final scheduler/result/log/cancel
vocabulary by proximity to ES lifecycle responses.

This applies to `.out/`, proof workspaces, generated evidence, reports, traces,
logs, summaries, support bundles, retained bundles, proof artifacts, example
package archives, local build directories, Python bytecode caches, OS metadata
files, and ad hoc packaging output.

Maintenance Agent summaries, if produced by an external scheduler/notifier or
local-evidence summarizer, remain scheduler/notifier/local-evidence outputs
only. They do not define ES route semantics, renewal semantics, runtime
authority, IM readiness/provenance authority, CP run-control authority, or
maintenance-agent authority inside this repository.

`Bounded slice rule`: the P0s/P0t dedicated status collector writes only
nonsecret evidence/projection under the pre-existing root-owned
`/var/lib/execution-substrate-remote-alpha/v1/status` namespace. Its exact
canonical files are `es-service-tls-status-summary.json` and
`es-governance-tls-status-summary.json`, with separate status-only schemas.
Their persistent same-scope locks are `.es-service-tls-status.lock` and
`.es-governance-tls-status.lock`.
They are not renewal, runtime, IM, CP, MA, scheduler, production-readiness,
or governed-proof authority. The collector contract is
`execution-substrate.remote-alpha.es-tls-status-collector/v1` and the path
contract is `execution-substrate.remote-alpha.es-tls-status-evidence/v1`.

The collector accepts no arbitrary output path. It requires the protected
root and status directories to exist as verified root:root `0755` directories;
missing or unsafe ancestry fails without fresh evidence. Canonical files are
root:root `0644`, regular, single-link, no-follow, bounded to one MiB and
without unresolved extended access. Same-scope locks are root:root `0600`
control objects, not evidence. Neither status mode nor this tranche creates
`private-backups`. The one-file staged source and invocation directory under
`/tmp` must be safely removed before status work; there is no later status
scratch. A completed pass or typed fail reaches the canonical name only by
atomic replacement after all required work, child reaping, and cleanup.
Replacement is the final evidence operation; there is no required post-rename
I/O or crash-durability claim. Incomplete attempts leave the previous
generation unchanged. The reader requires protected metadata, exact schema,
finalized marker, scope, route, new generation, five-minute freshness, closed
vocabulary, consistent result and false non-effect flags. Route acknowledgment
is separate from evidence acceptance.

`Bounded slice rule` failure witness diagnostics are separate from this evidence
namespace. On incomplete P0s/P0t attempts, the fixed root bootstrap may
emit one closed-vocabulary, source-bound ASCII line of at most 512 bytes to
the existing controlling terminal only after applicable child, temporary,
stage, status and lock closeout is proved. Uncertain disposition suppresses
it. The collector retains only a private invocation-local selection; no
witness file, summary field, durable log, raw error, TLS/config/key material,
digest of private material or alternate reader is added. A completed pass or
typed completed fail publishes its protected record without a witness;
successful replacement remains the last evidence operation immediately
before exit. The optional terminal line and the facade's remote-phase-unproved
failure acknowledgment are advisory and cannot grant reader acceptance,
renewal, restoration, retry or any execution authority.

Legacy `/var/tmp/execution-substrate-remote-alpha/*tls*summary*.json`, any
old `*-renew-summary.json`, blocked-candidate protected summaries, and old
renewal backup directories are historical evidence only. They are not current
status, fallback readers, or renewal/rollback authority; do not migrate,
copy, remove, overwrite, or symlink them. P0q retains its separate legacy
writer contract. P0u privileged legacy use remains held pending its own
migration or independently reviewed guard. P0v writes no retained remote
summary. Status records may contain only bounded typed public certificate,
topology, key-public-match and chain-check classifications, public
fingerprints and validity times, source-controlled fixed public paths, and
explicit non-effects. They must never contain private key bytes or digests,
full certificate PEM, raw config, raw OpenSSL output, environment values,
secrets, arbitrary paths or commands, backup/rollback fields, transcripts,
support bundles, or Mac `.out` copy-back.

`Bounded slice rule`: the tracked synthetic public fixtures
`testdata/remote_alpha_es_tls_status/openssl3_x509_text.stdout` and
`testdata/remote_alpha_es_tls_status/openssl3_public_cert.pem` are
non-authoritative test inputs for the exact P0s/P0t certificate-text
compatibility regression. The captured text is a local Homebrew OpenSSL
3.6.2 response to the synthetic public certificate, not Remote Alpha host
output, an accepted status summary, a trust anchor, or evidence that the
target's reported OpenSSL 3.0.13 behavior is qualified. No synthetic
private key, generator output, or reproduction archive is tracked with these
fixtures. Their presence does not widen the collector's other whole-response
acceptance sets or its renewal and publication authority.

`Bounded slice rule`: `testdata/remote_alpha_es_tls_status/openssl3013_negative_responses.json`
is a minimal, non-authoritative offline projection of thirteen exact synthetic
negative tuples captured in one nonroot target OpenSSL 3.0.13 observation,
plus the three exact native-only downstream malformed-response controls.
It contains only public certificate/anchor PEM, retained malformed literals,
fixed command arguments, base64-encoded stdout/stderr, case IDs and integrity
hashes. The source native-result SHA-256 and per-case hashes bind it to the
separately retained original evidence. It contains no private key, host/account
metadata, scratch path, complete evidence archive, generated package, or
status summary. The two original key-match inputs were not exported; this
fixture does not claim to reconstruct them. Tests decode exact bytes for
contained parser replay and use artificial mutations only as refusal
controls. Raw OpenSSL streams and private key bytes never enter published
status evidence. Completed typed failures may replace status only after the
normal cleanup and semantic checks; incomplete grammar preserves prior bytes
and generation. Neither fixture nor replay grants target contact, renewal,
service repair, or wider production authority.

The P0u operator healthcheck TLS status/renew summary
`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`
with schema
`execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1` is
also a non-secret helper summary only. It may include paths, byte counts,
certificate file SHA-256 digests, public fingerprints, validity windows,
configured SPIFFE URI/SAN classification, cert/key public-key match status,
current file policy metadata, verification statuses, safe mTLS `/health` and
`/v1/executions:contract` probe statuses, unsupported-signing-topology failure
classification, future CA custody/signing next-step text, not-run
backup/install/probe metadata, and explicit non-claim labels. It must not be
copied back to Mac `.out` by the operator facade, must not become an IM input
or CP proof artifact, and must not contain private key PEM bodies, full
certificate PEM bodies, private-key backup digests, Vault tokens, root tokens,
unseal keys, client tokens, JWT-SVID payloads, API keys, passwords, proof
secrets, terminal transcripts, support-bundle content, raw retained bundles,
raw workspace contents, or raw secret-bearing command output.

Future Mac-side Remote Alpha maintenance-monitor summaries, if introduced by a
separate project later, are local evidence/projection only. They may summarize
route names, owners, monitor mode, eligibility classification, timestamps,
expiry windows, public fingerprints, command ids, exit codes, digest refs,
notification decisions, and blocked-action reasons from documented ES, IM, or
CP evidence. They must not become ES renewal semantics, IM readiness authority,
CP run-control authority, production readiness, or deployment/reconciliation
truth. They must never record private keys, token values, secret environment
values, raw PEM bodies, raw support bundles, raw workspaces, raw logs, terminal
transcripts, command arguments containing secrets, or notification payloads
containing secrets.

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
