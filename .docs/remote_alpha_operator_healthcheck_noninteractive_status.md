# Remote Alpha Operator Healthcheck TLS Noninteractive Status Design

## 0. Purpose, Authority, And Status

This document defines a proposed ES-owned noninteractive, read-only status route
for Remote Alpha operator-healthcheck TLS material.

Status:

- `Bounded slice rule`: the existing P0u interactive
  `operator-healthcheck-tls-status` route remains the current implemented route.
- `Design/static-test prep only`: this document proposes a future
  noninteractive route contract. It does not implement a route, renewal, SSH
  changes, profile mutation, or scheduled execution.
- The proposed route is an extension of the ES-owned Remote Alpha
  operator-helper/status surface. It is not a redefinition of CP, IM, MA, or
  Bridge authority.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
code and tests win for current behavior and this document must be realigned.

## 1. Current Route Grounding

The current Mac-side facade route is:

```text
scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty
```

The current host-local helper accepts:

```text
scripts/remote_alpha_operator_healthcheck_tls_renew.sh --status
scripts/remote_alpha_operator_healthcheck_tls_renew.sh --check-only
scripts/remote_alpha_operator_healthcheck_tls_renew.sh --execute-renew
scripts/remote_alpha_operator_healthcheck_tls_renew.sh --summary-path <path>
```

Current implemented behavior:

- The Mac-side status facade requires `--ssh-target` and `--interactive-tty`.
- The facade performs local stdin/stdout TTY preflight before staging or SSH.
- The facade stages only the fixed public/internal operator-healthcheck TLS
  helper pair, invokes only `--status` for the status route, and uses
  `ssh -tt`.
- If the remote user is not root, the facade invokes `sudo` without `-n`, so a
  visible remote sudo/password prompt may occur.
- The current status path is non-mutating with respect to certificate renewal,
  service restart, CP proof, IM refresh, support-bundle collection, Vault,
  SPIRE, Nomad, workload-auth, runtime identity, and ES service/governance TLS
  scope.
- The current status helper writes a bounded non-secret remote summary at the
  documented operator-healthcheck TLS summary path, does not copy it back to
  Mac `.out`, and does not print full summary JSON.
- The host-local helper can parse public certificate metadata, confirm
  cert/key public-key match without printing private keys, verify the operator
  certificate against configured ES client CA material when available, detect
  `spiffe://execution.internal/operator/local`, detect the legacy
  `spiffe://execution.internal/operator`, and optionally probe safe local HTTPS
  endpoints without recording response bodies.
- The current ES route contract does not support scheduled/background
  noninteractive read-only execution.

Current exit-code meaning:

- Facade exit `2` means facade usage, preflight, or refusal. Examples include
  missing `--ssh-target`, missing `--interactive-tty`, duplicate flags,
  unknown flags, helper override flags, secret-like arguments, invalid SSH
  target shape, missing local TTY, or missing fixed helper files. In these
  cases the remote helper is not invoked.
- Helper exit `2` means host-local helper bad arguments or forbidden arguments,
  including secret-like CLI arguments, equals-form options, unknown flags,
  helper scope mixing, or unsupported helper override input.
- Helper exit `1` means helper execution reached a fail-closed condition or
  status blocker. For status, examples include expired/not-yet-valid
  certificate metadata, operator identity mismatch, cert/key public-key
  mismatch, trust verification failure, missing material, unreadable material,
  or probe failure. For renew, it includes the current
  `unsupported_signing_topology` blocker.
- Helper exit `0` means the helper completed and the current helper summary
  has `result.ok=true`.

Current renewal topology:

- `operator-healthcheck-tls-renew` remains blocked by
  `unsupported_signing_topology`.
- `unsupported_signing_topology` means ES has no authoritative documented CA
  custody/signing topology for the host-local operator healthcheck client
  identity.
- The helper must not assume a retained remote CA private key, must not accept
  ad hoc signing material, and must fail closed before backup, install, service
  restart, or post-renew probes.
- `es-service-tls-renew` covers the ARS/AGS/ES artifact-registry mTLS scope.
- `es-governance-tls-renew` covers the ES to EGS execution-governance
  trust-model mTLS scope.
- Neither service/governance route repairs operator-healthcheck client TLS by
  inference. Operator-healthcheck TLS is a separate host-local operator client
  identity scope.

Current CP/IM consumption:

- CP `diagnose-remote-profile` consumes profile certificate metadata and emits
  contact-free diagnostics such as `cert_metadata_expired`; it is not live
  remote contact, renewal, or ES route execution.
- CP owns profile acceptance, diagnostics, workflow state, Temporal state,
  review/finalization, and run-control semantics.
- IM emits the Remote Alpha profile, profile/provenance artifacts, remote
  doctor/readiness/support-bundle artifacts, and profile lineage refresh
  evidence. IM artifacts remain readiness/provenance/diagnostics only.
- Profile lineage is refreshed through IM/CP-owned documented profile and
  proof-profile lineage paths. ES status evidence may indicate that a refresh is
  needed, but it must not mutate profile lineage.
- Bridge projections remain evidence/projection adapters only. Bridge output
  is not CP, ES, IM, MA, runtime, or infrastructure authority.

## 2. Purpose And Non-Goals

Purpose:

- Allow bounded read-only operator-healthcheck TLS status collection without
  interactive TTY or password babysitting.
- Give MA, IM, and CP a safe ES-owned status evidence shape they can consume
  without defining ES route semantics.
- Preserve fail-closed behavior when noninteractive auth, remote status, trust
  metadata, identity metadata, helper output, or redaction cannot be proven.

Non-goals:

- No renewal.
- No certificate, key, trust bundle, profile, env file, support-bundle,
  retained-bundle, proof artifact, SQLite state, or remote-state mutation.
- No profile mutation and no profile lineage mutation.
- No CP authority, CP proof execution, CP run-control truth, Temporal action,
  worker startup, or workflow startup.
- No IM authority, IM refresh execution, support-bundle collection, or IM
  reconciliation.
- No MA authority, scheduler workaround, pseudo-TTY automation, password
  storage, password replay, or hidden remote reconciler.
- No Bridge authority or Bridge control path.
- No production readiness, live proof, submit readiness, runtime-profile
  readiness, retained-result readiness, governed execution proof, Vault
  readiness, SPIRE readiness, Nomad readiness, or deployment claim.

## 3. Authority Boundaries

- ES owns the route contract, helper semantics, TLS status semantics, failure
  classes, redaction requirements, and any future implementation.
- CP owns remote-supported-host profile parsing, profile acceptance,
  diagnostics, workflow/run-control, Temporal state, review, checkpointing, and
  finalization.
- IM owns profile/provenance/readiness/support-bundle emission and profile
  lineage refresh artifacts.
- MA may schedule, propose, summarize, or invoke only after ES defines the safe
  noninteractive route and a later MA tranche updates MA route metadata, docs,
  tests, and audit evidence.
- Bridge remains an evidence/projection adapter only. It must not start,
  control, or infer ES, CP, IM, or MA authority from this route.

The proposed route output is evidence/projection only. No repo may treat it as
CP run-control truth, ES runtime truth, IM authority, MA authority, Bridge
authority, or infrastructure reconciliation truth.

## 4. Route Shape

Decision: introduce a new route id instead of adding a mode flag to the current
interactive route.

Proposed route id:

```text
operator-healthcheck-tls-status-noninteractive
```

Rationale:

- The current `operator-healthcheck-tls-status` route has a documented,
  tested, interactive topology: required `--interactive-tty`, local TTY
  preflight, `ssh -tt`, visible sudo/password prompt behavior, remote staging,
  remote summary persistence, and no Mac `.out` copy-back.
- Adding a mode flag to the existing route would make it easy for MA, operators,
  or tests to confuse two different safety postures under one route name.
- A new route lets ES publish explicit route metadata:
  `requires_interactive_tty=false`, `supports_noninteractive=true`, and, after
  implementation and audit only, `scheduled_execution_allowed=true`.
- The existing interactive route remains valid for foreground operator use.

Proposed stable argv:

```text
scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json
```

Allowed flags:

- `--help`
- `--ssh-target <target>`
- `--format json`
- optional future `--output <local-json-path>` only if a later implementation
  constrains it to an approved local evidence root and still emits identical
  bounded JSON to stdout

Forbidden flags:

- `--interactive-tty`
- `--execute-renew`
- `--status`
- `--check-only`
- `--summary-path`
- `--output` until separately documented
- `--host-local`
- `--dry-run`
- `--apply`
- `--scope`
- reset, unseal, workload-auth, runtime-identity, service-user, config/TLS,
  binary deployment, IM, support-bundle, CP proof, helper override, path
  override, arbitrary command, equals-form, duplicate, positional, and
  secret-like arguments

Required local inputs:

- A single SSH target string.
- ES-owned route metadata that resolves the fixed remote read-only status
  command. The user must not supply a helper path or shell command.
- Local `ssh` capability.
- A route config stating whether noninteractive execution is implemented and
  audited.

Allowed output formats:

- JSON only for the route contract.
- Help text is allowed for `--help`.
- No Markdown, human transcript, raw helper stdout, raw helper stderr, raw SSH
  transcript, remote summary copy-back, or support bundle is part of the route
  contract.

Exit-code vocabulary:

- `0`: bounded JSON emitted, `status_available=true`, and no status blocker.
- `1`: bounded JSON emitted or local safe failure JSON emitted, but status is
  blocked, unavailable, redaction failed, remote contact failed, helper failed,
  or a fail-closed condition was reached.
- `2`: usage, local preflight, policy/refusal, forbidden argument, or invalid
  route metadata. Remote contact must not occur for facade exit `2`.

Consumers may retain the bounded JSON evidence document and numeric exit code.
Consumers must not retain raw stdout/stderr transcripts. If stdout is the JSON
channel, stdout is not a raw transcript; it is the bounded route output. Stderr
is limited to short safe diagnostics and is not required for classification.

Compatibility:

- The current `operator-healthcheck-tls-status` route remains unchanged.
- The current `operator-healthcheck-tls-renew` route remains blocked with
  `unsupported_signing_topology`.
- Service/governance TLS routes remain separate and must not be conflated with
  operator-healthcheck TLS.

## 5. Noninteractive Constraints

The proposed route must:

- Not require local stdin or stdout to be a TTY.
- Not allocate a pseudo-TTY.
- Not invoke SSH in a mode that prompts for passwords.
- Use no-prompt SSH semantics, such as BatchMode and zero password prompts, if
  SSH is used.
- Not call sudo in a way that prompts interactively.
- Use `sudo -n` only when root-only read access is required, or avoid sudo
  entirely when the installed helper/capability model can prove read access.
- Fail closed if required auth material is not already noninteractive-ready.
- Fail closed if SSH, sudo, helper execution, or status collection would need a
  prompt.
- Not stage helper files to a remote scratch directory.
- Not write the current remote summary file as the only evidence channel.
- Not mutate remote files, services, certs, keys, profiles, trust bundles, env
  files, state stores, support bundles, retained bundles, or proof artifacts.
- Not run renewal, install, backup, rollback, restart, `curl` probes that record
  bodies, IM refresh, support-bundle collection, CP proof, ES submit, Nomad,
  Docker, Vault, SPIRE mutation, reset, unseal, workload-auth bootstrap, or
  runtime identity generation.
- Not expose remote paths, endpoint secrets, cert bodies, PEM, env values,
  SPIFFE/Vault material, raw logs, raw helper transcripts, raw SSH transcripts,
  raw payloads, connector IDs, workspace IDs, org IDs, or unsafe local paths.

Implementation implication:

- A future implementation needs either a preinstalled ES-owned read-only helper
  or another ES-owned fixed remote command that can emit bounded JSON without
  remote staging and without remote summary mutation. Reusing the current
  staged `ssh -tt` facade is not sufficient.

## 6. Auth Posture Classification

Failure classes are stable strings in the bounded JSON evidence. They do not
authorize retries, mutation, renewal, profile acceptance, or run-control.

Local preflight classes:

- `facade_usage_failed`: invalid local argv, duplicate flag, forbidden flag,
  helper override, secret-like argument, invalid SSH target, or invalid route
  metadata. Exit `2`, no remote contact.
- `noninteractive_auth_required`: local route metadata or configured command
  shows the route would need a TTY, password prompt, prompt-capable sudo, or
  unsupported auth topology. Exit `1` or `2` depending on whether this is config
  refusal or usage.
- `remote_auth_not_ready`: contact-free local evidence says required
  noninteractive auth material is absent, stale, disabled, or unsupported. No
  remote contact.
- `redaction_unavailable`: the route cannot prove bounded output/redaction
  before returning evidence.

Remote-read-only contact classes:

- `ssh_batch_mode_failed`: the no-prompt SSH invocation failed before helper
  execution. The route must not parse or retain raw SSH stderr to infer secrets.
- `remote_status_unavailable`: the fixed remote status command could not run or
  did not produce safe status output, without a more specific class.
- `noninteractive_auth_required`: SSH or sudo reported a safe no-prompt refusal
  and no helper output was available.
- `helper_usage_failed`: the helper ran and returned usage/forbidden-argument
  exit `2`.
- `unknown_helper_failure`: the helper ran and failed without a safe class.

Certificate/status classes:

- `cert_metadata_expired`: safe certificate metadata proves `not_after` is in
  the past.
- `cert_metadata_not_yet_valid`: safe certificate metadata proves `not_before`
  is in the future.
- `trust_chain_unavailable`: configured trust chain or verification metadata is
  missing, unreadable, or unverifiable.
- `identity_mismatch`: the operator client identity does not match
  `spiffe://execution.internal/operator/local`, or legacy-only identity is
  present.
- `key_pair_mismatch`: public cert/key digests do not match.
- `remote_status_unavailable`: safe local probes or helper status could not
  produce a bounded status reading.

Reserved/future classes:

- `unsupported_signing_topology`: reserved for renewal and any future helper
  output that reports missing CA custody/signing topology. The noninteractive
  status route may surface this only as contextual renewal state, not as status
  renewal permission.
- `unexpected_output_shape`: helper output is not valid bounded JSON or does
  not match the schema.
- `forbidden_output_material`: output contains or may contain forbidden
  secret/raw material.

## 7. Status Evidence Schema

Schema version:

```text
execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1
```

Required top-level fields:

- `schema_version`
- `route`
- `generated_at`
- `live_contact_attempted`
- `status_available`
- `result`
- `failure_class`
- `exit_codes`
- `auth_posture`
- `certificate`
- `identity`
- `trust_chain`
- `redaction`
- `non_authority_labels`
- `owning_repo_contract_labels`
- `profile_lineage_hints`

Bounded JSON shape:

```json
{
  "schema_version": "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1",
  "route": {
    "id": "operator-healthcheck-tls-status-noninteractive",
    "version": "v1",
    "owner_repo": "execution-substrate",
    "requires_interactive_tty": false,
    "supports_noninteractive": true,
    "scheduled_execution_allowed": true,
    "current_status": "proposed"
  },
  "generated_at": "RFC3339-UTC",
  "live_contact_attempted": false,
  "status_available": false,
  "result": {
    "status": "pass|fail|not_available",
    "ok": false,
    "summary": "safe bounded summary"
  },
  "failure_class": "remote_auth_not_ready",
  "exit_codes": {
    "facade_exit_code": 1,
    "transport_exit_code": null,
    "helper_exit_code": null
  },
  "auth_posture": {
    "ssh_batch_mode": "not_attempted|used|failed",
    "tty_required": false,
    "pseudo_tty_created": false,
    "sudo_prompt_allowed": false,
    "password_prompt_observed": false,
    "noninteractive_ready": false
  },
  "certificate": {
    "status": "pass|fail|not_available",
    "not_before": null,
    "not_after": null,
    "expired": null,
    "not_yet_valid": null,
    "public_fingerprint_sha256": null,
    "file_sha256": null,
    "subject_label": null,
    "issuer_label": null,
    "safe_identity_label": null
  },
  "identity": {
    "expected_uri_label": "operator/local",
    "matches_expected": null,
    "legacy_operator_uri_present": null,
    "failure_class": null
  },
  "trust_chain": {
    "status": "pass|fail|not_available",
    "issuer_digest_sha256": null,
    "chain_label": null,
    "raw_certificate_body_included": false
  },
  "redaction": {
    "private_key_pem_bodies_included": false,
    "certificate_pem_bodies_included": false,
    "raw_stdout_retained": false,
    "raw_stderr_retained": false,
    "raw_logs_retained": false,
    "env_values_included": false,
    "remote_paths_included": false,
    "endpoint_secrets_included": false
  },
  "non_authority_labels": [
    "evidence_projection_only",
    "not_cp_run_control",
    "not_im_readiness_authority",
    "not_es_runtime_truth",
    "not_maintenance_agent_authority",
    "not_bridge_authority",
    "not_production_readiness",
    "not_live_proof"
  ],
  "owning_repo_contract_labels": {
    "route_contract_owner": "execution-substrate",
    "profile_diagnostic_owner": "control-plane",
    "profile_provenance_owner": "infrastructure-manager",
    "scheduler_summary_owner": "maintenance-agent"
  },
  "profile_lineage_hints": {
    "profile_refresh_may_be_needed": false,
    "cp_diagnose_remote_profile_rerun_may_be_needed": false,
    "mutates_profile": false,
    "lineage_authority": "none"
  }
}
```

Schema rules:

- `route.current_status` remains `proposed` until implementation and audit.
- `scheduled_execution_allowed=true` is part of the proposed target contract,
  not current executable metadata.
- `live_contact_attempted=false` is valid for local preflight failures.
- `helper_exit_code` is set only if the remote helper ran.
- `transport_exit_code` is numeric-only and optional.
- Certificate metadata is public metadata only. Raw certificate bodies and PEM
  bodies are forbidden.
- Identity labels are safe labels. They must not include raw certificate bodies
  or unsafe remote path material.
- Profile lineage hints are hints only. They do not mutate profile lineage and
  do not become CP or IM authority.

## 8. CP, IM, And MA Integration Contract

CP:

- `diagnose-remote-profile` may consume this route output only as diagnostic
  evidence after CP documents that consumption.
- CP profile acceptance still comes from CP profile parsing and diagnostics,
  not from this route output alone.
- CP must not treat this route output as workflow truth, Temporal truth,
  run-control truth, ES producer compatibility truth, or proof success.
- CP rerun planning remains a separate step after IM/profile material is
  refreshed through an owning-repo path.

IM:

- IM may consume this route output for readiness/profile/provenance reporting
  only after IM documents that consumption.
- IM may use status evidence to decide that profile/provenance refresh is
  needed, but it must not let this route mutate profile material directly.
- IM remains readiness/provenance/diagnostics only and must not infer ES renewal
  eligibility or mutation semantics.

MA:

- MA may schedule or run this route only after ES implements and audits it, and
  after MA updates route metadata to
  `supports_noninteractive=true` and `scheduled_execution_allowed=true`.
- Until then, MA must keep current `operator-healthcheck-tls-status` foreground
  interactive only and scheduled/background disallowed.
- MA must not implement pseudo-TTY automation, password storage/replay, raw
  transcript parsing, renewal, profile mutation, IM refresh, support-bundle
  collection, CP proof, or hidden reconciliation.

Bridge:

- Bridge may project already-safe evidence only. It must not start, control,
  or infer route execution, renewal, CP acceptance, IM readiness, or ES runtime
  authority.

## 9. Stop Conditions

The proposed route must fail closed when:

- Local argv is invalid.
- A TTY is required.
- A pseudo-TTY would be needed.
- SSH would prompt for a password.
- Sudo would prompt for a password.
- Noninteractive auth material cannot be proven ready.
- Required cert/key/trust material is missing or unreadable.
- Status collection would require remote state mutation.
- The command would stage helper files or write remote summary/proof/support
  artifacts.
- The command would expose forbidden token, env, endpoint, path, PEM, cert body,
  SPIFFE/Vault material, raw log, raw transcript, connector/workspace/org ID,
  or raw payload material.
- The helper detects `unsupported_signing_topology`.
- Helper output has an unexpected shape.
- Redaction cannot be guaranteed.
- A service/governance TLS route would be needed to explain
  operator-healthcheck TLS status.
- A consumer attempts to treat the output as CP, IM, MA, Bridge, ES runtime, or
  infrastructure authority.

## 10. Validation Plan

This design tranche permits safe local validation only.

Future implementation tests must include:

- Unit tests for argv construction.
- Tests that the noninteractive route uses no TTY and no pseudo-TTY.
- Tests that SSH, if used, includes BatchMode/no-prompt semantics.
- Tests that sudo, if used, uses no-prompt semantics and fails closed when
  prompt-capable sudo would be required.
- Tests proving the route does not stage helper files to the remote host.
- Tests proving the route does not write or require a remote summary file.
- Tests for failure-class mapping:
  `facade_usage_failed`, `remote_auth_not_ready`,
  `noninteractive_auth_required`, `ssh_batch_mode_failed`,
  `remote_status_unavailable`, `cert_metadata_expired`,
  `trust_chain_unavailable`, `identity_mismatch`, `helper_usage_failed`,
  `unsupported_signing_topology`, `unexpected_output_shape`,
  `forbidden_output_material`, and `unknown_helper_failure`.
- Tests for the redacted JSON schema.
- Tests that no raw stdout/stderr, helper transcript, SSH transcript, PEM body,
  raw cert body, env value, raw log, or unsafe path is emitted or retained.
- Tests preserving current interactive route compatibility.
- Tests that `operator-healthcheck-tls-renew` remains blocked.
- Tests that `es-service-tls-renew` and `es-governance-tls-renew` are not
  conflated with operator-healthcheck TLS.
- Tests that CP/IM/MA/Bridge authority boundaries remain documented.

No live remote tests, SSH to the real host, service startup, Temporal startup,
fake model server startup, worker startup, validation driver run, golden
capture, ES submit, Nomad/Docker jobs, certificate mutation, profile mutation,
support-bundle collection, retained-bundle mutation, or proof generation belong
to this design tranche.

## 11. Migration And Compatibility Plan

- Preserve the existing interactive `operator-healthcheck-tls-status` route for
  foreground operator use.
- Preserve the existing blocked `operator-healthcheck-tls-renew` route and
  `unsupported_signing_topology` classification.
- Introduce `operator-healthcheck-tls-status-noninteractive` only in a later ES
  implementation tranche after this design is audited.
- Keep MA scheduled/background eligibility unchanged until ES implementation,
  ES audit, MA metadata update, MA docs/tests, and MA audit all land.
- Keep CP `diagnose-remote-profile` as contact-free profile diagnostics until a
  CP tranche explicitly consumes this status output as diagnostic evidence.
- Keep IM profile/provenance refresh separate until IM documents how refreshed
  safe certificate metadata and lineage are emitted.
- Do not rerun CP/Temporal/live proof until CP profile diagnostics can pass over
  refreshed profile material through the owning-repo path.

Recommended next tranches:

- Implement the ES noninteractive status route.
- Audit the ES route implementation and redaction.
- Update MA to consume ES route metadata.
- Plan CP `diagnose-remote-profile` rerun over refreshed profile material.
- Design IM profile lineage refresh for renewed public certificate metadata.
- Design operator-approved renewal only after ES documents signing topology and
  CA custody.
- Document a manual certificate replacement path if renewal remains blocked.
