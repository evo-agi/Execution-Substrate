# Remote Alpha External TLS Single-Use Incident Authorization

## Classification And Authority

`Bounded slice rule`: this is an ES-owned documentation contract for one later
foreground incident on one existing Remote Alpha proof/support host. It creates
no executable recovery capability. Report-derived operational evidence
indicates that certificate-validity failures block the current external TLS
path; the required read-only live inventory must independently establish the
installed prior state before any incident-specific effect.

Remote Alpha remains bounded proof/support infrastructure. Certificate
lifetime is not a support commitment, and this record is not production PKI,
ongoing support, general remote topology, or target product architecture.

## Normative incident record

The fenced JSON object below is an internal documentation-contract test record.
It is not a public API, runtime schema, IM or CP protocol, or executable
authority. If explanatory prose is ambiguous, this record governs. Unknown or
duplicated normative members are invalid.

```json
{
  "record_kind": "execution-substrate.remote-alpha.external-tls-single-use-incident-contract.v1",
  "public_protocol": false,
  "classification": "bounded_proof_support_incident",
  "implementation_status": "documentation_only",
  "scope": {
    "hosts": 1,
    "incidents": 1,
    "executions": 1
  },
  "authorization": {
    "initial_state": "AUTHORIZED_NOT_CONSUMED",
    "pre_effect_binding": [
      "incident_id",
      "physical_host",
      "es_contract_commit",
      "es_contract_tree",
      "private_plan_sha256",
      "incident_packet_sha256",
      "rollback_packet_sha256"
    ],
    "pre_effect_candidate_manifest_allowed": false,
    "first_effect_irreversibly_consumes_authority": true,
    "consume_on_first_effect": [
      "key_generation",
      "csr_generation",
      "certificate_signing",
      "private_backup_creation",
      "active_tls_installation",
      "service_restart"
    ],
    "post_generation_candidate_manifest_required": true,
    "second_human_gate_required_before_installation": true,
    "installation_may_use_only_second_gate_manifest": true,
    "changed_candidate_requires_new_es_decision": true,
    "changed_candidate_requires_new_independent_audit": true,
    "second_packet_allowed": false,
    "return_to_authorized_not_consumed_allowed": false,
    "unchanged_rollback_packet_allowed_within_consumed_incident": true,
    "unchanged_rollback_packet_is_new_authority": false,
    "closure_states": [
      "ABANDONED_UNUSED",
      "CONSUMED_OPEN_INCIDENT",
      "CONSUMED_AND_CLOSED"
    ],
    "terminal_closure_states": [
      "ABANDONED_UNUSED",
      "CONSUMED_AND_CLOSED"
    ],
    "nonterminal_closure_state": "CONSUMED_OPEN_INCIDENT",
    "terminal_state_authorizes_another_packet": false
  },
  "topology": {
    "ca_roles": [
      "external_server_auth",
      "external_client_auth"
    ],
    "leaf_roles": [
      "ags_server",
      "es_server",
      "control_plane_client",
      "operator_client"
    ],
    "fresh_keypairs": 6,
    "key_reuse_allowed": false,
    "cross_role_key_reuse_allowed": false,
    "private_key_cross_machine": false
  },
  "identities": {
    "control_plane_uri": "spiffe://execution.internal/service/control-plane",
    "operator_uri": "spiffe://execution.internal/operator/local",
    "operator_compatibility_cn": "client.operator",
    "operator_compatibility_dns": "client.operator",
    "client_uri_count_per_leaf": 1,
    "authorization_from_common_name_allowed": false,
    "legacy_operator_uri_allowed": false,
    "ags_es_share_server_leaf": false
  },
  "cryptography": {
    "key_algorithm": "RSA-3072",
    "certificate_signature": "SHA-256",
    "minimum_tls": "1.2",
    "leaf_maximum_days": 365,
    "leaf_must_not_exceed_sunset": true,
    "ca_validity_is_leaf_coverage_plus_bounded_grace": true,
    "ca_basic_constraints_critical": true,
    "ca_path_length": 0,
    "ca_key_usage": [
      "keyCertSign",
      "cRLSign"
    ],
    "leaf_basic_constraints_critical": true,
    "server_leaf_eku": [
      "serverAuth"
    ],
    "client_leaf_eku": [
      "clientAuth"
    ],
    "digital_signature_required": true,
    "exact_san_required": true,
    "cross_role_trust_allowed": false
  },
  "custody": {
    "ca_keys_human_custodied_on_mac": true,
    "ca_keys_encrypted_at_rest": true,
    "leaf_keys_generated_at_point_of_use": true,
    "only_csr_and_public_material_cross_machine": true,
    "ca_key_end_condition_required": true
  },
  "preflight": {
    "live_inventory_required": true,
    "reported_expiry_is_not_repository_truth": true,
    "ags_es_allowlists_must_already_accept_required_identities": true,
    "bootstrap_issuer_comparison_values_must_be_inventoried": true,
    "authorization_configuration_mutation_allowed": false,
    "tls_binding_mutation_before_inventory_allowed": false
  },
  "cutover": {
    "complete_candidate_validation_required": true,
    "complete_private_backup_required": true,
    "complete_host_disk_set_before_restart": true,
    "restart_order": [
      "ags.service",
      "es.service"
    ],
    "rollback_outcome": "restored_prior_incident_state",
    "rollback_outcome_claims_health": false
  },
  "acceptance": {
    "owner": "execution_substrate",
    "im_projection_is_acceptance": false,
    "required_checks": [
      "installed_set_integrity",
      "configured_allowlist_match",
      "direct_operator_mtls",
      "direct_control_plane_ags_mtls",
      "direct_control_plane_es_mtls",
      "es_contract_endpoint",
      "fresh_substrate_observations"
    ],
    "ags_nonmutating_application_authorization_operation_available": false,
    "ags_application_authorization_claim_requires_source_defined_check": true
  },
  "profile_handoff": {
    "owner": "infrastructure_manager",
    "es_authorizes_profile_mutation": false,
    "separate_committed_im_contract_required": true,
    "im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required": true,
    "profile_replacement_is_es_consuming_effect": false,
    "profile_replacement_occurs_only_after_es_acceptance": true,
    "profile_handoff_failure_state": "CONSUMED_OPEN_INCIDENT",
    "profile_handoff_failure_revokes_es_acceptance": false,
    "profile_handoff_failure_triggers_automatic_host_tls_rollback": false,
    "terminal_closeout_requires_handoff_or_explicit_retirement": true
  },
  "sunset": {
    "default_disposition": "RETIRE_BEFORE_LEAF_EXPIRY",
    "exact_sunset_required_before_first_effect": true,
    "retirement_owner_required": true,
    "retirement_action_required": true,
    "retirement_evidence_required": true,
    "retirement_action_minimum_scope": [
      "disable_or_retire_external_access_path",
      "deactivate_runnable_mac_profile",
      "complete_ca_key_disposition",
      "record_host_topology_disposition"
    ],
    "active_authorization_docs_and_tests_removed_or_converted_on_terminal_closure": true
  },
  "non_goals": {
    "reusable_recovery_route": true,
    "automatic_renewal": true,
    "scheduler": true,
    "production_pki": true,
    "ongoing_remote_alpha_support": true,
    "im_recovery_authority": true,
    "ma_execution_authority": true,
    "os_update_or_reboot": true
  }
}
```

## One-Time State Transitions

Before first ES effect, authority binds the incident ID, physical host,
committed ES contract identity, private plan hash, and independently audited
incident and rollback packet hashes. No candidate-manifest hash exists yet.
If the objective requires restoring the runnable CP profile, that private plan
must also bind the exact committed and independently audited IM contract commit
and tree before any ES effect. Without that binding, the packet stops before
key generation, CSR generation, signing, private ES recovery backup,
installation, or restart. Read-only inventory, review, and audit do not consume
authority. The first such ES-governed effect consumes it irreversibly.

After generation and signing, the consumed incident validates one complete
candidate set and hashes one safe candidate manifest. A second visible human
gate may authorize installation of exactly that manifest. Any key, CSR,
certificate, identity, SAN, target, packet, or manifest change requires a new
ES decision and independent audit; it is never a retry under this authority.

After interruption, the exact unchanged pre-audited rollback packet may run
within the same consumed incident. It is not a second incident, fresh execution
authority, or return to `AUTHORIZED_NOT_CONSUMED`. Status remains
`CONSUMED_OPEN_INCIDENT` until forward completion, accepted rollback closeout,
or another separately authorized terminal resolution.

## Trust, Custody, And Preflight

The two role-separated CAs sign only their two named leaf roles. AGS and ES
have distinct endpoint-SAN server leaves; the Control Plane and operator leaves
each have exactly one authorized URI. CA certificates are path-length-zero
roots with critical CA constraints and signing usage. Leaves have critical
non-CA constraints, their one role EKU, digital-signature usage, exact SANs,
matching keys, intended-chain verification, and cross-role rejection.

Fresh leaf keys are generated and retained at point of use: AGS, ES, and
operator keys on Linux; the Control Plane key on the Mac. Encrypted CA keys
remain under named foreground human custody on the Mac. Only CSRs and public
material cross machines. Private keys, their digests, passphrases, tokens, PEM
bodies, profiles, and transcripts are excluded from repository and redacted
evidence surfaces.

Before first effect, secret-safe inventory must establish the exact installed
prior state, endpoints, TLS bindings, ownership and filesystem capabilities,
AGS and ES caller allowlists, and each configured bootstrap-issuer Common Name
comparison value. The required CP and operator identities must already be
accepted where used. This incident cannot change allowlists, SPIFFE prefixes,
issuer comparison settings, bootstrap behavior, or application authorization.
A mismatch stops for a separate configuration-authority decision.

Current AGS source has no non-mutating application operation that exercises its
caller authorization; `/health` does not do so and publish is mutating.
Therefore incident acceptance proves the AGS TLS path and the inventory-backed
configured allowlist match, not an AGS application operation. That latter claim
remains for a later governed proof. ES authorization is exercised by its
read-only contract endpoint.

## Cutover, Rollback, And Acceptance

The later private packet must produce complete candidate validation, a verified
private backup, safe activation with the complete host disk set before restart,
and fail-closed mixed-state handling. Exact commands, temporary paths, backup
file inventory, staging and fsync mechanics, OpenSSL syntax, serial generation,
KDF parameters, checkpoint ledger, forward-recovery branches, profile
transaction implementation, and diagnostic formatting remain packet-local.

Restart order is AGS and then ES, stopping on the first defect. Rollback
restores the exact inventory-bound prior bytes, bindings, and metadata under the
same bounded order. `restored_prior_incident_state` claims only restoration; it
does not claim the prior state is healthy, current, expired, or usable.

ES owns acceptance. The checks in the record establish installed-set integrity,
unchanged authorization configuration, direct operator and CP mTLS, the ES
contract endpoint, and fresh substrate observations. ES acceptance precedes and
does not depend on any later IM profile projection. ES does not authorize IM
profile mutation. Only after ES acceptance may IM replace or emit the runnable
profile under the separately committed and audited IM contract. That handoff
does not consume, re-consume, or restore ES incident authority.

A failed profile handoff leaves the operational incident
`CONSUMED_OPEN_INCIDENT`; it does not revoke ES acceptance or automatically roll
back the accepted host TLS set. Any later host rollback still requires the exact
unchanged pre-audited rollback packet inside the same consumed incident.
`CONSUMED_AND_CLOSED` requires either successful separately authorized IM
handoff or explicit retirement and closure without a runnable CP profile. IM
projection remains downstream evidence and never creates ES acceptance. IM, CP,
and MA gain no signing, recovery, execution, or ES-acceptance authority.

## Sunset, Retirement, And Closure

Before first effect, the packet binds one exact sunset date or event, one named
human incident custodian, one retirement action, redacted retirement evidence,
and one CA-key retention or destruction disposition. The action must cover the
four minimum scopes in the record. Silence never authorizes continued operation
or renewal; the default is `RETIRE_BEFORE_LEAF_EXPIRY`.

`ABANDONED_UNUSED` and `CONSUMED_AND_CLOSED` are terminal.
`CONSUMED_OPEN_INCIDENT` is not terminal. No terminal state authorizes another
packet. A terminal closure tranche must remove the active PLANS entry; remove
or convert this authorization into a compact historical closure record; remove
these active tests or replace them with one compact closure-state test; remove
the incident cross-references from the four P0u records; and preserve only the
minimum redacted outcome history.

## Non-Goals And Future Sequence

This incident contract adds no executable operator route. It does not widen,
replace, or depend on any existing operator-facade route, evidence-ingestion
behavior, producer placement, or readiness adapter. Existing route status
remains governed by its own repository contract. Reusable P0u renewal remains
blocked with `unsupported_signing_topology`.

No incident packet, rollback packet, certificate, key, profile, implementation,
live effect, update, or reboot is created here. The remaining sequence is a
fresh independent audit of this contract, read-only inventory, private packet
derivation and audit, one foreground execution, ES acceptance, any separately
governed IM handoff, and terminal closure.
