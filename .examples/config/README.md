# Execution Substrate Config Examples

These files are templates only. They are not live runtime config, policy truth,
or proof evidence.

The signer keys in `ags*.json` and `egs.json` and the verification keys in
`es*.json` are known keys: their private seeds are one byte repeated, and AGS,
EGS and ES refuse them at startup. Give each host its own AGS and EGS keys with
`scripts/internal/signingkeygen`, and put their public parts into the ES
`verification` group and the AGS key ID into the EGS
`runtime_trust.signer_policy.allowed_signers`
(`.docs/system_overview/configuration.md`, "Signing keys"). AGS and EGS also
refuse a config file that other users can read or write, so a copy that holds a
real key must be mode 0600, or 0640 for a group the service runs in.

Use the default ES templates for successful, non-denying paths:

- `es.json` is the operator-only default ES example.
- `es.operator_and_control_plane.json` is the success-path example that also
  admits the bounded Control Plane caller/profile shape.

Use `es.configured_literal_policy_demo.json` only as the non-default full ES
config template for the harmless configured-literal admission-policy demo. It
sets `admission_policy.configured_static_script_literal_deny.mode` to
`enforce`, includes one safe entry ID, uses
`static_script_payload_text`, and carries a public inert replace-me literal.
Replace that placeholder only in the actual ES runtime config used for a
filmed or local demo. Do not put real/private filming marker values in this
repository.

Supported-local runs select the ES runtime config through `$ES_CONFIG`. Remote
Alpha/systemd hosts use `/etc/execution-substrate/es.json`.

The configured-literal demo is a prepare-denial template. It is not the default
success path, and it should not be copied into the default examples by inertia.
CP may receive and render ES admission outcomes, but CP does not define,
configure, or supply ES admission-policy inputs.

This template is not OPA/Rego, a DSL, regex support, a policy bundle, an
external evaluator, request-supplied policy, CP-supplied policy, or broad
policy-engine support. The only supported input class for this policy is
`static_script_payload_text`.
