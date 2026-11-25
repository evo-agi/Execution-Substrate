# P0s/P0t OpenSSL 3 certificate-text fixtures

These files are synthetic public test inputs for the bounded
`x509 -in /dev/stdin -noout -text` response contract. They are not Remote
Alpha host evidence, installed TLS material, a trust anchor, or a completed
status result.

- `openssl3_x509_text.stdout`: 3,059 unchanged bytes from a local Homebrew
  OpenSSL 3.6.2 `x509 -in /dev/stdin -noout -text` run over the synthetic
  certificate below; SHA-256
  `b9b4211e036dee8819e68711e5d254db289abc20c6ae5bfbb2683fe4085087e4`.
  It has a terminal `Signature Value:` heading and eight-space hexadecimal
  signature rows.
- `openssl3_public_cert.pem`: 1,172-byte synthetic public certificate with
  subject under `ge-p0t-parser-fixture.invalid`; SHA-256
  `a6f1256b5d7ce3485eeadd59e974637e49e3857b4aa159923a1bd0dd0a367c55`.

The local text response is a deterministic regression input, not target
OpenSSL 3.0.13 evidence. The generator private key was removed and is not
tracked. Tests construct negative text shapes in memory and keep the fixed
command, SAN/EKU logic, validity precedence, and unknown-response refusal.

`openssl3013_negative_responses.json` is a separate, finite projection of
thirteen actionable synthetic negative tuples and three native-only downstream
malformed-response controls in the retained nonroot target native report (SHA-256 `41620e727d0f28e40a38f8a8965696274faa57679b3d91555e9becc903b19e34`).
It holds only the public certificate/anchor inputs or malformed literals used
by those cases, their exact fixed argv and base64 response streams, and
per-blob hashes. Decoding restores the captured bytes exactly. The original
report and evidence ZIP remain outside this repository. The fixture excludes
private keys, host/account metadata, scratch paths, and all unrelated native
rows. The two original key-match private inputs were not exported and are not
reconstructed. This fixture supports exactly two command-specific malformed
failures and the six coupled verification alternatives documented in
`.docs/standing_rules/remote_alpha_operator_routes.md` and `.docs/system_overview/remote_supported_host_alpha.md`; other
responses remain incomplete. It is not production material, a status result,
P0t qualification, or authority for target contact and service action.

`grammar_diagnostic_v2_schema.json` is the current private reference/test
contract for the nonpublishing first-rejection terminal advisory. It is not
runtime-loaded or a protected status schema. The prior
`grammar_diagnostic_schema.json` remains byte-identical historical v1 data.
The v2 body adds `verify_projection` only at the first rejected verification
failure. It retains ordered complete lines in separate streams through eight
lines globally and otherwise reports complete counts, tail kinds and explicit
cap flags. Closed known and numeric-unknown records never export raw reasons,
subjects or installed material. The schema annotations describe semantic
couplings enforced by the source validator; JSON Schema alone does not prove
native text or status acceptance. The consumed v1 advisory cannot be
reinterpreted as v2 without its unavailable native response.
