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

The local response is a deterministic regression input, not qualification of
the Linux host's reported OpenSSL 3.0.13 binary or of metadata, PEM, DER,
malformed-key, or verify response families. The generator private key was
removed and is not tracked. Tests construct negative text shapes in memory
and keep the collector's fixed command, SAN/EKU logic, validity precedence,
and unknown-response refusal in scope.
