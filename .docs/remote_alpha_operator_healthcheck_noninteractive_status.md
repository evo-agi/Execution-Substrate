# Remote Alpha Operator Healthcheck TLS Noninteractive Status Contract

## 0. Purpose, Authority, And Status

This document defines the implemented ES-owned noninteractive, read-only
operator-healthcheck TLS status route for Remote Alpha.

Status:

- `Bounded slice rule`: P0v implements one read-only ES observation route:
  `operator-healthcheck-tls-status-noninteractive`.
- `Current invariant`: the existing P0u interactive
  `operator-healthcheck-tls-status` route remains implemented and unchanged.
- `Current invariant`: the P0v route is evidence/projection only. It is not
  renewal, replacement, signer/custody resolution, profile mutation, scheduled
  execution, CP run-control truth, IM readiness authority, MA authority, Bridge
  authority, production readiness, operational acceptance, or ES runtime truth.
- `Current invariant`: no fallback emitter is allowed. The local Python
  runtime is the sole final route-schema emitter.
- `Current invariant`: `scheduled_execution_allowed=false`.

Authority for this document follows the repo-wide authority hierarchy:

1. `AGENTS.md` for agent operating rules
2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams
3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules
4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance
5. current Go code and tests for factual implemented behavior

If this document disagrees with current code and tests on implemented behavior,
code and tests win for current behavior and this document must be realigned.

## 1. Active Route

Active stable argv:

```text
scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json
```

Route metadata:

- route id: `operator-healthcheck-tls-status-noninteractive`
- route version: `v1`
- owner repo: `execution-substrate`
- current status: `implemented`
- requires interactive TTY: `false`
- supports noninteractive: `true`
- scheduled execution allowed: `false`

The current P0u route remains:

```text
scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty
```

The P0u route keeps its foreground operator topology: required
`--interactive-tty`, local stdin/stdout TTY preflight, `ssh -tt`, visible sudo
or password prompt behavior, fixed helper-pair staging, and remote summary
retention. P0v does not change P0u behavior.

## 2. Runtime Architecture

The P0v implementation has exactly three layers:

1. Bash facade:
   - parses and refuses route arguments;
   - performs contact-free local prerequisite checks;
   - constructs no JSON;
   - performs no SSH, SCP, sudo, staging, cleanup, or summary behavior for
     P0v;
   - execs the fixed checked-in local Python runtime.
2. Local Python runtime:
   - is the sole final emitter for
     `execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`;
   - owns SSH argv construction and bounded subprocess handling;
   - streams the fixed checked-in remote collector over SSH stdin;
   - classifies transport failures versus validated remote protocol documents;
   - validates the internal remote protocol;
   - maps failures through a fixed local vocabulary;
   - validates redaction and final schema before stdout emission.
3. Remote Python collector:
   - is streamed over SSH stdin and is never copied, installed, staged, or
     retained on the remote host;
   - writes no remote file, summary, log, or temporary file;
   - emits one compact internal protocol JSON document plus one newline;
   - accepts no caller command, path, helper, SSH option, privilege command,
     output path, summary path, credential, certificate path, or arbitrary
     positional input.

There is no shell fallback JSON path. Missing local `python3`, local `ssh`, the
local runtime, or the fixed collector is a facade/local preflight refusal with
exit `2` and no route JSON.

## 3. Bash Facade Contract

Allowed P0v flags:

- `--help`
- `--ssh-target <target>`
- `--format json`

Forbidden P0v inputs include:

- `--interactive-tty`
- `--execute-renew`
- `--status`
- `--check-only`
- `--summary-path`
- `--output`
- helper, path, command, SSH, privilege, runtime, collector, schema, timeout,
  or limit overrides
- equals-form options
- duplicate options
- unknown flags
- extra positionals
- secret-like arguments
- unrelated recovery modes

The Bash facade reuses the current sealed SSH-target shape semantics for a
single SSH target: the target must not be an option, whitespace-bearing value,
or shell command. Bash does not allocate or require a local TTY for P0v and
does not run a TTY preflight.

The only P0v execution handoff from Bash is the absolute Python 3 executable
resolved during contact-free preflight, invoked with isolated startup flags:

```text
<absolute-python3> -I -S -B scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py --ssh-target <validated-target> --format json
```

The Bash facade passes no collector path, SSH option, remote command, sudo
command, output path, timeout, limit, or schema override.

## 4. Local Runtime Contract

The local runtime is:

```text
scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py
```

It is an internal ES route runtime source file, not a supported executable
command. Its tracked mode is `0644`. The only supported public P0v entrypoint
is the Bash facade argv in Section 1.

It uses Python standard library only and requires Python 3.9 or newer. The Bash
facade resolves the local interpreter once to an absolute executable path,
checks that interpreter with `-I -S -B`, and execs the route with the same
isolated Python startup flags. At startup the runtime refuses to proceed unless
isolated mode is enabled, `site` loading is disabled, and bytecode writing is
disabled. Python-specific ambient customization such as `PYTHONPATH`, user site
packages, `sitecustomize`, `usercustomize`, `PYTHONINSPECT`, and
`PYTHONSTARTUP` is outside the supported facade entrypoint. Direct interpreter
invocation is unsupported and not part of the route contract. This is a fixed
source/startup boundary, not cryptographic attestation of the local operator
account or interpreter binary.

The runtime strictly parses only:

- `--ssh-target <target>`
- `--format json`

Parser and validation failures emit only fixed safe diagnostics. They do not
echo raw hostile values, raw SSH targets, absolute local paths, transcripts, or
remote stderr.

The runtime derives the collector from its own fixed checked-in location:

```text
scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py
```

There is no collector-path argument and no environment override.

The runtime reads its own source and the collector source and computes SHA-256
digests. In P0v v1, `provenance.source_revision` is always `null`: the runtime
does not search for `git`, does not spawn a Git subprocess, and does not read
branch, dirty state, repository path, Git stderr, or caller Git environment.
The source hashes are bounded provenance/correlation evidence, not remote
attestation.

The runtime computes a SHA-256 label for the validated SSH target and never
emits the raw target.

## 5. SSH And Remote Command

The local runtime constructs one exact SSH argv list with no shell:

```text
/usr/bin/ssh
-F
/dev/null
-T
-o
BatchMode=yes
-o
NumberOfPasswordPrompts=0
-o
KbdInteractiveAuthentication=no
-o
PasswordAuthentication=no
-o
StrictHostKeyChecking=yes
-o
ConnectTimeout=10
-o
ConnectionAttempts=1
-o
ProxyCommand=none
-o
ProxyJump=none
-o
PermitLocalCommand=no
-o
ClearAllForwardings=yes
-o
ForwardAgent=no
-o
RequestTTY=no
-o
ControlMaster=no
-o
ControlPath=none
-o
ControlPersist=no
-o
CanonicalizeHostname=no
<validated target>
exec /usr/bin/python3 -I -S -B - --protocol execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1 --collector-sha256 <collector-sha256>
```

The target is the only caller-derived value in the SSH argv and remains the
separate SSH target argument. The fixed remote command contains only the
internal protocol version and the locally derived collector SHA-256.

The runtime uses no caller-supplied SSH executable, SSH options, `shell=True`,
shell fallback, `scp`, remote temporary file, remote helper path, summary path,
output path, or retry loop. The route disables per-user SSH config with
`-F /dev/null` and does not admit `ProxyCommand`, `ProxyJump`, `LocalCommand`,
forwarding, control-master, or TTY behavior. Host authentication still depends
on the operator's allowed key/agent and known-host material. The route does not
attest to the local OS or operator account.

## 6. Subprocess Bounds

The local runtime enforces hard bounds:

- maximum checked-in collector source: `131072` bytes
- maximum SSH stdout: `65536` bytes
- maximum SSH stderr: `8192` bytes
- maximum final route JSON: `65536` bytes
- SSH wall-clock timeout: `20` seconds
- graceful termination interval: `2` seconds

The runtime captures stdout and stderr with bounded reads while the subprocess
runs. It does not use unbounded `subprocess.run(..., capture_output=True)` for
route execution.

On timeout or output overflow, the runtime terminates the SSH process group,
waits for the grace interval, kills if still running, reaps the process,
discards raw captured material, emits one bounded final failure document, and
does not retry.

Unexpected local selector, pipe, spawn, or process-management failures are
converted to `local_runtime_failed` before the canonical final builder when
possible. The resulting document records whether the SSH child was actually
started through `live_contact_attempted`. No raw exception, selector detail,
stdout, stderr, target, path, or traceback is emitted, and no retry occurs.

## 7. Internal Remote Protocol

The remote collector emits internal protocol version:

```text
execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1
```

The collector accepts only:

- `--protocol execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1`
- `--collector-sha256 <expected collector sha256>`

The collector emits exactly one compact JSON object plus one newline to stdout
and emits no normal stderr output.

The internal protocol is not the final route schema. Required internal fields
are allowlisted and include only:

- `protocol_version`
- `collector_sha256`
- `helper_exit_code`
- `status_available`
- `result`
- `auth_posture`
- `certificate`
- `key_pair`
- `identity`
- `trust_chain`
- `file_posture`
- `redaction`

The local runtime validates:

- exact protocol version;
- exact collector SHA-256 echo;
- exact field allowlist;
- duplicate-key rejection;
- unknown-field rejection;
- JSON constants such as NaN and Infinity rejection;
- type and cardinality checks;
- fixed failure-class vocabulary;
- closed enum vocabularies for every result/status/auth/certificate/key-pair/
  identity/subject/issuer/trust/file-posture label;
- strict SHA-256 values, strict timestamps, numeric fields as numbers, and
  booleans as booleans;
- absence of raw paths, transcripts, PEM, env values, endpoint values, tokens,
  logs, command strings, raw OpenSSL output, raw exceptions, and free-form
  error fields.

The runtime distinguishes a valid remote protocol document from a transport
failure by the protocol marker and collector digest, not by numeric exit code
alone. When a valid protocol document exists, the SSH process exit code must
agree with `helper_exit_code`; disagreement fails closed as
`unexpected_output_shape`.

## 8. Remote Collector Behavior

The remote collector is:

```text
scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py
```

It uses only Python standard library and fixed current Remote Alpha paths:

- `/etc/execution-substrate/tls/operator-client-cert.pem`
- `/etc/execution-substrate/tls/operator-client-key.pem`
- `/etc/execution-substrate/es-tls/server-client-ca.pem`

The paths are implementation facts only and are never emitted.

The collector performs only fixed read-only status collection:

- certificate file SHA-256;
- public certificate fingerprint;
- public key fingerprint;
- `notBefore` and `notAfter`;
- expired and not-yet-valid classification;
- safe subject classification;
- safe issuer classification and digest;
- expected `operator/local` URI classification;
- legacy operator URI presence;
- certificate/key public-key match;
- trust verification classification;
- safe file ownership and mode classifications;
- noninteractive privilege posture.

The collector never emits PEM, key bytes, certificate bodies, raw subject or
issuer text, raw OpenSSL output, raw exception text, raw stderr, raw paths,
environment values, endpoints, logs, or command strings. It performs no network
operation, performs no service operation, performs no certificate mutation,
performs no `/health` probe, and performs no `/v1/executions:contract` probe in
P0v v1.

Subject classification is derived from deterministic RFC2253-style OpenSSL
name output and exact parsed `CN=client.operator` component membership only.
SAN identity classification extracts exact URI SAN entries and compares the
complete URI against `spiffe://execution.internal/operator/local` and the
legacy `spiffe://execution.internal/operator` value; prefixes, suffixes, and
substrings are not matches. The identity passes only when the certificate
carries exactly one URI SAN and that URI is
`spiffe://execution.internal/operator/local`, because the caller
authentication contract (`.docs/system_overview/contracts.md` section 3A)
refuses a certificate with more than one URI SAN. A certificate with several
URI SANs, including the same URI twice, fails with `identity_mismatch` even
when one of them is the expected URI. The collector reads the URI SAN entries
from the certificate's own DER encoding, through the fixed
`openssl x509 -outform DER` read of the public certificate, and never from
OpenSSL's printed SAN text, because that text cannot tell a URI that contains
`, DNS:` apart from two entries, or a DNS name that contains `, URI:` apart
from a URI SAN. The DER decoding accepts only one-byte tags and definite,
minimal lengths, refuses trailing bytes, more than one extensions block, a
repeated extension, and an extension whose fields are not an object
identifier, an optional one-byte critical flag of `0x00` or `0xFF`, and an
octet string, and refuses a URI SAN that is empty, longer than 256
bytes, or holds a byte outside printable ASCII without spaces; such a
certificate is `identity_malformed` and fails with `identity_mismatch`. The
host-local renew helper's `--status` mode carries the same decoder, and a test
keeps the two copies identical. Malformed identity output maps only to fixed
classification labels and fixed failure classes.

Every fixed child command runs with an explicit minimal environment including
`LC_ALL=C`, `LANG=C`, `TZ=UTC`, fixed minimal `PATH`, fixed non-sensitive
`HOME`, and neutral OpenSSL config. The collector does not preserve caller
locale, Python, OpenSSL, random-file, SSL_CERT, or arbitrary environment
values. Fixed child commands that do not intentionally consume input receive
stdin from `/dev/null`.

The remote collector enforces these hard local bounds while running on the
remote host:

- maximum fixed TLS file bytes read for hashing: `1048576`
- maximum child stdout: `65536` bytes
- maximum child stderr: `8192` bytes
- maximum intentional child stdin: `65536` bytes
- child wall-clock timeout: `10` seconds
- child termination grace: `1` second
- file and pipe chunk size: `16384` bytes

Fixed TLS files are hashed in bounded chunks. Child stdout and stderr are
drained concurrently while the child runs; timeout or overflow terminates the
child process group where available, waits for the grace interval, kills if
still running, reaps, closes descriptors/selectors, discards raw output, and
returns only a typed result.

## 9. Remote Privilege Posture

The streamed collector runs as the SSH target user, or as root only when the
SSH target already is root. It must never run through:

- `sudo -n python3 -`
- `sudo python3`
- `sudo -n bash`
- `sudo bash`
- `sudo sh`
- an elevated general interpreter
- an elevated general shell

No sudoers configuration is added or modified.

Direct reads and direct fixed OpenSSL operations are preferred when permitted.
If a fixed root-only read is required, the collector may attempt `sudo -n`
only for a closed in-source set of immutable, non-mutating argv tuples over the
three fixed ES-owned files. The set may contain only the minimum exact
operations needed for fixed certificate metadata/public-key extraction
(including the fixed DER encoding of the public operator certificate, from
which the URI SAN entries are decoded), fixed private-key public-key
extraction, fixed certificate verification against the fixed ES server client
CA, fixed file SHA-256, and fixed stat metadata.

The bounded elevated command set uses absolute executables, fixed absolute data
paths, no caller values, no shell, no glob, no command substitution, no
`cat`-style arbitrary-read interface, no write operation, and no
install/chmod/chown/cp/mv/rm/tee operation. If noninteractive fixed privilege
is unavailable, the collector emits a valid internal protocol result with
`failure_class=noninteractive_auth_required` and no raw sudo output.

## 10. Final Route Schema

Final schema identity:

```text
execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1
```

Required top-level fields:

- `schema_version`
- `route`
- `generated_at`
- `target`
- `provenance`
- `live_contact_attempted`
- `status_available`
- `result`
- `failure_class`
- `exit_codes`
- `auth_posture`
- `certificate`
- `key_pair`
- `identity`
- `trust_chain`
- `redaction`
- `non_authority_labels`
- `owning_repo_contract_labels`
- `profile_lineage_hints`

`target` contains only a fixed target kind label and the SHA-256 of the
validated SSH target. It does not contain the raw target.

`provenance` contains only:

- local route runtime SHA-256;
- remote collector SHA-256;
- internal protocol version;
- `null` source revision in P0v v1.

`key_pair` contains bounded public-key-match evidence only.

All summaries and failure messages come from a fixed local vocabulary. No
remote-provided arbitrary string may become a final summary or failure message.
No remote-provided arbitrary string may become a final blocker label,
explanation, metadata value, or final route label. The runtime
converts recognized local, transport, protocol, remote-status, and TLS outcomes
into one typed local outcome, builds the route document with one canonical
builder from validated internal protocol values and local fixed mappings,
validates the complete final object with an explicit schema validator,
serializes deterministically, enforces the final byte limit, performs a
complete forbidden-material scan, and emits exactly one JSON object plus one
newline. Target privacy is structural: the raw target is never assigned to the
document; the final document contains only the fixed target kind and the
SHA-256 of the validated target. The forbidden-material scan rejects paths,
transcripts, PEM/key/certificate material, secret-like shapes, and unsafe
material classes; it does not reject a document merely because a valid target
alias is a substring of fixed route vocabulary.

## 11. Failure Mapping

The final route maps failures through this fixed vocabulary:

- `ssh_batch_mode_failed`
- `remote_status_unavailable`
- `unexpected_output_shape`
- `forbidden_output_material`
- `noninteractive_auth_required`
- `cert_metadata_expired`
- `cert_metadata_not_yet_valid`
- `trust_chain_unavailable`
- `trust_chain_failed`
- `identity_mismatch`
- `key_pair_mismatch`
- `remote_status_failed`
- `local_runtime_failed`

Mappings:

- SSH authentication, known-host, connection failure, timeout, or no-prompt
  transport failure without valid internal protocol:
  `ssh_batch_mode_failed`.
- Remote interpreter or collector unavailable without valid internal protocol:
  `remote_status_unavailable`.
- Oversized, truncated, malformed, mixed, unknown-field, duplicate-key, wrong
  protocol, wrong collector hash, or exit-code-disagreement output:
  `unexpected_output_shape`.
- Forbidden material detected in remote protocol or final JSON:
  `forbidden_output_material`.
- Fixed no-prompt privilege refusal reported by a valid collector:
  `noninteractive_auth_required`.
- Expired certificate: `cert_metadata_expired`.
- Not-yet-valid certificate: `cert_metadata_not_yet_valid`.
- Certificate/key public-key mismatch: `key_pair_mismatch`.
- Expected operator/local identity mismatch, legacy-only identity, or more
  than one URI SAN: `identity_mismatch`.
- Trust unavailable or failed: `trust_chain_unavailable` or
  `trust_chain_failed`.
- Unexpected local selector, pipe, spawn, or process-management failure:
  `local_runtime_failed`.

Failure classes do not authorize retries, mutation, renewal, profile
acceptance, scheduling, or run-control.

## 12. Exit Semantics

Exit `0`:

- final bounded route JSON emitted;
- valid internal protocol received;
- `status_available=true`;
- no status blocker;
- `result.ok=true`.

Exit `1`:

- for recognized operational failures: local runtime and schema/redaction
  prerequisites passed, final bounded route JSON emitted, and a transport,
  remote-runtime, no-prompt privilege, status, identity, trust, key-pair,
  malformed-output, oversized-output, forbidden-material,
  `local_runtime_failed`, or other fixed fail-closed condition occurred;
- for final-emitter invariant failure: no route JSON is emitted, one fixed safe
  stderr diagnostic is emitted, and no exception, traceback, target, path,
  remote value, captured output, or internal detail is emitted.

Exit `2`:

- facade/runtime usage or contact-free local prerequisite refusal;
- no remote contact;
- final route JSON is not required;
- only safe fixed diagnostics are emitted.

Once the local runtime begins remote contact, recognized outcomes produce exit
`0` or `1`, not `2`. The route does not claim that every Python defect can
safely produce route JSON; final-schema, final-redaction, and final-size
invariant failures fail closed without a fallback route document.

## 13. Consumer And Authority Boundaries

Current consumer non-claims:

- CP consumes nothing in this tranche.
- IM consumes nothing in this tranche.
- MA consumes, invokes, and schedules nothing in this tranche.
- Bridge invokes and synthesizes nothing in this tranche.
- Coordinator consumes nothing in this tranche.

The output is evidence/projection only. It is not CP run-control truth, not ES
runtime truth, not IM readiness authority, not MA authority, not Bridge
authority, not Coordinator authority, not infrastructure reconciliation truth,
not production readiness, not operational acceptance, not signer/custody
resolution, not profile lineage mutation, and not renewal authorization.

Renewal remains blocked with `unsupported_signing_topology`. Service TLS,
governance TLS, operator-healthcheck TLS status, and operator-healthcheck TLS
renewal remain separate scopes.

## 14. Validation And Later Gates

P0v implementation validation in this tranche is local/static/fake only:

- Bash syntax checks;
- Python syntax checks without bytecode retention;
- static source guards;
- fake SSH/process tests;
- protocol validation tests;
- remote collector tests with fake runners and temporary fixtures;
- docs-contract tests;
- P0u compatibility tests;
- full Go test and vet runs.

No live SSH, sudo, remote host contact, certificate operation, service
operation, Docker, Nomad, Vault, SPIRE, Temporal, CP, IM, MA, Bridge,
Coordinator, tunnel, live proof, or network-dependent validation belongs to
this tranche.

Remaining separately gated work:

- independent audit;
- audit repair and re-audit if needed;
- exact-byte commit/push;
- MA route metadata and scheduling;
- IM consumption and profile lineage;
- CP diagnostic consumption;
- Bridge or Coordinator consumption;
- signing/custody resolution;
- renewal/replacement;
- live remote smoke, if later separately authorized.
