# Policy Governance Contract (D2)

## 1. Purpose and status

This document is D2, the Workstream D re-derivation of policy and
authorization ownership. It says who decides what an installation of
Execution Substrate allows, how ES applies that decision, what EGS does, and
how the decision's history is kept off the host.

The project owner decided this design. Nothing in it is built yet. The build
steps of section 17 implement it, in order. Until the step that lands a part
merges, the current pages describe current behavior for that part (for
example `.docs/system_overview/configuration.md` for `es.json` and
`egs.json`, and `.docs/system_overview/contracts.md` for EGS v1), and this
document is the target that step implements. Each step moves the matching
current-behavior text to the new rule in the same change.

The owner decided:

- CGS is retired. Its authorize route has no caller in ES, and it never had a
  revoke in Go. Cutting off a workload's credentials belongs to SPIRE and
  Vault, one name at a time (`.docs/system_overview/runtime_identity_handoff.md`,
  section 11.7).
- The owner signs one standing policy, which does not expire, for each
  installation. ES applies it. ES is the only writer of numbered revocations.
- EGS is kept, with an automatic signer whose key lives in Vault's transit
  engine. EGS signs a record of each publisher it admits. A switch in the
  signed policy decides whether ES also requires EGS's admission. The switch
  is off at migration.
- The owner's everyday key lives in the keychain of the owner's workstation,
  with a printed recovery key whose only power is replacing it.

## 2. Names

The names below are working names. The owner settles each one before the
first build step that uses it in code or in a script; a repository test
enforces that (section 15).

| Working name | What it names |
| --- | --- |
| standing policy | The owner-signed policy document of section 4 |
| open class, closed class | The two publisher class kinds of section 5 |
| admission list | EGS's signed list of admitted publishers (section 9) |
| `use_egs` | The switch field of the standing policy (section 9.2) |
| `es-owner` | The owner's command-line tool (section 4.5 and section 17) |
| `es-log-reader` | The host account that exports the policy log (section 10.2) |
| `es-policy-log-export/v1` | The export format (section 10.2) |
| log anchor | The owner-side job that copies the policy log (section 10.3) |
| `es-recover-vault`, `es-resetup` | The recovery scripts (section 13) |
| `rehearsal-due` | The signal that a recovery rehearsal is overdue (section 13) |

## 3. Who vouches for what

| Question | Answered by | Key |
| --- | --- | --- |
| What are the owner's rules for this installation, and does ES rely on EGS? | The standing policy | The owner's key |
| Which open-class publishers has EGS admitted, bound to which key? | EGS's admission list, which ES filters against the standing policy | EGS's key, held in Vault's transit engine; it cannot widen anything |
| Who published these exact bytes, claiming what? | AGS evidence | AGS's key |
| Are these the bytes? | The digest, checked by ES | None |
| Where are the bytes? | ARS | None |
| May this run start, with which network and identity? | ES, applying the standing policy (and EGS's list when the switch is on) to the evidence and the caller | None of its own |
| What has happened under the policy? | The policy log, written by ES and copied off the host every hour | None: a hash chain, anchored by the owner's copy |
| Who is this workload, and what may it read? | SPIRE and Vault, per named identity | Their own |

## 4. The standing policy

### 4.1 What it holds

- The evidence-signing keys ES trusts. Today that is AGS's one key,
  `verification.provenance` in `es.json`; it moves into the policy. The two
  verifier keys ES loads and never uses, `verification.derivation_attestation`
  and `verification.workload_identity_binding`, are removed.
- The public half of the owner's recovery key (section 4.5).
- The publisher classes of section 5, each with its identity rule or member
  list and its limits.
- The workload grants of `.docs/execution_lifecycle/contracts.md`, section
  5B, moved out of `es.json` with their fields and matching unchanged, each
  inside a closed class.
- The identities that may revoke without the owner, and the subjects each may
  revoke (section 7).
- Revocation lifts and checkpoints (section 7).
- Caps: how many classes, members, grants and revocations ES accepts.
- The switch for EGS, EGS's public key bytes, and the epoch of EGS's list
  (section 9).

### 4.2 Signed bytes and format

- The signature covers the exact bytes delivered. Those bytes state the
  format name and version, the installation ID, the revision, and the SHA-256
  of the previous revision's bytes.
- The installation ID makes a policy for one installation useless on another,
  including a rebuilt host.
- Decoding is strict: an unknown, repeated or differently spelled key is
  refused.
- A signature of a type ES does not know is ignored, and the others are
  counted. A policy needs its required signatures from types ES knows.

### 4.3 Revisions and the floor

- Each revision is exactly the previous revision plus one. ES refuses any
  other number, so no revision can jump to a high number and block later
  ones.
- ES stores the new revision number durably before it first uses the new
  policy, so that a crash between the two cannot let an older revision in
  after a restart. That stored number is the floor.

### 4.4 Delivery to ES

- The owner installs a revision on the host over the owner's own SSH access,
  into a root-owned directory. It never passes through another service.
- ES reloads it without a restart and applies the newest valid revision at
  once.

### 4.5 The owner's key, the pin and rotation

- The owner's key is Ed25519, the signature ES already verifies on evidence.
- `es.json` pins the public half of the owner's everyday key. ES also stores
  the fingerprint of the key it last accepted, and refuses a different pin
  unless a revision introduced it that is signed by the new everyday key and
  by either the old everyday key or the recovery key. A rolled-back `es.json`
  therefore cannot bring back an old key.
- A planned key change is a revision signed by the old and the new everyday
  key. The same `es-owner` command updates the pin.
- After losing the everyday key, the owner replaces it with a revision signed
  by the recovery key and the new everyday key. The old everyday key is not
  needed.
- The recovery key may sign only a revision whose single change is replacing
  the everyday key. ES checks that by comparing it with the revision it holds.
- Replacing the recovery key is a revision signed by the everyday key and the
  new recovery key.
- `es-owner` shows the owner a plain-words summary computed from the exact
  bytes it is about to sign, from a clean checkout, and changes nothing before
  the owner confirms by typing the new revision number.

## 5. Publisher classes

A publisher is a caller that publishes through AGS. A signer is a key whose
stamp ES accepts on evidence.

| | Open class | Closed class |
| --- | --- | --- |
| Who is in it | Any publisher whose identity matches the class's rule: a namespace and an issuer, such as `user/*` from an installation-local user CA. The class follows from the identity; nobody picks it | Only the publishers the policy names |
| What it may get | Narrow limits: listed artifact types and runtime profiles, and which callers may run its artifacts. No network and no named identities | Exact grants of section 5B, including network and named identities |
| The owner's step for a new publisher | None. ES admits it (with the switch on, once EGS has admitted it too) and writes a "first seen" entry to the policy log | A revision that adds the name |

- **Identity.** mTLS under the class's namespace and issuer, never a workload
  identity (`.docs/system_overview/contracts.md`, section 3A). ES checks it at
  each admission. A closed class also needs the exact name.
- **Key custody** is decided when the identity is issued. ES does not check
  it again, and this contract claims nothing more. With the switch on, EGS's
  admission is bound to the key hash of section 12, and ES checks that the
  evidence names the same key.
- **Evidence.** Each artifact's AGS evidence declares its env keys and mount
  targets, its network need, its artifact type and its runtime profile, all
  within the class or the grant.
- **Networked publishers stay in closed classes** while the only lane is
  `unrestricted`. An open class with network would let anyone who can get an
  identity issued give a run full network without the owner. A narrow egress
  lane may later sit in an open class.
- **Publishers that relay others' content**, such as the operator and the
  Control Plane, sit in closed classes and are judged as the widest thing
  they relay.

## 6. How ES applies the policy

- At each admission, ES takes the publisher's name from AGS's verified
  evidence and the caller from the verified connection. It checks
  revocations first, then finds the publisher's class (by name for a closed
  class, by identity rule for an open one), then checks the artifact type,
  runtime profile, caller, network request and identity name against that
  class and its grants. With the switch on, an open-class publisher also
  needs EGS's admission. This is the grant matching of section 5B with
  classes added, not a new kind of decision.
- **Per-run record.** For each admitted run, ES writes to the policy log the
  standing revision's hash, the class and grant that matched, and the
  revocation count it checked against.
- **Health line.** ES reports the installation ID, the owner key's
  fingerprint, the standing revision and its hash, the revocation count and
  the policy log's head. The log anchor compares them with the owner's
  record.
- ES starts without EGS. With the switch on and EGS unreachable, publishers on
  EGS's last good list keep working, and new open-class publishers wait.

## 7. Revocations

- **One writer: ES.** Identities the policy names may revoke through an ES
  route. ES writes each revocation to the policy log with a number. It
  applies at once and stays.
- **Subjects** are limited to an artifact digest, a payload digest (so that
  publishing the same bytes again under a new intent digest does not escape
  it), a publisher name, and an evidence-signing key. The owner's key cannot
  be revoked this way, so nobody can lock the owner out.
- There is a cap and a rate limit.
- **Lifting names revocation numbers, never subjects.** A later revocation of
  the same subject gets a new number and stays.
- **Checkpoints.** Each revision the owner signs records "revocations up to
  number N considered", with the ones still in force. Revocations become
  owner-signed at the next revision and survive the loss of ES's state. To
  recover from mass abuse, a revision can clear revocations below a number,
  except those it lists.
- **A revoked publisher name stays revoked**, even if the identity tooling
  later issues the same name again. Caller names that the identity tooling
  revokes are written to the policy log too, so that a re-setup restores them
  (section 13).
- Spelling: a digest is `sha256:` and 64 lower-case hex characters, the one
  spelling ES accepts in a request. Any other spelling is refused, never
  normalized.

## 8. State rules

- ES refuses to start when its policy state is missing or empty, except
  through a deliberate first-install step that is loud and logged.
- No backup or restore tool includes the floor or the revocation log in its
  file list, and a repository test pins that. After a rebuild, revocations
  come back from the owner's last checkpoint and from the owner's copy of the
  log.
- An older ES binary that cannot read the stored policy state refuses to
  start. It never starts empty.

## 9. EGS v2: signed admissions behind the owner's switch

EGS v2 is a new versioned contract. The EGS v1 route `GET /v1/trust-model`
and its wrapper and payload stay as the EGS v1 compatibility surface until
build step 7 removes them.

### 9.1 What EGS does

- When the identity tooling issues a new identity, it asks EGS to admit it.
  Only the operator and ES may call EGS; publishers never do.
- EGS finds the class from the identity, using the policy's
  namespace-to-class table. Nobody picks the class.
- EGS checks admission evidence that ES can check again by itself: the
  certificate chain to the class's issuer, a signature by the publisher's own
  key over the request, and that key's hash, which AGS also records (section
  12).
- If every check passes, EGS writes an audit record, adds the publisher to
  its admission list, and signs a new revision with its key in Vault. If any
  check fails, it writes an audit record of the refusal.
- The list holds open-class admissions only: no grants, which stay in the
  standing policy, and no revocations, which ES owns.

### 9.2 The switch

| | Off (the setting at migration) | On |
| --- | --- | --- |
| Who admits an open-class publisher | ES, on a matching identity alone | ES, only if the identity matches and EGS's current list admits that publisher with the same key |
| What ES does with EGS's list | Fetches, checks and logs it, and logs every disagreement with its own decisions, so that EGS stays live and tested | Uses it as above, after filtering it against the current standing policy |
| If EGS is down or Vault is sealed | Nothing changes | Publishers already on EGS's last good list keep working; new ones wait |

- The switch is a field of the signed standing policy, so only the owner's
  key changes it. No value in `es.json`, `egs.json` or any other host file
  changes it.
- Before turning it on, `es-owner` shows which publishers active in the last
  30 days lack an EGS admission, and how many disagreements the log recorded.
  Turning it off has no pre-check: it is also the emergency stop.
- With the switch on, EGS can make admission stricter and leave a signed
  record. It cannot admit anyone the class rules do not already cover,
  because ES requires both.

### 9.3 ES's rules for EGS's list

- **Format:** the rules of section 4.2 and 4.3. The signed bytes state the
  format, the installation ID, the epoch, the revision (exactly the previous
  plus one) and the previous revision's hash. Decoding is strict.
- **Key:** the standing policy pins EGS's public key bytes, not a Vault key
  name. A list signed by a key the current policy no longer names is dropped,
  even as last good.
- **Filter at each use:** entries outside the current class rules, or for
  revoked publishers or keys, are ignored. A new standing revision applies at
  once, without waiting for EGS.
- **Fallback:** on proof that EGS showed two different lists under one
  revision number, or when the policy removes EGS's key, ES behaves as if the
  switch were off and alerts. An unreachable EGS is not that case.
- **Epoch:** a number in the standing policy that only the owner can raise. A
  new epoch restarts EGS's numbering at 1. It is the one recovery for a lost
  Vault key, a Vault reset, an EGS state restore or a stuck counter. EGS
  re-seeds itself from ES's last good copy when its own state is behind.
- **Audit head:** every revision carries the hash and count of EGS's audit
  log. ES fetches the records the revision adds, checks their hashes, and
  writes the head into the policy log, so the owner's copy anchors EGS's
  records.
- **Rate limit** on EGS revisions.

### 9.4 Vault key rules

- EGS's key is created inside Vault's transit engine, not exportable and not
  deletable. It is never a key that was ever in a file, including today's
  `egs.json` key.
- EGS's Vault policy allows signing with that key and nothing else, through a
  login role bound to EGS's exact identity and separate from the workloads'
  roles.
- The root token is revoked after setup, and Vault's audit log is on.
- Setup needs the root token, typed by the owner, once at migration and again
  after any Vault reset. A Vault reset is also an epoch change.

### 9.5 What EGS gains

Today EGS can widen nothing. After this change it still cannot widen
anything. With the switch on it can refuse or delay new publishers, and its
key is an online key. With the switch off it decides nothing.

## 10. The policy log and its off-box copy

### 10.1 Entries

- ES appends every policy event to one log, one JSON line per entry: `seq`
  (1, 2, 3 and so on), `prev` (the SHA-256 of the previous line's exact
  bytes; 64 zeros for the first), `kind`, the time and the event's fields.
- Kinds: first install, standing revision installed, revocation, revocations
  lifted, publisher first seen, run admitted, run refused (reason code only,
  rate-limited), EGS revision accepted (with the head of EGS's audit log), EGS
  disagreement (switch off), and caller name revoked.
- Changing any old entry changes every later hash.

### 10.2 Export

- A read-only host account, `es-log-reader`, may run one program and nothing
  else: sshd's `ForceCommand`, with no shell, terminal or forwarding. Its
  authorized-keys list is root-owned, so the account cannot change its own
  restrictions. It can read the log files and nothing else.
- The program answers three requests: `head`, `after N M` (up to 1,000
  entries after entry N) and `entry N`.
- Each answer starts with a header line: the format `es-policy-log-export/v1`,
  the installation ID, the head's number and hash, the standing revision and
  its hash, and the owner key's fingerprint. Entries follow exactly as stored.

### 10.3 The owner-side anchor

The log anchor runs on the owner's workstation every hour and at login:

1. It asks the host for the entries after the last one it holds, in pages of
   up to 1,000. Each page continues from the last entry it accepted, until a
   page reaches the head that page's header reports, or a per-run cap is
   reached; the next run continues from there.
2. It checks that each page's first entry's `prev` is the hash of its own
   last entry, that each later entry follows the one before, that no page
   goes beyond the head its header reports, and that a page reaching that
   head ends at the head's hash.
3. It appends each page that passed to its own copy and syncs it to disk.
   The host's answer is only ever parsed as data.
4. Once a day it asks for three old entries again and compares them byte for
   byte, so that a rewrite on the host is caught even if the host keeps
   feeding the old chain.
5. It compares the host's standing revision with the owner's signing record.

It alerts the owner when the chain breaks, an old entry was rewritten, the
host's log got shorter, the installation changed, the owner's key on the host
changed unexpectedly, the host shows a revision the owner did not sign, the
host has not installed a signed revision after a day, an answer is
malformed, or no pull has succeeded for 24 hours. After an alert it stops
pulling and keeps the bad answer as evidence.

The workstation opens every connection. The host holds no key or account for
the workstation, and the workstation's key can only read.

### 10.4 What it proves

Anything already copied off the host cannot later be changed on the host
without the anchor noticing. The window is up to an hour, longer while the
workstation sleeps. It does not prove that an entry was true when it was
written: root on the host can write a false entry before the next pull, or
feed a consistent invented future. Against mistakes made with root access,
which is the realistic risk, it is a real check.

## 11. Reliable submit

- Today reliable submit's private path stops admitting whenever the trust
  content changes, until a restart
  (`.docs/execution_lifecycle/reliable_submit_operational_handoff.md`,
  "Freshness"). With the switch on, EGS's list changes at each admission.
- So the reliable-submit admission digest covers only what a claim depends
  on: the standing revision's hash, the policy entries that matched, the EGS
  admission it used, and the revocations that could affect it. An unrelated
  admission or revocation does not stop a claim. A change to anything the
  digest covers stops it, as today.
- The 30-second confirmation with EGS is dropped. EGS's list can only add
  admissions inside the class rules, and revocations are ES's own, so a
  stale list cannot widen anything.
- `CP-ROLLBACK`: for the owner's rules, the signed revision and ES's floor;
  for revocations, ES's numbered log plus the owner's signed checkpoints,
  which is the equivalent this contract proposes for the owner to accept.
  `CP-POLICY-CUSTODY`: the owner signs the policy on the workstation; ES
  stores and applies it. The commissioning gate keeps both prerequisites
  listed until the integration step records them answered.

## 12. The evidence decision

AGS writes the publisher's name into the evidence, not its key, and the
artifact digest does not include the publisher. That lets a narrow publisher
publish known bytes first and squat them, and makes "revoke this stolen key,
keep the name" impossible. Decided:

- AGS records the caller certificate's key hash and issuer in the evidence.
- ARS indexes by digest and publisher.
- ES accepts evidence with or without the new fields until every live
  artifact carries them. Nothing acts on them before build steps 4 and 8.

Changing evidence means publishing every artifact again, so build step 3
lands before the next planned re-publication.

## 13. Recovery

ES must be recoverable from a lost Vault unseal key and from a full re-setup.

- **Seeding.** One step generates every secret a fresh install needs, on the
  host, from the operating system's random source. Each value goes into a
  root-only file or straight into Vault, and the step prints none of them. A
  re-run fills in only what is missing. A test fails if a generated value
  equals a value in the repository.
- **A lost unseal key** (`es-recover-vault`, extending the disposable-Vault
  reset helper): show the plan; reset and initialize Vault; pause while the
  owner stores the new key; unseal and re-seed; create EGS's new key; list
  the vendor secrets to re-enter, by name only; run the checks; print the one
  `es-owner` command (a new epoch) for the owner to run.
- **A full re-setup** (`es-resetup`, from a freshly installed host): seed
  every secret; install the services and initialize Vault; run ES's
  first-install step; hand the owner the command that signs revision 1 under
  the new installation ID with the content of the last signed revision, the
  anchor reinstall, and the list of artifacts to re-publish. Revocations and
  revoked caller names come back from the last checkpoint and the owner's log
  copy.
- **Prevention.** The unseal key stays in the owner's password manager only.
  `es-owner` reminds the owner once a year to confirm the entry still opens
  Vault. A daily Vault storage snapshot stays on the host, under a
  snapshot-only Vault policy.
- **Rehearsal.** In CI, a fresh-install job and a lost-unseal-key job run on
  every change to setup, seeding or recovery code, and weekly. Every 90 days
  both scripts run end to end on a throwaway machine, and `rehearsal-due` is
  raised once the last rehearsal is older than that.

## 14. What a compromised component can do

| Who is compromised | Can | Cannot |
| --- | --- | --- |
| An open-class publisher | Run artifacts within its class | Get network, named identities or more callers; pick a wider class |
| EGS, or its Vault login | Sign false audit records; with the switch on, refuse or delay new open-class publishers | Admit anyone the class rules do not cover; grant network or identities; undo a revocation; roll back its list; flip the switch; export its key with its own login |
| AGS, or its key | Stamp evidence naming any publisher, and so use any class or grant that names a publisher | Change the policy; admit beyond it; revoke |
| ES | Run any job its Nomad token allows, as today; write false log entries from then on | Forge evidence or the owner's signature; change entries already copied off the host unseen |
| An identity allowed to revoke | Revoke within its subjects, cap and rate limit | Revoke the owner's key or EGS's; widen anything; lift a revocation |
| The identity tooling's operator | Issue names in open classes and ask EGS to admit them | Put a name in a closed class; give network |
| A Vault administrator | Make EGS's key exportable and sign as EGS | More than a taken-over EGS can, because ES filters EGS's list |
| Root on the host | Anything on the host, including swapping the pin or resetting the floor | Change the owner's copy of the log, or rewrite copied history without the anchor noticing |
| The owner's workstation | Sign any standing policy, after the owner's login password | Nothing above it; the recovery key is kept apart |

## 15. Machine triggers

- **Class kinds stay local.** A repository test (build step 4) pins the class
  kinds (identity rule and closed), that every issuer a class names is an
  installation-local CA, and one installation ID per policy. Adding a class
  kind in which EGS's admission alone is enough, an outside issuer or
  multi-host scope fails that test, and its message points here: that change
  needs a design and a red-team first. It becomes worth its risk only when a
  second ES host must trust the same admissions, publishers come from an
  outside issuer, or an admission criterion cannot be evaluated by ES.
- **Owner load.** `es-owner` says so when the owner has signed more than six
  revisions in 90 days, because the manual part may have grown too heavy.
- **Names.** A repository test fails while section 2 marks a name as a
  working name and that name appears in Go code or scripts outside tests.

## 16. Acceptance tests

Each test must fail on a version without the rule it covers.

| Rule | Test |
| --- | --- |
| Classes | A publisher outside its class's identity rule, or not named in a closed class, is refused. An admission cannot choose its class |
| Revisions apply at once | A new standing revision applies at once; a grant outside it is not honoured |
| State | ES with missing or empty policy state refuses to start without the first-install step. No backup or restore tool's file list includes the floor or the revocation log |
| Revision numbers | A revision that is not the previous plus one is refused |
| Revocations | A subject revoked again after a lift stays revoked. A revocation naming the owner's key is refused. The same payload under a new intent digest is refused when its payload digest is revoked. A revoked publisher name issued again stays revoked |
| Reliable submit | The claim-scoped rule holds when a revocation lands |
| Owner key | A revision signed by the recovery key and a new everyday key, without the old everyday key, replaces the everyday key and the pin. A revision the recovery key signs with any other change is refused. A pin different from the stored fingerprint is refused unless a revision signed by the new key and by the old key or the recovery key introduced it |
| Decoding | A policy with an unknown, repeated or differently spelled key is refused; a policy for another installation ID is refused |
| Crash and downgrade | A crash between accepting and storing a revision does not let an older one in after restart. An older binary refuses newer stored state |
| EGS classes | With the switch on, an EGS admission for a publisher outside the class's identity rule is ignored, and a publisher matching the rule without an EGS admission is refused. With the switch off, EGS's list changes no decision |
| EGS key | An EGS list signed by a key the current policy no longer names is not used, even as last good. After proven equivocation ES behaves as switch-off and alerts |
| EGS epoch | A new epoch restarts EGS's numbering; a revision under an old epoch is refused |
| EGS audit | ES refuses an EGS revision whose added audit records are missing or do not match their hashes |
| Switch | Only a signed standing revision changes the switch; no value in a host configuration file does |
| Log | The export's answers match the format byte for byte; a changed old entry changes every later hash; more than 1,000 new entries reach the owner's copy in pages, in order, ending at the head's hash |

## 17. Delivery

Product steps start after the open security work on caller identities,
network grants, declared env keys and mounts, and per-host signing keys has
landed. Steps 1 and 2 are mostly docs and may go earlier when they collide
with none of it.

| Step | What it lands | Gate |
| --- | --- | --- |
| 1 | Retire CGS: delete it, drop it from images and bring-up, rewrite the docs that name it, and add a README check that names only the services the layout guard lists | Audit and the merge gate |
| 2 | This contract, `PLANS.md` Workstream D and its exit criteria. Docs only | Audit, a design red-team and the merge gate |
| 3 | Evidence fields (section 12) | Audit, red-team and the merge gate |
| 4 | ES applies the standing policy: decoder, verifier, floor, pin rules, classes, revocation log, lifts and checkpoints, state rules, reload, health line, per-run record, start without EGS | Audit, red-team and the merge gate |
| 5 | Policy log export and its account setup | Audit, red-team and the merge gate |
| 6 | `es-owner`, the log anchor with its tests, and the owner runbook | Audit, red-team and the merge gate |
| 7 | EGS v2 with its Vault setup; EGS v1's route and key removed | Audit, red-team and the merge gate |
| 8 | ES uses EGS's list: verification, filter, switch, fallback, epochs, audit head, and the claim-scoped reliable-submit rule | Audit, red-team and the merge gate |
| 9 | Automatic certificate renewal for EGS, ES, AGS and ARS, with an expiry health line | Audit and the merge gate |
| 10 | Host migration: today's lists, grants and AGS key into the first standing policy (switch off), EGS's Vault key, EGS v2 and the new ES, certificate renewal | Audit, red-team on the migration, a host run with the owner, and the merge gate |
| 11 | AGS's signing key into Vault's transit engine, before step 10 | Audit, red-team and the merge gate |
| 12 | Recovery (section 13), before step 10 | Audit, red-team and the merge gate |
| 13 | The project `README.md` and its diagram rewritten for this design, and Workstream D closed in `PLANS.md` in the same change, once its exit criteria hold | Audit and the merge gate |

Turning the switch on is not a step: it is an owner action, taken when the
owner is satisfied with EGS's disagreement record.

## 18. What this contract does not change

- ES still brokers no SPIRE or Vault credentials, and SPIRE and Vault still
  issue them.
- Workload grants keep their fields and exact matching; only their home
  moves, at step 10.
- The ES public execution request and response DTOs keep their shapes. New
  refusals use the existing redacted error envelope.
- Caller authentication keeps its contract
  (`.docs/system_overview/contracts.md`, section 3A).
