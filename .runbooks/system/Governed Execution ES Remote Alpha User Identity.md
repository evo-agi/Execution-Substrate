# Governed Execution ES Remote Alpha User Identity

## What is it?

This runbook gives a person or an agent its own API caller identity on the Remote Alpha box, `spiffe://execution.internal/user/<name>`, so that it calls AGS and ES as itself instead of borrowing the operator or Control Plane certificate. The first one is `user/claude`, decided by the box owner on 2026-11-23. It also covers renewal and revocation.

The helper is `scripts/remote_alpha_user_identity.sh`. Its contract is the section "Remote Alpha User Caller Identities" of [.docs/system_overview/remote_supported_host_alpha.md](../../.docs/system_overview/remote_supported_host_alpha.md).

A `user/<name>` identity is an API identity only. It is not a Unix account and gives no SSH or `sudo`. A Unix login of the same name on the box is a separate grant, so taking someone's access away means revoking both (step 9).

Who holds what:

| Item | Where | Leaves that machine? |
| --- | --- | --- |
| User CA key | box, `/etc/execution-substrate/user-ca/ca-key.pem`, root only | never |
| Caller key | caller's machine, `~/.config/execution-substrate/callers/<name>/key.pem`, `0600` | never |
| CSR | made on the caller's machine | copied to the box |
| Certificate | made on the box | copied to the caller's machine |

## What do I need?

- The pull request that added the helper has merged, and the box owner has said go for this box run. Nothing in this runbook runs on the box before both.
- The caller's machine reaches the box over SSH and reaches AGS and ES over HTTPS. On the Mac, Claude does this from a Remote Control session, because cloud sessions cannot reach the box.
- An Execution-Substrate checkout of the merged commit on the caller's machine, and the AGS/ES server CA bundle that the caller already trusts.
- On the caller's machine, `/usr/bin/python3` (3.9 or later) and `/usr/bin/openssl` (OpenSSL or LibreSSL). On the box, OpenSSL 3 and `sudo`.
- AGS and ES on the box run a build that has the namespace issuer binding (`trunk_dev` at or after the merge of the pull request that added the helper). `allow` writes that binding, and an older AGS or ES refuses it at startup: `allow` then fails, rolls back, and says to redeploy AGS and ES from `trunk_dev` first.
- No reboot and no Vault restart while you do this: `allow` and `revoke` restart only `ags.service` and `es.service`.

## How to use it?

Run every command on the caller's machine, in one shell: each step reads the variables that step 1 sets. Box commands go through `ssh`. The output to expect is taken from the helper in this repository; Test Evidence says what has been run.

Each helper run prints a report that ends with `Result:`. Steps that change the box print a plan first; add `--apply` to carry it out. What do the failures mean? lists the results and what each check outcome means. Add `--json` for a machine-readable report.

### 1. Set the variables

```bash
NAME='claude'                        # the identity is user/$NAME
BOX_SSH='<ssh alias of the box>'
BOX_ADDR='<box address AGS and ES listen on>'
ES_CHECKOUT='<path to the Execution-Substrate checkout of the merged commit>'
SERVER_CA='<path to the AGS/ES server CA bundle on this machine>'
TOOL_DIR='/usr/local/lib/execution-substrate-user-identity'   # on the box, root-owned
CALLER_DIR="$HOME/.config/execution-substrate/callers/$NAME"
```

Expect no output.

### 2. Put the helper on the box

The helper runs as root on the box, so copy exactly the merged files into a root-owned directory and compare their SHA-256 with the checkout:

```bash
( cd "$ES_CHECKOUT" && git status --porcelain --untracked-files=no && git log -1 --format='%H %s' )
( cd "$ES_CHECKOUT" && shasum -a 256 scripts/remote_alpha_user_identity.sh scripts/internal/remote_alpha_user_identity.py )
ssh "$BOX_SSH" 'rm -rf ~/user-identity-staging && mkdir -m 700 ~/user-identity-staging'
scp -q "$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" "$ES_CHECKOUT/scripts/internal/remote_alpha_user_identity.py" "$BOX_SSH:user-identity-staging/"
ssh "$BOX_SSH" "sudo install -d -o root -g root -m 0755 '$TOOL_DIR/scripts/internal' &&
  sudo install -o root -g root -m 0755 ~/user-identity-staging/remote_alpha_user_identity.sh '$TOOL_DIR/scripts/' &&
  sudo install -o root -g root -m 0644 ~/user-identity-staging/remote_alpha_user_identity.py '$TOOL_DIR/scripts/internal/' &&
  sha256sum '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' '$TOOL_DIR/scripts/internal/remote_alpha_user_identity.py'"
```

Expect no line from `git status`, the merged commit from `git log`, and two digests from the checkout. The two digests that the box prints must equal them. If they differ, stop.

Then look at the box as it is:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' status"
```

Before the first identity, expect `user CA` `not created`, both client CA paths `ok`, `client CA files identical` `yes`, one certificate in each client CA file, `client CA files read elsewhere` `ok`, and both units `active/running`. Anything marked `attention` or `fail` is a reason to stop and look.

### 3. Make the key and CSR on the caller's machine

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" request --name "$NAME"
```

Expect `Result: ok`. It writes `key.pem` (`0600`) and `request.csr` in `$CALLER_DIR` and prints `public_key_sha256`. Note that value. The key never leaves this machine; do not copy it anywhere.

### 4. Create the user CA, once

Skip this step when `status` in step 2 showed the user CA as created.

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca --apply"
```

Expect `Result: planned` from the first command and `Result: ok` from the second. A later `init-ca` is refused with "the user CA is created once"; replacing it is `init-ca --replace`, in step 9.

The user CA key can sign a certificate for any identity in `execution.internal`, the operator's included. The `user` binding that `allow` writes in step 6 keeps AGS and ES from accepting it for anything outside `user/`, but guard every copy of the key (a backup, a disk image) like the operator's key.

### 5. Issue and install the certificate

Copy the CSR to the box and plan the issue:

```bash
scp -q "$CALLER_DIR/request.csr" "$BOX_SSH:user-identity-staging/$NAME.csr"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' issue --name '$NAME' --csr \"\$HOME/user-identity-staging/$NAME.csr\" --out \"\$HOME/user-identity-staging/$NAME.crt\""
```

Expect `Result: planned`. The plan prints `csr_public_key_sha256`: it must equal the `public_key_sha256` from step 3, or the CSR is not the one you made. Then issue it, copy the certificate back and install it:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' issue --name '$NAME' --csr \"\$HOME/user-identity-staging/$NAME.csr\" --out \"\$HOME/user-identity-staging/$NAME.crt\" --apply"
scp -q "$BOX_SSH:user-identity-staging/$NAME.crt" "$CALLER_DIR/issued.crt"
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" install --name "$NAME" --cert "$CALLER_DIR/issued.crt" --server-ca "$SERVER_CA"
```

Expect `Result: ok` from both helper runs. `install` checks that the certificate names exactly `spiffe://execution.internal/user/$NAME`, is for client authentication, is valid now and matches `key.pem`, then stores it as `cert.pem` next to the key.

Before `allow`, a check shows that the services do not trust the user CA yet:

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8445"
```

Expect outcome `client_certificate_refused`.

### 6. Allow the identity

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' allow --name '$NAME'"
```

Expect `Result: planned`. The first time, the plan appends the user CA to the end of both client CA files, binds `user` to the user CA in the AGS and ES `security.namespace_issuers`, adds `user/$NAME` to the AGS and ES allowlists, and restarts `ags.service` then `es.service`. Later names only add their allowlist entry. The plan also says that `allow` adds no network grant. Read the plan, then apply it:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' allow --name '$NAME' --apply"
```

Expect `Result: ok`. If a restart fails, the helper restores the exact previous bytes of all four files, restarts the services again and reports `failed` with what it rolled back. If the message says the unit's log may name the unknown field `namespace_issuers`, check with `journalctl -u ags.service` and `journalctl -u es.service`: that build is older than the binding, so redeploy AGS and ES from `trunk_dev` and run `allow` again.

### 7. Check from the caller's machine

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8445" --service es
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8444" --service ags
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' status"
```

Expect outcome `authorized` from both checks. The ES check calls the read-only contract endpoint. The AGS check sends a publish request with an empty body: AGS authorizes the caller first and then refuses the empty body with `400 invalid_request`, so nothing is published. `status` should show `allowlist user/$NAME` `allowed by AGS and ES` and the name `active`.

Then remove the staging copies:

```bash
ssh "$BOX_SSH" 'rm -rf ~/user-identity-staging'
rm "$CALLER_DIR/issued.crt"
```

Expect no output.

### 8. Renew every 90 days

A certificate lasts 90 days. `check` and `status` flag it 14 days before it expires. Renewal makes a new key:

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" request --name "$NAME" --renew
```

Expect `Result: ok`. It writes the new key and CSR in `$CALLER_DIR/pending/`. Make the staging folder on the box again as in step 2, copy `pending/request.csr` there as `$NAME.csr`, and run step 5 (plan, compare the public key digest, `--apply`, copy back, `install`). `install` sees that the certificate matches the pending key, makes it the current key, and moves the old key and certificate to `previous/`. No `allow` is needed: the name is already allowed. Then run step 7.

### 9. Revoke

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' revoke --name '$NAME'"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' revoke --name '$NAME' --apply"
```

Expect `Result: planned`, then `Result: ok`. This marks the name revoked for good, removes every entry for `user/$NAME` from both allowlists (repeated copies and spellings with extra slashes included) and every workload grant rule that names `spiffe://execution.internal/user/$NAME` as publisher or caller, and restarts AGS and ES. A revoked name is never issued or allowed again, so a new grant needs a new name.

`revoke` never puts a removal back. The registry records the name as revoked, and the services still to restart, before AGS and ES change. If a restart fails or the run is stopped, the files keep the removal, so the service starts without the name whenever it starts; the report names what did not come back, and `status` lists it. Repair that service (`journalctl -u <unit>`), then run the same `revoke --apply` again: it restarts what is left. Until then `allow` and `init-ca --replace` are refused. A `check` afterwards gives `not_allowed`.

For Claude, also remove the box login `claude` with the revoke section of the Archived-Runbooks "Governed Execution Remote Alpha Claude Access" runbook. Each grant can be taken away without the other.

When the last name is revoked, `revoke --name <name> --remove-ca --apply` also removes the user CA from both client CA files, which returns them to the external client CA alone, removes the `user` binding from both services, and retires the CA: `issue` and `allow` refuse it from then on. It is refused while any other name is active or any other `user/` entry is in an allowlist. Until `--remove-ca`, a revoked name's certificate still completes the TLS handshake and can read `GET /health`, which asks for no allowlist entry.

If the user CA key may have leaked, revoke every name, use `--remove-ca`, and replace the CA before the next name:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca --replace"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca --replace --apply"
```

Expect `Result: planned`, then `Result: ok`. The old certificate stays in `user-ca/retired/`, the old key is deleted, and every revoked name stays revoked. If it stops part-way, every other mode refuses until `init-ca --replace --apply` runs again and finishes it.

## What do the failures mean?

What a helper run's `Result:` means:

| Result | Meaning | What to do |
| --- | --- | --- |
| `ok` | done | go on |
| `planned` | nothing changed; the plan is shown | read it, then run the same command with `--apply` |
| `refused` | a check failed before any change; the message says which | fix what it names; nothing needs undoing |
| `failed` | a step failed after changes began. A failed `allow` says what it rolled back; a failed `revoke` keeps what it removed and says what is left | read the message and run `status`; after a failed `revoke`, repair what it names and run it again; see "Undo by hand" under Notes if an `allow` rollback itself failed |
| `attention` | `status` or `check` found something to look at, or a `revoke` took effect but could not record its event in the registry | read the message; `status` names each item |

What a `check` outcome means:

| Outcome | Meaning | What to do |
| --- | --- | --- |
| `authorized` | AGS or ES accepted the identity | nothing |
| `client_certificate_refused` | the TLS handshake failed on the client certificate | the user CA is not installed (run `allow`), or the certificate has expired (step 8) |
| `not_authenticated` (401) | TLS passed, but the certificate is not an acceptable caller identity | compare the certificate with `install`'s checks; issue a new one |
| `not_allowed` (403) | authenticated, but `user/$NAME` is not on that service's allowlist | run `allow`; after `revoke` this is the expected outcome |
| `server_not_trusted` | this machine does not trust the server certificate | pass the right `--server-ca` |
| `unreachable` | no TCP connection | check `BOX_ADDR`, the port and the network path |

## Notes

- **No certificate revocation list.** ES and AGS have none, so a revoked name's certificates stay cryptographically valid until they expire, but AGS and ES answer its API calls with `403`. `GET /health` stays readable with them until they expire or `--remove-ca` removes the user CA. One certificate cannot be revoked alone; revoke the name.
- **The recovery runbook.** The Archived-Runbooks "Governed Execution Remote Alpha Linux Recovery" runbook must accept `user/<name>` allowlist entries and the `user` namespace binding in its topology check. Its external reissue carries the user CA over only when both client CA files being replaced end with that exact certificate (`/etc/execution-substrate/user-ca/ca-cert.pem`), and otherwise installs the new external client CA alone: it keeps the trust state and never creates it, so it cannot undo `revoke --remove-ca` or trust a CA that `allow` never installed. With an older copy of that runbook, its topology check stops on a box that has user identities, and an external reissue drops user access only (operator and Control Plane keep working). In that case run `allow` again for each active name after the reissue: it appends the user CA once more.
- **Network for user callers.** Network grants are not in this build: today a `user/<name>` caller's runs may ask for network access like any caller's. Network grants are planned (Workstream F, slice WI-2): ES will give a run network access only through an owner rule in `admission_policy.workload_grants` that names both its publisher and the ES caller that submits it, so a `user/<name>` caller has no network access until the box owner adds a rule naming it. `allow` does not add one, and the upgrade that brings grants writes none for a `user/` name. `revoke` removes every rule that names the identity, and `status` reports a rule that names an inactive user. Runs that do not ask for network access are not affected.
- **Undo by hand.** The helper rolls back a failed `allow` by itself; a failed `revoke` is finished by running it again, never undone. A successful `allow` is undone with `revoke`, which retires the name for good. A `revoke` cannot be undone: `allow` and `issue` refuse a revoked name, so a caller who needs access again gets a new name. If the helper itself cannot run, each backup directory in `/etc/execution-substrate/user-ca/backups/` holds the four files it replaced (`ags_config`, `es_config`, `ags_ca`, `es_ca`) and a `manifest.json` with each file's path, owner, group and mode. Restore them with `install -o <uid> -g <gid> -m <mode> <backup file> <path>`, then run `systemctl restart ags.service` and `systemctl restart es.service`, in that order. Restoring a `revoke` backup this way allows a name the registry marks revoked, and `status` then reports its entry as `attention`. The backups hold `ags.json`, which carries the AGS signer key, so keep them root-only.

## Test Evidence

- **Automated, in CI on every pull request:** the Linux job "build, vet and test" runs the tests in `scripts/remote_alpha_user_identity_test.go` and `scripts/remote_alpha_user_identity_guards_test.go` against throwaway box trees, a fake `systemctl` and the runner's OpenSSL 3. `TestUserIdentityFlowThroughRealESAndAGSHandlers` runs steps 3 to 7 and step 9 with `--remove-ca`, and after `install`, `allow`, `revoke` and `--remove-ca` calls the real ES and AGS handlers, loaded from the configs as the helper left them; it also signs certificates for `operator/local` and `service/control-plane` with the user CA key and requires both handlers to refuse them with `401` once `allow` has written the binding. `TestUserIdentityApplyRollsBackToTheExactBytes` makes each restart fail in turn and requires the exact previous bytes back after a failed `allow`, and requires a failed `revoke` to keep its removal and finish when run again. `TestUserIdentityStopSignalsLeaveNoHalfChange` stops `allow`, its rollback and `revoke` with signals. `TestUserIdentityRefusesAndChangesNothing`, `TestUserIdentityRefusesUnsafeStates`, `TestUserIdentityIssueChecksTheCSR`, `TestUserIdentityInstallRefusesCertificatesOffTheProfile`, `TestUserIdentityRefusesACAOffTheProfile` and `TestUserIdentityCraftedDERIsRefused` check the refusals; `TestUserIdentityRevokeRemovesEveryCopyAndGrant` checks step 9 against repeated entries and grant rules; `TestUserIdentityInitCAReplaceKeepsRevocations` and `TestUserIdentityInitCAReplaceFinishesAfterAStop` check the replacement in step 9; `TestUserIdentityRenewalPromotesTheNewKey` checks step 8. `TestUserIdentityCheckNamesEachOutcome` and `TestUserIdentityCheckRefusesAServerForAnotherHost` check how step 7 reads each answer, and `TestUserIdentityIssueChecksWhatOpenSSLSigned` checks that step 5 refuses a certificate other than the one it asked for. The job "test on macOS" runs the caller's `request` with the runner's LibreSSL (`TestUserIdentityRequestMakesAPrivateKeyAndAMatchingCSR`); the box-mode tests skip themselves there.
- **Not run:** the steps above have not been run on the box or on a Mac. `install` and `check` have not run with LibreSSL.

## History

- **2026-11-26:** first version, with the helper (PR #70). Not run on the box yet.
- **2026-11-27:** after the red-team and the audit of PR #70: the `user` namespace binding, a forward-only `revoke` that also removes repeated entries and grant rules, `init-ca --replace`, and the recovery reissue rule. Not run on the box yet.
