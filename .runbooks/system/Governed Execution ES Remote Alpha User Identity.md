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

Expect `Result: planned`, then `Result: ok`. This marks the name revoked for good, removes every entry for `user/$NAME` from both allowlists (repeated copies and spellings with extra slashes included) and every workload grant rule that names `spiffe://execution.internal/user/$NAME`, or a path below it, as publisher or caller, and restarts AGS and ES. A revoked name is never issued or allowed again, so a new grant needs a new name. `revoke` does not stop runs the caller already submitted; cancel any that must not finish. A `Result: attention` means the name is revoked but something else needs you, for example a CA key file whose owner or mode has changed: read the message.

`revoke` never puts a removal back. The registry records the name as revoked, and the services still to restart, before AGS and ES change. If a restart or a file write fails, or the run is stopped, the files keep the removal, so the service starts without the name whenever it starts; the report names what did not come back, and `status` lists it. Repair that service or file (`journalctl -u <unit>`), then run the same `revoke --apply` again: it writes and restarts what is left. Until then `allow` and `init-ca --replace` are refused. A `check` afterwards gives `not_allowed`. If the helper itself refuses to run, see "Revoke by hand" under Notes.

For Claude, also remove the box login `claude` with the revoke section of the Archived-Runbooks "Governed Execution Remote Alpha Claude Access" runbook. Each grant can be taken away without the other.

When the last name is revoked, `revoke --name <name> --remove-ca --apply` also retires the CA, so that `issue` and `allow` refuse it from then on, removes the user CA from both client CA files, which returns them to the external client CA alone, and then removes the `user` binding from each service whose file no longer holds the user CA. It is refused while any other name is active or any other `user/` entry is in an allowlist. If a client CA file cannot be written, that service keeps its binding, so the user CA still vouches only for `user/` paths there; the run reports `failed`, `status` names the file, and the next `revoke --apply` of that name finishes the removal once the file can be written (once the CA is retired, every `revoke` does). Until `--remove-ca`, a revoked name's certificate still completes the TLS handshake and can read `GET /health`, which asks for no allowlist entry.

If the user CA key may have leaked, revoke every name, use `--remove-ca`, delete the recovery archives made before that revoke (`/var/backups/execution-substrate-remote-alpha/pre-*.tar.gz`: each holds the old CA key and the old trust state, and the recovery runbook's rollback would extract its service files), and replace the CA before the next name:

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
| `attention` | `status` or `check` found something to look at, or a `revoke` took effect but could not record its event in the registry or found something else that needs you | read the message; `status` names each item |

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
- **The recovery runbook.** The Archived-Runbooks "Governed Execution Remote Alpha Linux Recovery" runbook must accept `user/<name>` allowlist entries and the `user` namespace binding in its topology check. Its external reissue carries the user CA over only when both client CA files being replaced end with that exact certificate (`/etc/execution-substrate/user-ca/ca-cert.pem`), and otherwise installs the new external client CA alone: it keeps the trust state and never creates it, so it cannot undo `revoke --remove-ca` or trust a CA that `allow` never installed. It holds this helper's lock while it installs, after checking that `ags.json` and both client CA files are still as it staged them, and its rollback commands leave `/etc/execution-substrate/user-ca` out, so a rollback cannot undo a revocation in the registry or bring back a deleted CA key; after such a rollback, run `status` and `revoke` again any name it lists as allowed but not active. If `status` also names an older user CA (the archive predates an `init-ca --replace`), that CA stays trusted, bound to `user`, until it is removed by hand: cut it from the end of both client CA files with the command in step (3) of "Revoke by hand" below, with `ca=/etc/execution-substrate/user-ca/retired/<its full sha256>.pem`, run that step's check, then delete the `user` entry from `security.namespace_issuers` in both configs, restart AGS then ES, and run `allow` again for each active name. With an older copy of that runbook, its topology check stops on a box that has user identities, and an external reissue drops user access only (operator and Control Plane keep working). In that case run `allow` again for each active name after the reissue: it appends the user CA once more.
- **The ES upgrade.** `scripts/remote_alpha_upgrade_es.sh` backs up `es.json` but not ES's client CA file. Its `rollback` and `restore` refuse, before anything stops, a backup whose `es.json` would drop the `user` binding while ES's client CA file holds the user CA, or would put back a `user/` allowlist entry that `es.json` no longer lists, a backup that holds a client CA file, and an `es.json` that Go could read otherwise than the check does. The upgrade's `apply`, `rollback` and `restore` hold this helper's lock throughout, so neither runs while the other does: run one after the other. To roll an ES upgrade back on a box with user identities, revoke every name, run `revoke --name <last> --remove-ca --apply`, then roll back. Revoked names stay revoked, so once ES is current again the identities come back under new names (`init-ca --replace`, then `issue` and `allow`). `allow` cannot repair a split on the older ES build a rollback brings back, because that build refuses the binding at its start.
- **Network for user callers.** Network grants are not in this build: today a `user/<name>` caller's runs may ask for network access like any caller's. Network grants are planned (Workstream F, slice WI-2): ES will give a run network access only through an owner rule in `admission_policy.workload_grants` that names both its publisher and the ES caller that submits it, so a `user/<name>` caller has no network access until the box owner adds a rule naming it. `allow` does not add one, and the upgrade that brings grants writes none for a `user/` name. `revoke` removes every rule that names the identity, and `status` reports a rule that names an inactive user. Runs that do not ask for network access are not affected.
- **Revoke by hand.** Use this only when the helper refuses to revoke, for example because a service file carries an ACL or a `user.` attribute, a directory is writable by group or others, or the registry or CA certificate cannot be read; a CA key file whose owner or mode has changed, or that is gone, does not stop `revoke`. It does not stop `status` either, which reports the key as a check of its own and still checks each service, or `init-ca --replace`, which never reads the old key and replaces it. A plain `revoke` also goes on past a client CA file it cannot read in the user CA's shape (another CA after the user CA, say) and ends `attention`; `--remove-ca` refuses there until the file is fixed by hand. As root on the box: (1) copy `ags.json`, `es.json` and both client CA files somewhere root-only; (2) in `/etc/execution-substrate/ags.json` and `es.json`, delete every `user/<name>` entry from `authorization.allowed_spiffe_path_prefixes`, in every spelling, and every rule in `admission_policy.workload_grants.rules` whose `publisher_principal` or `caller_principal` is `spiffe://execution.internal/user/<name>` or a path below it; (3) only to remove the user CA as well, first cut it from the end of both client CA files with `f=<client CA file>; ca=/etc/execution-substrate/user-ca/ca-cert.pem; n=$(wc -c < "$ca"); cmp -s <(tail -c "$n" "$f") "$ca" && head -c -"$n" "$f" > "$f.new" && chown --reference="$f" "$f.new" && chmod --reference="$f" "$f.new" && mv "$f.new" "$f" || echo "NOT CUT: $f does not end with $ca; keep the binding"` (for `/etc/execution-substrate/tls/external-client-auth-ca.pem` and `/etc/execution-substrate/es-tls/server-client-ca.pem`). Then check each file with `f=<client CA file>; out=$(set -o pipefail; openssl crl2pkcs7 -nocrl -certfile "$f" | openssl pkcs7 -print_certs -noout) && [ "$(grep -c '^subject=' <<< "$out")" = "$(grep -c -e '-----BEGIN CERTIFICATE-----' "$f")" ] && echo "user CA certificates: $(grep -c 'subject=.*Remote Alpha User CA' <<< "$out")" || echo "CHECK FAILED: $f; keep the binding"`, and only when it prints `user CA certificates: 0` for both delete the `user` entry from `security.namespace_issuers` in both configs: never the binding while a client CA file still holds a user CA. The check prints CHECK FAILED when OpenSSL cannot read the file, or lists fewer certificates than the file has certificate blocks (ES loads every block Go can parse and skips the rest, so a block OpenSSL cannot read may hide the user CA from the count). If the cut printed NOT CUT, or the check prints CHECK FAILED or a count above 0, keep the binding and find the user CA in that file by hand; (4) `systemctl restart ags.service`, then `systemctl restart es.service`, and check both are `active`. Once the helper runs again, run `revoke --name <name> --apply` (with `--remove-ca` if you removed the CA): it records the revocation and the retirement in the registry and finds the files already done; `status` shows anything left.
- **Undo by hand.** The helper rolls back a failed `allow` by itself; a failed `revoke` is finished by running it again, never undone. A successful `allow` is undone with `revoke`, which retires the name for good. A `revoke` cannot be undone: `allow` and `issue` refuse a revoked name, so a caller who needs access again gets a new name. If the helper itself cannot run, each backup directory in `/etc/execution-substrate/user-ca/backups/` holds the four files it replaced (`ags_config`, `es_config`, `ags_ca`, `es_ca`) and a `manifest.json` with each file's path, owner, group and mode. Restore them with `install -o <uid> -g <gid> -m <mode> <backup file> <path>`, then run `systemctl restart ags.service` and `systemctl restart es.service`, in that order. Restoring a `revoke` backup this way allows a name the registry marks revoked, and `status` then reports its entry as `attention`. The backups hold `ags.json`, which carries the AGS signer key, so keep them root-only.

## Test Evidence

- **Automated, in CI on every pull request:** the Linux job "build, vet and test" runs the tests in `scripts/remote_alpha_user_identity_test.go` and `scripts/remote_alpha_user_identity_guards_test.go` against throwaway box trees, a fake `systemctl` and the runner's OpenSSL 3. `TestUserIdentityFlowThroughRealESAndAGSHandlers` runs steps 3 to 7 and step 9 with `--remove-ca`, and after `install`, `allow`, `revoke` and `--remove-ca` calls the real ES and AGS handlers, loaded from the configs as the helper left them; it also signs certificates for `operator/local` and `service/control-plane` with the user CA key and requires both handlers to refuse them with `401` once `allow` has written the binding. `TestUserIdentityApplyRollsBackToTheExactBytes` makes each restart fail in turn and requires the exact previous bytes back after a failed `allow`, and requires a failed `revoke` to keep its removal and finish when run again. `TestUserIdentityStopSignalsLeaveNoHalfChange` stops `allow`, its rollback and `revoke` with signals. `TestUserIdentityNoCutLeavesTrustWithoutBinding` kills `allow` and `revoke --remove-ca` after each of their file writes, as a power cut would, and requires that no service would start trusting the user CA without its binding (the real handlers refuse a user-CA-signed `operator/local`) and that running the mode again finishes it. `TestUserIdentityRemoveCAKeepsTheBindingOfAFileItCannotWrite` and `TestUserIdentityAllowRollbackKeepsTheBindingWhileTheCAMayBeTrusted` make a client CA file write or restore fail. `TestUserIdentityRevokeGoesOnWithADriftedCAKeyMode` revokes with the CA key file open to others, and `TestUserIdentityStatusAndReplaceGoOnWithABadCAKey` runs `status` and `init-ca --replace` with it open to others or deleted. `TestUserIdentityPlainRevokeGoesOnPastAClientCAFileItCannotRead` revokes beside a client CA file with another CA after the user CA. `TestUserIdentityESUpgradeRestoreKeepsTheBinding` runs the ES upgrade's `restore` with a backup from before `allow`, one from before a `revoke` and one that holds a client CA file, and while this helper holds its lock, and requires each refused with the real handlers still refusing a user-CA-signed `operator/local`. `TestUserIdentityHandRemovalFollowsTheRunbook` follows "Revoke by hand", and the removal of an older user CA that a rollback put back, with the command this runbook prints and its check, and then requires the helper's `status` to say `ok`; `TestUserIdentityHandCutSaysWhenItCutNothing` requires the cut to print NOT CUT and the check to count the user CA when the file does not end with it, and the check to print CHECK FAILED for a mistyped path or a file with a block OpenSSL cannot read. `TestUserIdentityRefusesAndChangesNothing`, `TestUserIdentityRefusesUnsafeStates`, `TestUserIdentityIssueChecksTheCSR`, `TestUserIdentityInstallRefusesCertificatesOffTheProfile`, `TestUserIdentityRefusesACAOffTheProfile`, `TestUserIdentityCraftedDERIsRefused` and `TestUserIdentityIssueRefusesASecondEncodingOfAKey` check the refusals, and `TestUserIdentityReportEscapesCSRText` that CSR text cannot add a line to a report; `TestUserIdentityRevokeRemovesEveryCopyAndGrant` checks step 9 against repeated entries and grant rules; `TestUserIdentityInitCAReplaceKeepsRevocations` and `TestUserIdentityInitCAReplaceFinishesAfterAStop` check the replacement in step 9; `TestUserIdentityRenewalPromotesTheNewKey` checks step 8. `TestUserIdentityCheckNamesEachOutcome` and `TestUserIdentityCheckRefusesAServerForAnotherHost` check how step 7 reads each answer, and `TestUserIdentityIssueChecksWhatOpenSSLSigned` checks that step 5 refuses a certificate other than the one it asked for. The job "test on macOS" runs the caller's `request` with the runner's LibreSSL (`TestUserIdentityRequestMakesAPrivateKeyAndAMatchingCSR`); the box-mode tests skip themselves there.
- **Not run:** the steps above have not been run on the box or on a Mac. `install` and `check` have not run with LibreSSL.

## History

- **2026-11-26:** first version, with the helper (PR #70). Not run on the box yet.
- **2026-11-27:** after the red-team and the audit of PR #70: the `user` namespace binding, a forward-only `revoke` that also removes repeated entries and grant rules, `init-ca --replace`, and the recovery reissue rule. Not run on the box yet.
- **2026-11-27, later:** after the second red-team and the re-audit: the binding is written before the user CA and removed after it, so no failed or killed run leaves a service trusting the user CA without its binding; a later `revoke` finishes a `--remove-ca` from any point; `revoke` needs no CA key; "Revoke by hand" and removing an older user CA that a rollback put back; delete the recovery archives after a key leak. Not run on the box yet.
- **2026-11-27, later still:** after the third red-team and the third audits: the ES upgrade's `rollback` and `restore` refuse to split the user CA from its binding or bring back a revoked name; `status` and `init-ca --replace` go on with a bad or missing CA key; a plain `revoke` goes on past a client CA file in another shape; the hand cut says when it cut nothing, with a check before the binding goes. Not run on the box yet.
- **2026-11-27, last:** after the fourth re-checks: the ES upgrade holds this helper's lock and refuses a backup that holds a client CA file or that Go could read otherwise; the check before the binding goes prints CHECK FAILED when OpenSSL cannot read the whole file. Not run on the box yet.
