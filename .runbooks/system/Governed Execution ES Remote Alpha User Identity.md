# Governed Execution ES Remote Alpha User Identity

- Version: `v1`
- Last Updated: `2026-11-23`
- Contract: `.docs/system_overview/remote_supported_host_alpha.md`, section "Remote Alpha User Caller Identities"
- Helper: `scripts/remote_alpha_user_identity.sh`

## What is it?

How to give a person or an agent its own API caller identity on the Remote Alpha box, `spiffe://execution.internal/user/<name>`, so that it calls AGS and ES as itself. The first one is `user/claude`, decided by the box owner on 2026-11-23. It also covers renewal, revocation and what to do when something fails.

A `user/<name>` identity is an API identity only. It is not a Unix account and gives no SSH or `sudo`. A Unix login of the same name on the box is a separate grant, so taking someone's access away means revoking both (see [Revoke](#revoke)).

Who holds what:

| Item | Where | Leaves that machine? |
| --- | --- | --- |
| User CA key | box, `/etc/execution-substrate/user-ca/ca-key.pem`, root only | never |
| Caller key | caller's machine, `~/.config/execution-substrate/callers/<name>/key.pem`, `0600` | never |
| CSR | made on the caller's machine | copied to the box |
| Certificate | made on the box | copied to the caller's machine |

## Before you start

- The pull request that added the helper has merged, and the box owner has said go for this box run. Nothing in this runbook runs on the box before both.
- The caller's machine reaches the box over SSH (`BOX_SSH` below) and reaches AGS and ES over HTTPS. On the Mac, Claude does this from a Remote Control session, because cloud sessions cannot reach the box.
- An Execution-Substrate checkout of the merged commit on the caller's machine (`ES_CHECKOUT`), and the AGS/ES server CA bundle the caller already trusts (`SERVER_CA`).
- The caller's machine needs `/usr/bin/python3` (3.9 or later) and `/usr/bin/openssl` (OpenSSL or LibreSSL). The box needs OpenSSL 3.
- Avoid a reboot or a Vault restart while doing this: `allow` and `revoke` restart only `ags.service` and `es.service`.

Set these in the caller's shell first. Every block below uses them.

```bash
NAME='claude'                        # the identity is user/$NAME
BOX_SSH='<ssh alias of the box>'
BOX_ADDR='<box address AGS and ES listen on>'
ES_CHECKOUT='<path to the Execution-Substrate checkout of the merged commit>'
SERVER_CA='<path to the AGS/ES server CA bundle on this machine>'
TOOL_DIR='/usr/local/lib/execution-substrate-user-identity'   # on the box, root-owned
```

Each helper run prints a report that ends with `Result:`. `ok` means done, `planned` means nothing changed and the plan is shown, `refused` means a check failed and nothing changed, `failed` means a step failed after changes began (the message says what was rolled back). Add `--json` for a machine-readable report.

## 1. Put the helper on the box

The helper runs as root on the box, so copy exactly the merged files into a root-owned directory and compare their SHA-256 with the checkout.

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

The two digests printed by the box must equal the two printed from the checkout. If they differ, stop.

Then look at the box as it is:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' status"
```

Before the first identity, expect `user CA: not created`, both client CA paths `ok`, `client CA files identical: yes`, one certificate in each client CA file, and both units `active/running`. Anything marked `attention` or `fail` is a reason to stop and look.

## 2. Make the key and CSR on the caller's machine

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" request --name "$NAME"
```

It writes `key.pem` (`0600`) and `request.csr` in `~/.config/execution-substrate/callers/$NAME/` and prints `public_key_sha256`. Note that value. The key never leaves this machine; do not copy it anywhere.

## 3. Create the user CA (once) and issue the certificate

```bash
CALLER_DIR="$HOME/.config/execution-substrate/callers/$NAME"
scp -q "$CALLER_DIR/request.csr" "$BOX_SSH:user-identity-staging/$NAME.csr"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' init-ca --apply"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' issue --name '$NAME' --csr \"\$HOME/user-identity-staging/$NAME.csr\" --out \"\$HOME/user-identity-staging/$NAME.crt\""
```

`init-ca` is needed only the first time; a second run is refused with "the user CA is created once". The `issue` plan prints `csr_public_key_sha256`: it must equal the `public_key_sha256` from step 2, or the CSR is not the one you made. Then issue it:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' issue --name '$NAME' --csr \"\$HOME/user-identity-staging/$NAME.csr\" --out \"\$HOME/user-identity-staging/$NAME.crt\" --apply"
scp -q "$BOX_SSH:user-identity-staging/$NAME.crt" "$CALLER_DIR/issued.crt"
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" install --name "$NAME" --cert "$CALLER_DIR/issued.crt" --server-ca "$SERVER_CA"
```

`install` checks that the certificate names exactly `spiffe://execution.internal/user/$NAME`, is for client authentication, is valid now, and matches `key.pem`, then stores it as `cert.pem` next to the key.

Before `allow`, a check shows the services do not trust the user CA yet:

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8445"
```

Expect outcome `client_certificate_refused`.

## 4. Allow the identity

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' allow --name '$NAME'"
```

The first time, the plan appends the user CA to the end of both client CA files, adds `user/$NAME` to the AGS and ES allowlists, and restarts `ags.service` then `es.service`. Later names only add their allowlist entry. Read the plan, then apply it:

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' allow --name '$NAME' --apply"
```

If a restart fails, the helper restores the exact previous bytes of all four files, restarts the services again and reports `failed` with what it rolled back. The copies it made first are in `/etc/execution-substrate/user-ca/backups/`.

## 5. Check from the caller's machine

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8445" --service es
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" check --name "$NAME" --url "https://$BOX_ADDR:8444" --service ags
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' status"
```

Both checks must say `authorized`. The ES check calls the read-only contract endpoint. The AGS check sends a publish request with an empty body: AGS authorizes the caller first and then refuses the empty body with `400 invalid_request`, so nothing is published. `status` should show `allowlist user/$NAME: allowed by AGS and ES` and the name `active`.

Then remove the staging copies: `ssh "$BOX_SSH" 'rm -rf ~/user-identity-staging'` and `rm "$CALLER_DIR/issued.crt"`.

What a check outcome means:

| Outcome | Meaning | What to do |
| --- | --- | --- |
| `authorized` | AGS or ES accepted the identity | nothing |
| `client_certificate_refused` | the TLS handshake failed on the client certificate | the user CA is not installed (run `allow`), or the certificate is expired |
| `not_authenticated` (401) | TLS passed but the certificate is not an acceptable caller identity | compare the certificate with `install`'s checks; issue a new one |
| `not_allowed` (403) | authenticated, but `user/$NAME` is not on that service's allowlist | run `allow`; after `revoke` this is the expected outcome |
| `server_not_trusted` | this machine does not trust the server certificate | pass the right `--server-ca` |
| `unreachable` | no TCP connection | check `BOX_ADDR`, the port and the network path |

## Renew

A certificate lasts 90 days. `check` and `status` flag it 14 days before expiry. Renewal makes a new key:

```bash
"$ES_CHECKOUT/scripts/remote_alpha_user_identity.sh" request --name "$NAME" --renew
```

It writes the new key and CSR in `pending/`. Copy `pending/request.csr` to the box, run `issue` as in step 3 (plan, compare the public key digest, `--apply`), copy the certificate back and run `install` as in step 3. `install` sees that the certificate matches the pending key, makes it the current key, and moves the old key and certificate to `previous/`. No `allow` is needed: the name is already allowed. Run step 5 again.

## Revoke

```bash
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' revoke --name '$NAME'"
ssh "$BOX_SSH" "sudo '$TOOL_DIR/scripts/remote_alpha_user_identity.sh' revoke --name '$NAME' --apply"
```

This removes `user/$NAME` from both allowlists, restarts AGS and ES, and marks the name revoked for good: it is never issued or allowed again, so a new grant needs a new name. ES has no certificate revocation list, so the name's certificates stay cryptographically valid until they expire, but AGS and ES answer them with `403`. One certificate cannot be revoked alone; revoke the name.

For Claude, also remove the box login `claude` with the revoke section of the Archived-Runbooks "Governed Execution Remote Alpha Claude Access" runbook. Each grant can be taken away without the other.

When the last name is revoked, `revoke --name <name> --remove-ca --apply` also removes the user CA from both client CA files, which returns them to the external client CA alone. It is refused while any other name is active. If the user CA key may have leaked, revoke every name and then use `--remove-ca`.

## Interaction with the recovery runbook

The Archived-Runbooks "Governed Execution Remote Alpha Linux Recovery" runbook must accept `user/<name>` allowlist entries in its topology check, and its external reissue must append `/etc/execution-substrate/user-ca/ca-cert.pem` to the new client CA before installing it. With an older copy of that runbook, its topology check stops on a box that has user identities, and an external reissue drops user access only (operator and Control Plane keep working). In that case run `allow` again for each active name after the reissue: it appends the user CA once more.

## Undo by hand

The helper rolls back by itself when a step fails. To undo a successful `allow` or `revoke` later, run the opposite mode. If the helper itself cannot run, each backup directory in `/etc/execution-substrate/user-ca/backups/` holds the four files it replaced (`ags_config`, `es_config`, `ags_ca`, `es_ca`) and a `manifest.json` with each file's path, owner, group and mode. Restore them with `install -o <uid> -g <gid> -m <mode> <backup file> <path>`, then `systemctl restart ags.service` and `systemctl restart es.service`, in that order.

## History

- 2026-11-23: first version, written with the helper. Not run on the box yet.
