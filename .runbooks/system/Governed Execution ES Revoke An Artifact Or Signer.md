# Governed Execution ES Revoke An Artifact Or Signer

## What is it?

This runbook stops ES from admitting one artifact, or everything that one AGS signing key signed, on a host where EGS and ES run as systemd units (the Remote Alpha box).

ES refuses an artifact when EGS's signed runtime-trust list names it:

- `runtime_trust.artifact_policy.revoked_artifacts` names artifacts by their digest (`sha256:` and 64 lowercase hex characters). ES compares it with the artifact digest of the request and refuses with HTTP 403 and code `artifact_revoked`.
- `runtime_trust.signer_policy.revoked_signers` names AGS signing keys by key ID. ES compares it with the key ID in the artifact's evidence seal and refuses with HTTP 403 and code `signer_revoked`, even when `allowed_signers` also names that key.

Both lists live in EGS's config file, `/etc/execution-substrate/egs.json` on the box ([egs/contract/trustmodel.go](../../egs/contract/trustmodel.go), [es/admission/service.go](../../es/admission/service.go), function `enforceTrustModel`).

**A revocation takes effect only after EGS restarts and then ES restarts.** EGS reads its config file when it starts ([cmd/egs/main.go](../../cmd/egs/main.go)). ES fetches EGS's signed list once, when it starts, and does not fetch it again on the normal prepare and submit path (the comment at the top of `Health` in [es/admission/service.go](../../es/admission/service.go)). The private reliable-submit path, which no production caller uses yet, never applies a new list while running: when EGS's list changes, it stops admitting and stays stopped until ES restarts ([.docs/execution_lifecycle/reliable_submit_operational_handoff.md](../../.docs/execution_lifecycle/reliable_submit_operational_handoff.md), section "Admission content, digest, token and view").

A revocation does not stop runs that ES already admitted. Step 5 cancels those.

Revoking a signer revokes every artifact that key signed. ES checks every evidence seal against the one AGS key in its own `verification.provenance` before it reads these lists, so revoking that key stops every admission until AGS signs with a new key that both EGS's `allowed_signers` and ES's `verification.provenance` name. Use it as an emergency stop, not to remove one artifact.

## What do I need?

- SSH access to the box with `sudo` (the usual path from the Mac).
- For an artifact: its artifact digest, as printed by the publish step (`artifact_digest` in the publish response; see step 3 of [.runbooks/execution/Governed Execution ES Submit Static Script Workload.md](../execution/Governed%20Execution%20ES%20Submit%20Static%20Script%20Workload.md)). The evidence digest and the payload digest are different values and do not work here.
- For a signer: the key ID. For the key AGS signs with now, step 1 prints it.
- To confirm the refusal: the operator client certificate and the ES URL, exported as in steps 2 and 3 of [.runbooks/system/Governed Execution ES System Bring-Up.md](Governed%20Execution%20ES%20System%20Bring-Up.md), and a prepare request file for the revoked artifact (`PREPARE_JSON`, as in step 4 of the static-script runbook).

Each command below prints only the revocation lists, the allowed signers, a key ID, or the problems it finds in those lists. None prints a private key or the value of any other field of the config files. Do not open `egs.json` in an editor, with `sudo -e` or with `cat`: it holds EGS's private signing key (`signer.private_key_hex`), and whoever has that key can sign a list with no revocations.

## How to use it?

Run these on the box, or wrap each one in `ssh <box> '...'` from the Mac.

### 1. Look at the current lists

```bash
sudo python3 -I - /etc/execution-substrate/egs.json /etc/execution-substrate/ags.json <<'PY'
import json, sys
egs = json.load(open(sys.argv[1], encoding="utf-8"))["runtime_trust"]
print("allowed_signers:  ", (egs.get("signer_policy") or {}).get("allowed_signers") or [])
print("revoked_signers:  ", (egs.get("signer_policy") or {}).get("revoked_signers") or [])
print("revoked_artifacts:", (egs.get("artifact_policy") or {}).get("revoked_artifacts") or [])
print("AGS signs now with key ID:", json.load(open(sys.argv[2], encoding="utf-8"))["signer"]["key_id"])
PY
```

Expect four lines. Keep them: step 2 prints the lists again after the change.

### 2. Add the revocation

Set `ACTION` to `add`, `KIND` to `artifact` or `signer`, and `VALUE` to the artifact digest or the key ID. Step 6 runs the same command with `ACTION=remove`.

```bash
ACTION=add
KIND=artifact
VALUE='sha256:<64 lowercase hex characters>'
sudo python3 -I - /etc/execution-substrate/egs.json "$ACTION" "$KIND" "$VALUE" <<'PY'
import json, os, re, sys, tempfile
path, action, kind, value = sys.argv[1:5]
if os.path.islink(path):
    sys.exit(f"{path} is a symbolic link; edit the file it points to; nothing changed")
if action not in ("add", "remove"):
    sys.exit("ACTION must be add or remove; nothing changed")
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)
trust = doc["runtime_trust"]
if kind == "artifact":
    policy_key, list_key = "artifact_policy", "revoked_artifacts"
    if action == "add" and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        sys.exit("an artifact digest is sha256: followed by 64 lowercase hex characters; nothing changed")
elif kind == "signer":
    policy_key, list_key = "signer_policy", "revoked_signers"
    if action == "add" and (not value or value != value.strip()):
        sys.exit("give the key ID exactly, with no surrounding spaces; nothing changed")
else:
    sys.exit("KIND must be artifact or signer; nothing changed")
if not value:
    sys.exit("VALUE is empty; nothing changed")
policy = trust.get(policy_key) or {}
entries = policy.get(list_key) or []
if action == "add" and value in entries:
    print("already revoked; the file is unchanged")
elif action == "remove" and value not in entries:
    print("not in the list; the file is unchanged")
else:
    if action == "add":
        entries.append(value)
    else:
        entries = [entry for entry in entries if entry != value]
    policy[list_key] = entries
    trust[policy_key] = policy
    st = os.stat(path)
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".egs.json.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(doc, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    print(("added" if action == "add" else "removed") + "; the file keeps its owner and mode")
print("revoked_signers:  ", (trust.get("signer_policy") or {}).get("revoked_signers") or [])
print("revoked_artifacts:", (trust.get("artifact_policy") or {}).get("revoked_artifacts") or [])
PY
```

Expect `added; the file keeps its owner and mode`, then the two lists with your entry at the end. The file is rewritten with two-space indentation; its content is otherwise the same. Nothing has taken effect yet.

### 3. Restart EGS, then ES

```bash
sudo systemctl restart egs.service
sleep 5
systemctl is-active egs.service
sudo journalctl -u egs.service --since "-1 min" --no-pager | tail -n 5
```

Expect `active`, and no `decode config` or `runtime_trust` error in the journal lines. The wait matters: a unit that exits on a bad config can still show `active` for a moment. Only then restart ES:

```bash
sudo systemctl restart es.service
sleep 5
systemctl is-active es.service
```

Expect `active`. The order matters: ES fetches EGS's list once when it starts, with no retry, so ES started before EGS is up fails to start.

Runs already in Nomad keep running while ES restarts. Requests that reach ES during the restart fail and can be sent again (Inference: ES holds no run state that a restart discards; check `journalctl -u es.service` if a request behaves otherwise).

### 4. Confirm the refusal

From the Mac, with the variables from "What do I need?" exported:

```bash
export PREPARE_JSON="/abs/path/execution.json"   # a prepare request for the revoked artifact
scripts/30_prepare.sh
```

Expect the prepare to fail with HTTP 403 and the code `artifact_revoked` (or `signer_revoked` for a revoked key). A prepare that still succeeds means ES did not restart after EGS, or the value in the list is not the artifact digest or the key ID of that artifact's seal.

### 5. Cancel runs that must not finish

A revocation does not stop runs ES already admitted. ES has no route that lists runs, and it does not record the artifact digest in the Nomad job, so take the run IDs from the submit responses (`run_id`) or the caller's records. On the box, `nomad job status` (with `NOMAD_ADDR` and `NOMAD_CACERT` exported as in the static-script runbook) lists ES's runs as jobs named `exec-<run_id>`, which shows which ones are still running.

From the Mac, with the variables from "What do I need?" exported, cancel each run:

```bash
RUN_ID='<run id>' DO_CANCEL=1 WAIT_FOR_TERMINAL=0 scripts/50_lifecycle.sh
```

A cancel is a request to stop, not proof that the workload has stopped. Run the same command with `DO_CANCEL=0 WAIT_FOR_TERMINAL=1` to wait until the status is terminal.

### 6. To undo a revocation

Run step 2 with `ACTION=remove` and the exact value to lift. Removal accepts any spelling, so it also removes an entry that EGS refuses. Check the lists with step 1, and restart as in step 3. Lift a revocation only when you know why it was made.

## What do the failures mean?

| What you see | What it means | What to do |
| --- | --- | --- |
| Step 2 exits with "an artifact digest is sha256: followed by 64 lowercase hex characters" | The value is not a labeled SHA-256 digest; EGS would refuse to start with it | Copy the `artifact_digest` from the publish response; nothing was changed |
| `egs.service` is not `active` after step 3; `journalctl -u egs.service` shows `decode config` or `runtime_trust...` | EGS refuses the file: invalid JSON, an unknown field, a duplicate entry, or a bad digest. Steps 2 and 6 write none of these, so another edit or tool changed the file | Run the check below. Remove a bad list entry with step 6, then repeat step 3. Invalid JSON, or an unknown field outside `runtime_trust`, came from the tool that last wrote the file: repair it with that tool, not with an editor. ES cannot start until EGS is up |
| `es.service` is not `active` after step 3 | ES could not fetch or verify EGS's list at start | Check that `egs.service` is `active`, then read `journalctl -u es.service` |
| Step 4 still succeeds | ES is still using the list it fetched before the change, or the value does not match | Repeat step 3 in order; compare the value with the artifact digest or the evidence seal's key ID |
| Step 4 fails with `signer_not_allowed` instead | The artifact's key is not in `allowed_signers` at all | Nothing to revoke for that key; ES already refuses it |

To find the problems in the lists without showing any other field, run the check below. It also flags an entry EGS accepts but ES would never match, such as a digest in upper-case hex.

```bash
sudo python3 -I - /etc/execution-substrate/egs.json <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
except json.JSONDecodeError as exc:
    sys.exit(f"not valid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}")
trust = doc.get("runtime_trust") or {}
known = {"signer_policy": {"allowed_signers", "revoked_signers"}, "artifact_policy": {"revoked_artifacts"}}
for name in sorted(set(trust) - set(known)):
    print("unknown field in runtime_trust:", name)
for part, fields in known.items():
    for name in sorted(set(trust.get(part) or {}) - fields):
        print(f"unknown field in runtime_trust.{part}:", name)
    for field in sorted(fields):
        seen = set()
        for entry in (trust.get(part) or {}).get(field) or []:
            if not isinstance(entry, str):
                print(f"{field}: not a string: {entry!r}")
                continue
            if entry.strip() in seen:
                print(f"{field}: duplicate: {entry!r}")
            seen.add(entry.strip())
            if field == "revoked_artifacts":
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", entry):
                    print(f"{field}: not sha256: and 64 lowercase hex characters: {entry!r}")
            elif not entry.strip():
                print(f"{field}: empty entry: {entry!r}")
print("check finished")
PY
```

It prints one line for each problem in the lists or unknown field name under `runtime_trust`, then `check finished`.

## Notes

- EGS accepts upper-case hex in a digest, but ES compares the exact text, so an upper-case entry would pass EGS and never match an artifact. Step 2 accepts lower-case only.
- Any later tool that rewrites `egs.json` (a key rotation, a hardening run) must keep both lists. After such a run, check them with step 1.
- A supported-local install keeps the same file at its proof root (`EGS_CONFIG`). Make the same change there with `EGS_CONFIG` as the path, stop the proof with step 7 of the bring-up runbook (`scripts/01_bringup.sh down`), and start it again with step 4, which starts EGS before ES.
- Steps 2 and 6 leave `publication.update_revision` as it is: ES does not read it.
- This procedure edits the lists the current code reads. It is interim: the planned owner-policy work moves revocations out of `egs.json` and lets ES apply them without a restart.

## Test Evidence

- **Automated, in CI on every pull request:**
  - In `es/admission/service_direct_test.go`, the `enforceTrustModel` cases check the three refusals this runbook relies on: `signer_not_allowed`, `signer_revoked` and `artifact_revoked`. `TestPrepareReturns403WhenSignerIsRevoked` and `TestPrepareReturns403WhenArtifactIsRevoked` in `es/app/app_integration_test.go` check them through a running ES and EGS.
  - `TestRuntimeTrustPolicyRefusesEntriesTheRevocationRunbookWarnsAbout` in `egs/contract/trustmodel_test.go` checks the entries the failure table says EGS refuses: a digest without its label, of 62, 63 or 66 hex characters, or of 64 characters that are not hex, a duplicate, an empty signer.
  - `TestEGSRefusesToStartOnEntriesTheRevocationRunbookWarnsAbout` in `egs/app/revocation_config_test.go` checks that EGS's start path (`config.Load`, then `app.New`) refuses a bad digest, a duplicate and an unknown field, with the journal text the failure table names.
  - `TestRevocationRunbookNoteOnUpperCaseDigestsMatchesEGS` in `egs/contract/trustmodel_test.go` keeps the note on upper-case digests equal to what EGS does.
- **Not run:** the steps above, as written, have not been run on the box. The Python in steps 1 and 2 was run against a test config shaped like the box's: it refused a bad digest, added an entry, left a second run unchanged, kept the file's mode, and printed no other field. The `remove` action and the check in the failure table were run the same way.

## History

- **2026-11-27:** written, because no runbook said how to revoke an artifact or a signer, and a revocation takes effect only after EGS and then ES restart. Audit fixes the same day: lifting and checking no longer open the file (it holds EGS's private key), step 5's cancel is a working command, step 3 waits before it checks, and the reliable-submit sentence matches the code.
