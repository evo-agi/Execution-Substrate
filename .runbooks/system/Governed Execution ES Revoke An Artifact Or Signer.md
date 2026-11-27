# Governed Execution ES Revoke An Artifact Or Signer

## What is it?

This runbook stops ES from admitting one artifact, or everything that one AGS signing key signed, on a host where EGS and ES run as systemd units (the Remote Alpha box).

ES refuses an artifact when EGS's signed runtime-trust list names it:

- `runtime_trust.artifact_policy.revoked_artifacts` names artifacts by their digest (`sha256:` and 64 lowercase hex characters). ES compares it with the artifact digest of the request and refuses with HTTP 403 and code `artifact_revoked`.
- `runtime_trust.signer_policy.revoked_signers` names AGS signing keys by key ID. ES compares it with the key ID in the artifact's evidence seal and refuses with HTTP 403 and code `signer_revoked`, even when `allowed_signers` also names that key.

Both lists live in EGS's config file, `/etc/execution-substrate/egs.json` on the box ([egs/contract/trustmodel.go](../../egs/contract/trustmodel.go), [es/admission/service.go](../../es/admission/service.go), function `enforceTrustModel`).

**A revocation takes effect only after EGS restarts and then ES restarts.** EGS reads its config file when it starts ([cmd/egs/main.go](../../cmd/egs/main.go)). ES fetches EGS's signed list once, when it starts, and does not fetch it again on the normal prepare and submit path (the comment at the top of `Health` in [es/admission/service.go](../../es/admission/service.go)). The private reliable-submit path fetches the list again before each use ([.docs/execution_lifecycle/reliable_submit_operational_handoff.md](../../.docs/execution_lifecycle/reliable_submit_operational_handoff.md), section "Admission content, digest, token and view"), so it follows EGS's restart without an ES restart; the normal path does not.

A revocation does not stop runs that ES already admitted. Step 5 cancels those.

Revoking a signer revokes every artifact that key signed. While AGS signs with a single key, revoking that key stops every admission until AGS has a new key: use it as an emergency stop, not to remove one artifact.

## What do I need?

- SSH access to the box with `sudo` (the usual path from the Mac).
- For an artifact: its artifact digest, as printed by the publish step (`artifact_digest` in the publish response; see step 3 of [.runbooks/execution/Governed Execution ES Submit Static Script Workload.md](../execution/Governed%20Execution%20ES%20Submit%20Static%20Script%20Workload.md)). The evidence digest and the payload digest are different values and do not work here.
- For a signer: the key ID. For the key AGS signs with now, step 1 prints it.
- To confirm the refusal: the operator client certificate and the ES URL, exported as in steps 2 and 3 of [.runbooks/system/Governed Execution ES System Bring-Up.md](Governed%20Execution%20ES%20System%20Bring-Up.md), and a prepare request file for the revoked artifact (`PREPARE_JSON`, as in step 4 of the static-script runbook).

Each command below prints only the two revocation lists, the allowed signers or a key ID. None prints a private key or any other field of the config files.

## How to use it?

Run these on the box, or wrap each one in `ssh <box> '...'` from the Mac.

### 1. Look at the current lists

```bash
sudo python3 -I - /etc/execution-substrate/egs.json /etc/execution-substrate/ags.json <<'PY'
import json, sys
egs = json.load(open(sys.argv[1], encoding="utf-8"))["runtime_trust"]
print("allowed_signers:  ", egs.get("signer_policy", {}).get("allowed_signers", []))
print("revoked_signers:  ", egs.get("signer_policy", {}).get("revoked_signers", []))
print("revoked_artifacts:", egs.get("artifact_policy", {}).get("revoked_artifacts", []))
print("AGS signs now with key ID:", json.load(open(sys.argv[2], encoding="utf-8"))["signer"]["key_id"])
PY
```

Expect four lines. Keep them: step 2 prints the lists again after the change.

### 2. Add the revocation

Set `KIND` to `artifact` or `signer`, and `VALUE` to the artifact digest or the key ID:

```bash
KIND=artifact
VALUE='sha256:<64 lowercase hex characters>'
sudo python3 -I - /etc/execution-substrate/egs.json "$KIND" "$VALUE" <<'PY'
import json, os, re, sys, tempfile
path, kind, value = sys.argv[1:4]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)
trust = doc["runtime_trust"]
if kind == "artifact":
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        sys.exit("an artifact digest is sha256: followed by 64 lowercase hex characters; nothing changed")
    entries = trust.setdefault("artifact_policy", {}).setdefault("revoked_artifacts", [])
elif kind == "signer":
    if not value or value != value.strip():
        sys.exit("give the key ID exactly, with no surrounding spaces; nothing changed")
    entries = trust.setdefault("signer_policy", {}).setdefault("revoked_signers", [])
else:
    sys.exit("KIND must be artifact or signer; nothing changed")
if value in entries:
    print("already revoked; the file is unchanged")
else:
    entries.append(value)
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
    print("added; the file keeps its owner and mode")
print("revoked_signers:  ", trust.get("signer_policy", {}).get("revoked_signers", []))
print("revoked_artifacts:", trust.get("artifact_policy", {}).get("revoked_artifacts", []))
PY
```

Expect `added; the file keeps its owner and mode`, then the two lists with your entry at the end. The file is rewritten with two-space indentation; its content is otherwise the same. Nothing has taken effect yet.

### 3. Restart EGS, then ES

```bash
sudo systemctl restart egs.service
systemctl is-active egs.service
sudo systemctl restart es.service
systemctl is-active es.service
```

Expect `active` twice. The order matters: ES fetches EGS's list when it starts, so ES started before EGS is up would fail to start or keep the old list.

Runs already in Nomad keep running while ES restarts. Requests that reach ES during the restart fail and can be sent again (Inference: ES holds no run state that a restart discards; check `journalctl -u es.service` if a request behaves otherwise).

### 4. Confirm the refusal

From the Mac, with the variables of step "What do I need?" exported:

```bash
export PREPARE_JSON="/abs/path/execution.json"   # a prepare request for the revoked artifact
scripts/30_prepare.sh
```

Expect the prepare to fail with HTTP 403 and the code `artifact_revoked` (or `signer_revoked` for a revoked key). A prepare that still succeeds means ES did not restart after EGS, or the value in the list is not the artifact digest or the key ID of that artifact's seal.

### 5. Cancel runs that must not finish

A revocation does not stop runs ES already admitted. For each run that must not finish, use the cancel route through `scripts/50_lifecycle.sh` or `POST /v1/executions/{run_id}:cancel`, as in step 6 of the static-script runbook. A cancel is a request to stop, not proof that the workload has stopped: watch the status until it is terminal.

### 6. To undo a revocation

Remove the entry with `sudo -e /etc/execution-substrate/egs.json` (it keeps the file's owner and mode), check the lists with step 1, and restart as in step 3. Lift a revocation only when you know why it was made.

## What do the failures mean?

| What you see | What it means | What to do |
| --- | --- | --- |
| Step 2 exits with "an artifact digest is sha256: followed by 64 lowercase hex characters" | The value is not a labeled SHA-256 digest; EGS would refuse to start with it | Copy the `artifact_digest` from the publish response; nothing was changed |
| `egs.service` is not `active` after step 3; `journalctl -u egs.service` shows `decode config` or `runtime_trust...` | EGS refuses the file: invalid JSON, an unknown field, a duplicate entry, or a digest without its label | Fix the entry with `sudo -e`, then repeat step 3. ES cannot start until EGS is up |
| `es.service` is not `active` after step 3 | ES could not fetch or verify EGS's list at start | Check that `egs.service` is `active`, then read `journalctl -u es.service` |
| Step 4 still succeeds | ES is still using the list it fetched before the change, or the value does not match | Repeat step 3 in order; compare the value with the artifact digest or the evidence seal's key ID |
| Step 4 fails with `signer_not_allowed` instead | The artifact's key is not in `allowed_signers` at all | Nothing to revoke for that key; ES already refuses it |

## Notes

- EGS accepts upper-case hex in a digest, but ES compares the exact text, so an upper-case entry would pass EGS and never match an artifact. Step 2 accepts lower-case only.
- Any later tool that rewrites `egs.json` (a key rotation, a hardening run) must keep both lists. After such a run, check them with step 1.
- A supported-local install keeps the same file at its proof root (`EGS_CONFIG`). Make the same change there with `EGS_CONFIG` as the path, and restart EGS and then ES with step 8 of the bring-up runbook.
- This procedure edits the lists the current code reads. It is interim: the planned owner-policy work moves revocations out of `egs.json` and lets ES apply them without a restart.

## Test Evidence

- **Automated, in CI on every pull request:** in `es/admission/service_direct_test.go`, the `enforceTrustModel` cases check the three refusals this runbook relies on: `signer_not_allowed`, `signer_revoked` and `artifact_revoked`. `TestPrepareReturns403WhenSignerIsRevoked` and `TestPrepareReturns403WhenArtifactIsRevoked` in `es/app/app_integration_test.go` check them through a running ES and EGS. `TestRuntimeTrustPolicyRefusesEntriesTheRevocationRunbookWarnsAbout` in `egs/contract/trustmodel_test.go` checks the entries the failure table says EGS refuses: a digest without its label or of the wrong length, a duplicate, an empty signer.
- **Not run:** the steps above, as written, have not been run on the box. The Python in steps 1 and 2 was run against a test config shaped like the box's: it refused a bad digest, added an entry, left a second run unchanged, kept the file's mode, and printed no other field.

## History

- **2026-11-27:** written, because no runbook said how to revoke an artifact or a signer, and a revocation takes effect only after EGS and then ES restart.
