# Governed Execution ES Revoke An Artifact Or Signer

## What is it?

This runbook stops ES from admitting one artifact, or everything that one AGS signing key signed, on a host where EGS and ES run as systemd units (the Remote Alpha box).

ES refuses an artifact when EGS's signed runtime-trust list names it:

- `runtime_trust.artifact_policy.revoked_artifacts` names artifacts by their digest (`sha256:` and 64 lowercase hex characters). ES compares it with the artifact digest of the request and refuses with HTTP 403 and code `artifact_revoked`.
- `runtime_trust.signer_policy.revoked_signers` names AGS signing keys by key ID. ES compares it with the key ID in the artifact's evidence seal and refuses with HTTP 403 and code `signer_revoked`, even when `allowed_signers` also names that key.

Both lists live in EGS's config file, `/etc/execution-substrate/egs.json` on the box ([egs/contract/trustmodel.go](../../egs/contract/trustmodel.go), [es/admission/service.go](../../es/admission/service.go), function `enforceTrustModel`).

**A revocation takes effect only after EGS restarts and then ES restarts.** EGS reads its config file when it starts ([cmd/egs/main.go](../../cmd/egs/main.go)). ES fetches EGS's signed list once, when it starts, and does not fetch it again on the normal prepare and submit path (the comment at the top of `Health` in [es/admission/service.go](../../es/admission/service.go)). The private reliable-submit path, which no production caller uses yet, never applies a new list while running: when EGS's list changes, it stops admitting and stays stopped until ES restarts and that path is commissioned or advanced again ([.docs/execution_lifecycle/reliable_submit_operational_handoff.md](../../.docs/execution_lifecycle/reliable_submit_operational_handoff.md), sections "Admission content, digest, token and view" and "Freshness").

A revocation does not stop runs that ES already admitted. Step 5 cancels those.

Revoking a signer revokes every artifact that key signed. ES checks every evidence seal against the one AGS key in its own `verification.provenance` before it reads these lists, so revoking that key stops every admission until AGS signs with a new key that both EGS's `allowed_signers` and ES's `verification.provenance` name. Use it as an emergency stop, not to remove one artifact.

## What do I need?

- SSH access to the box with `sudo` (the usual path from the Mac).
- For an artifact: its artifact digest, as printed by the publish step (`artifact_digest` in the publish response; see step 3 of [.runbooks/execution/Governed Execution ES Submit Static Script Workload.md](../execution/Governed%20Execution%20ES%20Submit%20Static%20Script%20Workload.md)). The evidence digest and the payload digest are different values and do not work here.
- For a signer: the key ID. For the key AGS signs with now, step 1 prints it.
- To find the runs to cancel in step 5: the `nomad` command on the box. Step 5 runs it as root, through `sudo`.
- To confirm the refusal: the operator client certificate and the ES URL, exported as in steps 2 and 3 of [.runbooks/system/Governed Execution ES System Bring-Up.md](Governed%20Execution%20ES%20System%20Bring-Up.md), and a prepare request file for the revoked artifact (`PREPARE_JSON`, as in step 4 of the static-script runbook).

Each command below prints only the revocation lists, the allowed signers, a key ID, the problems it finds in those lists, or a run's status, run ID and artifact digest. None prints a private key, a Nomad token or the value of any other field of the config files. Do not open `egs.json` in an editor, with `sudo -e` or with `cat`: it holds EGS's private signing key (`signer.private_key_hex`), and whoever has that key can sign a list with no revocations.

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

Set `ACTION` to `add`, `KIND` to `artifact` or `signer`, and `VALUE` to the artifact digest or the key ID. Step 6 runs the same command with `ACTION=remove` or `ACTION=drop-invalid`.

```bash
ACTION=add
KIND=artifact
VALUE='sha256:<64 lowercase hex characters>'
sudo python3 -I - /etc/execution-substrate/egs.json "$ACTION" "$KIND" "$VALUE" <<'PY'
import json, os, re, sys, tempfile
path, action, kind, value = sys.argv[1:5]
if os.path.islink(path):
    sys.exit(f"{path} is a symbolic link; run this command on the file it points to; nothing changed")
if action not in ("add", "remove", "drop-invalid"):
    sys.exit("ACTION must be add, remove or drop-invalid; nothing changed")
lists = {"artifact": ("artifact_policy", "revoked_artifacts"), "signer": ("signer_policy", "revoked_signers"),
         "allowed": ("signer_policy", "allowed_signers")}
if kind not in lists:
    sys.exit("KIND must be artifact, signer or allowed; nothing changed")
if kind == "allowed" and action != "drop-invalid":
    sys.exit("KIND=allowed takes only ACTION=drop-invalid: this runbook never adds or removes an allowed signer; nothing changed")
policy_key, list_key = lists[kind]
def well_formed(entry):
    if not isinstance(entry, str):
        return False
    if kind == "artifact":
        return re.fullmatch(r"sha256:[0-9a-f]{64}", entry) is not None
    return entry != "" and entry == entry.strip()
if action == "add" and kind == "artifact" and not well_formed(value):
    sys.exit("an artifact digest is sha256: followed by 64 lowercase hex characters; nothing changed")
if action == "add" and kind == "signer" and not well_formed(value):
    sys.exit("give the key ID exactly, with no surrounding spaces; nothing changed")
if action == "remove" and not value.strip():
    sys.exit("VALUE is empty; to drop empty or non-string entries, use ACTION=drop-invalid; nothing changed")
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)
trust = doc["runtime_trust"]
policy = trust.get(policy_key)
policy = {} if policy is None else policy
entries = policy.get(list_key) if isinstance(policy, dict) else None
entries = [] if entries is None and isinstance(policy, dict) else entries
if not isinstance(entries, list):
    sys.exit(f"runtime_trust.{policy_key}.{list_key} is not a list; repair the file with the tool that wrote it; nothing changed")
def key(entry):
    return entry.strip() if isinstance(entry, str) else None
def keep_one(entries, name):
    # Of the copies of one value, keep the first well-formed one, else the first one.
    copies = [entry for entry in entries if key(entry) == name]
    keep = next((entry for entry in copies if well_formed(entry)), copies[0])
    out, kept = [], False
    for entry in entries:
        if key(entry) == name:
            if kept or entry != keep:
                continue
            kept = True
        out.append(entry)
    rest = list(copies)
    rest.remove(keep)
    return keep, rest, out
copies = [entry for entry in entries if key(entry) == value.strip()]
message = None
if action == "add":
    if copies == [value]:
        print(f"already revoked as {value!r}; the file is unchanged")
    elif copies:
        first = entries.index(copies[0])
        entries = [entry for index, entry in enumerate(entries) if index == first or key(entry) != value]
        entries[first] = value
        message = "replaced " + ", ".join(repr(entry) for entry in copies) + f" with {value!r}, the spelling ES matches"
    else:
        entries.append(value)
        message = "added"
elif action == "remove":
    if not copies:
        print("not in the list; the file is unchanged")
    elif len(copies) == 1:
        entries = [entry for entry in entries if key(entry) != value.strip()]
        message = "removed"
    else:
        keep, rest, entries = keep_one(entries, value.strip())
        if well_formed(keep):
            message = f"listed {len(copies)} times; kept one copy, {keep!r}, so it stays revoked; run remove again to lift it"
        else:
            message = f"listed {len(copies)} times; kept one copy, {keep!r}, which is not a spelling ES matches; run remove again to drop it"
else:
    dropped = [entry for entry in entries if not isinstance(entry, str) or not entry.strip()]
    entries = [entry for entry in entries if isinstance(entry, str) and entry.strip()]
    for name in dict.fromkeys(key(entry) for entry in entries):
        if sum(1 for entry in entries if key(entry) == name) > 1:
            keep, rest, entries = keep_one(entries, name)
            dropped.extend(rest)
    if dropped:
        message = "dropped " + ", ".join(repr(entry) for entry in dropped)
    else:
        print("no empty, non-string or duplicate entries; the file is unchanged")
if message:
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
    print(message + "; the file keeps its owner and mode")
if kind == "allowed":
    print("allowed_signers:  ", policy.get("allowed_signers") or [])
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

A revocation does not stop runs ES already admitted. ES has no route that lists runs, but each job it submits to Nomad records the run ID and the artifact digest (task meta `run_id` and `artifact_digest`; [es/admission/submit.go](../../es/admission/submit.go), function `buildNomadJobSpec`). The jobs are named `exec-<run_id>` and live in the Nomad namespace `es-submit-v1`, and the box's Nomad gives a request without a token no access to them. The read-only observer token can list and read them, and cannot stop them. On the box that token belongs to root (the ES upgrade sets it up that way: `OBSERVER_USER` in [scripts/internal/remote_alpha_upgrade_es.py](../../scripts/internal/remote_alpha_upgrade_es.py)), so the block runs as root. On the box, run:

```bash
sudo bash -s <<'SH'
export NOMAD_ADDR=https://127.0.0.1:4646 NOMAD_CACERT=/etc/nomad.d/tls/ca.pem
IFS= read -r NOMAD_TOKEN < /etc/execution-substrate/nomad-acl/observer-token
[ -n "$NOMAD_TOKEN" ] || { echo "no observer token" >&2; exit 1; }
export NOMAD_TOKEN NOMAD_NAMESPACE=es-submit-v1
for job in $(nomad job status | grep -oE '^exec-run-[0-9a-f]{16}'); do
  nomad job inspect -t '{{.Status}}{{range .TaskGroups}}{{range .Tasks}} {{index .Meta "run_id"}} {{index .Meta "artifact_digest"}}{{end}}{{end}}' "$job"
done
SH
```

Expect one line for each ES job Nomad still holds: its status (`pending`, `running` or `dead`), its run ID and its artifact digest. The token stays in the environment of the root shell that runs the block: it is never on a command line, and it is gone when that shell ends. The block prints nothing else from the job; Nomad may also print a hint about its web UI. Cancel every `pending` or `running` run whose digest is the revoked one. Nomad does not record the signer: for a revoked signer, take the runs from the callers' records, or cancel every `pending` or `running` run.

From the Mac, with the variables from "What do I need?" exported, cancel each run:

```bash
RUN_ID='<run id>' DO_CANCEL=1 WAIT_FOR_TERMINAL=0 scripts/50_lifecycle.sh
```

Expect the output to end with ES's answer to the cancel, which holds `"status": "cancel_requested"`: ES answered 200 and has asked Nomad to stop the job. The script reads the run's status and logs before it cancels, so if it stops with an error before that answer, no cancel was sent: run it again. A run that is already terminal needs no cancel; if it did not exit 0, the script says so and exits 1 without cancelling.

A cancel is a request to stop, not proof that the workload has stopped. Run the same command with `DO_CANCEL=0 WAIT_FOR_TERMINAL=1` to wait until the status is terminal. After a cancel, it usually ends with `reached terminal state without an exit_code` or `reached terminal state with exit_code=` and a code that is not 0, and exits 1; a workload that finished with exit code 0 before the stop took effect ends with `lifecycle: execution completed successfully` and exits 0. Either way, what matters is that the status is terminal. It gives up after `TIMEOUT_SECONDS` (120 by default). The Nomad block above then shows the job as `dead`.

### 6. To undo a revocation

Run step 2 with `ACTION=remove` and the value to lift. Removal matches an entry the way EGS compares entries, ignoring surrounding spaces, and accepts any spelling, so it also removes an entry that EGS refuses, such as a digest without its label. If the value is listed more than once, which EGS refuses, removal keeps one copy and says which: a copy in the spelling ES matches when there is one, and then the value stays revoked; a second removal lifts it. Check the lists with step 1, and restart as in step 3. Lift a revocation only when you know why it was made.

`ACTION=drop-invalid`, with `VALUE=''`, repairs one list without lifting or granting anything. It drops the entries that are not text or are empty once spaces are trimmed, which name nothing, and the extra copies of a value listed more than once, keeping one copy in the spelling ES matches when there is one. It prints each entry it drops. `KIND` names the list: `artifact` or `signer` for the two revocation lists, or `allowed` for `allowed_signers`, which EGS also refuses to start with when it holds such entries. `KIND=allowed` takes no other action: this runbook never adds or removes an allowed signer.

## What do the failures mean?

| What you see | What it means | What to do |
| --- | --- | --- |
| Step 2 exits with "an artifact digest is sha256: followed by 64 lowercase hex characters" | The value is not `sha256:` and 64 lower-case hex characters, the only spelling ES matches | Copy the `artifact_digest` from the publish response; nothing was changed |
| `egs.service` is not `active` after step 3; `journalctl -u egs.service` shows `decode config` or `runtime_trust...` | EGS refuses the file: invalid JSON, an unknown field, a duplicate entry, or a bad digest. Steps 2 and 6 write none of these, so another edit or tool changed the file | Run the check below. For an empty, non-string or duplicate entry in any of the three lists it names, run step 2 with `ACTION=drop-invalid` and `KIND` set to `artifact`, `signer` or `allowed` (step 6). For a revoked digest in a spelling EGS refuses, run step 2 with `ACTION=remove` and the text the check prints between the quotes, then add the digest again with `ACTION=add` if it must stay revoked. Then repeat step 3. Invalid JSON, a list that is not a list, or an unknown field outside `runtime_trust` came from the tool that last wrote the file: repair it with that tool, not with an editor. ES cannot start until EGS is up |
| `es.service` is not `active` after step 3 | ES could not fetch or verify EGS's list at start | Check that `egs.service` is `active`, then read `journalctl -u es.service` |
| Step 4 still succeeds | ES is still using the list it fetched before the change, or the value does not match | Repeat step 3 in order; compare the value with the artifact digest or the evidence seal's key ID |
| Step 4 fails with `signer_not_allowed` instead | The artifact's key is not in `allowed_signers` at all | Nothing to revoke for that key; ES already refuses it |

To find the problems in the lists without showing any other field, run the check below. It also flags a digest in upper-case hex, which ES would never match.

```bash
sudo python3 -I - /etc/execution-substrate/egs.json <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
except json.JSONDecodeError as exc:
    sys.exit(f"not valid JSON: {exc.msg}: line {exc.lineno}, column {exc.colno}")
if not isinstance(doc, dict):
    sys.exit("the file is not a JSON object")
trust = doc.get("runtime_trust")
trust = {} if trust is None else trust
if not isinstance(trust, dict):
    sys.exit("runtime_trust is not an object")
known = {"signer_policy": {"allowed_signers", "revoked_signers"}, "artifact_policy": {"revoked_artifacts"}}
for name in sorted(set(trust) - set(known)):
    print("unknown field in runtime_trust:", name)
for part, fields in known.items():
    section = trust.get(part)
    section = {} if section is None else section
    if not isinstance(section, dict):
        print(f"runtime_trust.{part} is not an object")
        continue
    for name in sorted(set(section) - fields):
        print(f"unknown field in runtime_trust.{part}:", name)
    for field in sorted(fields):
        entries = section.get(field)
        entries = [] if entries is None else entries
        if not isinstance(entries, list):
            print(f"{field}: not a list")
            continue
        seen = set()
        for entry in entries:
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

It prints one line for each problem in the lists or unknown field name under `runtime_trust`, then `check finished`. No line does not prove that EGS accepts the file: the journal in step 3 is the test.

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
  - `TestRevocationRunbookNoteOnUpperCaseDigestsMatchesEGS` in `egs/contract/trustmodel_test.go` checks every line before this section that mentions upper case: the note in Notes must be the one for what EGS does now, and the check's sentence and failure-table row 1 must hold either way.
  - `TestResolvedSubmitLegacyEquivalenceOneNomadRegistrationAndAuthorityRecovery` in `es/admission/resolved_execution_plan_test.go` checks that each Nomad job records the artifact digest in its task meta, which step 5 reads.
- **Run outside the box, on 2026-11-27:**
  - The three Python blocks (steps 1 and 2 and the check), cut from this runbook byte for byte, ran as root against box-shaped config files (owner 1234:5678, mode 0640, a freshly generated EGS key), and each result was loaded with EGS's own `config.Load`, built with the key and file checks of the per-host signing keys change. 71 cases passed. Step 2 added an entry and left a second add unchanged; replaced a copy with surrounding spaces by the exact spelling; refused a digest that is upper-case, 63 hex characters long or unlabeled, a padded or empty signer, a bad `ACTION` or `KIND`, a symbolic link, and a list that is not a list (an empty object included); and kept the owner, the mode and every other field. `remove` lifted a single entry; kept one copy of a value listed two or three times, the well-formed copy even when a padded copy came first (EGS then started, and a second `remove` lifted it); matched an entry with surrounding spaces; removed a spelling EGS refuses; and refused an empty value. `drop-invalid` dropped empty, spaces-only, number, null and list entries and extra copies from one list only, kept a malformed digest, and EGS then started; with `KIND=allowed` it repaired a duplicate, empty, number or padded entry in `allowed_signers`, and `KIND=allowed` refused `add` and `remove`. The check printed the expected lines for duplicates in each list, empty and non-string entries, an upper-case digest, lists and sections of the wrong type (empty ones included), an unknown field, and invalid JSON. No output held the private key.
  - Step 5's Nomad block, cut from this runbook, ran against Nomad 2.1.1 (a server with ACLs on, the namespace `es-submit-v1`, a client token with the observer policy's rules in a root-owned 0400 file, and two jobs shaped like ES's), over plain HTTP instead of TLS, started by an ordinary user with `sudo`. It printed the status, run ID and digest of each job, and `dead` for a stopped one. That user could not read the token without `sudo`. The command this step gave before (no token, no namespace) and the observer token in the `default` namespace were both refused with 403, and the observer token could not stop a job. The box's Nomad comes from HashiCorp's apt repository; its version is Unknown.
- **Not run:** the steps above, as written, have not been run on the box.

## History

- **2026-11-27:** written, because no runbook said how to revoke an artifact or a signer, and a revocation takes effect only after EGS and then ES restart. Audit fixes the same day: lifting and checking no longer open the file (it holds EGS's private key), step 5's cancel is a working command, step 3 waits before it checks, and the reliable-submit sentence matches the code. Second audit fixes the same day: step 5 finds runs through Nomad with the observer token (ES does record the digest in each job), says what a sent cancel and the wait after it print, `remove` keeps one copy of a value listed more than once, `drop-invalid` drops entries that name nothing, and the reliable-submit sentence names what resumes that path. Third round the same day: step 5 runs as root, because the box's observer token is root's; `remove` keeps the copy in the spelling ES matches; `add` replaces a copy EGS refuses; `drop-invalid` also drops extra copies and, with `KIND=allowed`, repairs `allowed_signers`; the check reports empty containers of the wrong type.
