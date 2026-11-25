# Governed Execution ES Submit Runtime Identity Reference Workload

## What is it?

This runbook submits the legacy reference runtime-identity workload through the governed execution path:

`AGS publish -> ARS -> ES submit -> Nomad/Docker -> workload discovers identity endpoint -> workload authenticates to Vault -> observable logs + exit code`

This runbook is retained for legacy compatibility validation only. It exercises the older workload-authored bridge example on top of the same static-script execution model documented in [.runbooks/execution/Governed Execution ES Submit Static Script Workload.md](Governed%20Execution%20ES%20Submit%20Static%20Script%20Workload.md). It is not the slice-1 platform-owned runtime identity proof path.

For the current bounded platform-owned proof path, use [.runbooks/execution/Governed Execution ES Submit Runtime Identity Vault Login Workload.md](Governed%20Execution%20ES%20Submit%20Runtime%20Identity%20Vault%20Login%20Workload.md) instead.

For a local non-production Vault dev path plus a simple HTTP identity adapter, see [.runbooks/execution/Governed Execution ES Local Runtime Identity Validation.md](Governed%20Execution%20ES%20Local%20Runtime%20Identity%20Validation.md).

### The runtime-identity contract in this legacy reference path

The workload-visible contract shared with the current platform-owned path is:

- discover the endpoint from `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- use the non-secret Vault metadata ES injects:
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`
  - `VAULT_CACERT` when the resolved workload-zone Vault config carries CA trust material

This legacy reference runbook then adds workload-authored bridge behavior on top of that contract. The workload must **not** assume a fixed `/execution/...` socket path. ES chooses the actual backing endpoint path internally and exposes only the discovered endpoint URI.

Slice 1 changes the ownership behind that endpoint: the platform-owned helper serves the bounded endpoint and the workload no longer authors the bridge itself.

## What do I need?

All prerequisites from the static-script runbook still apply, plus:

- ES base image includes `python3`
- the publish request sets `admission.access.network_access = true`
- the submit request includes `REFERENCE_IDENTITY_URL`
- the legacy workload-local bridge protocol is documented in [.examples/runtime_identity_reference/README.md](../../.examples/runtime_identity_reference/README.md)
- the workload-zone Vault config reachable by ES points at a Vault-compatible address reachable from the workload container

The reference artifact lives at:

- [.examples/runtime_identity_reference/entrypoint](../../.examples/runtime_identity_reference/entrypoint)

Optional local helpers remain available:

- [.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py](../../.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py)
- [.examples/runtime_identity_reference/helpers/mock_vault.py](../../.examples/runtime_identity_reference/helpers/mock_vault.py)

These helpers are reference tooling only. They are not platform components and they are not the slice-1 helper implementation.

## How to use it?

Run command examples from the repository root unless a step says otherwise. Use one shell for steps 4 to 6: later steps read the variables that earlier ones export. The output to expect is taken from the scripts in this repository; Test Evidence says what has been run.

### 1. Package the reference workload

```bash
".examples/runtime_identity_reference/package.sh"
```

The resulting archive is:

- `.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz`

### 2. Bring up the stack

Use the primary full bring-up path:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
```

Expect `bring-up complete` near the end of the output.

Then re-check readiness:

```bash
scripts/01_bringup.sh check
```

For this full-profile runbook, do not continue unless the check reports `submit-ready: true`.

### 3. Optional: start the local reference helpers

Start the reference identity endpoint:

```bash
python3 ".examples/runtime_identity_reference/helpers/mock_identity_endpoint.py" \
  --http-bind 0.0.0.0 \
  --http-port 18081 \
  --audience vault \
  --jwt reference-runtime-identity-jwt
```

Start the reference Vault-compatible endpoint:

```bash
python3 ".examples/runtime_identity_reference/helpers/mock_vault.py" \
  --bind 0.0.0.0 \
  --port 18200 \
  --auth-mount jwt \
  --role service_execution \
  --jwt reference-runtime-identity-jwt \
  --secret-value runtime-identity-ok
```

Each keeps running in the foreground, so start each in its own terminal.

Ensure the workload-zone Vault config reachable by ES points `VAULT_ADDR` at a Vault-compatible address the workload container can reach.

### 4. Publish

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

Expect `Using WORKDIR=` and a new temporary directory.

Prepare payload bytes and publish-time inputs:

```bash
export ARTIFACT_PAYLOAD_B64="$(python3 - ".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz" <<'PY'
import base64, pathlib, sys
print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode("ascii"))
PY
)"

export INTENT_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export DERIVATION_SPEC_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
export BUILD_LOG_DIGEST="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
export OUTPUT_ID="runtime-identity-reference"
```

Expect no output.

Create the current AGS publish request:

```bash
python3 - <<'PY' > "$WORKDIR/publish.json"
import json, os

payload = {
    "artifact_payload_b64": os.environ["ARTIFACT_PAYLOAD_B64"],
    "artifact": {
        "artifact_type": "static-script",
        "intent_digest": os.environ["INTENT_DIGEST"],
    },
    "publication": {
        "policy_decisions": [
            {"rule": "allow", "result": "applied"}
        ],
        "build_log_digest": os.environ["BUILD_LOG_DIGEST"],
    },
    "admission": {
        "runtime": {
            "environment_variables": [
                "REFERENCE_IDENTITY_URL",
                "REFERENCE_SECRET_PATH",
                "REFERENCE_VAULT_INSECURE_SKIP_VERIFY",
            ],
            "required_capabilities": [],
        },
        "access": {
            "network_access": True,
        },
        "derivation": {
            "derivation_spec_digest": os.environ["DERIVATION_SPEC_DIGEST"],
            "output_id": os.environ["OUTPUT_ID"],
        },
        "workload": {
            "target_platform": "docker",
        },
    },
}

print(json.dumps(payload))
PY
```

Expect no output, and the request in `$WORKDIR/publish.json`.

Publish with the helper:

```bash
export PUBLISH_JSON="$WORKDIR/publish.json"
export PUBLISH_RESPONSE="$WORKDIR/publish-response.json"
scripts/20_publish.sh
```

Expect `saved publish response to` the response path, `publish: success`, the AGS response as JSON, and last `ARTIFACT_DIGEST=sha256:…`.

Extract the published artifact digest:

```bash
export ARTIFACT_DIGEST="$(python3 - <<'PY' "$WORKDIR/publish-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["artifact_digest"])
PY
)"
echo "ARTIFACT_DIGEST=$ARTIFACT_DIGEST"
```

Expect the same `ARTIFACT_DIGEST=sha256:…` line as the helper printed.

### 5. Submit

Set the reference identity URL to something the workload container can actually reach:

```bash
export REFERENCE_IDENTITY_URL_VALUE="http://<container-reachable-identity-host>:18081"
```

`host.docker.internal` is only one possible runtime-specific value for `REFERENCE_IDENTITY_URL_VALUE`; it is not a platform default.

Create the current ES execution request:

```bash
python3 - <<'PY' > "$WORKDIR/execution.json"
import json, os

payload = {
    "schema_version": "v1",
    "invocation": {
        "schema_version": "v1",
        "artifact_digest": os.environ["ARTIFACT_DIGEST"],
        "derivation_spec_digest": os.environ["DERIVATION_SPEC_DIGEST"],
        "output_id": os.environ["OUTPUT_ID"],
        "env": {
            "REFERENCE_IDENTITY_URL": os.environ["REFERENCE_IDENTITY_URL_VALUE"],
            "REFERENCE_SECRET_PATH": "secret/data/runtime-identity-reference",
        }
    },
    "mode": "async",
    "resources": {
        "cpu": 10,
        "memory_mb": 128
    }
}

print(json.dumps(payload))
PY
```

Expect no output, and the request in `$WORKDIR/execution.json`.

Optional bounded preflight:

```bash
export PREPARE_JSON="$WORKDIR/execution.json"
export PREPARE_RESPONSE="$WORKDIR/prepare-response.json"
scripts/30_prepare.sh
```

Expect `prepare: success` and the response `{"success": true}`.

Submit:

```bash
export SUBMIT_JSON="$WORKDIR/execution.json"
export SUBMIT_RESPONSE="$WORKDIR/submit-response.json"
scripts/40_submit.sh
```

Expect `submit: accepted`, the receipt, and `RUN_ID=run-…`.

Extract the run ID:

```bash
export RUN_ID="$(python3 - <<'PY' "$WORKDIR/submit-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["run_id"])
PY
)"
echo "RUN_ID=$RUN_ID"
```

Expect the same `RUN_ID=run-…` line as the helper printed.

### 6. Verify success

Observe the workload through the public lifecycle helper:

```bash
export WAIT_FOR_TERMINAL=1
scripts/50_lifecycle.sh
```

Expect the status JSON, the workload logs, and last `lifecycle: execution completed successfully`.

Success requires:

- workload starts
- identity JWT retrieval succeeds
- Vault auth succeeds
- secret read succeeds
- terminal exit code is `0`

This proves only the legacy reference path. It does not prove the slice-1 platform-owned runtime identity model.

Expected log markers include:

```text
RUNTIME-IDENTITY-REFERENCE-START
IDENTITY-JWT-RECEIVED
VAULT-AUTH-SUCCESS
SECRET-READ-SUCCESS:runtime-identity-ok
{"artifact_digest":"sha256:...","secret_message":"runtime-identity-ok","status":"ok"}
```

### 7. If a helper fails

If the later publish / prepare / submit / lifecycle helpers fail, first re-run `scripts/01_bringup.sh check`, then use the operator troubleshooting matrix in [.runbooks/system/Governed Execution ES System Bring-Up.md](../system/Governed%20Execution%20ES%20System%20Bring-Up.md) to choose the right logs, readiness checks, staging inspection path, and next action for the surfaced failure category. If you want the bounded data bundle for that same guidance, run `scripts/70_diagnostics.sh --category ...` or `scripts/70_diagnostics.sh --run-id ...`, then `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>`.

Inspect retained staging whenever exclusive run-root creation may have occurred.
Every post-claim failure and every accepted run retains its root, including
partial Submit failures that return no receipt, ambiguous registration, and
terminal success. Failures before run assignment/claim still create no staging.

## Test Evidence

- **Automated:** none for this legacy path. No test in this repository runs the reference workload or its helpers; the publish, prepare, submit and lifecycle helpers it uses are covered by the tests named in the static-script runbook's Test Evidence.
- **Not run:** the steps above, as written, were not run end to end when this runbook was restructured into this layout on 2026-11-25; no step's commands changed then.

## History

- **2026-04-05:** version `v1` of this runbook, last updated on this date before it came into this repository (from its former header).
- **2026-04-19:** came into this repository as `v1_submit_runtime_identity_reference.md` (PR #1).
- **2026-11-18:** retained staging: inspect it whenever exclusive run-root creation may have occurred (PR #8).
- **2026-11-23:** renamed to its current name (PR #37).
- **2026-11-25:** restructured into the layout of the project's other runbooks (What is it?, What do I need?, How to use it? with numbered steps and the output to expect, Test Evidence, History). Packaging the workload moved from the former section "Reference Workload" to step 1, and the former section "Runtime-Identity Contract In This Legacy Reference Path" is now under "What is it?"; the bring-up runbook was renamed to `Governed Execution ES System Bring-Up.md`. No command changed.
