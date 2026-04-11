# Runbook: Submit Runtime Identity Reference Workload (v1)

- Version: `v1`
- Last Updated: `2026-04-05`

## 1. Objective

Submit the legacy reference runtime-identity workload through the governed execution path:

`AGS publish -> ARS -> ES submit -> Nomad/Docker -> workload discovers identity endpoint -> workload authenticates to Vault -> observable logs + exit code`

This runbook is retained for legacy compatibility validation only. It exercises the older workload-authored bridge example on top of the same static-script execution model documented in [.runbooks/execution/v1_submit_static_script.md](v1_submit_static_script.md). It is not the slice-1 platform-owned runtime identity proof path.

For the current bounded platform-owned proof path, use [.runbooks/execution/v1_submit_runtime_identity_vault_login.md](v1_submit_runtime_identity_vault_login.md) instead.

For a local non-production Vault dev path plus a simple HTTP identity adapter, see [.runbooks/execution/v1_runtime_identity_local_validation.md](v1_runtime_identity_local_validation.md).

Run command examples from the repository root unless a step says otherwise.

## 2. Reference Workload

The reference artifact lives at:

- [.examples/runtime_identity_reference/entrypoint](../../.examples/runtime_identity_reference/entrypoint)

Package it with:

```bash
".examples/runtime_identity_reference/package.sh"
```

The resulting archive is:

- `.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz`

## 3. Runtime-Identity Contract In This Legacy Reference Path

The workload-visible contract shared with the current platform-owned path is:

- discover the endpoint from `EXEC_WORKLOAD_IDENTITY_ENDPOINT`
- use the non-secret Vault metadata ES injects:
  - `EXEC_WORKLOAD_VAULT_AUTH_MODE`
  - `EXEC_WORKLOAD_VAULT_AUTH_MOUNT`
  - `EXEC_WORKLOAD_VAULT_AUTH_ROLE`
  - `EXEC_WORKLOAD_VAULT_JWT_AUDIENCE`

This legacy reference runbook then adds workload-authored bridge behavior on top of that contract. The workload must **not** assume a fixed `/execution/...` socket path. ES chooses the actual backing endpoint path internally and exposes only the discovered endpoint URI.

Slice 1 changes the ownership behind that endpoint: the platform-owned helper serves the bounded endpoint and the workload no longer authors the bridge itself.

## 4. Environment Assumptions

All prerequisites from the static-script runbook still apply, plus:

- ES base image includes `python3`
- the publish request sets `admission.access.network_access = true`
- the submit request includes `REFERENCE_IDENTITY_URL`
- the legacy workload-local bridge protocol is documented in [.examples/runtime_identity_reference/README.md](../../.examples/runtime_identity_reference/README.md)
- the workload-zone Vault config reachable by ES points at a Vault-compatible address reachable from the workload container

Optional local helpers remain available:

- [.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py](../../.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py)
- [.examples/runtime_identity_reference/helpers/mock_vault.py](../../.examples/runtime_identity_reference/helpers/mock_vault.py)

These helpers are reference tooling only. They are not platform components and they are not the slice-1 helper implementation.

## 5. Bring Up The Stack

Use the primary full bring-up path:

```bash
export BRINGUP_PROFILE="full"
scripts/01_bringup.sh up
```

Then re-check readiness:

```bash
scripts/01_bringup.sh check
```

For this full-profile runbook, do not continue unless the check reports `submit-ready: true`.

If the later publish / prepare / submit / lifecycle helpers fail, first re-run `scripts/01_bringup.sh check`, then use the operator troubleshooting matrix in [.runbooks/system/v1_bringup.md](../system/v1_bringup.md) to choose the right logs, readiness checks, staging inspection path, and next action for the surfaced failure category. If you want the bounded data bundle for that same guidance, run `scripts/70_diagnostics.sh --category ...` or `scripts/70_diagnostics.sh --run-id ...`, then `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>`.

Inspect retained staging only when `:submit` already returned a real `run_id` and the later lifecycle outcome was non-success. Earlier publish / prepare / submit failures are not staging-debug problems.

## 6. Optional Local Reference Helpers

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

Ensure the workload-zone Vault config reachable by ES points `VAULT_ADDR` at a Vault-compatible address the workload container can reach.

## 7. Publish

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

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

Publish with the helper:

```bash
export PUBLISH_JSON="$WORKDIR/publish.json"
export PUBLISH_RESPONSE="$WORKDIR/publish-response.json"
scripts/20_publish.sh
```

Extract the published artifact digest:

```bash
export ARTIFACT_DIGEST="$(python3 - <<'PY' "$WORKDIR/publish-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["artifact_digest"])
PY
)"
echo "ARTIFACT_DIGEST=$ARTIFACT_DIGEST"
```

## 8. Submit

Set the reference identity URL to something the workload container can actually reach:

```bash
export REFERENCE_IDENTITY_URL_VALUE="http://<container-reachable-identity-host>:18081"
```

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

Optional bounded preflight:

```bash
export PREPARE_JSON="$WORKDIR/execution.json"
export PREPARE_RESPONSE="$WORKDIR/prepare-response.json"
scripts/30_prepare.sh
```

Submit:

```bash
export SUBMIT_JSON="$WORKDIR/execution.json"
export SUBMIT_RESPONSE="$WORKDIR/submit-response.json"
scripts/40_submit.sh
```

Extract the run ID:

```bash
export RUN_ID="$(python3 - <<'PY' "$WORKDIR/submit-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["run_id"])
PY
)"
echo "RUN_ID=$RUN_ID"
```

`host.docker.internal` is only one possible runtime-specific value for `REFERENCE_IDENTITY_URL_VALUE`; it is not a platform default.

## 9. Verify Success

Observe the workload through the public lifecycle helper:

```bash
export WAIT_FOR_TERMINAL=1
scripts/50_lifecycle.sh
```

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
