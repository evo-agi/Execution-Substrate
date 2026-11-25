# Governed Execution ES Submit Static Script Workload

## What is it?

This runbook submits one real workload end to end, by hand, through the current governed execution path, and checks that it ran:

`AGS publish -> ARS -> ES :prepare -> ES :submit -> Nomad -> Docker -> ES status/logs`

The workload is a small static script that prints a banner, three heartbeats and a JSON line with its artifact digest. This runbook documents the current bounded static-script slice only. It does not define a richer execution model above Nomad.

The steps below are the transparent manual breakdown of that slice. For the preferred one-command smoke path over the same public APIs, use:

```bash
scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json
```

For the first repo-owned non-operator API-facing path, use `".examples/control_plane_static_script/run.sh"`; see Notes.

## What do I need?

- The stack is already up through [.runbooks/system/Governed Execution ES System Bring-Up.md](../system/Governed%20Execution%20ES%20System%20Bring-Up.md)
- `BRINGUP_PROFILE=full`
- `curl`, `python3`, `tar`, `gzip`, `nomad`, and `docker` are available
- `CA_CERT`, `OPERATOR_CERT`, `OPERATOR_KEY`, `ARS_URL`, `AGS_URL`, `EGS_URL`, `ES_URL`, `NOMAD_ADDR` (`https://127.0.0.1:4646`), and `NOMAD_CACERT` (Nomad's CA, `/etc/nomad.d/tls/ca.pem`) are exported
- Optional `AGS_RESOLVE` and `ES_RESOLVE` are exported if your local URLs require `curl --resolve`

## How to use it?

Run command examples from the repository root unless a step says otherwise. Use one shell for all steps: later steps read the variables that earlier steps export. The output to expect is taken from the scripts in this repository; Test Evidence says what has been run.

### 1. Check that the stack is submit-ready

Before publishing or submitting, re-run the stack check:

```bash
scripts/01_bringup.sh check
```

Expect the readiness report of the bring-up runbook. For this full-profile runbook, do not continue unless the check reports `submit-ready: true`.

### 2. Create the artifact payload

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

Expect `Using WORKDIR=` and a new temporary directory.

Create the entrypoint:

```bash
cat > "$WORKDIR/entrypoint" <<'EOF'
#!/bin/sh
set -eu
echo START-BANNER
for i in 1 2 3; do
  echo HEARTBEAT:$i
  sleep 2
done
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
EOF
chmod +x "$WORKDIR/entrypoint"
tar -C "$WORKDIR" -czf "$WORKDIR/artifact.tar.gz" entrypoint
```

Expect no output, and `$WORKDIR/artifact.tar.gz` next to the entrypoint.

Prepare the publish-time inputs:

```bash
export ARTIFACT_PAYLOAD_B64="$(python3 - <<'PY' "$WORKDIR/artifact.tar.gz"
import base64, pathlib, sys
print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode("ascii"))
PY
)"

export INTENT_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export DERIVATION_SPEC_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
export BUILD_LOG_DIGEST="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
export OUTPUT_ID="runtime"
```

Expect no output.

### 3. Publish through AGS

Create the current AGS publish request using the live `artifact` / `publication` / `admission` grammar:

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
            "environment_variables": ["APP_MODE"],
            "required_capabilities": [],
        },
        "access": {
            "network_access": False,
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

The current runtime path no longer assumes `artifact_digest == payload_digest`. ES resolves payload bytes from ARS discovery and cross-checks them against aggregate evidence during prepare/submit.

### 4. Optional: run preflight

Create the current ES request body:

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
            "APP_MODE": "test"
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

Expect no output, and the request in `$WORKDIR/execution.json`. Step 5 submits the same body, so create it even if you skip preflight.

Run bounded preflight:

```bash
export PREPARE_JSON="$WORKDIR/execution.json"
export PREPARE_RESPONSE="$WORKDIR/prepare-response.json"
scripts/30_prepare.sh
```

Expect `saved prepare response to` the response path, `prepare: success`, the response, and the note that prepare proves bounded preflight only. Success today is only:

```json
{"success": true}
```

`POST /v1/executions:prepare` is still active, but it remains a bounded auxiliary surface. It does not return a run ID or scheduler receipt.

### 5. Submit through ES

Submit with the same request body:

```bash
export SUBMIT_JSON="$WORKDIR/execution.json"
export SUBMIT_RESPONSE="$WORKDIR/submit-response.json"
scripts/40_submit.sh
```

Expect `saved submit response to` the response path, `submit: accepted`, the receipt, `RUN_ID=run-…`, `STATUS=…`, and the note that submit acceptance does not prove runtime success.

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

The public submission receipt is intentionally bounded. It now returns `run_id` and bounded status only; it does not return Nomad job or eval identifiers.

### 6. Observe the lifecycle

Use the current public lifecycle helper:

```bash
export WAIT_FOR_TERMINAL=1
scripts/50_lifecycle.sh
```

It polls until the run is terminal (up to `TIMEOUT_SECONDS`, 120 by default), then prints the status request and the status JSON, the logs request and the workload logs. Expect `lifecycle: execution completed successfully` last.

This helper now drives only the public ES contract:

- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- optional `POST /v1/executions/{run_id}:cancel`

It no longer requires Nomad job or eval IDs.

Success indicators:

- status becomes `"terminal"`
- `terminal` becomes `true`
- `exit_code` is `0`
- logs contain:
  - `START-BANNER`
  - `HEARTBEAT:1`
  - `HEARTBEAT:2`
  - `HEARTBEAT:3`
  - a final JSON line containing the published artifact digest

### 7. If a helper fails

A failing helper prints `<phase>: failed`, a `failure category:`, a `message:` and a `next:` line that points at the bring-up runbook's troubleshooting matrix. Keep the bring-up check as the readiness source of truth:

- first re-run `scripts/01_bringup.sh check`
- then use the operator troubleshooting matrix in [.runbooks/system/Governed Execution ES System Bring-Up.md](../system/Governed%20Execution%20ES%20System%20Bring-Up.md) to choose the right logs, readiness checks, staging inspection path, and next action for the surfaced failure category
- if you want the bounded data bundle for that same guidance, run `scripts/70_diagnostics.sh --category ...` or `scripts/70_diagnostics.sh --run-id ...`, then `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>` for the compact summary

Inspect retained staging whenever exclusive run-root creation may have occurred.
Every post-claim failure and every accepted run retains its root, including
partial Submit failures that return no receipt, ambiguous registration, and
terminal success. Failures before run assignment/claim still create no staging.

## Notes

- `:submit` remains the primary public execution handoff in the current slice.
- The current execution slice remains:
  - async-only
  - `static-script` only
  - Nomad-backed for lifecycle
  - Docker-backed for runtime
- Runtime networking still comes only from the signed `network_access` input:
  - `false` -> Docker `network_mode = none`
  - `true` -> Docker `network_mode = bridge`
- Runtime mounts remain bounded to governed artifact digests mounted read-only under `/execution/mounts/...`
- **The direct API example.** `".examples/control_plane_static_script/run.sh"` drives the AGS and ES HTTPS+mTLS APIs directly as `spiffe://execution.internal/service/control-plane` for publish, submit, status, and logs; it does not use the operator helper wrappers above.
  On this Mac, the supported-local guest path is the grounded positive verification path for the logs step.
  When that direct example waits for terminal status without `CANCEL_AFTER_SUBMIT=1`, it now exits nonzero if ES reports a terminal nonzero workload exit.
  When you supply a long-running static-script payload and set `CANCEL_AFTER_SUBMIT=1 FETCH_LOGS=0`, the same direct API example instead exercises the bounded ES `cancel` surface and then waits for terminal status if requested.
  The focused app integration harness at [es/app/control_plane_integration_path_test.go](../../es/app/control_plane_integration_path_test.go) remains the repo-owned verification layer for the same direct API path and for disallowed-caller failures. On this Mac, that harness remains bounded to publish, submit, status, cancel, and disallowed-caller coverage rather than positive logs retrieval.
  On the supported-local guest path, `SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE=1 scripts/72_supported_local_setup.sh setup` now generates the matching Control Plane client cert/key and includes `service/control-plane` in the proof-scoped AGS/ES allowlists without changing the default operator-only helper path.

## Test Evidence

- **Automated, in CI on every pull request:** the Linux job "build, vet and test" runs the `es/app` integration tests against a real Nomad agent and Docker. `TestExecuteLoopScriptSuccessAndDeterministicDigests` runs `scripts/60_execute_loop.sh` (publish, prepare, submit, status and logs, the path this runbook breaks down) on a static-script workload and checks terminal state, exit code `0`, the banner in the logs and the artifact digest in its final line. `TestLifecycleScriptObservesExecutionViaPublicRunID` runs `scripts/50_lifecycle.sh` on a submitted run. `TestPublishScriptCategorizesAuthorizationFailure`, `TestPrepareScriptCategorizesRuntimeConfigFailure`, `TestSubmitScriptCategorizesSubstrateFailure` and `TestLifecycleScriptCategorizesExecutionFailure` check the failure reports that step 7 describes.
- **Not run:** the manual steps above, as written, were not run end to end when this runbook was restructured into this layout on 2026-11-25; no step's commands changed then.

## History

- **2026-04-09:** version `v1` of this runbook, last updated on this date before it came into this repository (from its former header).
- **2026-04-19:** came into this repository as `v1_submit_static_script.md` (PR #1).
- **2026-11-18:** retained staging: inspect it whenever exclusive run-root creation may have occurred, because every post-claim failure and every accepted run retains its root (PR #8).
- **2026-11-23:** renamed to its current name (PR #37).
- **2026-11-25:** Nomad over HTTPS: `NOMAD_ADDR` is `https://127.0.0.1:4646`, and `NOMAD_CACERT` is required (PR #60).
- **2026-11-25:** restructured into the layout of the project's other runbooks (What is it?, What do I need?, How to use it? with numbered steps and the output to expect, Notes, Test Evidence, History); the bring-up runbook it builds on was renamed to `Governed Execution ES System Bring-Up.md`. No command changed.
