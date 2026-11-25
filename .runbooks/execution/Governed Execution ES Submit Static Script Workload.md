# Governed Execution ES Submit Static Script Workload

- Version: `v1`
- Last Updated: `2026-04-09`
- Compatible System Version: `Execution Substrate current working tree`

## 1. Objective

Submit one real workload end to end through the current governed execution path:

`AGS publish -> ARS -> ES :prepare -> ES :submit -> Nomad -> Docker -> ES status/logs`

This runbook documents the current bounded static-script slice only. It does not define a richer execution model above Nomad.

Run command examples from the repository root unless a step says otherwise.

For the preferred one-command smoke path over the same public APIs, use:

```bash
scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json
```

For the first repo-owned non-operator API-facing path, use:

```bash
".examples/control_plane_static_script/run.sh"
```

That example drives the AGS and ES HTTPS+mTLS APIs directly as `spiffe://execution.internal/service/control-plane` for publish, submit, status, and logs; it does not use the operator helper wrappers below.
On this Mac, the supported-local guest path is the grounded positive verification path for the logs step.
When that direct example waits for terminal status without `CANCEL_AFTER_SUBMIT=1`, it now exits nonzero if ES reports a terminal nonzero workload exit.
When you supply a long-running static-script payload and set `CANCEL_AFTER_SUBMIT=1 FETCH_LOGS=0`, the same direct API example instead exercises the bounded ES `cancel` surface and then waits for terminal status if requested.
The focused app integration harness at [es/app/control_plane_integration_path_test.go](../../es/app/control_plane_integration_path_test.go) remains the repo-owned verification layer for the same direct API path and for disallowed-caller failures. On this Mac, that harness remains bounded to publish, submit, status, cancel, and disallowed-caller coverage rather than positive logs retrieval.
On the supported-local guest path, `SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE=1 scripts/72_supported_local_setup.sh setup` now generates the matching Control Plane client cert/key and includes `service/control-plane` in the proof-scoped AGS/ES allowlists without changing the default operator-only helper path.

The steps below remain the transparent manual breakdown for the same current slice.

## 2. Prerequisites

- The stack is already up through [.runbooks/system/v1_bringup.md](../system/v1_bringup.md)
- `BRINGUP_PROFILE=full`
- `curl`, `python3`, `tar`, `gzip`, `nomad`, and `docker` are available
- `CA_CERT`, `OPERATOR_CERT`, `OPERATOR_KEY`, `ARS_URL`, `AGS_URL`, `EGS_URL`, `ES_URL`, `NOMAD_ADDR` (`https://127.0.0.1:4646`), and `NOMAD_CACERT` (Nomad's CA, `/etc/nomad.d/tls/ca.pem`) are exported
- Optional `AGS_RESOLVE` and `ES_RESOLVE` are exported if your local URLs require `curl --resolve`

Before publishing or submitting, re-run the stack check:

```bash
scripts/01_bringup.sh check
```

For this full-profile runbook, do not continue unless the check reports `submit-ready: true`.

When later helpers fail, keep the bring-up check as the readiness source of truth:

- first re-run `scripts/01_bringup.sh check`
- then use the operator troubleshooting matrix in [.runbooks/system/v1_bringup.md](../system/v1_bringup.md) to choose the right logs, readiness checks, staging inspection path, and next action for the surfaced failure category
- if you want the bounded data bundle for that same guidance, run `scripts/70_diagnostics.sh --category ...` or `scripts/70_diagnostics.sh --run-id ...`, then `scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>` for the compact summary

Inspect retained staging whenever exclusive run-root creation may have occurred.
Every post-claim failure and every accepted run retains its root, including
partial Submit failures that return no receipt, ambiguous registration, and
terminal success. Failures before run assignment/claim still create no staging.

## 3. Create The Artifact Payload

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

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

## 4. Publish Through AGS

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

The current runtime path no longer assumes `artifact_digest == payload_digest`. ES resolves payload bytes from ARS discovery and cross-checks them against aggregate evidence during prepare/submit.

## 5. Optional Preflight

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

Run bounded preflight:

```bash
export PREPARE_JSON="$WORKDIR/execution.json"
export PREPARE_RESPONSE="$WORKDIR/prepare-response.json"
scripts/30_prepare.sh
```

Success today is only:

```json
{"success": true}
```

`POST /v1/executions:prepare` is still active, but it remains a bounded auxiliary surface. It does not return a run ID or scheduler receipt.

## 6. Submit Through ES

Submit with the same request body:

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

The public submission receipt is intentionally bounded. It now returns `run_id` and bounded status only; it does not return Nomad job or eval identifiers.

## 7. Observe Lifecycle

Use the current public lifecycle helper:

```bash
export WAIT_FOR_TERMINAL=1
scripts/50_lifecycle.sh
```

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

## 8. Notes

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
