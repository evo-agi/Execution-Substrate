# Runbook: Submit Static Script Workload (v1)

- Version: `v1`
- Last Updated: `2026-04-02`
- Compatible System Version: `Execution-Platform commit 1a74b208cf970299e295d4479d2f4e1444930216`

## 1. Objective

Submit one real workload end to end through the governed execution path:

`AGS publish -> ARS store/register -> ES submit -> Nomad batch job -> Docker container runs -> observable logs + exit code`

This runbook proves the minimal real execution slice only. It does not cover durable run records, ES log/status APIs, cancel flows, sync waiting, or broader runtime orchestration.

For a reference workload that exercises the bounded runtime-identity contract on top of the same static-script execution model, see:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_runtime_identity_reference.md`

In the current bounded slice, runtime networking is controlled only by signed derivation constraints:

- `network_access=false` -> Docker `network_mode = none`
- `network_access=true` -> Docker `network_mode = bridge`

The slice still forbids host networking, port publishing, custom networks, and network-policy interpretation.

Runtime mounts are also bounded in this slice:

- mounts may reference only governed artifact digests
- mounts must be read-only
- mounts must target absolute cleaned paths under `/monolith/mounts/`
- host-path mounts, writable mounts, identity injection, and secret injection remain unsupported

## 2. Prerequisites

### Required services

The following services must already be running and reachable over HTTPS:

- ACS
- ARS
- AGS
- EGS
- ES
- Nomad server/client with Docker driver enabled

### Required tools

- `curl`
- `python3`
- `tar`
- `gzip`
- `nomad`
- `docker`

### Required environment state

The environment must already satisfy these assumptions:

- AGS is configured to write to ARS over the public ARS write boundary.
- EGS TrustModel `allowed_signers` includes the AGS provenance signer key ID.
- ES verification keys match the AGS and EGS public keys.
- ACS already has the `workload-zone/vault` assignment seeded.
- ARS already contains the workload-zone Vault JSON blob referenced by ACS.
- ES is configured for the `vault_identity_jwt` path, not `cgs_proof_legacy`.
- ES is configured with Nomad submission settings:
  - `nomad.base_url`
  - `nomad.datacenter`
  - `execution.staging_root_dir`
  - `execution.base_image`
  - `execution.workload_identity_endpoint_host_path`
- `execution.workload_identity_endpoint_host_path` points to a local Unix socket named `endpoint.sock` that exposes the external workload identity endpoint.
  - ES does not read credentials from it.
  - ES mounts its containing directory read-only so the workload sees it at `/monolith/runtime-identity/endpoint.sock`.
- The Nomad client has the Docker driver available and bind mounts enabled.
  - The minimal ES slice depends on Docker bind mounts for staged payload execution.
  - In Nomad client config this means `docker.volumes.enabled = true`.
- The ES base image is available or pullable by the Nomad client.
  - The current minimal slice expects something equivalent to `alpine:3.20`.
- The artifact payload is a `tar.gz` archive whose root contains executable `./entrypoint`.
- The current slice assumes `artifact_digest == payload_digest` when ES reads the payload from ARS.

### Required TLS material

You need a CA bundle and a client certificate/key that authenticates as either:

- `spiffe://monolith.internal/service/deployment`
- `spiffe://monolith.internal/operator`

The examples below use a deployment caller.

### Export environment variables

Adjust these paths and URLs for your environment before running the steps:

```bash
export ACS_URL="https://127.0.0.1:8441"
export ARS_URL="https://127.0.0.1:8442"
export AGS_URL="https://127.0.0.1:8443"
export EGS_URL="https://127.0.0.1:8444"
export ES_URL="https://127.0.0.1:8445"
export NOMAD_ADDR="http://127.0.0.1:4646"

export CA_CERT="/path/to/runtime-ca.pem"
export DEPLOY_CERT="/path/to/deployment-client.pem"
export DEPLOY_KEY="/path/to/deployment-client-key.pem"
```

## 3. Steps

### Step 1 — Verify system readiness

Check public health for each service:

```bash
curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ACS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ARS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$AGS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$EGS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ES_URL/health" | python3 -m json.tool
```

Expected result:

- Each service returns HTTP `200`
- Each response contains `"ready": true`

Check Nomad and Docker:

```bash
nomad status
docker info >/dev/null
```

Expected result:

- `nomad status` succeeds
- `docker info` succeeds

### Step 2 — Create artifact payload

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

Create the entrypoint script:

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
```

Package it as `tar.gz` with `entrypoint` at archive root:

```bash
tar -C "$WORKDIR" -czf "$WORKDIR/artifact.tar.gz" entrypoint
```

Prepare base64 payload and stable labeled digests for the publish request:

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
export POLICY_VERSION="2026-03-31"
export WORKLOAD_IDENTITY_ID="spiffe://monolith.internal/service/execution"
```

### Step 3 — Publish via AGS

Create the AGS publish request:

```bash
python3 - <<'PY' > "$WORKDIR/publish.json"
import json, os

payload = {
    "artifact_payload_b64": os.environ["ARTIFACT_PAYLOAD_B64"],
    "manifest": {
        "artifact_type": "static-script",
        "intent_digest": os.environ["INTENT_DIGEST"],
        "runtime_interface": {
            "parameters": [],
            "environment_variables": ["APP_MODE"],
            "required_capabilities": []
        }
    },
    "provenance": {
        "builder_service": "artifact-governance",
        "invoker": {
            "service": "deployment",
            "principal": "spiffe://monolith.internal/service/deployment"
        },
        "policy_decisions": [
            {"rule": "allow", "result": "applied"}
        ],
        "build_log_digest": os.environ["BUILD_LOG_DIGEST"]
    },
    "derivation_metadata": {
        "derivation_spec_digest": os.environ["DERIVATION_SPEC_DIGEST"],
        "output_id": os.environ["OUTPUT_ID"],
        "producer_run_id": "runbook-publish-1"
    },
    "derivation_attestation": {
        "constraints": {
            "allowed_toolchains": [],
            "forbidden_toolchains": [],
            "os": "linux",
            "arch": "amd64",
            "network_access": False,
            "writable_paths": [],
            "forbidden_paths": [],
            "determinism_expectation": "deterministic"
        },
        "policy_version": os.environ["POLICY_VERSION"],
        "expected_artifact_type": "static-script"
    },
    "workload_identity_binding": {
        "artifact_class": "service",
        "workload_type": "service",
        "module_path": "services.execution.ExecutionServer",
        "policy_version": os.environ["POLICY_VERSION"],
        "service_name": "execution",
        "target_platform": "docker",
        "description": "Execution workload",
        "workload_identity_id": os.environ["WORKLOAD_IDENTITY_ID"]
    }
}

print(json.dumps(payload))
PY
```

Publish the artifact:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -H 'Content-Type: application/json' \
  --data @"$WORKDIR/publish.json" \
  "$AGS_URL/v1/artifacts:publish" | tee "$WORKDIR/publish-response.json"
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

Expected response:

- HTTP `200`
- JSON with:
  - `"published": true`
  - `"artifact_digest": "sha256:..."`
  - the fact digests and payload digest

### Step 4 — Submit via ES

Create the ES submit request:

```bash
python3 - <<'PY' > "$WORKDIR/submit.json"
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

Submit the execution:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -H 'Content-Type: application/json' \
  --data @"$WORKDIR/submit.json" \
  "$ES_URL/v1/executions:submit" | tee "$WORKDIR/submit-response.json"
```

Extract Nomad identifiers:

```bash
export RUN_ID="$(python3 - <<'PY' "$WORKDIR/submit-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["run_id"])
PY
)"

export NOMAD_JOB_ID="$(python3 - <<'PY' "$WORKDIR/submit-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["nomad_job_id"])
PY
)"

export NOMAD_EVAL_ID="$(python3 - <<'PY' "$WORKDIR/submit-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["nomad_eval_id"])
PY
)"

echo "RUN_ID=$RUN_ID"
echo "NOMAD_JOB_ID=$NOMAD_JOB_ID"
echo "NOMAD_EVAL_ID=$NOMAD_EVAL_ID"
```

Expected response:

- HTTP `202`
- JSON with:
  - `"success": true`
  - `"submitted": true`
  - `"run_id": "..."`
  - `"nomad_job_id": "..."`
  - `"nomad_eval_id": "..."`
  - `"status": "submitted"`

### Step 5 — Verify execution in Nomad

Confirm the job exists:

```bash
nomad job status "$NOMAD_JOB_ID"
nomad eval status "$NOMAD_EVAL_ID"
```

Find the allocation:

```bash
export ALLOC_ID="$(nomad job allocs -json "$NOMAD_JOB_ID" | python3 - <<'PY'
import json, sys
allocs = json.load(sys.stdin)
if not allocs:
    raise SystemExit("no allocations found")
print(allocs[0]["ID"])
PY
)"

echo "ALLOC_ID=$ALLOC_ID"
```

Wait for the allocation to reach a terminal state:

```bash
while true; do
  STATUS="$(nomad alloc status -json "$ALLOC_ID" | python3 - <<'PY'
import json, sys
print(json.load(sys.stdin)["ClientStatus"])
PY
)"
  echo "allocation status: $STATUS"
  case "$STATUS" in
    complete|failed|lost) break ;;
  esac
  sleep 2
done
```

Inspect the allocation and logs:

```bash
nomad alloc status "$ALLOC_ID"
nomad alloc logs -stdout "$ALLOC_ID"
```

Extract the task exit code:

```bash
nomad alloc status -json "$ALLOC_ID" | python3 - <<'PY'
import json, sys
payload = json.load(sys.stdin)
events = payload["TaskStates"]["task"]["Events"]
exit_code = None
for event in reversed(events):
    if event.get("Type") == "Terminated":
        exit_code = event.get("ExitCode")
        break
print(f"task exit code: {exit_code}")
if exit_code != 0:
    raise SystemExit(1)
PY
```

## 4. Expected Output

Success looks like all of the following:

- AGS publish returns HTTP `200` with `"published": true`
- ES submit returns HTTP `202` with `"status": "submitted"`
- `nomad job status "$NOMAD_JOB_ID"` shows a real batch job
- `nomad alloc status "$ALLOC_ID"` reaches `complete`
- task exit code is `0`
- task logs contain:
  - `START-BANNER`
  - `HEARTBEAT:1`
  - `HEARTBEAT:2`
  - `HEARTBEAT:3`
  - final JSON line containing `"status":"ok"` and the artifact digest

Example log output:

```text
START-BANNER
HEARTBEAT:1
HEARTBEAT:2
HEARTBEAT:3
{"status":"ok","artifact_digest":"sha256:..."}
```

## 5. Failure Modes

### AGS publish failure

What it means:

- The artifact was not published into ARS.
- ES cannot submit it because it is not discoverable.

Common causes:

- malformed JSON
- invalid base64 in `artifact_payload_b64`
- invalid labeled SHA-256 digests
- missing required publish fields
- AGS cannot write to ARS

How to debug:

```bash
cat "$WORKDIR/publish.json" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$AGS_URL/health" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$ARS_URL/health" | python3 -m json.tool
```

Interpretation hints:

- HTTP `400` usually means request-shape or digest-format error
- HTTP `503` usually means ARS write/register is unavailable

### ES rejection

What it means:

- ES refused the workload before Nomad submission.

Common causes:

- ES cannot validate the artifact facts from ARS
- TrustModel rejects the AGS signer or artifact digest
- ACS cannot resolve workload-zone Vault config
- ARS payload/fact retrieval failed
- request mode is not `async`
- artifact type is not `static-script`
- `required_capabilities` is not empty
- auth mode resolves to `cgs_proof_legacy`
- runtime-identity endpoint validation or startup capability probing failed when submit is configured

How to debug:

```bash
cat "$WORKDIR/submit.json" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$ES_URL/health" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$ACS_URL/health" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$ARS_URL/health" | python3 -m json.tool
curl --silent --show-error --cacert "$CA_CERT" "$EGS_URL/health" | python3 -m json.tool
```

Interpretation hints:

- HTTP `400` means request or artifact-type constraints failed
- HTTP `403` means caller certificate is not authorized
- HTTP `409` means unsupported auth mode such as `cgs_proof_legacy`
- HTTP `503` means an upstream dependency or payload/fact read failed

### Nomad job not created

What it means:

- ES accepted the request far enough to attempt submission, but Nomad did not accept or materialize the job.

Common causes:

- ES Nomad config is wrong
- Nomad is not reachable from ES
- Docker driver is unavailable on the Nomad client
- bind mounts are disabled on the Nomad client
- the configured ES base image cannot be pulled

How to debug:

```bash
nomad status
nomad eval status "$NOMAD_EVAL_ID"
docker info >/dev/null
```

Interpretation hints:

- If `nomad job status "$NOMAD_JOB_ID"` fails, focus on ES submit response and Nomad connectivity
- If the eval exists but no allocation starts, inspect Nomad eval output for placement or driver errors

### Container exits non-zero

What it means:

- Nomad scheduled the job, but the containerized workload failed at runtime.

Common causes:

- `entrypoint` missing from archive root
- `entrypoint` not executable
- malformed `tar.gz`
- script exits non-zero
- the task timed out
- the base image is missing required utilities such as `tar` or `/bin/sh`

How to debug:

```bash
nomad alloc status "$ALLOC_ID"
nomad alloc logs -stdout "$ALLOC_ID"
nomad alloc logs -stderr "$ALLOC_ID"
```

Interpretation hints:

- If logs never show `START-BANNER`, the wrapper likely failed before running `./entrypoint`
- If logs show some heartbeats and then stop, check timeout or script failure
- If the final JSON marker is missing, the script did not finish cleanly
