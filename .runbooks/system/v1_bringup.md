# Runbook: Governed System Bring-up (v1)

- Version: `v1`
- Last Updated: `2026-04-01`
- Compatible System Version: `Execution-Platform current working tree`

## 1. Objective

Bring up the current bounded governed system manually and verify the end-to-end path:

`AGS publish -> ARS -> ES prepare -> ES submit -> Nomad -> Docker -> ES/Nomad lifecycle`

This runbook is intentionally manual. It does not introduce orchestration, startup automation, hidden coordination, or implicit service dependencies.

Optional helper scripts are available in `/Users/ds/Repositories/Execution-Platform/scripts`. They are direct wrappers around the explicit commands in this runbook. They do not add orchestration, dependency resolution, retries, config generation, or process management.

## 2. Prerequisites

### Required software

- Go `1.22.x`
- `curl`
- `python3`
- `tar`
- `gzip`
- `nomad`
- `docker`

### Required environment

- Docker daemon running
- Nomad available locally
- Runtime CA, service certificates, and client certificates already provisioned
- All service config files prepared as JSON

### Required config files

Export absolute paths before starting anything:

```bash
export ACS_CONFIG="/abs/path/acs.json"
export ARS_CONFIG="/abs/path/ars.json"
export EGS_CONFIG="/abs/path/egs.json"
export AGS_CONFIG="/abs/path/ags.json"
export ES_CONFIG="/abs/path/es.json"
export NOMAD_CONFIG="/abs/path/nomad.hcl"
```

This repository does not ship ready-to-run JSON config files. Build them explicitly from the current validators and the configuration matrix in `/Users/ds/Repositories/Execution-Platform/.docs/system_overview/configuration.md`.
All service configs used in this runbook must be built from that configuration matrix rather than inferred from older repos, ad-hoc examples, or implicit defaults.
Example templates are available in `/Users/ds/Repositories/Execution-Platform/configs/examples/`:

- `acs.json`
- `ars.json`
- `egs.json`
- `ags.json`
- `es.json`
- `nomad.hcl`

These example files are templates only. They are not authoritative configs, do not create defaults, and still require you to replace paths, keys, digests, certificates, and other environment-specific values before use.

### Required TLS material for manual API calls

For manual verification you also need a CA bundle and a client certificate/key that authenticate as either:

- `spiffe://monolith.internal/service/deployment`
- `spiffe://monolith.internal/operator`

Export them:

```bash
export CA_CERT="/abs/path/runtime-ca.pem"
export DEPLOY_CERT="/abs/path/deployment-client.pem"
export DEPLOY_KEY="/abs/path/deployment-client-key.pem"
```

### Required service URLs

Adjust these to match your configs:

```bash
export ACS_URL="https://127.0.0.1:8441"
export ARS_URL="https://127.0.0.1:8442"
export EGS_URL="https://127.0.0.1:8443"
export AGS_URL="https://127.0.0.1:8444"
export ES_URL="https://127.0.0.1:8445"
export NOMAD_ADDR="http://127.0.0.1:4646"
```

### Required data assumptions

The current bounded system assumes:

- ACS is seeded with the required `workload-zone/vault` assignment
- ARS already contains the workload-zone Vault JSON blob referenced by ACS
- EGS TrustModel `allowed_signers` includes the AGS signer key ID
- ES verification keys match EGS and AGS signing keys
- ES `workload_vault_auth.default_mode` is `vault_identity_jwt`
- ES `nomad` and `execution` sections are configured if you want to verify `:submit`
- Nomad Docker bind mounts are enabled
- the configured ES base image is available or pullable

CGS is not required for this bring-up runbook because it is not part of the current ES hot path.

### Minimal Nomad config

The current ES submit slice depends on a real Nomad dev agent with the Docker driver available and bind mounts enabled. A minimal `nomad.hcl` looks like:

```hcl
data_dir = "/abs/path/nomad-data"
bind_addr = "127.0.0.1"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  options = {
    "docker.volumes.enabled" = "true"
  }
}
```

Adjust ports or other local settings as needed, but keep the Docker bind-mount option visible and explicit.

## 3. Startup Order

Run all commands from the repository root:

`/Users/ds/Repositories/Execution-Platform`

Use a separate terminal per long-running process.

If you prefer wrappers instead of typing the commands manually, you may use the matching `scripts/01_start_*.sh` through `scripts/06_start_nomad.sh` helpers. They require the same explicit environment variables and run the same foreground commands shown below.

### Step 1 — Start ACS

```bash
go run ./cmd/acs -config "$ACS_CONFIG"
```

Expected output includes:

```text
artifact-catalog listening on ...
```

### Step 2 — Start ARS

```bash
go run ./cmd/ars -config "$ARS_CONFIG"
```

Expected output includes:

```text
artifact-registry listening on ...
```

### Step 3 — Start EGS

```bash
go run ./cmd/egs -config "$EGS_CONFIG"
```

Expected output includes:

```text
execution-governance listening on ...
```

### Step 4 — Start AGS

```bash
go run ./cmd/ags -config "$AGS_CONFIG"
```

Expected output includes:

```text
artifact-governance listening on ...
```

### Step 5 — Start ES

```bash
go run ./cmd/es -config "$ES_CONFIG"
```

Expected output includes:

```text
execution listening on ...
```

ES can start before Nomad in the current slice because ES `/health` remains admission-oriented and does not include Nomad readiness. `:submit` and lifecycle verification still require Nomad to be running before those checks begin.

### Step 6 — Start Nomad

Use an explicit config file so Docker driver and bind-mount behavior are visible and repeatable:

```bash
nomad agent -dev -config="$NOMAD_CONFIG"
```

Keep Docker running while Nomad is up.

## 4. Verification Flow

Treat failures in this section as diagnostic signals. They indicate which boundary, config, or runtime assumption is currently unsatisfied and should be investigated directly rather than worked around.

If you prefer wrappers instead of typing the commands manually, you may use `scripts/10_health_check.sh`, `scripts/20_publish.sh`, `scripts/30_prepare.sh`, `scripts/40_submit.sh`, and `scripts/50_lifecycle.sh`. These helpers are direct command wrappers only. They do not generate configs, infer topology, or manage service state.

### Step 1 — Verify service health

```bash
curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ACS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ARS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$EGS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$AGS_URL/health" | python3 -m json.tool

curl --fail-with-body --silent --show-error --cacert "$CA_CERT" \
  "$ES_URL/health" | python3 -m json.tool
```

Expected result:

- each service returns HTTP `200`
- each response contains `"ready": true`

For ES specifically, `"ready": true` confirms ACS, ARS, and TrustModel readiness only. It does not prove Nomad is reachable.

Verify Nomad and Docker:

```bash
nomad status
docker info >/dev/null
```

### Step 2 — Create a minimal test payload

```bash
WORKDIR="$(mktemp -d)"
echo "WORKDIR=$WORKDIR"

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

Prepare working values:

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

### Step 3 — Publish through AGS

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
        "producer_run_id": "bringup-publish-1"
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

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -H 'Content-Type: application/json' \
  --data @"$WORKDIR/publish.json" \
  "$AGS_URL/v1/artifacts:publish" | tee "$WORKDIR/publish-response.json"
```

Extract the artifact digest:

```bash
export ARTIFACT_DIGEST="$(python3 - <<'PY' "$WORKDIR/publish-response.json"
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["artifact_digest"])
PY
)"

echo "ARTIFACT_DIGEST=$ARTIFACT_DIGEST"
```

Expected result:

- HTTP `200`
- `"published": true`

### Step 4 — Verify ES prepare

```bash
python3 - <<'PY' > "$WORKDIR/prepare.json"
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
    "mode": "async"
}

print(json.dumps(payload))
PY
```

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -H 'Content-Type: application/json' \
  --data @"$WORKDIR/prepare.json" \
  "$ES_URL/v1/executions:prepare" | tee "$WORKDIR/prepare-response.json"
```

Expected result:

- HTTP `200`
- `"success": true`

### Step 5 — Verify ES submit

This step and the lifecycle checks that follow require Nomad to be running and reachable. If Nomad is not up yet, do not continue past `:prepare`.

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

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -H 'Content-Type: application/json' \
  --data @"$WORKDIR/submit.json" \
  "$ES_URL/v1/executions:submit" | tee "$WORKDIR/submit-response.json"
```

Extract the runtime identifiers:

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
```

Expected result:

- HTTP `202`
- `"submitted": true`
- non-empty `run_id`, `nomad_job_id`, `nomad_eval_id`

### Step 6 — Verify lifecycle through ES and Nomad

Check Nomad first:

```bash
nomad job status "$NOMAD_JOB_ID"
nomad eval status "$NOMAD_EVAL_ID"
```

Check ES lifecycle status:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  "$ES_URL/v1/executions/$RUN_ID/status" | python3 -m json.tool
```

Read logs through ES:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  "$ES_URL/v1/executions/$RUN_ID/logs"
```

If logs are not ready yet, ES may return `409`. Wait for the allocation to start and retry.

Wait for completion and inspect the allocation directly if needed:

```bash
export ALLOC_ID="$(nomad job allocs -json "$NOMAD_JOB_ID" | python3 - <<'PY'
import json, sys
allocs = json.load(sys.stdin)
if not allocs:
    raise SystemExit("no allocations found")
print(allocs[0]["ID"])
PY
)"

nomad alloc status "$ALLOC_ID"
nomad alloc logs -stdout "$ALLOC_ID"
```

Optional cancel check if the workload is still running:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" \
  --cert "$DEPLOY_CERT" \
  --key "$DEPLOY_KEY" \
  -X POST \
  "$ES_URL/v1/executions/$RUN_ID:cancel" | python3 -m json.tool
```

Verify observability at the same time by inspecting the ACS, ARS, and ES service terminals. Boundary-event logs should appear as JSON lines and include:

- `trace_id`
- `request_id`
- `service`
- `route`
- `status`
- `duration`

For outbound dependency events they should also include:

- `dependency`

Expected observability behavior in this slice:

- the same `trace_id` appears across internal service hops for one request chain
- each service hop emits its own `request_id`
- outbound dependency calls emit a fresh `request_id` rather than reusing the inbound one

## 5. Expected Outcome

The bounded system is up and healthy when all of the following are true:

- every service health endpoint returns `"ready": true`
- AGS publish succeeds
- ES prepare succeeds
- ES submit succeeds
- Nomad creates the job and allocation
- ES status and logs return execution data
- container logs include:
  - `START-BANNER`
  - `HEARTBEAT:*`
  - final JSON success line

## 6. Boundaries

This runbook intentionally does not add:

- orchestration services
- implicit startup logic
- background coordination
- hidden dependencies

If bring-up requires new runtime behavior, update `PLANS.md` and the authoritative docs before changing code.
