# Runbook: Submit Runtime Identity Reference Workload (v1)

- Version: `v1`
- Last Updated: `2026-04-02`

## 1. Objective

Submit the reference runtime-identity workload end to end through the existing governed execution path:

`AGS publish -> ARS store/register -> ES submit -> Nomad/Docker run -> workload obtains identity from mounted endpoint -> workload authenticates to Vault -> workload reads secret -> observable logs + exit code`

This runbook does not change platform behavior. It uses the existing runtime identity contract:

- ES passes non-secret Vault auth metadata only
- ES exposes one mounted workload identity endpoint only
- workload obtains identity externally
- workload authenticates to Vault locally

For a minimal local validation path using Vault dev mode plus a static-JWT Unix-socket adapter, see:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_runtime_identity_local_validation.md`

## 2. Reference Workload

The reference artifact lives at:

- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/entrypoint`

Package it with:

```bash
/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/package.sh
```

The packaged artifact is:

- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz`

## 3. Environment Assumptions

All prerequisites from `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_static_script.md` still apply, plus:

- ES base image must include `python3`
- the publish request must set `constraints.network_access = true`
- the mounted workload identity endpoint must implement the reference JSON-line protocol documented in:
  - `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/README.md`
- `VAULT_ADDR` must resolve to a Vault-compatible HTTP endpoint reachable from the workload container
- the configured Vault endpoint must accept:
  - `MONOLITH_WORKLOAD_VAULT_AUTH_MOUNT`
  - `MONOLITH_WORKLOAD_VAULT_AUTH_ROLE`
  - `MONOLITH_WORKLOAD_VAULT_JWT_AUDIENCE`

Optional local helpers are provided:

- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py`
- `/Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_vault.py`

These helpers are reference tooling only. They are not platform components.

## 4. Optional Local Reference Helpers

Start the reference identity endpoint on the ES host:

```bash
python3 /Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_identity_endpoint.py \
  --socket /abs/path/to/endpoint.sock \
  --audience vault \
  --jwt reference-runtime-identity-jwt
```

Start the reference Vault-compatible endpoint:

```bash
python3 /Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/helpers/mock_vault.py \
  --bind 0.0.0.0 \
  --port 18200 \
  --auth-mount jwt \
  --role service_execution \
  --jwt reference-runtime-identity-jwt \
  --secret-value runtime-identity-ok
```

Ensure the workload-zone Vault config reachable by ES points `VAULT_ADDR` at a Vault-compatible address that the workload container can reach in your environment.

## 5. Publish

Create a working directory:

```bash
WORKDIR="$(mktemp -d)"
echo "Using WORKDIR=$WORKDIR"
```

Prepare base64 payload and labeled digests:

```bash
export ARTIFACT_PAYLOAD_B64="$(python3 - <<'PY' /Users/ds/Repositories/Execution-Platform/.examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz
import base64, pathlib, sys
print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode("ascii"))
PY
)"

export INTENT_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export DERIVATION_SPEC_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
export BUILD_LOG_DIGEST="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
export OUTPUT_ID="runtime-identity-reference"
export POLICY_VERSION="2026-04-02"
export WORKLOAD_IDENTITY_ID="spiffe://monolith.internal/service/execution"
```

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
            "environment_variables": ["REFERENCE_SECRET_PATH", "REFERENCE_VAULT_INSECURE_SKIP_VERIFY"],
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
        "producer_run_id": "runtime-identity-reference-1"
    },
    "derivation_attestation": {
        "constraints": {
            "allowed_toolchains": [],
            "forbidden_toolchains": [],
            "os": "linux",
            "arch": "amd64",
            "network_access": True,
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
        "description": "Runtime identity reference workload",
        "workload_identity_id": os.environ["WORKLOAD_IDENTITY_ID"]
    }
}

print(json.dumps(payload))
PY
```

Publish and extract the artifact digest exactly as in:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_static_script.md`

## 6. Submit

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
            "REFERENCE_SECRET_PATH": "secret/data/runtime-identity-reference"
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

Submit and extract `RUN_ID`, `NOMAD_JOB_ID`, and `NOMAD_EVAL_ID` exactly as in:

- `/Users/ds/Repositories/Execution-Platform/.runbooks/execution/v1_submit_static_script.md`

## 7. Verify Success

Inspect allocation logs:

```bash
nomad alloc logs -stdout "$ALLOC_ID"
```

Success requires all of:

- workload starts
- identity JWT retrieval succeeds
- Vault auth succeeds
- secret read succeeds
- task exit code is `0`

Expected log markers:

```text
RUNTIME-IDENTITY-REFERENCE-START
IDENTITY-JWT-RECEIVED
VAULT-AUTH-SUCCESS
SECRET-READ-SUCCESS:runtime-identity-ok
{"artifact_digest":"sha256:...","secret_message":"runtime-identity-ok","status":"ok"}
```
