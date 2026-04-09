# Control Plane Static Script API Path

This directory contains the first repo-owned non-operator integration path for:

- `spiffe://execution.internal/service/control-plane`

It is intentionally narrow. It proves that a Control Plane caller can drive the current HTTPS+mTLS API surface directly for:

- `POST /v1/artifacts:publish`
- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`

It does **not** use:

- `scripts/20_publish.sh`
- `scripts/30_prepare.sh`
- `scripts/40_submit.sh`
- `scripts/50_lifecycle.sh`
- `scripts/60_execute_loop.sh`

Those remain operator/proof helpers, not the product interface.

## Required Environment

- `AGS_URL`
- `ES_URL`
- `CA_CERT`
- `CONTROL_PLANE_CERT`
- `CONTROL_PLANE_KEY`

Optional:

- `AGS_RESOLVE`
- `ES_RESOLVE`
- `WORKDIR_BASE`
- `PAYLOAD_PATH`
- `BUILD_LOG_PATH`
- `TIMEOUT_SECONDS`
- `POLL_INTERVAL_SECONDS`
- `WAIT_FOR_TERMINAL=1`

## Config Templates

If you want the repo-owned template pair for this path, use:

- [/Users/ds/Repositories/Execution Substrate/.examples/config/ags.operator_and_control_plane.json](/Users/ds/Repositories/Execution%20Substrate/.examples/config/ags.operator_and_control_plane.json)
- [/Users/ds/Repositories/Execution Substrate/.examples/config/es.operator_and_control_plane.json](/Users/ds/Repositories/Execution%20Substrate/.examples/config/es.operator_and_control_plane.json)

The default templates remain operator-only:

- [/Users/ds/Repositories/Execution Substrate/.examples/config/ags.json](/Users/ds/Repositories/Execution%20Substrate/.examples/config/ags.json)
- [/Users/ds/Repositories/Execution Substrate/.examples/config/es.json](/Users/ds/Repositories/Execution%20Substrate/.examples/config/es.json)

## Run

```bash
"/Users/ds/Repositories/Execution Substrate/.examples/control_plane_static_script/run.sh"
```

The script writes a work directory under `.out/`, records the direct API request/response JSON there, and prints the final `workdir=` path so it is easy to inspect what went over the wire.
