# Control Plane Static Script API Path

This directory contains the first repo-owned non-operator integration path for:

- `spiffe://execution.internal/service/control-plane`

It is intentionally narrow. It proves that a Control Plane caller can drive the current HTTPS+mTLS API surface directly for:

- `POST /v1/artifacts:publish`
- `POST /v1/executions:submit`
- `GET /v1/executions/{run_id}/status`
- `GET /v1/executions/{run_id}/logs`
- optional `GET /v1/executions/{run_id}/result`
- optional `POST /v1/executions/{run_id}:cancel`

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
- `CANCEL_AFTER_SUBMIT=1`
- `FETCH_LOGS=0`
- `GENERATE_RESULT_PAYLOAD=1`
- `FETCH_RESULT=1`

By default the example proves publish, submit, status, and logs over the real HTTPS+mTLS API.
The supported-local guest path is the grounded positive verification path for that logs step on this Mac.
When the example waits for terminal status without `CANCEL_AFTER_SUBMIT=1`, it now exits nonzero if ES reports a terminal nonzero workload exit.

Set `GENERATE_RESULT_PAYLOAD=1 FETCH_RESULT=1 WAIT_FOR_TERMINAL=1` to generate a compact static-script payload that writes files under `/execution/run/result` and then fetches the retained `GET /v1/executions/{run_id}/result` bundle into the example work directory. That mode proves the bounded terminal-result contract without requiring Control Plane to scrape stdout or know host staging paths.

Set `CANCEL_AFTER_SUBMIT=1` only when `PAYLOAD_PATH` points to a long-running static-script payload. In that bounded cancel mode, also set `FETCH_LOGS=0`; the same direct API example then proves publish, submit, status, and `POST /v1/executions/{run_id}:cancel`, then polls bounded ES status until terminal if `WAIT_FOR_TERMINAL=1`.

The focused AGS/ES app integration harness at [es/app/control_plane_integration_path_test.go](../../es/app/control_plane_integration_path_test.go) remains the repo-owned verification layer for the same direct API path, including retained result fetch and disallowed-caller failures. On this Mac, positive logs activation is still grounded through the supported-local guest path above.

For the supported-local guest path, `SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE=1 scripts/72_supported_local_setup.sh setup` now generates the matching Control Plane client cert/key and proof-scoped AGS/ES allowlist entries without changing the default operator-only setup.

## Config Templates

If you want the repo-owned template pair for this path, use:

- [.examples/config/ags.operator_and_control_plane.json](../config/ags.operator_and_control_plane.json)
- [.examples/config/es.operator_and_control_plane.json](../config/es.operator_and_control_plane.json)

The default templates remain operator-only:

- [.examples/config/ags.json](../config/ags.json)
- [.examples/config/es.json](../config/es.json)

## Run

From the repository root:

```bash
".examples/control_plane_static_script/run.sh"
```

The script writes a work directory under `.out/`, records the direct API request/response payloads there, and prints the final `workdir=` path so it is easy to inspect what went over the wire. When `FETCH_RESULT=1` succeeds it writes `result.tar.gz`; when `CANCEL_AFTER_SUBMIT=1` is enabled it also writes `cancel-response.json`.
