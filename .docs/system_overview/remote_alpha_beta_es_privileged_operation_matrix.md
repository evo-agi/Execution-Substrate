# Remote Alpha To Beta ES Privileged-Operation Matrix

## 1. Purpose and status

This document is the design-only privileged-operation matrix recommended by
`.docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md`.

It inventories the current privileged or potentially privileged ES operations
that still matter after the accepted Remote Supported-Host Alpha config/TLS
ownership prep slice.

It does not authorize implementation by itself. It does not claim that ES is
already de-rooted. It does not change the accepted Alpha posture where:

- `Current invariant`: AGS, ARS, and EGS are already de-rooted.
- `Bounded slice rule`: the ES config/TLS ownership prep slice is applied and
  productized.
- `Temporary compatibility edge`: live `es.service` remains `root(default)`.
- `Temporary compatibility edge`: the current root-start runtime helper/task
  model, broad root selector scope, and Nomad task `User: "0:0"` remain
  explicit compatibility edges rather than solved architecture.

Authoritative inputs for this matrix are:

- `PLANS.md`
- `.docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md`
- `.docs/system_overview/configuration.md`
- `.docs/system_overview/remote_supported_host_alpha.md`
- `.docs/system_overview/contracts.md`
- `.docs/execution_lifecycle/design.md`
- `.docs/execution_lifecycle/implementation.md`
- current ES runtime/helper code and tests

## 2. How to read the matrix

To keep the matrix readable, some requested fields are grouped:

- `Current actor / privilege` includes the current actor or process plus the
  current privilege assumption.
- `Touchpoints` includes filesystem paths, sockets or endpoints, and external
  systems involved.
- `Root need / why` states whether the operation truly requires root today and
  why.
- `Future owner / boundary` combines the candidate future owner plus the
  proposed boundary change.
- `Risk / benefit` combines compatibility risk plus expected security benefit.
- `Evidence / rollback / track` combines required tests or evidence, rollback
  notes, and whether the row is Beta-suitable or later Option C work.

The matrix is scoped to the recommended **Option B** direction:

- de-root the long-lived ES service for Beta if the ownership model is
  explicitly re-derived and tested
- keep the current root-start runtime helper/task model explicit as a bounded
  compatibility edge initially
- defer full runtime-boundary re-derivation to later **Option C** work

## 3. Privileged-operation matrix

| Operation | Current actor / privilege | Touchpoints | Root need / why | Future owner / boundary | Risk / benefit | Evidence / rollback / track |
| --- | --- | --- | --- | --- | --- | --- |
| ES startup config/TLS read plus artifact-registry and governance client TLS access | Current actor: long-lived `es.service` process.<br>Current privilege: `Temporary compatibility edge`; live service is still `root(default)` even though the prep slice staged dedicated `root:es` readable config/TLS material for a later step. | Paths: `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls/es-server-cert.pem`, `/etc/execution-substrate/es-tls/es-server-key.pem`, `/etc/execution-substrate/es-tls/server-client-ca.pem`, `/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`, `/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`, `/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`, `/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`, `/etc/execution-substrate/es-tls/execution-governance-client-key.pem`, `/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`.<br>Sockets/endpoints: ES HTTPS listener, ARS base URL, EGS base URL.<br>External systems: ARS, EGS. | Truly requires root today: no for steady-state read access.<br>Why root exists now: legacy service posture and current host packaging, not a semantic ES requirement. | Candidate future owner: non-root ES service.<br>Proposed boundary: remain in ES; eliminate root by making config/TLS readability sufficient for the chosen service account and proving startup works without root. | Compatibility risk: medium because startup can fail if owner or mode assumptions drift.<br>Security benefit: high because the long-lived network-facing ES service stops running as root while holding external mTLS client keys. | Required evidence: startup as the target non-root service account, successful ARS readiness and EGS trust-model initialization, stable `/health`, stable `GET /v1/executions:contract`, and file owner or mode assertions for the dedicated ES-readable config/TLS paths.<br>Rollback: restore pre-change service user or group plus the accepted config/TLS ownership model from the prep backup if needed.<br>Track: must move before any Beta claim that the long-lived ES service is non-root. |
| ES config rewrite and ownership maintenance | Current actor: operator-staged helper flow, not the ES hot path.<br>Current privilege: root-run helper because it rewrites host-local config and TLS ownership under `/etc` and records bounded host-local evidence. | Paths: `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls/`, `/var/tmp/execution-substrate-remote-alpha/`, `/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract` for post-apply evidence.<br>External systems: operator maintenance flow, Infrastructure Manager evidence consumption. | Truly requires root today: yes.<br>Why: filesystem ownership changes under `/etc`, narrow prep-account creation or validation, bounded backup creation, and host-local service management assumptions. This is not a reason to keep the long-lived ES process root. | Candidate future owner: operator maintenance helper or provisioning/bootstrap flow.<br>Proposed boundary: move to provisioning/bootstrap or keep behind an explicit root-only maintenance helper; do not move this responsibility into the long-lived ES API process. | Compatibility risk: low if it stays operator-only; medium if its scope is widened silently.<br>Security benefit: medium because it removes one common justification for treating ES runtime privilege and maintenance privilege as the same thing. | Required evidence: existing check-only and apply summary contracts, non-mutating enforcement, rewrite-scope validation, and IM evidence compatibility must remain fail-closed.<br>Rollback: use the timestamped backup plus rollback notes already required by the prep slice.<br>Track: Beta-suitable as an operator-only compatibility edge. |
| ES service restart and host-local maintenance | Current actor: operator or systemd-controlled host maintenance.<br>Current privilege: current host restart path assumes root-managed system service control. | Paths: system service state plus current ES config and TLS paths.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract` after restart.<br>External systems: systemd or host service manager, operator maintenance flow. | Truly requires root today: yes under the accepted host service-management model.<br>Why: service start, stop, restart, and unit-level ownership remain host-admin operations. | Candidate future owner: operator maintenance helper or a root-only host supervisor outside the ES hot path.<br>Proposed boundary: move behind root-only maintenance; do not keep long-lived ES root just because restart is privileged. | Compatibility risk: medium because migration and rollback need clear service-unit ownership rules.<br>Security benefit: medium because service-management privilege stays separated from the ES request path. | Required evidence: documented service user model, post-restart health and contract probes, and explicit rollback notes that restore the last accepted service posture.<br>Rollback: restore prior `User=` and `Group=` settings plus the prior config/TLS posture, then restart once.<br>Track: Beta-suitable as operator-only maintenance. |
| Submit-time staging directory creation and payload or mount staging | Current actor: ES submit path in `es/admission/submit.go`, `executionpackage.go`, and `mounts.go`.<br>Current privilege: current root-run ES service creates and populates run-scoped host staging today. | Paths: `execution.staging_root_dir/<run_id>/payload`, `execution.staging_root_dir/<run_id>/run`, `execution.staging_root_dir/<run_id>/run/platform`, `execution.staging_root_dir/<run_id>/run/result`, `execution.staging_root_dir/<run_id>/mounts/*`.<br>Sockets/endpoints: none directly.<br>External systems: ARS payload and mount reads, staging filesystem, Nomad handoff. | Truly requires root today: no in principle.<br>Why root exists now: the current service posture owns the staging root implicitly. The operation itself is file creation and write access that can move to a non-root service if staging ownership is re-derived. | Candidate future owner: non-root ES service.<br>Proposed boundary: remain in ES; eliminate root by re-deriving writable staging-root ownership, retention, and cleanup rules for the target service account. | Compatibility risk: medium because submit can fail or leave partial host state if staging ownership is wrong.<br>Security benefit: high because one of the largest writable host-side surfaces leaves the root-run service. | Required evidence: non-root submit integration, mount-validation coverage, failed-submit cleanup behavior, and explicit assertions about staging-root owner or mode for the service account.<br>Rollback: restore prior staging-root ownership and service user if submit or staging regressions appear.<br>Track: must move or be live-measured before any Beta claim that the long-lived ES service is non-root. |
| Result-directory preparation and final readability inside the task | Current actor: `es-runtime-support supervisor` inside the Nomad task.<br>Current privilege: root-start per-run supervisor recreates the result directory, chowns it to the workload UID:GID, and finalizes result-tree readability after workload exit. | Paths: `/execution/run/result`, backed by `execution.staging_root_dir/<run_id>/run/result`.<br>Sockets/endpoints: none directly.<br>External systems: runtime helper, staging filesystem, workload process. | Truly requires root today: yes under the current runtime model.<br>Why: the supervisor starts as `0:0`, clears and recreates the result directory, changes ownership to `10000:10000`, and normalizes the result tree after exit before ES packages retained results. | Candidate future owner: root-only supervisor for Beta, or later the Nomad/runtime layer if the runtime model is re-derived.<br>Proposed boundary: keep behind the runtime companion for Beta; do not treat it as long-lived ES service work. | Compatibility risk: high because changing this can break workload writes or retained-result readability.<br>Security benefit: medium because a cleaner split reduces accidental privilege bleed into the long-lived ES service. | Required evidence: runtime-helper tests showing the result directory is workload-writable, final result-tree readability is sufficient for ES retention, and workload privilege drop remains intact with no supplemental groups or privilege escalation.<br>Rollback: retain the current root-start supervisor behavior.<br>Track: may remain a bounded compatibility edge for Beta; cleaner ownership redesign is later Option C work. |
| Retained-result bundle packaging and retained-result reads | Current actor: ES lifecycle and result paths in `lifecycle.go` and `results.go`.<br>Current privilege: current root-run ES service packages retained bundles and reads them back from the ES-owned results root. | Paths: source `execution.staging_root_dir/<run_id>/run/result`, retained bundle `execution.results_root_dir/<run_id>/result.tar.gz`.<br>Sockets/endpoints: `GET /v1/executions/{run_id}/result`.<br>External systems: results filesystem, staging filesystem, Nomad lifecycle observation, downstream callers such as Control Plane. | Truly requires root today: no for bundle packaging and reads if the results root and staged result tree are readable by the ES service account.<br>Why root still matters now: current results-root ownership is implicit in the root-run service, and the final readability contract from the root-start supervisor must be measured explicitly for a non-root ES service. | Candidate future owner: non-root ES service.<br>Proposed boundary: remain in ES; eliminate root by re-deriving results-root ownership and proving result-tree readability for retention. | Compatibility risk: medium because retained-result behavior is a current public ES contract and must not regress.<br>Security benefit: high because post-run host result packaging leaves the root-run service. | Required evidence: non-root retained-result integration, repeat result fetch idempotence, `404 result_not_found` behavior, retained bundle readability after successful staging cleanup, and negative tests for unreadable bundles.<br>Rollback: restore prior results-root ownership and service user if retained-result packaging breaks.<br>Track: must move or be live-measured before any Beta claim that the long-lived ES service is non-root. |
| Successful staging cleanup | Current actor: ES `status` and `logs` paths after terminal success.<br>Current privilege: current root-run ES service removes `execution.staging_root_dir/<run_id>` best-effort after successful terminal observation and retained-result handling. | Paths: `execution.staging_root_dir/<run_id>`.<br>Sockets/endpoints: none directly.<br>External systems: staging filesystem, Nomad lifecycle projection, retained-result path. | Truly requires root today: no if the staging tree belongs to the ES service account.<br>Why root exists now: current staging ownership is implicit in the root-run service posture. | Candidate future owner: non-root ES service.<br>Proposed boundary: remain in ES; eliminate root by re-deriving stage-root ownership and cleanup semantics for the target service account. | Compatibility risk: medium because premature cleanup can break debugging or result retention, while failed cleanup can leak host state.<br>Security benefit: medium because it reduces privileged host-write scope in the long-lived ES service. | Required evidence: tests proving cleanup occurs only after terminal success, non-success outcomes still retain staging for debugging, and retained-result bundles survive cleanup because they live outside staging.<br>Rollback: restore prior staging-root ownership and the last accepted cleanup semantics.<br>Track: must move or be live-measured before any Beta claim that the long-lived ES service is non-root. |
| Runtime helper supervisor bootstrap and runtime-filesystem preparation | Current actor: `es-runtime-support supervisor` launched by the Nomad task.<br>Current privilege: current implementation requires the supervisor to start as `0:0`. | Paths: `/run/es-runtime-identity/<run_id>`, `/run/es-runtime-identity/<run_id>/internal`, `/execution/run/platform`, `/execution/run/work`, staged payload archive, staged runtime-support binary.<br>Sockets/endpoints: helper-private SPIRE alias path and the workload-visible endpoint path are prepared here.<br>External systems: Nomad task runtime, runtime helper, SPIRE, staging filesystem. | Truly requires root today: yes under the current runtime model.<br>Why: the supervisor changes ownership and mode on runtime-identity directories, materializes the helper-private raw SPIRE alias, resets runtime work directories, prepares the result path, and then execs the workload behind a fixed non-root boundary. | Candidate future owner: root-only supervisor for Beta.<br>Proposed boundary: move root-only runtime bootstrap behind an explicit per-run companion rather than treating it as evidence that the long-lived ES service must stay root. | Compatibility risk: high because helper bootstrap failure currently fails the task before workload start.<br>Security benefit: medium to high because it isolates runtime-only root work from the long-lived ES request surface. | Required evidence: helper-readiness ordering tests, runtime-filesystem owner or mode assertions, helper-death task-fatal behavior, and workload-boundary logs proving the non-root execution boundary still holds.<br>Rollback: retain the current root-start supervisor path and helper binary behavior.<br>Track: may remain a bounded compatibility edge for Beta; fuller redesign is later Option C work. |
| Runtime identity endpoint serving and helper steady-state privilege drop | Current actor: `es-runtime-support helper`.<br>Current privilege: helper must start as `0:0`, then it binds the workload-visible endpoint, changes ownership to the workload UID:GID, and drops steady-state capabilities. | Paths: `/run/es-runtime-identity/<run_id>/endpoint`, `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`.<br>Sockets/endpoints: workload-visible `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, helper-private raw SPIRE alias.<br>External systems: SPIRE Workload API, Vault-targeting workload runtime, runtime helper. | Truly requires root today: startup yes, steady-state intentionally no.<br>Why: current startup does socket ownership handoff and filesystem-boundary enforcement before dropping capability sets and setting `no_new_privs`. | Candidate future owner: runtime helper for Beta, or a split root-only bootstrap plus non-root steady-state helper later.<br>Proposed boundary: keep helper root-start explicit for Beta, then revisit whether the bootstrap and steady-state helper should split in Option C. | Compatibility risk: high because any mistake breaks JWT-SVID delivery and therefore workload Vault login.<br>Security benefit: medium because a cleaner split narrows the amount of code that starts with root in the runtime companion. | Required evidence: tests for helper endpoint owner or mode, dropped capability snapshots, helper readiness before workload start, helper-death task-fatal behavior, and negative tests proving the workload cannot access the raw SPIRE channel.<br>Rollback: keep the current helper startup and privilege-drop path.<br>Track: Beta compatibility edge initially; later Option C if the helper model is re-derived. |
| Nomad task launch and task user model | Current actor: ES submit path builds the Nomad job spec and submits one Docker task with `User: "0:0"`.<br>Current privilege: current task user model is root-start by design so the runtime-support binary can create the current helper and workload boundary inside the task. | Paths: job-spec metadata plus the mounted runtime paths under `/execution` and `/run/es-runtime-identity`.<br>Sockets/endpoints: Nomad `/v1/jobs`, Docker task runtime, helper endpoint paths once the task starts.<br>External systems: Nomad, Docker, runtime helper. | Truly requires root today: yes under the current helper and supervisor design.<br>Why: the runtime-support binary requires `0:0` at task start to create the helper-private runtime identity boundary and to exec the workload as fixed `10000:10000`. | Candidate future owner: Nomad/runtime layer design, not the long-lived ES service.<br>Proposed boundary: keep the current task user model as an explicit compatibility edge for Beta, then move or eliminate it only as part of a broader runtime-boundary redesign. | Compatibility risk: high because it changes task admission, helper launch, workload launch, and current runtime expectations together.<br>Security benefit: high if eventually removed because it narrows the root-start scope inside the runtime task itself. | Required evidence: job-spec assertions for the selected user model, successful helper bootstrap and workload launch under the new model, and negative tests for privilege leakage or supplemental groups.<br>Rollback: restore `User: "0:0"` in the job spec.<br>Track: later Option C work; Beta may keep it only as a documented compatibility edge. |
| SPIRE socket traversal and helper-private raw socket alias | Current actor: ES mount-spec assembly plus the runtime supervisor and helper.<br>Current privilege: ES bind-mounts the directory containing `execution.spire_workload_api_socket_path` into the helper-private runtime subtree, and the per-run runtime companion uses the helper-private alias there. | Paths: host source directory `dirname(execution.spire_workload_api_socket_path)` such as `/run/spire/sockets`, runtime private source dir `/run/es-runtime-identity/<run_id>/internal/source`, helper-private alias `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`.<br>Sockets/endpoints: host SPIRE Workload API socket, helper-private alias, workload-visible endpoint socket.<br>External systems: SPIRE, Nomad mount layer, runtime helper. | Truly requires root today: mixed.<br>Why: bind-mounting the containing directory is not itself the main root issue, but the current raw-socket permissions, traversal model, and helper-private boundary are coupled to the root-start runtime companion and the current host SPIRE posture. | Candidate future owner: runtime helper for Beta, later SPIRE setup or runtime layer if the boundary is redesigned.<br>Proposed boundary: keep the raw SPIRE channel helper-private for Beta; re-derive traversal only in Option C. | Compatibility risk: high because the raw SPIRE channel is the root of the current workload-identity contract.<br>Security benefit: medium to high if later narrowed because it reduces implicit privilege reach into the raw SPIRE channel. | Required evidence: tests proving the raw SPIRE socket path is not leaked into workload env, the workload cannot connect to the helper-private raw socket, and the helper can still fetch JWT-SVIDs reliably through its private alias.<br>Rollback: restore the current mount and helper-private alias model.<br>Track: Beta compatibility edge initially; later Option C if selector or helper model changes. |
| SPIRE selector and workload registration posture | Current actor: SPIRE registration and host-identity setup outside the long-lived ES request path.<br>Current privilege: current Remote Alpha proof posture still uses the broad root selector set `unix:uid:0` plus `unix:gid:0` for the workload SPIFFE identity. | Paths: no ES-owned filesystem path is the authority here.<br>Sockets/endpoints: SPIRE server registration surface and SPIRE agent workload API indirectly depend on this identity model.<br>External systems: SPIRE. | Truly requires root today: no in itself.<br>Why this is privilege-relevant anyway: the current identity model grants the helper proof through a broad root principal, so it is a structural compatibility edge even though selector registration is not a long-lived ES root operation. | Candidate future owner: SPIRE setup or provisioning phase.<br>Proposed boundary: move selector or registration redesign to provisioning/bootstrap; do not hide it inside a service-user change. | Compatibility risk: high because narrowing the selector model can break JWT-SVID fetch and Vault login if the replacement principal is not derived cleanly.<br>Security benefit: high because it is the direct path to replacing the current broad root identity scope with an explicit helper principal or other bounded model. | Required evidence: documented replacement selector model, successful helper JWT-SVID fetch under that model, and negative tests showing non-helper identities cannot claim the same registration.<br>Rollback: restore the current broad root selector posture if the new identity model fails.<br>Track: Beta may keep the current selector scope only as an explicit compatibility edge; real replacement is later Option C work. |
| Vault workload-zone runtime-config fetch and non-secret runtime handoff | Current actor: ES `Prepare` and `Submit` resolve the typed workload-zone Vault config, stage optional CA trust, and inject only non-secret runtime metadata plus `EXEC_WORKLOAD_IDENTITY_ENDPOINT`.<br>Current privilege: the current root-run service owns the staging path used for this handoff, but the handoff itself is already non-secret and bounded. | Paths: staged runtime CA material under `/execution/run/platform/workload-vault-ca.pem` and `/execution/run/platform/workload-ca-bundle.pem` when configured.<br>Sockets/endpoints: ARS runtime-config blob reads, Vault HTTPS address, workload-visible identity endpoint, workload-side JWT auth mount.<br>External systems: ARS, Vault, SPIRE, runtime helper. | Truly requires root today: no for ES fetch and handoff.<br>Why root still matters indirectly: current stage-root ownership and helper-delivered identity flow are still coupled to the root-run ES service and root-start runtime companion. | Candidate future owner: non-root ES service for fetch and staging, with SPIRE and Vault prerequisites still owned by provisioning/runtime setup.<br>Proposed boundary: remain in ES as a non-secret handoff surface; do not turn ES into a Vault or token broker. | Compatibility risk: medium because handoff facts are visible in `Prepare`, `Submit`, and `authority_handoff` and are consumed by current runtime-profile flows.<br>Security benefit: medium because it keeps a valuable runtime authority surface while removing unnecessary root dependence from the service process. | Required evidence: prepare and submit tests for typed workload-zone Vault config resolution, CA bundle staging, `authority_handoff` stability, and workload-side Vault login using the helper-delivered JWT-SVID path.<br>Rollback: restore the prior service user and writable-state ownership if handoff staging fails under the non-root service account.<br>Track: must remain functional for Beta; broader auth-model redesign is later Option C work. |
| Health and producer-contract probes | Current actor: ES HTTP server plus repo-owned operator checks.<br>Current privilege: current root-run service serves `/health` and `GET /v1/executions:contract`, while operator checks layer additional readiness probes around them. | Paths: current config and runtime-config references are read at startup, but the probe surfaces themselves are API-only.<br>Sockets/endpoints: ES `/health`, ES `GET /v1/executions:contract`, ARS health for readiness composition, operator-side readiness helpers.<br>External systems: ARS, operator tooling, Infrastructure Manager reporting. | Truly requires root today: no for serving the probes.<br>Why root still appears now: the service user is still root, not because the probe logic needs root. | Candidate future owner: non-root ES service for the API surfaces, operator tooling for host-local readiness aggregation.<br>Proposed boundary: remain in ES for service responses; keep richer readiness or maintenance checks outside the ES privilege model. | Compatibility risk: low because the endpoints are narrow and already bounded.<br>Security benefit: low to medium because it removes another read-only API surface from the root-run service. | Required evidence: stable `/health` and producer-contract responses after the service-user change, readiness integration tests that still distinguish service health, prepare-ready, and submit-ready, and no new coupling to host-only evidence collection.<br>Rollback: restore the previous service user and restart once if probe behavior regresses.<br>Track: must continue to work in Beta. |
| Cancellation and other guarded mutation paths that call Nomad | Current actor: ES `Cancel` calls Nomad to stop a submitted job.<br>Current privilege: current root-run service owns the HTTP path and Nomad client, but the mutation itself is remote scheduler control rather than host-root work. | Paths: none beyond run-id lookup and current internal Nomad locator mapping.<br>Sockets/endpoints: `POST /v1/executions/{run_id}:cancel`, Nomad stop endpoint.<br>External systems: Nomad. | Truly requires root today: no.<br>Why root still appears now: current service posture only. | Candidate future owner: non-root ES service.<br>Proposed boundary: remain in ES; do not conflate Nomad control-plane mutation with host-root privilege. | Compatibility risk: low because the public surface is narrow and already bounded by current outcome-evidence semantics.<br>Security benefit: medium because an externally reachable mutation path leaves the root-run service. | Required evidence: cancel integration tests, auth coverage, and proof that the non-root service can still reach Nomad and return the same bounded cancel receipt semantics.<br>Rollback: restore the previous service user if Nomad control fails after the change.<br>Track: must continue to work in Beta. |
| Support-bundle and readiness evidence collection when privilege-relevant | Current actor: operator tooling and Infrastructure Manager support-bundle or checkpoint collection, not the ES runtime hot path.<br>Current privilege: some host-local evidence collection may still require root to read service, config, log, or helper-maintenance facts on the remote host. | Paths: profile evidence such as `.out/remote-alpha-m75q/*`, host-local helper summaries and backups under `/var/tmp/execution-substrate-remote-alpha/*`, and any bounded config or service-posture evidence needed by support-bundle flows.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract`, AGS or ARS or EGS local health probes when collected as support evidence.<br>External systems: Infrastructure Manager, AGS, ARS, EGS, operator tooling. | Truly requires root today: sometimes for host-local evidence collection, but not as part of the long-lived ES service privilege model.<br>Why: this is operator evidence and maintenance access, not runtime execution privilege. | Candidate future owner: operator maintenance helper or Infrastructure Manager support-bundle layer.<br>Proposed boundary: move or keep all privilege-sensitive evidence collection in operator tooling; do not let it leak back into the ES service. | Compatibility risk: low because support-bundle and readiness evidence are already bounded, non-proof, non-runtime-authority surfaces.<br>Security benefit: medium because it keeps remote evidence collection separate from the network-facing ES service. | Required evidence: current support-bundle or checkpoint fixtures remain fail-closed, helper-staging evidence remains accepted, and non-claims stay explicit that support-bundle artifacts are provenance and hardening evidence only, not governed proof.<br>Rollback: revert evidence tooling independently from the ES service-user change.<br>Track: Beta-suitable as operator-only evidence work. |

## 4. Recommended Beta cut line

For the recommended **Option B** path, the Beta cut line should be:

- **Must move before a non-root long-lived ES Beta claim**:
  - long-lived ES startup config and TLS reads
  - ARS and EGS client TLS access from the long-lived ES service
  - submit-time staging directory creation and payload or mount staging
  - retained-result bundle packaging and retained-result reads
  - successful staging cleanup
  - all externally reachable ES read or mutation endpoints that are currently
    root only because `es.service` still runs as `root(default)`
- **May remain as bounded compatibility edges for Beta**:
  - root-start runtime supervisor and helper
  - runtime result-directory preparation and final readability inside the task
  - current Nomad task `User: "0:0"`
  - helper-private raw SPIRE socket traversal model
  - broad root selector scope, but only if it remains labeled explicitly as a
    compatibility edge and Beta does not claim that the full ES privilege
    boundary is solved
  - operator-only root maintenance for config rewrite, service restart, and
    support-bundle or readiness evidence collection
- **Must wait for later Option C work**:
  - re-deriving the Nomad task user model
  - replacing the root-start helper and supervisor model with a different
    runtime-boundary architecture
  - replacing the broad root selector scope with a new explicit helper
    principal or another narrowed identity model
  - re-deriving helper-private raw SPIRE traversal and any deeper
    runtime-identity ownership change as one package

## 5. Implementation preconditions for de-rooting the long-lived ES service

Before approving implementation to de-root the long-lived ES service, the repo
should require:

- the documented target ES service account and group model remains accepted
  and aligned with the chosen implementation slice
- the documented writable-state ownership model for
  `execution.staging_root_dir` and `execution.results_root_dir`
- branch-local design docs, repo-local tests, and checker-backed readiness
  evidence remain aligned with each other, while still being treated as
  readiness evidence rather than as live-host proof
- a non-mutating host readiness check proving the current staging/results
  ownership posture and any observed normalization evidence, using
  `scripts/remote_alpha_check_es_writable_state_readiness.sh`
  with explicit `--mode future-non-root-required` when the repo needs a future
  non-root readiness gate rather than Alpha-compatible evidence reporting
- explicit confirmation that the non-root ES service can still stage payloads,
  retain results, and clean successful staging without helper-only shortcuts
- an explicit statement of which root-start runtime companion behaviors remain
  bounded compatibility edges for Beta
- a documented separation between long-lived ES privilege, operator maintenance
  privilege, and per-run runtime-companion privilege
- tests proving startup, prepare, submit, status, logs, result, and cancel all
  work under the chosen non-root ES service account
- tests proving the raw SPIRE channel remains helper-private and the workload
  still runs as fixed non-root `10000:10000` with no supplemental groups or
  privilege-escalation path
- tests proving retained-result packaging, retained-result reads, and
  successful staging cleanup still work under the chosen ownership model
- a documented migration and rollback sequence that restores the last accepted
  Alpha posture without ambiguity

## 6. Current Option B Readiness Ledger

The current branch now carries mixed readiness states for Option B. The ledger
below records what is already satisfied on this branch, what is only proved
repo-locally or through the non-mutating checker, and what remains blocked or
intentionally out of scope for the current slice.

| Prerequisite | Current classification | Notes |
| --- | --- | --- |
| ES config/TLS ownership prep | `satisfied by current branch` | The accepted Alpha prep slice is documented as applied and productized while keeping live `es.service` at `root(default)`. |
| Staging/results writable-state model | `design-only` | The writable-state ownership model and normalization contract now exist as authoritative docs, but they do not by themselves prove live host ownership under `es:es`. |
| Retained-result packaging under service-user-owned state | `repo-local test-backed` | Repo-local owner-only tests cover retained-result preflight and bundle creation semantics; real live-host `es:es` readability remains unmeasured. |
| Repeat result fetch after cleanup | `repo-local test-backed` | Repo-local coverage proves repeat retained-result reads remain stable after successful cleanup. |
| Successful cleanup | `repo-local test-backed` | Repo-local cleanup-readiness coverage proves cleanup only follows retained-result handling and fails closed without partial deletion. |
| Failed/lost/canceled staging retention | `repo-local test-backed` | Repo-local normalized-run tests now cover failed, lost, and canceled retention plus invalid-marker fail-closed behavior. |
| Marker validator | `repo-local test-backed` | The shared ownership-normalization marker validator is implemented and exercised in repo-local tests. |
| Helper marker emission | `repo-local test-backed` | Runtime-helper tests cover marker emission after successful normalization and fail-closed behavior when marker write or validation fails. |
| Target UID/GID verification | `checker-backed` | Future-mode validation and preflights require expected-owner match when an `es` UID:GID is supplied, but real live-host owner discovery remains unmeasured. |
| Future-non-root-required checker mode | `checker-backed` | `scripts/remote_alpha_check_es_writable_state_readiness.sh --mode future-non-root-required` is a non-mutating gate only. |
| Real live `es:es` ownership of staging/results | `live-host unmeasured` | No current branch evidence proves a real Remote Alpha host already has staging/results paths owned, readable, and deletable as `es:es`. |
| Service `User=es` migration | `blocked` | The long-lived service-user flip is not implemented, not approved, and remains out of scope for the current slice. |
| Root-start runtime helper | `explicitly out of scope` | This remains a bounded Beta compatibility edge rather than a solved privilege-boundary redesign in the current branch. |
| Nomad task `User: "0:0"` | `explicitly out of scope` | The current task user model may remain a bounded Beta compatibility edge and is not being re-derived here. |
| Helper-private SPIRE traversal | `explicitly out of scope` | The helper-private raw SPIRE path must remain intact in the current slice; traversal redesign is later work if reopened. |
| Broad root selector scope | `explicitly out of scope` | The current selector posture remains a compatibility edge, not a solved part of the current service-user readiness slice. |
| Vault/workload-zone handoff | `satisfied by current branch` | The non-secret workload-zone Vault handoff, CA staging, and workload-side auth path are already part of the accepted bounded runtime contract and must stay unchanged by any service-user work. |
| Operator maintenance/rollback | `design-only` | Migration and rollback sequencing is documented, but no approved long-lived ES service-user rollout or live rehearsal exists yet. |

## 7. Remaining implementation blockers

The remaining blockers to implementing a non-root long-lived ES service are:

- live-host `es:es` ownership, readability, and deletability for staging and
  retained-result state remain unmeasured under a real service-user-owned
  posture
- changing `es.service` away from `root(default)` remains unimplemented and
  unapproved
- the current root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, and broad root selector scope remain bounded
  compatibility edges rather than solved privilege-boundary work
- migration and rollback sequencing is documented, but there is still no
  approved host-side rollout package for a long-lived ES service-user flip

## 8. Explicit Current Conclusion

The current conclusion for Option B readiness is:

- current Alpha remains accepted with ES `root(default)`
- the current branch has strong repo-local readiness for parts of Option B,
  especially writable-state modeling, normalization-marker validation,
  retained-result readability checks, cleanup-readiness checks, checker modes,
  and normalized-run lifecycle coverage
- ES de-root implementation is still not approved
- any later implementation slice must be gated by non-mutating check-only and
  live measurement evidence plus an explicit rollback plan before any host
  mutation or `es.service` service-user change is treated as acceptable

## 9. Explicit non-goals

Non-goals of this document are:

- implementing ES de-rooting
- changing `es.service` `User=` or `Group=`
- changing the current Nomad task user model
- changing the current root-start runtime helper or supervisor implementation
- changing the current SPIRE selector posture
- changing the current helper-private raw SPIRE traversal model
- changing Vault runtime handoff semantics
- changing ES public APIs, producer contract semantics, lifecycle semantics,
  retained-result semantics, or `authority_handoff` semantics
- running live host changes, SSH steps, ES apply, or governed proof

## 10. Approval boundary

This matrix is not approval to implement ES de-rooting.

It is a design input only. Implementation work still requires updated
authoritative docs for the chosen architecture, explicit compatibility-edge
labeling, tests, migration steps, rollback steps, and bounded evidence
requirements before any code or host change is treated as accepted.
