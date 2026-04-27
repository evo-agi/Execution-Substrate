# Remote Alpha To Beta ES Privileged-Operation Matrix

## 1. Purpose and status

This document is the design-only privileged-operation matrix recommended by
`.docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md`.

It inventories the current privileged or potentially privileged ES operations
that still matter after the accepted Remote Supported-Host Alpha config/TLS
ownership prep slice.

This matrix does not authorize additional live host changes by itself. It does
not claim that the full ES/runtime privilege boundary is solved. It describes
the accepted Alpha
posture where:

- `Current invariant`: AGS, ARS, and EGS are already de-rooted.
- `Bounded slice rule`: the ES config/TLS ownership prep slice is applied and
  productized.
- `Bounded slice rule`: the ES stable writable-state ownership slice is applied
  and future writable-state readiness passed.
- `Bounded slice rule`: the long-lived `es.service` now runs as `User=es`,
  `Group=es`, `UMask=0027`, with post-apply `/health`,
  `GET /v1/executions:contract`, and the current lowest-cost existing happy
  path passing.
- `Temporary compatibility edge`: the current root-start runtime helper/task
  model, helper-private SPIRE traversal, broad root selector scope, and Nomad
  task `User: "0:0"` remain explicit compatibility edges rather than solved
  architecture.

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

- preserve the completed long-lived `es.service` service-user migration as the
  accepted bounded slice, with that completed migration remaining limited to
  `es.service` only
- keep the current root-start runtime helper/task model explicit as a bounded
  compatibility edge initially
- defer full runtime-boundary re-derivation to later **Option C** work

## 3. Privileged-operation matrix

| Operation | Current actor / privilege | Touchpoints | Root need / why | Future owner / boundary | Risk / benefit | Evidence / rollback / track |
| --- | --- | --- | --- | --- | --- | --- |
| ES startup config/TLS read plus artifact-registry and governance client TLS access | Current actor: long-lived `es.service` process.<br>Current privilege: `Current invariant`; the live service now runs as `User=es`, `Group=es`, consuming the applied dedicated `root:es` readable config/TLS material. | Paths: `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls/es-server-cert.pem`, `/etc/execution-substrate/es-tls/es-server-key.pem`, `/etc/execution-substrate/es-tls/server-client-ca.pem`, `/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`, `/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`, `/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`, `/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`, `/etc/execution-substrate/es-tls/execution-governance-client-key.pem`, `/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`.<br>Sockets/endpoints: ES HTTPS listener, ARS base URL, EGS base URL.<br>External systems: ARS, EGS. | Truly requires root today: no for steady-state read access.<br>Why root mattered historically: legacy service posture and host packaging before the landed service-user slice, not a semantic ES requirement. | Current/future owner: non-root ES service.<br>Proposed boundary: preserve this as the accepted long-lived ES boundary and do not reintroduce root by inertia. | Compatibility risk: medium because startup can fail if owner or mode assumptions drift.<br>Security benefit: high because the long-lived network-facing ES service no longer runs as root while holding external mTLS client keys. | Required evidence: startup as the target non-root service account, successful ARS readiness and EGS trust-model initialization, stable `/health`, stable `GET /v1/executions:contract`, and file owner or mode assertions for the dedicated ES-readable config/TLS paths.<br>Rollback: restore pre-change service user or group plus the accepted config/TLS ownership model from the prep backup if needed.<br>Track: landed for the current live long-lived ES service-user slice; keep as a current invariant unless a later redesign changes it explicitly. |
| ES config rewrite and ownership maintenance | Current actor: operator-staged helper flow, not the ES hot path.<br>Current privilege: root-run helper because it rewrites host-local config and TLS ownership under `/etc` and records bounded host-local evidence. | Paths: `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls/`, `/var/tmp/execution-substrate-remote-alpha/`, `/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract` for post-apply evidence.<br>External systems: operator maintenance flow, Infrastructure Manager evidence consumption. | Truly requires root today: yes.<br>Why: filesystem ownership changes under `/etc`, narrow prep-account creation or validation, bounded backup creation, and host-local service management assumptions. This is not a reason to keep the long-lived ES process root. | Candidate future owner: operator maintenance helper or provisioning/bootstrap flow.<br>Proposed boundary: move to provisioning/bootstrap or keep behind an explicit root-only maintenance helper; do not move this responsibility into the long-lived ES API process. | Compatibility risk: low if it stays operator-only; medium if its scope is widened silently.<br>Security benefit: medium because it removes one common justification for treating ES runtime privilege and maintenance privilege as the same thing. | Required evidence: existing check-only and apply summary contracts, non-mutating enforcement, rewrite-scope validation, and IM evidence compatibility must remain fail-closed.<br>Rollback: use the timestamped backup plus rollback notes already required by the prep slice.<br>Track: Beta-suitable as an operator-only compatibility edge. |
| ES service restart and host-local maintenance | Current actor: operator or systemd-controlled host maintenance.<br>Current privilege: current host restart path assumes root-managed system service control. | Paths: system service state plus current ES config and TLS paths.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract` after restart.<br>External systems: systemd or host service manager, operator maintenance flow. | Truly requires root today: yes under the accepted host service-management model.<br>Why: service start, stop, restart, and unit-level ownership remain host-admin operations. | Candidate future owner: operator maintenance helper or a root-only host supervisor outside the ES hot path.<br>Proposed boundary: move behind root-only maintenance; do not keep long-lived ES root just because restart is privileged. | Compatibility risk: medium because migration and rollback need clear service-unit ownership rules.<br>Security benefit: medium because service-management privilege stays separated from the ES request path. | Required evidence: documented service user model, post-restart health and contract probes, and explicit rollback notes that restore the last accepted service posture.<br>Rollback: restore prior `User=` and `Group=` settings plus the prior config/TLS posture, then restart once.<br>Track: Beta-suitable as operator-only maintenance. |
| Submit-time staging directory creation and payload or mount staging | Current actor: ES submit path in `es/admission/submit.go`, `executionpackage.go`, and `mounts.go`.<br>Current privilege: the current non-root ES service creates and populates run-scoped host staging under the documented `es:es` ownership model. | Paths: `execution.staging_root_dir/<run_id>/payload`, `execution.staging_root_dir/<run_id>/run`, `execution.staging_root_dir/<run_id>/run/platform`, `execution.staging_root_dir/<run_id>/run/result`, `execution.staging_root_dir/<run_id>/mounts/*`.<br>Sockets/endpoints: none directly.<br>External systems: ARS payload and mount reads, staging filesystem, Nomad handoff. | Truly requires root today: no in principle.<br>Why root mattered historically: the old service posture owned the staging root implicitly. The operation itself is file creation and write access that now lives under the non-root service account. | Current/future owner: non-root ES service.<br>Proposed boundary: preserve the explicit writable staging-root ownership, retention, and cleanup rules for the target service account, including the run-scoped `<staging_root>/<run_id>` directory itself rather than only its child descendants. | Compatibility risk: medium because submit can fail or leave partial host state if staging ownership drifts.<br>Security benefit: high because one of the largest writable host-side surfaces no longer belongs to a root-run service. | Required evidence: non-root submit integration, mount-validation coverage, failed-submit cleanup behavior, explicit assertions about the run-scoped stage-root owner or mode for the service account, and bounded legacy-artifact quarantine coverage for stale incompatible run roots left behind by earlier root-run submissions.<br>Rollback: restore prior staging-root ownership and service user if submit or staging regressions appear.<br>Track: landed for the current live long-lived ES service-user slice; preserve as current behavior. |
| Result-directory preparation and final readability inside the task | Current actor: `es-runtime-support supervisor` inside the Nomad task.<br>Current privilege: root-start per-run supervisor recreates the result directory, chowns it to the workload UID:GID, and finalizes result-tree readability after workload exit. | Paths: `/execution/run/result`, backed by `execution.staging_root_dir/<run_id>/run/result`.<br>Sockets/endpoints: none directly.<br>External systems: runtime helper, staging filesystem, workload process. | Truly requires root today: yes under the current runtime model.<br>Why: the supervisor starts as `0:0`, clears and recreates the result directory, changes ownership to `10000:10000`, and normalizes the result tree after exit before ES packages retained results. | Candidate future owner: root-only supervisor for Beta, or later the Nomad/runtime layer if the runtime model is re-derived.<br>Proposed boundary: keep behind the runtime companion for Beta; do not treat it as long-lived ES service work. | Compatibility risk: high because changing this can break workload writes or retained-result readability.<br>Security benefit: medium because a cleaner split reduces accidental privilege bleed into the long-lived ES service. | Required evidence: runtime-helper tests showing the result directory is workload-writable, final result-tree readability is sufficient for ES retention, and workload privilege drop remains intact with no supplemental groups or privilege escalation.<br>Rollback: retain the current root-start supervisor behavior.<br>Track: may remain a bounded compatibility edge for Beta; cleaner ownership redesign is later Option C work. |
| Retained-result bundle packaging and retained-result reads | Current actor: ES lifecycle and result paths in `lifecycle.go` and `results.go`.<br>Current privilege: the current non-root ES service packages retained bundles and reads them back from the ES-owned results root. | Paths: source `execution.staging_root_dir/<run_id>/run/result`, retained bundle `execution.results_root_dir/<run_id>/result.tar.gz`, preserved normalization evidence `execution.results_root_dir/<run_id>/ownership-normalization.json`.<br>Sockets/endpoints: `GET /v1/executions/{run_id}/result`.<br>External systems: results filesystem, staging filesystem, Nomad lifecycle observation, downstream callers such as Control Plane. | Truly requires root today: no for bundle packaging and reads if the results root and staged result tree are readable by the ES service account.<br>Why root still matters indirectly: final readability still depends on the root-start supervisor contract, and successful cleanup would otherwise erase the only completed-run normalization evidence if ES did not preserve it outside staging. | Current/future owner: non-root ES service.<br>Proposed boundary: preserve the explicit results-root ownership, result-tree readability contract, and preserved normalization evidence outside staging. | Compatibility risk: medium because retained-result behavior is a current public ES contract and must not regress.<br>Security benefit: high because post-run host result packaging no longer belongs to a root-run service. | Required evidence: non-root retained-result integration, repeat result fetch idempotence, `404 result_not_found` behavior, retained bundle readability after successful staging cleanup, preserved normalization evidence after successful cleanup, negative tests for unreadable bundles or invalid preserved markers, and bounded operator reconciliation coverage showing that legacy retained run directories without preserved evidence are quarantined rather than silently rewritten or treated as proof.<br>Rollback: restore prior results-root ownership and service user if retained-result packaging breaks.<br>Track: landed for the current live long-lived ES service-user slice; preserve as current behavior. |
| Successful staging cleanup | Current actor: ES `status` and `logs` paths after terminal success.<br>Current privilege: the current non-root ES service removes `execution.staging_root_dir/<run_id>` only after successful terminal observation, retained-result handling, and cleanup-readiness preflight. | Paths: `execution.staging_root_dir/<run_id>`.<br>Sockets/endpoints: none directly.<br>External systems: staging filesystem, Nomad lifecycle projection, retained-result path. | Truly requires root today: no if the staging tree belongs to the ES service account.<br>Why root mattered historically: stage-root ownership used to be implicit in the root-run service posture. | Current/future owner: non-root ES service.<br>Proposed boundary: preserve the explicit stage-root ownership and cleanup semantics for the target service account. | Compatibility risk: medium because premature cleanup can break debugging or result retention, while failed cleanup can leak host state.<br>Security benefit: medium because it reduces privileged host-write scope in the long-lived ES service. | Required evidence: tests proving cleanup occurs only after terminal success, non-success outcomes still retain staging for debugging, and retained-result bundles survive cleanup because they live outside staging.<br>Rollback: restore prior staging-root ownership and the last accepted cleanup semantics.<br>Track: landed for the current live long-lived ES service-user slice; preserve as current behavior. |
| Runtime helper supervisor bootstrap and runtime-filesystem preparation | Current actor: `es-runtime-support supervisor` launched by the Nomad task.<br>Current privilege: current implementation requires the supervisor to start as `0:0`. | Paths: `/run/es-runtime-identity/<run_id>`, `/run/es-runtime-identity/<run_id>/internal`, `/execution/run/platform`, `/execution/run/work`, staged payload archive, staged runtime-support binary.<br>Sockets/endpoints: helper-private SPIRE alias path and the workload-visible endpoint path are prepared here.<br>External systems: Nomad task runtime, runtime helper, SPIRE, staging filesystem. | Truly requires root today: yes under the current runtime model.<br>Why: the supervisor changes ownership and mode on runtime-identity directories, materializes the helper-private raw SPIRE alias, resets runtime work directories, prepares the result path, and then execs the workload behind a fixed non-root boundary. | Candidate future owner: root-only supervisor for Beta.<br>Proposed boundary: move root-only runtime bootstrap behind an explicit per-run companion rather than treating it as evidence that the long-lived ES service must stay root. | Compatibility risk: high because helper bootstrap failure currently fails the task before workload start.<br>Security benefit: medium to high because it isolates runtime-only root work from the long-lived ES request surface. | Required evidence: helper-readiness ordering tests, runtime-filesystem owner or mode assertions, helper-death task-fatal behavior, and workload-boundary logs proving the non-root execution boundary still holds.<br>Rollback: retain the current root-start supervisor path and helper binary behavior.<br>Track: may remain a bounded compatibility edge for Beta; fuller redesign is later Option C work. |
| Runtime identity endpoint serving and helper steady-state privilege drop | Current actor: `es-runtime-support helper`.<br>Current privilege: helper must start as `0:0`, then it binds the workload-visible endpoint, changes ownership to the workload UID:GID, and drops steady-state capabilities. | Paths: `/run/es-runtime-identity/<run_id>/endpoint`, `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`.<br>Sockets/endpoints: workload-visible `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, helper-private raw SPIRE alias.<br>External systems: SPIRE Workload API, Vault-targeting workload runtime, runtime helper. | Truly requires root today: startup yes, steady-state intentionally no.<br>Why: current startup does socket ownership handoff and filesystem-boundary enforcement before dropping capability sets and setting `no_new_privs`. | Candidate future owner: runtime helper for Beta, or a split root-only bootstrap plus non-root steady-state helper later.<br>Proposed boundary: keep helper root-start explicit for Beta, then revisit whether the bootstrap and steady-state helper should split in Option C. | Compatibility risk: high because any mistake breaks JWT-SVID delivery and therefore workload Vault login.<br>Security benefit: medium because a cleaner split narrows the amount of code that starts with root in the runtime companion. | Required evidence: tests for helper endpoint owner or mode, dropped capability snapshots, helper readiness before workload start, helper-death task-fatal behavior, and negative tests proving the workload cannot access the raw SPIRE channel.<br>Rollback: keep the current helper startup and privilege-drop path.<br>Track: Beta compatibility edge initially; later Option C if the helper model is re-derived. |
| Nomad task launch and task user model | Current actor: ES submit path builds the Nomad job spec and submits one Docker task with `User: "0:0"`.<br>Current privilege: current task user model is root-start by design so the runtime-support binary can create the current helper and workload boundary inside the task. | Paths: job-spec metadata plus the mounted runtime paths under `/execution` and `/run/es-runtime-identity`.<br>Sockets/endpoints: Nomad `/v1/jobs`, Docker task runtime, helper endpoint paths once the task starts.<br>External systems: Nomad, Docker, runtime helper. | Truly requires root today: yes under the current helper and supervisor design.<br>Why: the runtime-support binary requires `0:0` at task start to create the helper-private runtime identity boundary and to exec the workload as fixed `10000:10000`. | Candidate future owner: Nomad/runtime layer design, not the long-lived ES service.<br>Proposed boundary: keep the current task user model as an explicit compatibility edge for Beta, then move or eliminate it only as part of a broader runtime-boundary redesign. | Compatibility risk: high because it changes task admission, helper launch, workload launch, and current runtime expectations together.<br>Security benefit: high if eventually removed because it narrows the root-start scope inside the runtime task itself. | Required evidence: job-spec assertions for the selected user model, successful helper bootstrap and workload launch under the new model, and negative tests for privilege leakage or supplemental groups.<br>Rollback: restore `User: "0:0"` in the job spec.<br>Track: later Option C work; Beta may keep it only as a documented compatibility edge. |
| SPIRE socket traversal and helper-private raw socket alias | Current actor: ES mount-spec assembly plus the runtime supervisor and helper.<br>Current privilege: ES records `execution.spire_workload_api_socket_path`, bind-mounts the containing directory into the helper-private runtime subtree, and the per-run runtime companion uses the helper-private alias there. | Paths: host source directory `dirname(execution.spire_workload_api_socket_path)` such as `/run/spire/sockets`, runtime private source dir `/run/es-runtime-identity/<run_id>/internal/source`, helper-private alias `/run/es-runtime-identity/<run_id>/internal/spire-agent.sock`.<br>Sockets/endpoints: host SPIRE Workload API socket, helper-private alias, workload-visible endpoint socket.<br>External systems: SPIRE, Nomad mount layer, runtime helper. | Truly requires root today: mixed.<br>Why: bind-mounting the containing directory is not itself the main root issue, but the current raw-socket permissions, traversal model, and helper-private boundary are coupled to the root-start runtime companion and the current host SPIRE posture. The long-lived ES service does not need direct raw-socket traversal authority at startup. | Candidate future owner: runtime helper for Beta, later SPIRE setup or runtime layer if the boundary is redesigned.<br>Proposed boundary: keep the raw SPIRE channel helper-private for Beta; keep host-socket existence/type validation in operator or readiness checks; re-derive traversal only in Option C. | Compatibility risk: high because the raw SPIRE channel is the root of the current workload-identity contract.<br>Security benefit: medium to high if later narrowed because it reduces implicit privilege reach into the raw SPIRE channel while avoiding an unnecessary long-lived service-user dependency on `/run/spire/sockets`. | Required evidence: tests proving the raw SPIRE socket path is not leaked into workload env, the workload cannot connect to the helper-private raw socket, the helper can still fetch JWT-SVIDs reliably through its private alias, and service-user migration check-only fails closed on actual long-lived startup blockers without requiring direct raw-socket access.<br>Rollback: restore the current mount and helper-private alias model.<br>Track: Beta compatibility edge initially; later Option C if selector or helper model changes. |
| SPIRE selector and workload registration posture | Current actor: SPIRE registration and host-identity setup outside the long-lived ES request path.<br>Current privilege: current Remote Alpha proof posture still uses the broad root selector set `unix:uid:0` plus `unix:gid:0` for the workload SPIFFE identity. | Paths: no ES-owned filesystem path is the authority here.<br>Sockets/endpoints: SPIRE server registration surface and SPIRE agent workload API indirectly depend on this identity model.<br>External systems: SPIRE. | Truly requires root today: no in itself.<br>Why this is privilege-relevant anyway: the current identity model grants the helper proof through a broad root principal, so it is a structural compatibility edge even though selector registration is not a long-lived ES root operation. | Candidate future owner: SPIRE setup or provisioning phase.<br>Proposed boundary: move selector or registration redesign to provisioning/bootstrap; do not hide it inside a service-user change. | Compatibility risk: high because narrowing the selector model can break JWT-SVID fetch and Vault login if the replacement principal is not derived cleanly.<br>Security benefit: high because it is the direct path to replacing the current broad root identity scope with an explicit helper principal or other bounded model. | Required evidence: documented replacement selector model, successful helper JWT-SVID fetch under that model, and negative tests showing non-helper identities cannot claim the same registration.<br>Rollback: restore the current broad root selector posture if the new identity model fails.<br>Track: Beta may keep the current selector scope only as an explicit compatibility edge; real replacement is later Option C work. |
| Vault workload-zone runtime-config fetch and non-secret runtime handoff | Current actor: ES `Prepare` and `Submit` resolve the typed workload-zone Vault config, stage optional CA trust, and inject only non-secret runtime metadata plus `EXEC_WORKLOAD_IDENTITY_ENDPOINT`.<br>Current privilege: the current non-root service owns the staging path used for this handoff, while the handoff itself remains non-secret and bounded. | Paths: staged runtime CA material under `/execution/run/platform/workload-vault-ca.pem` and `/execution/run/platform/workload-ca-bundle.pem` when configured.<br>Sockets/endpoints: ARS runtime-config blob reads, Vault HTTPS address, workload-visible identity endpoint, workload-side JWT auth mount.<br>External systems: ARS, Vault, SPIRE, runtime helper. | Truly requires root today: no for ES fetch and handoff.<br>Why root still matters indirectly: helper-delivered identity flow and the runtime companion remain bounded compatibility edges. | Current/future owner: non-root ES service for fetch and staging, with SPIRE and Vault prerequisites still owned by provisioning/runtime setup.<br>Proposed boundary: remain in ES as a non-secret handoff surface; do not turn ES into a Vault or token broker. | Compatibility risk: medium because handoff facts are visible in `Prepare`, `Submit`, and `authority_handoff` and are consumed by current runtime-profile flows.<br>Security benefit: medium because it keeps a valuable runtime authority surface while removing unnecessary root dependence from the service process. | Required evidence: prepare and submit tests for typed workload-zone Vault config resolution, CA bundle staging, `authority_handoff` stability, and workload-side Vault login using the helper-delivered JWT-SVID path.<br>Rollback: restore the prior service user and writable-state ownership if handoff staging fails under the non-root service account.<br>Track: must remain functional for Beta; broader auth-model redesign is later Option C work. |
| Health and producer-contract probes | Current actor: ES HTTP server plus repo-owned operator checks.<br>Current privilege: the current non-root service serves `/health` and `GET /v1/executions:contract`, while operator checks layer additional readiness probes around them. | Paths: current config and runtime-config references are read at startup, but the probe surfaces themselves are API-only.<br>Sockets/endpoints: ES `/health`, ES `GET /v1/executions:contract`, ARS health for readiness composition, operator-side readiness helpers.<br>External systems: ARS, operator tooling, Infrastructure Manager reporting. | Truly requires root today: no for serving the probes.<br>Why root mattered historically: the earlier service user was root, not because the probe logic required it. | Current/future owner: non-root ES service for the API surfaces, operator tooling for host-local readiness aggregation.<br>Proposed boundary: remain in ES for service responses; keep richer readiness or maintenance checks outside the ES privilege model. | Compatibility risk: low because the endpoints are narrow and already bounded.<br>Security benefit: low to medium because it removes another read-only API surface from the root-run service. | Required evidence: stable `/health` and producer-contract responses after the service-user change, readiness integration tests that still distinguish service health, prepare-ready, and submit-ready, and no new coupling to host-only evidence collection.<br>Rollback: restore the previous service user and restart once if probe behavior regresses.<br>Track: must continue to work in Beta. |
| Cancellation and other guarded mutation paths that call Nomad | Current actor: ES `Cancel` calls Nomad to stop a submitted job.<br>Current privilege: the current non-root service owns the HTTP path and Nomad client, but the mutation itself is remote scheduler control rather than host-root work. | Paths: none beyond run-id lookup and current internal Nomad locator mapping.<br>Sockets/endpoints: `POST /v1/executions/{run_id}:cancel`, Nomad stop endpoint.<br>External systems: Nomad. | Truly requires root today: no.<br>Why root mattered historically: service posture only, not because Nomad control required host-root privilege. | Current/future owner: non-root ES service.<br>Proposed boundary: remain in ES; do not conflate Nomad control-plane mutation with host-root privilege. | Compatibility risk: low because the public surface is narrow and already bounded by current outcome-evidence semantics.<br>Security benefit: medium because an externally reachable mutation path leaves the root-run service. | Required evidence: cancel integration tests, auth coverage, and proof that the non-root service can still reach Nomad and return the same bounded cancel receipt semantics.<br>Rollback: restore the previous service user if Nomad control fails after the change.<br>Track: must continue to work in Beta. |
| Support-bundle and readiness evidence collection when privilege-relevant | Current actor: operator tooling and Infrastructure Manager support-bundle or checkpoint collection, not the ES runtime hot path.<br>Current privilege: some host-local evidence collection may still require root to read service, config, log, or helper-maintenance facts on the remote host. | Paths: profile evidence such as `.out/remote-alpha-m75q/*`, host-local helper summaries and backups under `/var/tmp/execution-substrate-remote-alpha/*`, and any bounded config or service-posture evidence needed by support-bundle flows.<br>Sockets/endpoints: local ES `/health`, local `GET /v1/executions:contract`, AGS or ARS or EGS local health probes when collected as support evidence.<br>External systems: Infrastructure Manager, AGS, ARS, EGS, operator tooling. | Truly requires root today: sometimes for host-local evidence collection, but not as part of the long-lived ES service privilege model.<br>Why: this is operator evidence and maintenance access, not runtime execution privilege. | Candidate future owner: operator maintenance helper or Infrastructure Manager support-bundle layer.<br>Proposed boundary: move or keep all privilege-sensitive evidence collection in operator tooling; do not let it leak back into the ES service. | Compatibility risk: low because support-bundle and readiness evidence are already bounded, non-proof, non-runtime-authority surfaces.<br>Security benefit: medium because it keeps remote evidence collection separate from the network-facing ES service. | Required evidence: current support-bundle or checkpoint fixtures remain fail-closed, helper-staging evidence remains accepted, and non-claims stay explicit that support-bundle artifacts are provenance and hardening evidence only, not governed proof.<br>Rollback: revert evidence tooling independently from the ES service-user change.<br>Track: Beta-suitable as operator-only evidence work. |

## 4. Recommended Beta cut line

For the recommended **Option B** path, the Beta cut line is now:

- **Already moved for the current live long-lived ES Beta claim**:
  - long-lived ES startup config and TLS reads
  - ARS and EGS client TLS access from the long-lived ES service
  - submit-time staging directory creation and payload or mount staging
  - retained-result bundle packaging and retained-result reads
  - successful staging cleanup
  - all externally reachable ES read or mutation endpoints that were root only
    before the now-landed long-lived `es.service` migration
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

## 5. Bounded requirements satisfied by the landed long-lived ES service slice

Before the live host moved the long-lived ES service off root, the repo
required:

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
- that future-mode gate must also prove that `execution.staging_root_dir` and
  `execution.results_root_dir` resolve to one shared target owner UID:GID;
  mismatched stable-root owner models are blockers, not tolerated future-proof
  evidence
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

The current branch now carries a mixed post-apply ledger for Option B. The
ledger below records what is already satisfied on the live host, what remains
repo-local or checker-backed only, and what is still intentionally out of scope
for the current slice.

| Prerequisite | Current classification | Notes |
| --- | --- | --- |
| ES config/TLS ownership prep | `live-host evidenced` | The accepted Alpha prep slice is documented as applied and productized, and the live `User=es` service now consumes that dedicated `root:es` readable config/TLS model. |
| Staging/results writable-state model | `design-authoritative + live-host evidenced` | The writable-state ownership model and normalization contract remain the authoritative docs, and the bounded live rollout plus the future writable-state readiness pass now evidence the stable live-root cut line under `es:es`. |
| Stable-root target owner consistency | `repo-local test-backed + checker-backed` | Submit-time staging now fails closed if `execution.staging_root_dir` and `execution.results_root_dir` do not resolve to the same target owner UID:GID, and the future readiness checker plus service-user migration check-only report that mismatch explicitly. |
| Retained-result packaging under service-user-owned state | `live-host evidenced + repo-local test-backed` | Repo-local owner-only tests cover retained-result preflight and bundle creation semantics, and the live post-apply lowest-cost happy path passed retained-result fetch/materialization under the long-lived `User=es` service. |
| Repeat result fetch after cleanup | `live-host evidenced + repo-local test-backed` | Repo-local coverage proves repeat retained-result reads remain stable after successful cleanup, and the live post-apply happy path passed the retained-result fetch/materialization flow. |
| Successful cleanup | `repo-local test-backed` | Repo-local cleanup-readiness coverage proves cleanup only follows retained-result handling and fails closed without partial deletion; the live bounded apply did not widen cleanup semantics beyond that tested slice. |
| Failed/lost/canceled staging retention | `repo-local test-backed` | Repo-local normalized-run tests now cover failed, lost, and canceled retention plus invalid-marker fail-closed behavior. |
| Marker validator | `repo-local test-backed` | The shared ownership-normalization marker validator is implemented and exercised in repo-local tests. |
| Helper marker emission | `repo-local test-backed` | Runtime-helper tests cover marker emission after successful normalization and fail-closed behavior when marker write or validation fails. |
| Target UID/GID verification | `checker-backed + live-host evidenced` | Future-mode validation and preflights require expected-owner match when an `es` UID:GID is supplied, and the live future writable-state readiness pass now records that evidence. |
| Future-non-root-required checker mode | `live-host evidenced + checker-backed` | `scripts/remote_alpha_check_es_writable_state_readiness.sh --mode future-non-root-required` remains a non-mutating gate only, and the live host pass now forms part of the bounded evidence set for the current posture. |
| Live ES/runtime-helper binary parity | `live-host evidenced` | The bounded binary-deployment slice resolved the earlier parity blocker for `/usr/local/lib/execution-substrate/bin/es` and `/usr/local/bin/es-runtime-support` before the later writable-state and service-user steps. |
| Repo-side ES/runtime-helper binary deployment helper | `live-host apply evidenced` | The bounded helper updated only the live `es` and `es-runtime-support` binaries, preserved the earlier slice-specific service posture for that step, and recorded post-restart `/health` plus `GET /v1/executions:contract` validation. |
| Repo-side stable writable-state ownership helper | `live-host apply evidenced` | The bounded helper prepared `execution.staging_root_dir` and `execution.results_root_dir` to the documented stable `es:es` ownership model, preserved old root-era roots as rollback/debug/evidence state, did not recursively re-owner retained run trees, and did not claim full ES/runtime de-root by itself. |
| Real live `es:es` ownership of staging/results | `live-host evidenced` | The future writable-state readiness pass now proves the stable live roots are owned, readable, and deletable as `es:es` for the bounded long-lived service-user slice. |
| Service `User=es` migration | `live-host apply evidenced` | The bounded operator migration helper applied the long-lived `es.service` drop-in for `User=es`, `Group=es`, and `UMask=0027`, with post-apply `/health`, `GET /v1/executions:contract`, and lowest-cost happy-path validation passing. |
| Root-start runtime helper | `explicitly out of scope` | This remains a bounded Beta compatibility edge rather than a solved privilege-boundary redesign in the current branch. |
| Nomad task `User: "0:0"` | `explicitly out of scope` | The current task user model may remain a bounded Beta compatibility edge and is not being re-derived here. |
| Helper-private SPIRE traversal | `explicitly out of scope` | The helper-private raw SPIRE path must remain intact in the current slice; traversal redesign is later work if reopened. |
| Broad root selector scope | `explicitly out of scope` | The current selector posture remains a compatibility edge, not a solved part of the current service-user readiness slice. |
| Vault/workload-zone handoff | `satisfied by current branch` | The non-secret workload-zone Vault handoff, CA staging, and workload-side auth path are already part of the accepted bounded runtime contract and must stay unchanged by any service-user work. |
| Operator maintenance/rollback | `documented + partially live-host evidenced` | Migration and rollback sequencing is documented, the bounded live rollout is evidenced, and old root-era roots were intentionally preserved; a full rollback rehearsal still does not exist. |

## 7. Remaining runtime-boundary blockers

The remaining blockers are no longer about the landed long-lived ES service-user
slice itself. They are the blockers to full ES/runtime de-root:

- the current root-start runtime helper, Nomad task `User: "0:0"`,
  helper-private SPIRE traversal, broad root selector scope, and unchanged
  Vault/workload-zone handoff remain bounded compatibility edges rather than
  solved privilege-boundary work
- the bounded live evidence does not claim full runtime/task/helper redesign,
  browser/WebAuthn proof, compare-child proof, or governed proof
- old root-era staging/results roots remain intentionally preserved for
  rollback/debug/evidence state until a later explicit cleanup/archive action
- migration and rollback sequencing is documented, but a full rollback
  rehearsal for the current bounded service-user posture still does not exist

## 8. Explicit Current Conclusion

The current conclusion for Option B readiness is:

- current Alpha remains accepted with long-lived ES `User=es`, `Group=es`,
  `UMask=0027`
- ES config/TLS prep is applied, ES writable-state roots are prepared,
  post-apply lowest-cost happy-path validation passed, future writable-state
  readiness passed, and Infrastructure Manager readiness is accepted
- the current branch also retains strong repo-local readiness for the bounded
  retained-result and cleanup semantics that support that live posture
- the current live posture does not claim full ES/runtime de-root because the
  root-start runtime helper, Nomad task `User: "0:0"`, helper-private SPIRE
  traversal, broad selector posture, and Vault/workload-zone handoff remain
  bounded compatibility edges
- long-lived ES startup keeps the SPIRE socket path as config-shape and submit
  input only, while operator/readiness flows validate the host socket and the
  runtime helper remains the fail-closed consumer of helper-private raw SPIRE
  access
- any later implementation slice must still be gated by non-mutating check-only
  and live measurement evidence plus an explicit rollback plan before any
  further host mutation or runtime-boundary change is treated as acceptable

## 9. Explicit non-goals

Non-goals of this document are:

- claiming full ES/runtime de-root
- authorizing or performing additional live `es.service` `User=` or `Group=`
  changes beyond the completed bounded `es.service` service-user migration
- changing the current Nomad task user model
- changing the current root-start runtime helper or supervisor implementation
- changing the current SPIRE selector posture
- changing the current helper-private raw SPIRE traversal model
- changing Vault runtime handoff semantics
- changing ES public APIs, producer contract semantics, lifecycle semantics,
  retained-result semantics, or `authority_handoff` semantics
- running live host changes, SSH steps, ES apply, or governed proof

## 10. Approval boundary

This matrix does not authorize additional live host changes by itself.

Further runtime-boundary changes require separate approval, updated
authoritative docs for the chosen architecture, explicit compatibility-edge
labeling, tests, migration steps, rollback steps, and bounded evidence
requirements before any code or host change is treated as accepted.

The completed long-lived service-user migration remains bounded to
`es.service` only.
