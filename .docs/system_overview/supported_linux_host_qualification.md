# Supported Linux Host Qualification Spec

This document defines the current host qualification boundary for the Execution Substrate supported Linux environment.

It is a system-level environment spec, not an architecture redesign document. It does not widen workload compatibility, does not redefine the Nomad/Docker substrate, and does not lower the honesty bar for the existing `supported`, `bounded-fallback`, and `unsupported` categories.

This qualification spec is not a complete fresh-host ES provisioner. Fresh-host
provisioning ownership and acceptance remain open; reuse of an old or nonempty
Remote Alpha host is blocked unless a separately governed existing-host
migration contract is selected. The former Remote Alpha ES writable-state and
service-user routes are retired and provide no such contract.

## 1. Purpose And Scope

This spec answers one narrow question:

- what kind of Linux host or VM can honestly be treated as a real `supported` environment for the current bounded Execution Substrate slice

This spec is:

- a host qualification spec for the current Linux workload-zone baseline
- a guide for operators and Codex to decide whether a host qualifies before claiming support
- a boundary document for supported vs bounded-fallback vs unsupported substrate states

This spec is not:

- a rewrite or reopen-by-default architecture exercise
- a proposal to move the control plane onto the host as the final model
- a workload compatibility broadening document
- permission to normalize `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`

The bounded platform direction remains unchanged:

- governed execution
- platform-owned runtime identity
- Docker/Nomad as the current bounded execution substrate
- Unix/Linux as the intended workload-zone direction
- SPIFFE/SPIRE integration as a real milestone rather than optional polish

## 2. Current Support Categories

### `supported`

A host is `supported` only when the normal operator/readiness path can honestly report all of the following without `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`:

- Docker healthy
- pre-managed Nomad service already running at `NOMAD_ADDR`
- `GET /v1/agent/self` reports `config.DevMode=false`
- at least one ready Nomad node with positive natural `cpu.totalcompute`
- healthy Docker driver on that ready node
- operator/readiness labels:
  - `nomad-startup-mode: pre-managed`
  - `submit-ready-mode: natural`
  - `supported-environment: supported`

### `bounded-fallback`

A host is `bounded-fallback` when the current bounded slice can still be proved, but the environment does not satisfy the clean supported-host claim. Current bounded-fallback cases include:

- script-managed local Nomad startup through `scripts/01_bringup.sh up`
- explicit `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`
- a host that can run the bounded proof path only after temporary deployment troubleshooting measures

Bounded-fallback is real evidence for the current bounded slice. It is not evidence that the host is a supported environment.

### `unsupported`

A host is `unsupported` when the current substrate boundary cannot be honestly qualified. Current unsupported cases include:

- `nomad agent -dev`
- user-started foreground Nomad standing in for a pre-managed service
- no ready node with positive natural `cpu.totalcompute`
- unhealthy Docker driver
- a host profile that does not expose enough CPU-performance data for Nomad to detect natural compute under the real root-managed service

## 3. Supported Host Requirements

The current supported Linux host profile requires all of the following.

### Operating system and service model

- Linux host or Linux VM
- systemd available
- Docker daemon installed and healthy
- packaged `nomad.service` available and running as the active Nomad endpoint
- Nomad running as a pre-managed non-`-dev` service before the normal full-profile bring-up path

### Nomad requirements

- `nomad.service` active and enabled
- `GET /v1/agent/self` reports `config.DevMode=false`
- at least one ready client node
- that ready node exposes positive natural `cpu.totalcompute`
- that ready node reports Docker driver `Healthy`
- when the current supported-local runtime-profile surface is enabled, Nomad Docker image cleanup disabled through `client.options["docker.cleanup.image"]="false"` so local runtime-profile images survive completed allocations for repeated client runs
- no `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`
- no `client.cpu_total_compute` override in the active Nomad service config

### Operator/readiness requirements

Through the normal operator path, the environment must be able to report:

- `nomad-startup-mode: pre-managed`
- `submit-ready-mode: natural`
- `supported-environment: supported`

### Additional current prerequisites

The supported host still has to satisfy the other active slice-0 runtime assumptions already enforced by the current scripts and runbooks:

- Docker host networking can reach host loopback from the control-plane containers
- Nomad Docker bind mounts are enabled
- the supported-local single-node Nomad baseline disables Nomad Docker image cleanup for local runtime-profile image durability; external Docker image pruning remains outside the support claim and must be followed by a refresh before submit-readiness is claimed again
- the configured ES runtime support binary and SPIRE socket paths are valid for the execution path
- the normal governed operator flow can proceed through the existing runbooks

### Tranche A filesystem-custody validation posture

The supported-host profile above does not by itself validate ES
filesystem-custody syscalls. Historical Tranche A sequencing allowed a fresh
read-only audit of the retirement/retain-staging candidate to clear Tranche B
while native Linux remained pending when its source and bounded checks were
defect-free and Tranche B was independent of those native checks. That former
sequence does not impose a blanket native pre-commit gate on local source
preservation or integration. The owning acceptance and local-commit split is in
`PLANS.md` and `.docs/execution_lifecycle/contracts.md`.

For an actual claimed operating environment and architecture, governed Ubuntu
24.04 linux/amd64 for Remote Alpha and governed Ubuntu 24.04 linux/arm64 for
supported-local must supply real filesystem-custody syscall and mount-crossing
observations. The relevant admission test must exercise:

- `openat2` with beneath, no-magic-link, no-symlink, and no-cross-device
  resolution;
- `renameat2(RENAME_NOREPLACE)` collision behavior;
- exclusive run-root claim and descriptor-held identity custody; and
- an actual mount-crossing refusal.

Cross-compilation is compile evidence only and cannot replace those runtime
observations. Darwin behavior, a fake filesystem, containers running a
different kernel or architecture, and an OS label cannot replace them either.
C's selected native programme remains historical evidence for its exact source
and environments, not an execution of the then-unaccepted H/C/T integrated
tree. PR #8 later completed source publication only.
Evidence reuse or a new bounded witness depends on the concrete changed
interaction and operating claim; merge ancestry alone does not require a
blanket native campaign. Until the relevant claimed-architecture behavior is
qualified, report that operating claim as pending rather than supported by
inference. Neither the Remote Alpha amd64 nor supported-local arm64 claim is
narrowed, and no universal platform guarantee is inferred. These operating
requirements are not an automatic prerequisite to a separately authorized
local source-preservation or integration commit.

## 4. Explicit Disqualifiers

The following conditions disqualify a host from `supported`.

- `nomad agent -dev`
- a user-started foreground Nomad process being treated as equivalent to a pre-managed service
- `cpu.totalcompute=0` on all ready nodes under the real active service path
- any reliance on `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`
- active Nomad config containing `client.cpu_total_compute`
- unhealthy or unavailable Docker daemon
- unhealthy Docker task driver on the ready Nomad node
- a host profile that exposes no usable CPU-performance data for Nomad to derive natural compute

For the current slice, package installation alone is not qualification. A host that has Docker and Nomad installed but still cannot expose positive natural `cpu.totalcompute` remains unsupported.

## 5. Known Local Qualification Results On This Mac

These observed qualification results are for the current Apple Silicon Mac and the specific local guest profiles investigated here. They are host/profile-specific facts, not global platform claims.

### Current supported local reference profile on this Mac

The current supported local reference profile on this Mac is:

- Lima `qemu`
- Ubuntu 24.04 arm64
- Docker healthy
- packaged pre-managed non-`-dev` `nomad.service`
- positive natural `cpu.totalcompute`
- no `NOMAD_CLIENT_CPU_TOTAL_COMPUTE`
- operator/readiness reports `nomad-startup-mode: pre-managed`, `submit-ready-mode: natural`, and `supported-environment: supported`

### Current known unsupported local profiles on this Mac

The following investigated local guest profiles are currently unsupported for the natural `supported` claim on this Mac.

- Ubuntu 24.04 VMware/aarch64 guest
- Lima `vz` guest running Ubuntu 24.04 arm64

Observed facts from the real root-managed path for those unsupported local profiles:

- packaged `nomad.service` was enabled and started successfully
- the active Nomad endpoint was root-managed and non-`-dev`
- Docker was healthy
- Nomad leadership was present
- the ready node still reported `cpu.totalcompute=0`
- `/proc/cpuinfo` exposed no usable `cpu MHz`
- `/sys/devices/system/cpu/cpu*/cpufreq/*` exposed no readable CPU-frequency data
- SMBIOS processor information reported unusable or unknown processor speed
- installing `dmidecode` or `cpufrequtils` confirmed the missing inputs but did not make natural Nomad CPU fingerprinting succeed

The narrow current conclusions are:

- on this Mac, Lima `qemu` + Ubuntu 24.04 arm64 currently qualifies as the real supported local profile
- on this Mac, the investigated VMware/aarch64 and Lima `vz` local guest profiles are unsupported for the natural supported-host claim today because the real service path still leaves natural `cpu.totalcompute=0`

This does not prove:

- Ubuntu is unsupported in general
- Apple Silicon local Linux guests are unsupported in general
- VMware/aarch64 is impossible in general
- Lima `vz` is impossible in general
- Nomad is the wrong bounded substrate
- architecture should be reopened

## 6. Qualification Procedure

Use this procedure to qualify a future Linux host or VM.

### Step 1: verify the service baseline

Run:

```bash
systemctl is-enabled nomad
systemctl is-active nomad
systemctl status nomad --no-pager --full | sed -n '1,80p'
ps -eo pid,user,args | grep '[n]omad' || true
ss -ltnp '( sport = :4646 )' || true
curl --fail-with-body --silent --show-error http://127.0.0.1:4646/v1/agent/self
curl --fail-with-body --silent --show-error http://127.0.0.1:4646/v1/status/leader
curl --fail-with-body --silent --show-error http://127.0.0.1:4646/v1/nodes
```

Pass only if all of the following hold:

- `nomad.service` is the active endpoint
- the service is pre-managed rather than a user-started foreground agent
- `DevMode=false`
- leader is present

Fail immediately if:

- the active endpoint is `-dev`
- `nomad.service` is not active
- a user-started process is standing in for the supported service path

### Step 2: verify natural schedulability

For each ready node, inspect node detail:

```bash
python3 - <<'PY'
import json, urllib.request
nodes = json.load(urllib.request.urlopen("http://127.0.0.1:4646/v1/nodes"))
for node in nodes:
    if node.get("Status") != "ready":
        continue
    node_id = (node.get("ID") or "").strip()
    detail = json.load(urllib.request.urlopen(f"http://127.0.0.1:4646/v1/node/{node_id}"))
    attrs = detail.get("Attributes") or {}
    docker = ((detail.get("Drivers") or {}).get("docker") or {})
    print(node.get("Name"), attrs.get("cpu.totalcompute"), docker.get("Healthy"), docker.get("HealthDescription"))
PY
```

Pass only if at least one ready node reports:

- positive natural `cpu.totalcompute`
- Docker driver `Healthy`

Fail if:

- all ready nodes report `cpu.totalcompute=0`
- Docker driver is unhealthy

### Step 3: verify absence of override-based support

Run:

```bash
grep -R -n 'cpu_total_compute\|NOMAD_CLIENT_CPU_TOTAL_COMPUTE' /etc/nomad.d || true
env | grep '^NOMAD_CLIENT_CPU_TOTAL_COMPUTE=' || true
```

Pass only if no active override is present.

Fail if any override is required for schedulability.

### Step 4: inspect CPU-performance visibility when natural compute is zero

Run:

```bash
lscpu
grep -n -i 'cpu mhz\|bogomips\|model name\|hardware\|processor' /proc/cpuinfo || true
find /sys/devices/system/cpu -maxdepth 3 -path '*/cpufreq/*' -type f 2>/dev/null | sort
systemd-detect-virt || true
sudo dmidecode -t system -t processor | sed -n '1,220p' || true
cpufreq-info 2>&1 | sed -n '1,220p' || true
```

Treat the host as unsupported for the supported-profile claim if the real service path still has `cpu.totalcompute=0` and the host also shows all of the following:

- no usable `cpu MHz` in `/proc/cpuinfo`
- no readable `cpufreq` sysfs files for CPU frequency
- SMBIOS processor `Current Speed` unusable or unknown

Installing `dmidecode` or `cpufrequtils` is diagnostic only. Those packages do not qualify a host by themselves.

### Step 5: verify the operator labels

After the control plane is started with the normal repo configs and TLS material, use the repo-owned path that preserves pre-managed Nomad truth:

```bash
scripts/72_supported_local_setup.sh setup
source /tmp/execution-substrate-supported-local-proof/env.sh
export BRINGUP_PROFILE="prepare-only"
scripts/01_bringup.sh up
BRINGUP_PROFILE=full scripts/01_bringup.sh check
```

Pass only if the output includes:

- `nomad-startup-mode: pre-managed`
- `submit-ready-mode: natural`
- `supported-environment: supported`
- `runtime profile image durability: nomad docker.cleanup.image=false` when `control-plane-normal-shell/v1` is enabled
- `submit-ready: true`

If the output instead shows `managed-local`, `bounded-override`, or a failed submit-readiness result, the host is not supported.

Do not use `BRINGUP_PROFILE=full scripts/01_bringup.sh up` as the supported proof path. That path manages Nomad locally and remains `bounded-fallback` by definition.

On the current supported local reference host on this Mac, `scripts/72_supported_local_setup.sh setup` is the guest-side repo-owned replacement for the earlier out-of-repo experiment harnesses. It prepares the bounded supported-local proof environment, including the proof-scoped real SPIRE server/agent path and the proof-scoped real Vault dev/test target used by the higher-value runtime-identity credential-flow proof, but it still does not qualify the host by itself.

Because Lima mounts the host repo tree read-only inside the current `qemu` guest on this Mac, the canonical supported-local proof wrapper now stages a fresh host-worktree snapshot into guest bootstrap scratch and executes the proof from that staged snapshot rather than from the mounted repo view. The canonical proof record still lives on the host under `.out/es-proof-<id>/`. Any guest `/tmp/es-proof-<id>` or `/tmp/es-proof-<id>.bootstrap` workspace used by the repo-owned supported-local wrapper is proof-owned transient scratch, not the canonical proof workspace: stale proof-owned guest scratch is cleaned before a new wrapper run and successful current-run guest scratch is removed after the host evidence copy.

## 7. Evidence Collection Checklist

Capture the following for every host qualification attempt.

- `systemctl is-enabled nomad`
- `systemctl is-active nomad`
- `systemctl status nomad --no-pager --full`
- Nomad process list
- active listener on `:4646`
- `GET /v1/agent/self`
- `GET /v1/status/leader`
- `GET /v1/nodes`
- per-node detail from `GET /v1/node/<id>`
- `docker info`
- `lscpu`
- relevant `/proc/cpuinfo` lines
- presence or absence of `cpufreq` sysfs files
- `systemd-detect-virt`
- `dmidecode -t system -t processor`
- `cpufreq-info`
- current operator/readiness output from `scripts/01_bringup.sh check`

If natural compute is zero, also capture:

- `journalctl -u nomad` lines around CPU fingerprinting
- any host-specific indication that CPU-performance data is absent rather than merely unread

## 8. Proof Step After Qualification

Once a host passes qualification, use the normal operator path rather than ad hoc Nomad probes.

Current proof order:

1. bring up the stack through the normal system runbook
2. re-run `scripts/01_bringup.sh check`
3. run one real governed execution proof through the operator path

The current primary proof path is documented in:

- [.runbooks/system/v1_bringup.md](../../.runbooks/system/v1_bringup.md)

The preferred command path there is now:

```bash
scripts/73_supported_local_proof.sh run
```

That order keeps host qualification and smoke execution separate:

- `scripts/73_supported_local_proof.sh run` creates one canonical proof workspace under `.out/es-proof-<id>/` and records both qualification and execution evidence there
- inside that wrapper, the `prepare-only` bring-up plus full-profile `check` still proves the supported host boundary before any workload proof is accepted
- the later execute-loop runs use the bounded runtime-identity Vault-login workload and the bounded Control Plane normal-shell runtime-contract workload as the canonical higher-value governed execution proofs on that already-qualified host
- the Control Plane normal-shell proof fetches the retained result bundle and validates the expected proof Codex stdout/stderr, final message, workspace diff, and workspace archive artifacts
- the wrapper may still use guest `/tmp/es-proof-<id>` plus `/tmp/es-proof-<id>.bootstrap` internally on this Mac because the Lima-mounted repo tree is read-only inside the guest, but those scratch paths are proof-owned transient implementation detail rather than the canonical proof workspace

The bounded useful credential flow runbook remains the higher-value proof on top of that qualified host, not a replacement for host qualification.

## 9. Non-Goals And Deferred Items

This spec does not cover:

- workload compatibility broadening
- root workloads or arbitrary image-user execution
- X.509 SVID delivery
- multi-host topology
- final control-plane network architecture
- broader substrate redesign
- re-deriving Nomad out of the current bounded slice

## 10. Operator Honesty Note

The current supported-host claim is intentionally narrower than “packages installed and something ran once.”

Be explicit:

- installing Docker and Nomad is not qualification
- bounded-fallback is not supported
- `nomad agent -dev` is not supported
- a user-started foreground Nomad process is not supported
- `NOMAD_CLIENT_CPU_TOTAL_COMPUTE` is not supported
- positive natural `cpu.totalcompute` under the real pre-managed service is required before claiming `supported`
