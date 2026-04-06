#!/usr/bin/env bash
set -euo pipefail

# This script prepares a fresh Linux VM for the current one-host workload-zone
# baseline and then tries to qualify the repo's narrow supported Linux profile.
# It stays explicit on purpose:
# - no retry loops
# - no polling
# - no background waiting
# - one SSH key handoff for cloning
# - one Nomad service qualification attempt
#
# Supported host target:
# - Ubuntu/Debian-style Linux with apt-get and systemd
#
# NOTE: This script does not handle VM installation or the setup for SSH.
#
#       For Linux VM, run the following commands manually on Linux after installation:
#       ```bash
#       # Get IP
#       hostname -I
#       ```
#
#       For MacOS host, run the following commands manually on Mac after installation:
#       ```bash
#       # Start generating SSH key
#       ssh-keygen -t ed25519
#
#       # Copy public key to Linux VM
#       ssh-copy-id vm-user@vm-ip-address
#
#       # Verify SSH connection by logging in
#       ssh vm-user@vm-ip-address
#
#       # Terminate SSH connection
#       exit
#
#       # Copy this script to Linux VM and run it
#       scp 70_linux_setup.sh vm-user@vm-ip-address:/tmp
#       ssh vm-user@vm-ip-address
#       bash /tmp/70_linux_setup.sh
#
#       # Follow the script's prompts to complete the setup
#
#       # Enable Docker
#       sudo usermod -aG docker vm-user
#
#       # Refresh group membership
#       exit
#       ssh vm-user@vm-ip-address
#
#       # Verify Docker is working
#       docker info
#       ```
#
# This helper does not install the VM itself and it does not bypass root-owned
# service management. It uses sudo for package installation, Docker enablement,
# Nomad service configuration, and Nomad startup. If those steps fail, treat
# the host as not yet qualified rather than as a supported profile.

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This setup script is for Linux VMs only." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup script currently supports apt-based Linux distributions only." >&2
  echo "Use Ubuntu or Debian, or adapt the package installation commands manually." >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for the supported Linux profile." >&2
  exit 1
fi

REPO_URL="${REPO_URL:-git@github.com:SeritArbores/Execution-Substrate.git}"
CLONE_PARENT="${CLONE_PARENT:-$HOME/Repositories}"
CLONE_DIR="${CLONE_DIR:-$CLONE_PARENT/Execution Substrate}"
HASHICORP_KEYRING="/usr/share/keyrings/hashicorp-archive-keyring.gpg"
HASHICORP_LIST="/etc/apt/sources.list.d/hashicorp.list"
NOMAD_CONFIG_DIR="/etc/nomad.d"
NOMAD_CONFIG_PATH="${NOMAD_CONFIG_DIR}/nomad.hcl"
NOMAD_CONFIG_BACKUP_PATH="${NOMAD_CONFIG_DIR}/nomad.hcl.execution-substrate.bak"
NOMAD_DATA_DIR="/opt/nomad/data"
NOMAD_HTTP_ADDR="${NOMAD_HTTP_ADDR:-http://127.0.0.1:4646}"
NOMAD_MANAGED_MARKER="# Managed by Execution Substrate scripts/70_linux_setup.sh for the single-node workload-zone baseline."
CURRENT_USER="$(id -un)"
DOCKER_GROUP_CHANGED=0
SUPPORTED_SUBSTRATE_READY=0

cleanup_tempfiles() {
  local path
  for path in "$@"; do
    rm -f "${path}"
  done
}

ensure_user_in_docker_group() {
  if id -nG "${CURRENT_USER}" | tr ' ' '\n' | grep -qx "docker"; then
    echo "==> Reusing existing docker group membership for ${CURRENT_USER}"
    return 0
  fi

  echo "==> Adding ${CURRENT_USER} to the docker group"
  sudo usermod -aG docker "${CURRENT_USER}"
  DOCKER_GROUP_CHANGED=1
}

install_nomad_service_config() {
  local backup_suffix

  echo "==> Installing supported single-node Nomad service config"
  sudo install -d -o nomad -g nomad -m 0755 "${NOMAD_CONFIG_DIR}"
  sudo install -d -o nomad -g nomad -m 0755 "${NOMAD_DATA_DIR}"

  if sudo test -f "${NOMAD_CONFIG_PATH}" && ! sudo grep -Fq "${NOMAD_MANAGED_MARKER}" "${NOMAD_CONFIG_PATH}"; then
    backup_suffix="$(date +%Y%m%d%H%M%S)"
    echo "Backing up existing Nomad config to ${NOMAD_CONFIG_BACKUP_PATH}.${backup_suffix}"
    sudo cp "${NOMAD_CONFIG_PATH}" "${NOMAD_CONFIG_BACKUP_PATH}.${backup_suffix}"
  fi

  cat <<EOF | sudo tee "${NOMAD_CONFIG_PATH}" >/dev/null
${NOMAD_MANAGED_MARKER}
data_dir = "${NOMAD_DATA_DIR}"
bind_addr = "127.0.0.1"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  options = {
    "docker.volumes.enabled" = "true"
  }
}

ports {
  http = 4646
  rpc  = 4647
  serf = 4648
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}
EOF
  sudo chown nomad:nomad "${NOMAD_CONFIG_PATH}"
  sudo chmod 0644 "${NOMAD_CONFIG_PATH}"
}

warn_existing_nomad_processes() {
  local ps_output

  ps_output="$(ps -eo pid,user,args | grep '[n]omad' || true)"
  if [[ -z "${ps_output}" ]]; then
    return 0
  fi

  echo "==> Existing Nomad processes detected"
  printf '%s\n' "${ps_output}"
  echo "The supported profile requires the root-managed nomad.service on 127.0.0.1:4646."
  echo "Stop leftover user-started nomad agents before treating this VM as supported."
}

docker_ready_for_operator() {
  if docker info >/dev/null 2>&1; then
    echo "docker: ready (docker info succeeded without sudo)"
    return 0
  fi

  if sudo docker info >/dev/null 2>&1; then
    echo "docker: daemon reachable, but the current login shell still needs re-login before repo scripts can call docker without sudo" >&2
    return 1
  fi

  echo "docker: daemon is not reachable even through sudo docker info" >&2
  return 1
}

report_nomad_cpu_visibility_diagnostics() {
  local arch
  local virt
  local cpufreq_file_count
  local proc_cpu_mhz
  local dmi_current_speed="unavailable"

  if ! python3 - <<'PY' "${NOMAD_HTTP_ADDR}" >/dev/null 2>&1
import json
import sys
import urllib.error
import urllib.request

base_url = sys.argv[1].rstrip("/")
try:
    nodes = json.load(urllib.request.urlopen(f"{base_url}/v1/nodes"))
except Exception:
    raise SystemExit(1)

ready = [node for node in nodes if node.get("Status") == "ready"]
if not ready:
    raise SystemExit(1)

for node in ready:
    node_id = (node.get("ID") or "").strip()
    if not node_id:
        raise SystemExit(1)
    detail = json.load(urllib.request.urlopen(f"{base_url}/v1/node/{node_id}"))
    attrs = detail.get("Attributes") or {}
    try:
        cpu_total_compute = int(str(attrs.get("cpu.totalcompute", "0")).strip() or "0")
    except Exception:
        cpu_total_compute = 0
    if cpu_total_compute > 0:
        raise SystemExit(1)
PY
  then
    return 0
  fi

  arch="$(uname -m)"
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  cpufreq_file_count="$(find /sys/devices/system/cpu -maxdepth 3 -path '*/cpufreq/*' -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
  if grep -qi 'cpu MHz' /proc/cpuinfo 2>/dev/null; then
    proc_cpu_mhz="present"
  else
    proc_cpu_mhz="absent"
  fi

  if command -v dmidecode >/dev/null 2>&1; then
    dmi_current_speed="$(sudo dmidecode -t processor 2>/dev/null | awk -F': *' '/Current Speed:/ {print $2; exit}')"
    if [[ -z "${dmi_current_speed}" ]]; then
      dmi_current_speed="unknown"
    fi
  fi

  echo "nomad: ready node(s) still report cpu.totalcompute=0 under the root-managed non-dev service" >&2
  echo "nomad: host cpu-frequency visibility: virtualization=${virt:-unknown} arch=${arch} cpufreq_files=${cpufreq_file_count} proc_cpu_mhz=${proc_cpu_mhz} dmi_current_speed=${dmi_current_speed}" >&2

  if [[ "${cpufreq_file_count}" == "0" && "${proc_cpu_mhz}" == "absent" ]]; then
    echo "nomad: this host does not expose CPU frequency data via cpufreq sysfs or /proc/cpuinfo; natural cpu.totalcompute can remain 0 even with root-managed nomad.service" >&2
  fi

  case "${dmi_current_speed}" in
    Unknown|unknown|"Not Specified"|unavailable)
      echo "nomad: SMBIOS processor Current Speed is not usable on this host; dmidecode/cpufrequtils can confirm the gap but do not unlock Nomad CPU fingerprinting by themselves" >&2
      ;;
  esac
}

qualify_supported_substrate() {
  local leader_path
  local agent_path
  local nodes_path

  echo "==> Enabling and starting Nomad"
  if ! sudo systemctl enable --now nomad; then
    echo "nomad: failed to enable/start the root-managed nomad.service" >&2
    sudo systemctl status nomad --no-pager --full || true
    return 1
  fi

  if ! sudo systemctl is-active --quiet docker; then
    echo "docker: systemd unit is not active" >&2
    return 1
  fi
  docker_ready_for_operator || return 1

  if ! sudo systemctl is-active --quiet nomad; then
    echo "nomad: systemd unit is not active after enable/start" >&2
    sudo systemctl status nomad --no-pager --full || true
    return 1
  fi

  leader_path="$(mktemp)"
  agent_path="$(mktemp)"
  nodes_path="$(mktemp)"

  if ! curl --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/status/leader" >"${leader_path}"; then
    echo "nomad: leader request failed for ${NOMAD_HTTP_ADDR}/v1/status/leader" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi
  if ! curl --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/agent/self" >"${agent_path}"; then
    echo "nomad: agent self request failed for ${NOMAD_HTTP_ADDR}/v1/agent/self" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi
  if ! curl --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/nodes" >"${nodes_path}"; then
    echo "nomad: node request failed for ${NOMAD_HTTP_ADDR}/v1/nodes" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi

  if ! python3 - <<'PY' "${NOMAD_HTTP_ADDR}" "${leader_path}" "${agent_path}" "${nodes_path}"
import json
import pathlib
import sys
import urllib.request

base_url = sys.argv[1].rstrip("/")
leader = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if not isinstance(leader, str) or not leader.strip():
    raise SystemExit("nomad: leader missing")

agent = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
config = agent.get("config") or {}
if config.get("DevMode") is True:
    raise SystemExit("nomad: agent reports DevMode=true; this VM is not a supported profile")

nodes = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
ready = [node for node in nodes if node.get("Status") == "ready"]
if not ready:
    raise SystemExit("nomad: no ready client nodes")

reasons = []
schedulable = []
for node in ready:
    node_id = (node.get("ID") or "").strip()
    node_name = (node.get("Name") or node_id or "unknown").strip()
    if not node_id:
        reasons.append(f"{node_name}=missing-id")
        continue
    detail = json.load(urllib.request.urlopen(f"{base_url}/v1/node/{node_id}"))
    attrs = detail.get("Attributes") or {}
    drivers = detail.get("Drivers") or {}
    docker = drivers.get("docker") or {}
    try:
        cpu_total_compute = int(str(attrs.get("cpu.totalcompute", "0")).strip() or "0")
    except Exception:
        cpu_total_compute = 0
    if cpu_total_compute <= 0:
        reasons.append(f"{node_name}=cpu.totalcompute:{cpu_total_compute}")
        continue
    if docker.get("Healthy") is not True:
        reasons.append(f"{node_name}=docker:{docker.get('HealthDescription') or 'unhealthy'}")
        continue
    schedulable.append((node_name, cpu_total_compute))

if not schedulable:
    reason = "nomad: no ready client nodes with positive cpu.totalcompute and healthy docker driver"
    if reasons:
        reason += "; " + ", ".join(reasons)
    raise SystemExit(reason)

details = ", ".join(f"{name}:cpu.totalcompute={cpu}" for name, cpu in schedulable)
print(f"nomad: leader={leader} mode=non-dev ready_nodes={len(ready)} schedulable_nodes={len(schedulable)} {details}")
PY
  then
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi

  cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
  SUPPORTED_SUBSTRATE_READY=1
}

echo "==> Validating sudo access"
sudo -v

echo "==> Installing base packages"
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  gnupg \
  jq \
  lsb-release \
  openssh-client \
  openssl \
  python3 \
  software-properties-common \
  unzip \
  docker.io \
  golang-go

# Add the official HashiCorp apt repository so vault and nomad come from a
# predictable source on Ubuntu/Debian systems.
echo "==> Configuring HashiCorp apt repository"
curl -fsSL https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o "$HASHICORP_KEYRING"
echo \
  "deb [signed-by=$HASHICORP_KEYRING] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee "$HASHICORP_LIST" >/dev/null

echo "==> Installing Nomad and Vault"
sudo apt-get update
sudo apt-get install -y nomad vault

echo "==> Enabling Docker"
sudo systemctl enable --now docker
ensure_user_in_docker_group
install_nomad_service_config
warn_existing_nomad_processes

echo "==> Qualifying supported substrate baseline"
if ! qualify_supported_substrate; then
  echo "supported-substrate: not yet qualified" >&2
  report_nomad_cpu_visibility_diagnostics || true
  echo "This VM still needs manual root investigation before it matches the repo's supported profile." >&2
  echo "Check nomad.service, stop leftover user-started Nomad agents, inspect 'sudo journalctl -u nomad --no-pager', and rerun this script." >&2
fi

# The current runtime identity validation flow uses SSH cloning. Generate the default
# key only if the user does not already have one.
SSH_KEY_PATH="$HOME/.ssh/id_ed25519"
SSH_PUB_PATH="$SSH_KEY_PATH.pub"

if [[ ! -f "$SSH_KEY_PATH" ]]; then
  echo "==> Generating SSH key at $SSH_KEY_PATH"
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"
  ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "${USER}@$(hostname)"
else
  echo "==> Reusing existing SSH key at $SSH_KEY_PATH"
fi

if [[ ! -f "$SSH_PUB_PATH" ]]; then
  echo "SSH public key is missing: $SSH_PUB_PATH" >&2
  exit 1
fi

echo
echo "================================================================"
echo "Add this SSH public key to GitHub before cloning the repository:"
echo "================================================================"
cat "$SSH_PUB_PATH"
echo "================================================================"
echo
echo "After adding the key in GitHub:"
echo "1. Open GitHub -> Settings -> SSH and GPG keys"
echo "2. Add the public key shown above"
echo "3. Return here"
echo
read -r -p "Press Enter after adding the key to GitHub..."

mkdir -p "$CLONE_PARENT"

if [[ -e "$CLONE_DIR" ]]; then
  echo "Clone target already exists: $CLONE_DIR" >&2
  echo "Remove it or set CLONE_DIR to a different path, then rerun this script." >&2
  exit 1
fi

echo "==> Cloning repository"
if ! git clone "$REPO_URL" "$CLONE_DIR"; then
  echo "Repository clone failed." >&2
  echo "Check GitHub SSH access and rerun this script." >&2
  exit 1
fi

echo "==> Verifying required tools"
printf 'git: '; git --version
printf 'ssh: '; ssh -V 2>&1 | head -n 1
printf 'python3: '; python3 --version
printf 'openssl: '; openssl version
printf 'curl: '; curl --version | head -n 1
printf 'go: '; go version
printf 'vault: '; vault version | head -n 1
printf 'nomad: '; nomad version | head -n 1
printf 'docker: '; docker --version

echo
echo "==> Next steps"
echo "1. Review the governed submit bring-up runbook:"
echo "   $CLONE_DIR/.runbooks/system/v1_bringup.md"
echo "2. Review the bounded useful credential flow runbook:"
echo "   $CLONE_DIR/.runbooks/execution/v1_submit_runtime_identity_vault_login.md"
echo "3. Keep the legacy compatibility runbook only for older reference-bridge validation:"
echo "   $CLONE_DIR/.runbooks/execution/v1_submit_runtime_identity_reference.md"
echo "4. Start the Go platform with explicit configs and TLS material."
echo "5. Verify the VM still reports nomad-startup-mode: pre-managed, submit-ready-mode: natural, and supported-environment: supported through scripts/01_bringup.sh check."
echo "6. Treat script-managed local Nomad startup and any compute override as bounded fallback/troubleshooting, not the supported Linux environment story."
echo "7. Start the bounded Vault-compatible HTTPS endpoint used by the runbook."
echo "8. Run the publish -> submit -> log verification flow from the runbooks."
echo
echo "Environment notes:"
echo "- This script assumes an apt-based Linux VM."
echo "- The supported Linux profile is Docker healthy plus a root-managed non-dev nomad.service with positive natural cpu.totalcompute and no override."
echo "- This script writes /etc/nomad.d/nomad.hcl for the single-node loopback Nomad service used by the current one-host workload-zone profile."
echo "- If supported-substrate qualification failed above, do not treat this VM as supported yet."
echo "- If nomad.service could not start or remain healthy, fix that with root-managed host investigation instead of falling back to a user-started Nomad proof."
echo "- Some proof VMs may still need manual root investigation or bounded fallback when Nomad fingerprinting leaves cpu.totalcompute at 0."
echo "- A host that still reports cpu.totalcompute=0 under the root-managed non-dev service and exposes no usable CPU-frequency data via cpufreq sysfs, /proc/cpuinfo, or SMBIOS Current Speed is currently unsupported for the supported Linux profile."
echo "- The workload-visible Vault address must be reachable from bridge-networked containers."
if [[ "${DOCKER_GROUP_CHANGED}" == "1" ]]; then
  echo "- Docker group membership changed for ${CURRENT_USER}; log out and back in before running repo scripts without sudo."
fi
if [[ "${SUPPORTED_SUBSTRATE_READY}" == "1" ]]; then
  echo "- Supported substrate baseline: qualified."
else
  echo "- Supported substrate baseline: not yet qualified from this script run."
fi

if [[ "${SUPPORTED_SUBSTRATE_READY}" != "1" ]]; then
  exit 1
fi
