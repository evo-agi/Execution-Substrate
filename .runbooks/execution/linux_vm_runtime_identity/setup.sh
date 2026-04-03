#!/usr/bin/env bash
set -euo pipefail

# This script prepares a Linux VM for the existing runtime identity validation
# flow. It stays explicit on purpose:
# - no retry loops
# - no polling
# - no background waiting
# - one SSH key handoff
# - one clone attempt
#
# Supported target:
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
#       scp setup.sh vm-user@vm-ip-address:/tmp
#       ssh vm-user@vm-ip-address
#       bash /tmp/setup.sh
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

REPO_URL="${REPO_URL:-git@github.com:SeritArbores/Execution-Platform.git}"
CLONE_PARENT="${CLONE_PARENT:-$HOME/Repositories}"
CLONE_DIR="${CLONE_DIR:-$CLONE_PARENT/Execution-Platform}"
HASHICORP_KEYRING="/usr/share/keyrings/hashicorp-archive-keyring.gpg"
HASHICORP_LIST="/etc/apt/sources.list.d/hashicorp.list"

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

# The runtime identity validation flow uses SSH cloning. Generate the default
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
echo "1. Review the runtime identity validation runbook:"
echo "   $CLONE_DIR/.runbooks/execution/v1_runtime_identity_local_validation.md"
echo "2. Review the governed submit runbook:"
echo "   $CLONE_DIR/.runbooks/execution/v1_submit_runtime_identity_reference.md"
echo "3. Start the Go platform with explicit configs and TLS material."
echo "4. Start Nomad with docker.volumes.enabled = true."
echo "5. Start Vault dev mode and the local identity adapter."
echo "6. Run the publish -> submit -> log verification flow from the runbooks."
echo
echo "Environment notes:"
echo "- This script assumes an apt-based Linux VM."
echo "- The runtime identity validation flow is currently easiest on Linux amd64."
echo "- The workload-visible Vault address must be reachable from bridge-networked containers."
