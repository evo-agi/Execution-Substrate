#!/usr/bin/env bash
set -euo pipefail

# This script prepares a fresh Linux VM for the current one-host workload-zone
# baseline and then tries to qualify the repo's narrow supported Linux profile.
# It stays explicit on purpose:
# - no retry loops
# - no polling, except one bounded wait (up to 30 s) for Nomad's leader,
#   which the ACL bootstrap needs
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
NOMAD_HTTP_ADDR="${NOMAD_HTTP_ADDR:-https://127.0.0.1:4646}"
# Nomad's API and RPC use TLS 1.3 with a certificate this script issues (see
# nomad_tls_issue). Readers trust only this CA; ES also pins the server key.
NOMAD_TLS_DIR="${NOMAD_CONFIG_DIR}/tls"
NOMAD_CACERT="${NOMAD_TLS_DIR}/ca.pem"
NOMAD_MANAGED_MARKER="# Managed by Execution Substrate scripts/70_linux_setup.sh for the single-node workload-zone baseline."
# The supported Nomad enforces ACLs: ES submits only with its own token and
# refuses a Nomad that accepts jobs without one. This script bootstraps the
# ACLs and keeps the management token root-only here; after cloning,
# scripts/nomad_acl_setup.sh creates ES's namespace, policies and tokens.
NOMAD_ACL_DIR="${NOMAD_ACL_DIR:-/etc/execution-substrate/nomad-acl}"
NOMAD_ACL_MANAGEMENT_TOKEN_FILE="${NOMAD_ACL_DIR}/management-token"
NOMAD_LEADER_WAIT_SECONDS=30
# nomad.service runs Nomad as root. While Nomad is down any local account can
# hold its port, so the management token and the bootstrap secret go only to
# a listener that root owns (an interim guard: HTTPS with a pinned server key
# replaces it).
NOMAD_SERVICE_UID=0
NOMAD_CONFIG_CHANGED=0
NOMAD_TLS_ISSUED=0
NOMAD_QUALIFY_TOKEN=""
GO_REQUIRED_VERSION="go1.26.5"
GO_DOWNLOAD_BASE_URL="https://go.dev/dl"
GO_PATH_PROFILE="/etc/profile.d/execution-substrate-go.sh"
GO_SELECTED_ARCHIVE=""
GO_SELECTED_SHA256=""
GO_TOOLCHAIN_ARCHIVE_CLEANUP_PATH=""
CURRENT_USER="$(id -un)"
DOCKER_GROUP_CHANGED=0
SUPPORTED_SUBSTRATE_READY=0

cleanup_tempfiles() {
  local path
  for path in "$@"; do
    rm -f "${path}"
  done
}

select_go_toolchain_archive() {
  local machine

  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)
      GO_SELECTED_ARCHIVE="go1.26.5.linux-amd64.tar.gz"
      GO_SELECTED_SHA256="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
      ;;
    aarch64|arm64)
      GO_SELECTED_ARCHIVE="go1.26.5.linux-arm64.tar.gz"
      GO_SELECTED_SHA256="fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49"
      ;;
    *)
      echo "unsupported Linux architecture for Go ${GO_REQUIRED_VERSION}: ${machine}" >&2
      exit 1
      ;;
  esac
}

cleanup_go_toolchain_archive() {
  if [[ -n "${GO_TOOLCHAIN_ARCHIVE_CLEANUP_PATH}" ]]; then
    rm -f -- "${GO_TOOLCHAIN_ARCHIVE_CLEANUP_PATH}"
  fi
}

clear_go_toolchain_archive_cleanup() {
  trap - EXIT
  trap - HUP
  trap - INT
  trap - TERM
  GO_TOOLCHAIN_ARCHIVE_CLEANUP_PATH=""
}

go_toolchain_archive_cleanup_exit() {
  local status="${1:-0}"

  cleanup_go_toolchain_archive
  clear_go_toolchain_archive_cleanup
  exit "${status}"
}

go_toolchain_archive_cleanup_signal() {
  local signal="${1}"

  cleanup_go_toolchain_archive
  clear_go_toolchain_archive_cleanup
  kill -s "${signal}" "$$"
  exit 128
}

require_go_toolchain_archive_cleanup_trap_ownership() {
  local signal

  for signal in EXIT HUP INT TERM; do
    if [[ -n "$(trap -p "${signal}")" ]]; then
      echo "pre-existing ${signal} trap prevents Go archive installation: standalone installer requires exclusive cleanup-trap ownership for the bounded Go archive installation step" >&2
      return 1
    fi
  done
}

register_go_toolchain_archive_cleanup() {
  local archive_path="${1}"

  GO_TOOLCHAIN_ARCHIVE_CLEANUP_PATH="${archive_path}"
  trap 'go_toolchain_archive_cleanup_exit "$?"' EXIT
  trap 'go_toolchain_archive_cleanup_signal HUP' HUP
  trap 'go_toolchain_archive_cleanup_signal INT' INT
  trap 'go_toolchain_archive_cleanup_signal TERM' TERM
}

finish_go_toolchain_archive_cleanup() {
  local status=$?

  cleanup_go_toolchain_archive
  clear_go_toolchain_archive_cleanup
  return "${status}"
}

install_go_toolchain() {
  local archive
  local expected_sha256
  local download_url
  local archive_path
  local observed_sha256
  local observed_version

  archive="${GO_SELECTED_ARCHIVE}"
  expected_sha256="${GO_SELECTED_SHA256}"
  if [[ -z "${archive}" || -z "${expected_sha256}" ]]; then
    echo "Go ${GO_REQUIRED_VERSION} archive selection preflight did not run" >&2
    exit 1
  fi

  require_go_toolchain_archive_cleanup_trap_ownership

  download_url="${GO_DOWNLOAD_BASE_URL}/${archive}"
  archive_path="$(mktemp)"
  register_go_toolchain_archive_cleanup "${archive_path}"
  echo "==> Installing official Go ${GO_REQUIRED_VERSION} from ${download_url}"
  if ! curl --fail --location --silent --show-error -o "${archive_path}" "${download_url}"; then
    echo "failed to download official Go archive ${archive}" >&2
    exit 1
  fi

  observed_sha256="$(sha256sum "${archive_path}" | awk '{print $1}')"
  if [[ "${observed_sha256}" != "${expected_sha256}" ]]; then
    echo "Go archive digest mismatch for ${archive}: expected ${expected_sha256} observed ${observed_sha256}" >&2
    exit 1
  fi

  sudo rm -rf /usr/local/go
  sudo mkdir -p /usr/local
  sudo tar -C /usr/local -xzf "${archive_path}"

  printf '%s\n' 'export PATH="/usr/local/go/bin:${PATH}"' | sudo tee "${GO_PATH_PROFILE}" >/dev/null
  sudo chmod 0644 "${GO_PATH_PROFILE}"
  export PATH="/usr/local/go/bin:${PATH}"

  observed_version="$(env GOTOOLCHAIN=local go version 2>/dev/null | awk '{print $3}' || true)"
  if [[ "${observed_version}" != "${GO_REQUIRED_VERSION}" ]]; then
    echo "unsupported Go toolchain: expected ${GO_REQUIRED_VERSION}, observed ${observed_version:-unavailable}" >&2
    exit 1
  fi
  finish_go_toolchain_archive_cleanup
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

# BEGIN nomad_tls (the tests run these functions on their own)
# Nomad's HTTPS identity: a server certificate for server.global.nomad,
# localhost, 127.0.0.1 and ::1, signed by a CA that signs nothing else. The CA's
# key exists only while the certificate is issued, so no other certificate can
# chain to ca.pem. ES pins the server certificate's public key as well.
NOMAD_TLS_SERVER_NAME="server.global.nomad"
NOMAD_TLS_VALID_DAYS=825
NOMAD_TLS_RENEW_DAYS=30

# nomad_tls_issue <dir>: write ca.pem, server.pem (0644) and server-key.pem
# (0600) into <dir>, owned by the user who runs it (root on a host).
nomad_tls_issue() {
  local dir=$1
  local work
  local status=0

  work="$(umask 077 && mktemp -d)" || return 1
  # Each step stops the subshell on failure (set -e does not apply inside a
  # subshell whose status is tested).
  (
    umask 077
    cd "${work}" || exit 1
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca-key.pem || exit 1
    openssl req -x509 -new -key ca-key.pem -sha256 -days "${NOMAD_TLS_VALID_DAYS}" \
      -subj "/CN=Execution Substrate Nomad CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign" \
      -addext "subjectKeyIdentifier=hash" \
      -out ca.pem || exit 1
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server-key.pem || exit 1
    openssl req -new -key server-key.pem -subj "/CN=${NOMAD_TLS_SERVER_NAME}" -out server.csr || exit 1
    printf '%s\n' \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth,clientAuth" \
      "subjectAltName=DNS:${NOMAD_TLS_SERVER_NAME},DNS:localhost,IP:127.0.0.1,IP:::1" \
      "subjectKeyIdentifier=hash" \
      "authorityKeyIdentifier=keyid" >server.ext || exit 1
    serial="$(openssl rand -hex 16)" || exit 1
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -set_serial "0x${serial}" \
      -days "${NOMAD_TLS_VALID_DAYS}" -sha256 -extfile server.ext -out server.pem 2>/dev/null || exit 1
    rm -f ca-key.pem || exit 1
    openssl verify -CAfile ca.pem -purpose sslserver server.pem >/dev/null || exit 1
    mkdir -p "${dir}" && chmod 0755 "${dir}" || exit 1
    chmod 0644 ca.pem server.pem && chmod 0600 server-key.pem || exit 1
    # Replace the key first and the CA last: a reader that sees the new CA
    # also finds the certificate it signed.
    mv -f server-key.pem "${dir}/server-key.pem" || exit 1
    mv -f server.pem "${dir}/server.pem" || exit 1
    mv -f ca.pem "${dir}/ca.pem" || exit 1
  ) || status=$?
  rm -rf "${work}"
  return "${status}"
}

# nomad_tls_material_ok <dir>: succeed when <dir> holds, owned by the user
# who runs it, a server certificate for Nomad's names that ca.pem signed, the
# matching key (mode 0600), and at least NOMAD_TLS_RENEW_DAYS of validity.
nomad_tls_material_ok() {
  local dir=$1
  local file
  local check

  for file in ca.pem server.pem server-key.pem; do
    [[ -f "${dir}/${file}" && ! -L "${dir}/${file}" && -O "${dir}/${file}" ]] || return 1
  done
  [[ "$(stat -c '%a' "${dir}/server-key.pem")" == "600" ]] || return 1
  openssl verify -CAfile "${dir}/ca.pem" -purpose sslserver "${dir}/server.pem" >/dev/null 2>&1 || return 1
  openssl x509 -in "${dir}/server.pem" -noout -checkend "$((NOMAD_TLS_RENEW_DAYS * 86400))" >/dev/null 2>&1 || return 1
  # One name per call: openssl x509 honours only the last -checkip given.
  for check in "-checkhost ${NOMAD_TLS_SERVER_NAME}" "-checkhost localhost" "-checkip 127.0.0.1" "-checkip ::1"; do
    # shellcheck disable=SC2086 # option and name split on purpose
    [[ "$(openssl x509 -in "${dir}/server.pem" -noout ${check} 2>/dev/null)" == *" does match certificate" ]] || return 1
  done
  [[ "$(openssl x509 -in "${dir}/server.pem" -noout -pubkey 2>/dev/null)" == \
    "$(openssl pkey -in "${dir}/server-key.pem" -pubout 2>/dev/null)" ]] || return 1
}

# nomad_tls_spki_sha256 <certificate>: print the lowercase hex SHA-256 of the
# certificate's public key (SubjectPublicKeyInfo), the value ES pins in
# nomad.server_spki_sha256.
nomad_tls_spki_sha256() {
  local digest
  digest="$(openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r)" || return 1
  printf '%s\n' "${digest%% *}"
}

# nomad_tls_as_root <function> <args...>: run one of the functions above as
# root, so Nomad's key is created and read only by root.
nomad_tls_as_root() {
  sudo bash -c "set -euo pipefail; $(declare -p NOMAD_TLS_SERVER_NAME NOMAD_TLS_VALID_DAYS NOMAD_TLS_RENEW_DAYS); $(declare -f nomad_tls_issue nomad_tls_material_ok nomad_tls_spki_sha256); \"\$@\"" nomad-tls "$@"
}
# END nomad_tls

# Keep Nomad's TLS material while it is sound and has at least
# NOMAD_TLS_RENEW_DAYS left; otherwise issue new material, which changes the
# key ES pins (nomad.server_spki_sha256) and restarts Nomad.
install_nomad_tls_material() {
  if nomad_tls_as_root nomad_tls_material_ok "${NOMAD_TLS_DIR}"; then
    echo "nomad tls: keeping the certificate in ${NOMAD_TLS_DIR}"
    return 0
  fi
  echo "==> Issuing Nomad's TLS certificate in ${NOMAD_TLS_DIR}"
  nomad_tls_as_root nomad_tls_issue "${NOMAD_TLS_DIR}"
  NOMAD_TLS_ISSUED=1
  NOMAD_CONFIG_CHANGED=1
}

install_nomad_service_config() {
  local backup_suffix

  echo "==> Installing supported single-node Nomad service config"
  # Nomad runs as root, so only root may change what it reads or keeps
  # (audit INF-16): its config directory and data directory (Raft state and
  # the keyring) are root-owned.
  sudo install -d -o root -g root -m 0755 "${NOMAD_CONFIG_DIR}"
  sudo install -d -o root -g root -m 0700 "${NOMAD_DATA_DIR}"
  sudo install -d -o root -g root -m 0755 "${NOMAD_TLS_DIR}"
  install_nomad_tls_material

  if sudo test -f "${NOMAD_CONFIG_PATH}" && ! sudo grep -Fq "${NOMAD_MANAGED_MARKER}" "${NOMAD_CONFIG_PATH}"; then
    backup_suffix="$(date +%Y%m%d%H%M%S)"
    echo "Backing up existing Nomad config to ${NOMAD_CONFIG_BACKUP_PATH}.${backup_suffix}"
    sudo cp "${NOMAD_CONFIG_PATH}" "${NOMAD_CONFIG_BACKUP_PATH}.${backup_suffix}"
  fi

  local previous_config=""
  previous_config="$(sudo cat "${NOMAD_CONFIG_PATH}" 2>/dev/null || true)"

  cat <<EOF | sudo tee "${NOMAD_CONFIG_PATH}" >/dev/null
${NOMAD_MANAGED_MARKER}
data_dir = "${NOMAD_DATA_DIR}"
bind_addr = "127.0.0.1"

acl {
  enabled = true
}

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  # Nomad gives the node its host network from loopback, where it already
  # binds and advertises. ES jobs ask for no ports and need only that host
  # network to exist, and loopback exists whether the host is on Wi-Fi or a
  # cable. Without this line Nomad takes the default route's interface and
  # does not start while there is none (Wi-Fi not up yet); pinned to a wired
  # port, the node has no host network while the cable is out, and every ES
  # job fails to place ("missing network").
  network_interface = "lo"
  options = {
    "driver.allowlist" = "docker"
  }
}

# ES runs every task through its runtime helper on the Docker driver, so only
# that driver is enabled and the Docker plugin is limited (audit INF-02): no
# privileged containers, and only the capabilities the helper uses to prepare
# a run and drop to the workload user. ES's bind mounts need volumes enabled.
# Runtime profile images must survive image garbage collection.
plugin "docker" {
  config {
    allow_privileged = false
    allow_caps       = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]

    volumes {
      enabled = true
    }

    gc {
      image = false
    }
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

# HTTPS and RPC over TLS 1.3 only, with the certificate this script issues.
# Clients authenticate with ACL tokens, not certificates.
tls {
  http = true
  rpc  = true

  ca_file   = "${NOMAD_TLS_DIR}/ca.pem"
  cert_file = "${NOMAD_TLS_DIR}/server.pem"
  key_file  = "${NOMAD_TLS_DIR}/server-key.pem"

  verify_server_hostname = true
  verify_https_client    = false
  tls_min_version        = "tls13"
}
EOF
  sudo chown root:root "${NOMAD_CONFIG_PATH}"
  sudo chmod 0640 "${NOMAD_CONFIG_PATH}"
  if [[ "$(sudo cat "${NOMAD_CONFIG_PATH}")" != "${previous_config}" ]]; then
    NOMAD_CONFIG_CHANGED=1
  fi
}

# BEGIN nomad_acl_bootstrap (the tests run these functions on their own)
# nomad_curl <curl args...>: HTTPS to Nomad only, TLS 1.3, trusting only
# Nomad's CA, with no proxy.
nomad_curl() {
  curl --noproxy '*' --proto =https --tlsv1.3 --cacert "${NOMAD_CACERT}" --capath /dev/null "$@"
}

# require_nomad_listener: every socket listening where NOMAD_HTTP_ADDR points
# (127.0.0.1, or a wildcard address, on its port) belongs to NOMAD_SERVICE_UID.
# It reads the kernel's TCP tables, whose addresses are hex words in host byte
# order; the supported hosts (x86_64, aarch64) are little-endian.
require_nomad_listener() {
  local port
  local -a tables=()
  local table

  if [[ ! "${NOMAD_HTTP_ADDR}" =~ ^https://127\.0\.0\.1:([0-9]{1,5})/?$ ]]; then
    echo "nomad acl: ${NOMAD_HTTP_ADDR} is not https://127.0.0.1:<port>, so its listener cannot be checked; nothing was sent" >&2
    return 1
  fi
  port="$(printf '%04X' "$((10#${BASH_REMATCH[1]}))")"
  for table in /proc/net/tcp /proc/net/tcp6; do
    [[ -r "${table}" ]] && tables+=("${table}")
  done
  if (( ${#tables[@]} == 0 )) || ! awk -v port="${port}" -v want="${NOMAD_SERVICE_UID}" '
    FNR == 1 { next }
    $4 == "0A" {
      split($2, endpoint, ":")
      if (endpoint[2] != port) next
      if (endpoint[1] == "0100007F" || endpoint[1] == "00000000" ||
          endpoint[1] == "00000000000000000000000000000000" ||
          endpoint[1] == "0000000000000000FFFF00000100007F") {
        found = 1
        if ($8 != want) other = 1
      }
    }
    END { exit !(found && !other) }
  ' "${tables[@]}"; then
    echo "nomad acl: the listener on ${NOMAD_HTTP_ADDR} is missing or not owned by Nomad's user (uid ${NOMAD_SERVICE_UID}); another local account may hold Nomad's port while Nomad is down, so nothing was sent" >&2
    return 1
  fi
}

# nomad_token_curl <token> <curl args...>: the token reaches curl through a
# configuration on a file descriptor, never through a command line, and only
# a listener that Nomad's user owns.
nomad_token_curl() {
  local token=$1
  shift
  require_nomad_listener || return 1
  nomad_curl --config <(printf 'header = "X-Nomad-Token: %s"\n' "${token}") "$@"
}

# Bootstrap Nomad's ACLs once. The management secret is written root-only
# before Nomad sees it, so a lost response never loses it, and a rerun reuses
# it. Nomad needs a leader to bootstrap; it elects one a few seconds after
# start, so this is the script's one bounded wait.
bootstrap_nomad_acl() {
  local secret=""
  local created=0
  local status
  local response_path
  local leader=""
  local waited=0

  # Nomad answers "" while it elects a leader; only a named leader counts.
  while ! { leader="$(nomad_curl --fail --silent "${NOMAD_HTTP_ADDR}/v1/status/leader" 2>/dev/null)" && [[ "${leader}" =~ ^\"[^\"]+\"$ ]]; }; do
    if (( waited >= NOMAD_LEADER_WAIT_SECONDS )); then
      echo "nomad: no leader within ${NOMAD_LEADER_WAIT_SECONDS}s, so ACLs cannot be bootstrapped" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  require_nomad_listener || return 1

  if ! sudo test -d "${NOMAD_ACL_DIR}"; then
    sudo install -d -o root -g root -m 0755 "${NOMAD_ACL_DIR}"
  fi
  if sudo test -e "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}"; then
    secret="$(sudo cat "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}")"
  else
    secret="$(python3 -I -c 'import uuid; print(uuid.uuid4())')"
    printf '%s\n' "${secret}" | sudo sh -c 'umask 077 && cat > "$1"' sh "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}"
    created=1
  fi
  if [[ ! "${secret}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "nomad acl: ${NOMAD_ACL_MANAGEMENT_TOKEN_FILE} does not hold one Nomad token" >&2
    return 1
  fi

  response_path="$(mktemp)"
  status="$(nomad_token_curl "${secret}" --silent --output "${response_path}" --write-out '%{http_code}' "${NOMAD_HTTP_ADDR}/v1/acl/token/self")" || status="000"
  if [[ "${status}" == "200" ]] && grep -q '"Type":"management"' "${response_path}"; then
    cleanup_tempfiles "${response_path}"
    NOMAD_QUALIFY_TOKEN="${secret}"
    echo "nomad acl: enforced; management token in ${NOMAD_ACL_MANAGEMENT_TOKEN_FILE} (root only)"
    return 0
  fi
  if [[ "${status}" == "200" ]] && grep -q '"AccessorID":"acls-disabled"' "${response_path}"; then
    cleanup_tempfiles "${response_path}"
    echo "nomad acl: Nomad still runs without ACLs; restart nomad.service so it reads the acl block" >&2
    return 1
  fi

  if ! require_nomad_listener; then
    cleanup_tempfiles "${response_path}"
    return 1
  fi
  status="$(nomad_curl --silent --output "${response_path}" --write-out '%{http_code}' -X POST --data-binary @- \
    "${NOMAD_HTTP_ADDR}/v1/acl/bootstrap" <<<"{\"BootstrapSecret\":\"${secret}\"}")" || status="000"
  if [[ "${status}" == "200" ]]; then
    cleanup_tempfiles "${response_path}"
    NOMAD_QUALIFY_TOKEN="${secret}"
    echo "nomad acl: bootstrapped; management token in ${NOMAD_ACL_MANAGEMENT_TOKEN_FILE} (root only)"
    return 0
  fi
  if [[ "${status}" == "400" ]] && grep -qi 'bootstrap already done' "${response_path}"; then
    cleanup_tempfiles "${response_path}"
    if (( created == 1 )); then
      sudo rm -f "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}"
    fi
    echo "nomad acl: ACLs were bootstrapped before and ${NOMAD_ACL_MANAGEMENT_TOKEN_FILE} does not hold that management token; put it there (root, 0600) or follow Nomad's ACL bootstrap reset procedure, then rerun" >&2
    return 1
  fi
  echo "nomad acl: bootstrap returned HTTP ${status}: $(head -c 200 "${response_path}")" >&2
  cleanup_tempfiles "${response_path}"
  return 1
}
# END nomad_acl_bootstrap

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

# BEGIN nomad_cpu_visibility_diagnostics (the tests run this function on its own)
report_nomad_cpu_visibility_diagnostics() {
  local arch
  local virt
  local cpufreq_file_count
  local proc_cpu_mhz
  local dmi_current_speed="unavailable"

  if ! require_nomad_listener || ! NOMAD_TOKEN="${NOMAD_QUALIFY_TOKEN}" NOMAD_CACERT="${NOMAD_CACERT}" python3 -I - <<'PY' "${NOMAD_HTTP_ADDR}" >/dev/null 2>&1
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# HTTPS with TLS 1.3, trusting only Nomad's CA; no proxy and no redirects:
# a token reaches only the loopback Nomad.
nomad_tls = ssl.create_default_context(cafile=os.environ["NOMAD_CACERT"])
nomad_tls.minimum_version = ssl.TLSVersion.TLSv1_3
nomad_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=nomad_tls), _NoRedirect()
)

base_url = sys.argv[1].rstrip("/")
if not base_url.startswith("https://"):
    raise SystemExit("nomad: the Nomad address must use https")
headers = {"X-Nomad-Token": os.environ.get("NOMAD_TOKEN", "")}
try:
    nodes = json.load(nomad_opener.open(urllib.request.Request(f"{base_url}/v1/nodes", headers=headers)))
except Exception:
    raise SystemExit(1)

ready = [node for node in nodes if node.get("Status") == "ready"]
if not ready:
    raise SystemExit(1)

for node in ready:
    node_id = (node.get("ID") or "").strip()
    if not node_id:
        raise SystemExit(1)
    detail = json.load(nomad_opener.open(urllib.request.Request(f"{base_url}/v1/node/{node_id}", headers=headers)))
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
# END nomad_cpu_visibility_diagnostics

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
  # A running Nomad reads a changed config (such as the acl block) only when
  # it restarts. Jobs keep running; the client reattaches to them.
  if [[ "${NOMAD_CONFIG_CHANGED}" == "1" ]] && ! sudo systemctl restart nomad; then
    echo "nomad: failed to restart nomad.service after its config changed" >&2
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
  bootstrap_nomad_acl || return 1

  leader_path="$(mktemp)"
  agent_path="$(mktemp)"
  nodes_path="$(mktemp)"

  if ! nomad_curl --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/status/leader" >"${leader_path}"; then
    echo "nomad: leader request failed for ${NOMAD_HTTP_ADDR}/v1/status/leader" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi
  if ! nomad_token_curl "${NOMAD_QUALIFY_TOKEN}" --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/agent/self" >"${agent_path}"; then
    echo "nomad: agent self request failed for ${NOMAD_HTTP_ADDR}/v1/agent/self" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi
  if ! nomad_token_curl "${NOMAD_QUALIFY_TOKEN}" --fail-with-body --silent --show-error "${NOMAD_HTTP_ADDR}/v1/nodes" >"${nodes_path}"; then
    echo "nomad: node request failed for ${NOMAD_HTTP_ADDR}/v1/nodes" >&2
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi

  if ! require_nomad_listener; then
    cleanup_tempfiles "${leader_path}" "${agent_path}" "${nodes_path}"
    return 1
  fi
  if ! NOMAD_TOKEN="${NOMAD_QUALIFY_TOKEN}" NOMAD_CACERT="${NOMAD_CACERT}" python3 -I - <<'PY' "${NOMAD_HTTP_ADDR}" "${leader_path}" "${agent_path}" "${nodes_path}"
import json
import os
import pathlib
import ssl
import sys
import urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# HTTPS with TLS 1.3, trusting only Nomad's CA; no proxy and no redirects:
# a token reaches only the loopback Nomad.
nomad_tls = ssl.create_default_context(cafile=os.environ["NOMAD_CACERT"])
nomad_tls.minimum_version = ssl.TLSVersion.TLSv1_3
nomad_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=nomad_tls), _NoRedirect()
)

base_url = sys.argv[1].rstrip("/")
if not base_url.startswith("https://"):
    raise SystemExit("nomad: the Nomad address must use https")
headers = {"X-Nomad-Token": os.environ.get("NOMAD_TOKEN", "")}
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
    detail = json.load(nomad_opener.open(urllib.request.Request(f"{base_url}/v1/node/{node_id}", headers=headers)))
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
    # ES's jobs need a host-mode network on the node (network_interface above).
    networks = (detail.get("NodeResources") or {}).get("Networks") or []
    if not any(isinstance(network, dict) and network.get("Mode") == "host" for network in networks):
        reasons.append(f"{node_name}=no-host-network")
        continue
    schedulable.append((node_name, cpu_total_compute))

if not schedulable:
    reason = "nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network"
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

# Non-mutating Go archive selection must run before the first sudo invocation.
select_go_toolchain_archive
require_go_toolchain_archive_cleanup_trap_ownership

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
  docker.io

install_go_toolchain

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
printf 'python3: '; python3 -I --version
printf 'openssl: '; openssl version
printf 'curl: '; curl --version | head -n 1
printf 'go: '; env GOTOOLCHAIN=local go version
printf 'vault: '; vault version | head -n 1
printf 'nomad: '; nomad version | head -n 1
printf 'docker: '; docker --version

NOMAD_SERVER_SPKI_SHA256="$(nomad_tls_spki_sha256 "${NOMAD_TLS_DIR}/server.pem" 2>/dev/null)" || NOMAD_SERVER_SPKI_SHA256="<unavailable: rerun this script>"

echo
echo "==> Next steps"
echo "1. Review the governed submit bring-up runbook:"
echo "   $CLONE_DIR/.runbooks/system/v1_bringup.md"
echo "2. Review the bounded useful credential flow runbook:"
echo "   \"$CLONE_DIR/.runbooks/execution/Governed Execution ES Submit Runtime Identity Vault Login Workload.md\""
echo "3. Keep the legacy compatibility runbook only for older reference-bridge validation:"
echo "   \"$CLONE_DIR/.runbooks/execution/Governed Execution ES Submit Runtime Identity Reference Workload.md\""
echo "4. Lock Nomad so only ES can submit: run 'sudo \"$CLONE_DIR/scripts/nomad_acl_setup.sh\"' (ES_USER=<ES's user> if ES does not run as root), set nomad.token_file in ES's config to ${NOMAD_ACL_DIR}/es-token, and export NOMAD_TOKEN_FILE=${NOMAD_ACL_DIR}/observer-token for readiness checks."
echo "   In ES's config set nomad.base_url to ${NOMAD_HTTP_ADDR}, nomad.server_name to ${NOMAD_TLS_SERVER_NAME}, nomad.root_ca_file to ${NOMAD_CACERT} and nomad.server_spki_sha256 to ${NOMAD_SERVER_SPKI_SHA256}; export NOMAD_ADDR=${NOMAD_HTTP_ADDR} and NOMAD_CACERT=${NOMAD_CACERT} for the scripts and the nomad CLI."
echo "   Start the Go platform with explicit configs and TLS material. After every Nomad start, run 'sudo \"$CLONE_DIR/scripts/nomad_acl_setup.sh\" placement' with the same ES_USER and OBSERVER_USER as above (and ES_CONFIG=<ES's config> if not /etc/execution-substrate/es.json): it checks that Nomad can place ES's jobs."
echo "5. Verify the VM still reports nomad-startup-mode: pre-managed, submit-ready-mode: natural, and supported-environment: supported through scripts/01_bringup.sh check."
echo "6. Treat script-managed local Nomad startup and any compute override as bounded fallback/troubleshooting, not the supported Linux environment story."
echo "7. Use the repo-owned proof bootstrap to start the proof-scoped Vault dev/test target used by the runbook."
echo "8. Run the publish -> submit -> log verification flow from the runbooks."
echo
echo "Environment notes:"
echo "- This script assumes an apt-based Linux VM."
echo "- The supported Linux profile is Docker healthy plus a root-managed non-dev nomad.service with positive natural cpu.totalcompute and no override."
echo "- Nomad takes the node's host network from loopback (network_interface = \"lo\"), so the setup works on Wi-Fi or a cable and assumes neither."
echo "- This script writes /etc/nomad.d/nomad.hcl for the single-node loopback Nomad service used by the current one-host workload-zone profile."
echo "- That Nomad config enables ACLs; the bootstrap management token is in ${NOMAD_ACL_MANAGEMENT_TOKEN_FILE} (root only). Keep it out of ES and operator scripts."
echo "- That Nomad config disables Docker image cleanup so local runtime-profile images survive completed allocations for repeated supported-local client runs."
echo "- That Nomad config enables only the Docker driver, refuses privileged containers and allows only the capabilities ES's runtime helper uses; it and Nomad's data directory are root-owned."
echo "- That Nomad config serves its API and RPC over TLS 1.3 only, with a certificate this script issued in ${NOMAD_TLS_DIR} (key root-only; the CA's key was destroyed after signing). A rerun keeps it until fewer than ${NOMAD_TLS_RENEW_DAYS} days remain, then issues a new one: update nomad.server_spki_sha256 and restart ES after that."
echo "- If supported-substrate qualification failed above, do not treat this VM as supported yet."
echo "- If nomad.service could not start or remain healthy, fix that with root-managed host investigation instead of falling back to a user-started Nomad proof."
echo "- Some proof VMs may still need manual root investigation or bounded fallback when Nomad fingerprinting leaves cpu.totalcompute at 0."
echo "- A host that still reports cpu.totalcompute=0 under the root-managed non-dev service and exposes no usable CPU-frequency data via cpufreq sysfs, /proc/cpuinfo, or SMBIOS Current Speed is currently unsupported for the supported Linux profile."
echo "- The workload-visible Vault address must be reachable from bridge-networked containers."
if [[ "${NOMAD_TLS_ISSUED}" == "1" ]]; then
  echo "- This run issued a new Nomad certificate: its key pin is ${NOMAD_SERVER_SPKI_SHA256}. Put it in nomad.server_spki_sha256 and restart ES."
fi
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
