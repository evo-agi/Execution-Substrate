# shellcheck shell=bash
#
# Remote Alpha host firewall.
#
# Owns two nftables tables on the Remote Alpha host, "inet es_host_firewall"
# and "bridge es_host_firewall", and nothing else:
#
#   - workload containers reach the internet, the listed DNS resolvers and
#     Vault on the Docker bridge address, and nothing private: not the home
#     LAN, not the box's other services, not each other;
#   - from the LAN, the box accepts SSH from SSH_SOURCES, the ES and AGS
#     listener ports from SERVICE_CALLERS, DHCP replies and basic ICMP, and
#     drops everything else.
#
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote Alpha Host Firewall". Entry point: scripts/remote_alpha_host_firewall.sh.
# Rendering, validation and probes live in remote_alpha_host_firewall.py next
# to this file.

remote_alpha_host_firewall_schema_version="execution-substrate.remote-alpha.host-firewall.v1"

# ===========================================================================
# Editable settings
#
# Each value can be edited here or given in the environment of the same
# name. Addresses and networks are separated by spaces. The script refuses
# a value it cannot validate; it never guesses one.
# ===========================================================================
remote_alpha_host_firewall_defaults() {
  # Who may open SSH to the box. The whole home LAN by default, so that a new
  # DHCP address on the Mac never locks the box out. sshd's own key-only
  # authentication protects the login.
  : "${REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES:=192.168.1.0/24 fe80::/10}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_SSH_PORT:=22}"

  # Who may reach the ES (8445) and AGS (8444) listeners from the LAN. No
  # default: set it to the operator Mac's address, for example
  # 192.168.1.23/32. Setting the whole LAN subnet is the explicit
  # "mTLS only" fallback.
  : "${REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS:=}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_SERVICE_PORTS:=8444 8445}"

  # The one service on the box that containers may reach: the workload-zone
  # Vault listener on the Docker bridge address.
  : "${REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS:=172.17.0.1}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_VAULT_PORT:=8200}"

  # Resolvers containers may query on port 53 even when they sit in a private
  # range. "auto" picks them the way Docker does for its default bridge
  # (daemon.json "dns", else resolv.conf without loopback, else
  # systemd-resolved's upstream list) and prints the result.
  : "${REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS:=auto}"

  # Interfaces whose traffic counts as container traffic. A trailing "*"
  # matches a prefix: "br-*" covers user-defined Docker networks.
  : "${REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_INTERFACES:=docker0 br-* nomad}"

  # Bridge subnets whose containers must not reach each other at layer 2.
  # Must include the subnet of the bridge that holds VAULT_ADDRESS (docker0).
  : "${REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_BRIDGE_SUBNETS:=172.17.0.0/16}"

  # Listening sockets that the firewall makes unreachable from the LAN and
  # that an operator has checked nobody needs, as tcp/PORT or udp/PORT.
  # --apply refuses while an unlisted one exists.
  : "${REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS:=}"

  # Seconds after --apply at which the previous rules come back unless
  # --confirm ran from a new SSH connection.
  : "${REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS:=180}"

  # Probe settings (--probe only). PROBE_IMAGE must already exist locally and
  # contain "sleep"; nothing is pulled. PROBE_LAN_GATEWAY "auto" uses the
  # default IPv4 gateway; "-" skips that probe.
  : "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_IMAGE:=}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_LAN_ADDRESS:=192.168.1.156}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_LAN_GATEWAY:=auto}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_DNS_NAME:=github.com}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_INTERNET_PORT:=443}"

  # Paths. Changing them is for tests.
  : "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR:=/etc/execution-substrate/host-firewall}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH:=/etc/systemd/system/es-host-firewall.service}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR:=/run/es-host-firewall}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_DOCKER_DAEMON_JSON:=/etc/docker/daemon.json}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_RESOLV_CONF:=/etc/resolv.conf}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_SYSTEMD_RESOLV_CONF:=/run/systemd/resolve/resolv.conf}"
  : "${REMOTE_ALPHA_HOST_FIREWALL_NFTABLES_CONF:=/etc/nftables.conf}"
  # Set to 1 only when confirming at the box's own console, where no SSH
  # connection can prove that SSH still works.
  : "${REMOTE_ALPHA_HOST_FIREWALL_CONFIRM_WITHOUT_NEW_SSH:=0}"

  export REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES REMOTE_ALPHA_HOST_FIREWALL_SSH_PORT \
    REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS REMOTE_ALPHA_HOST_FIREWALL_SERVICE_PORTS \
    REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS REMOTE_ALPHA_HOST_FIREWALL_VAULT_PORT \
    REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_INTERFACES \
    REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_BRIDGE_SUBNETS REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS \
    REMOTE_ALPHA_HOST_FIREWALL_DOCKER_DAEMON_JSON REMOTE_ALPHA_HOST_FIREWALL_RESOLV_CONF \
    REMOTE_ALPHA_HOST_FIREWALL_SYSTEMD_RESOLV_CONF
}

# ===========================================================================
# End of editable settings
# ===========================================================================

remote_alpha_host_firewall_table="es_host_firewall"
remote_alpha_host_firewall_unit="es-host-firewall.service"
remote_alpha_host_firewall_rollback_unit="es-host-firewall-rollback"

remote_alpha_host_firewall_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_host_firewall.sh [--plan]
  sudo scripts/remote_alpha_host_firewall.sh --apply
  sudo scripts/remote_alpha_host_firewall.sh --confirm
  sudo scripts/remote_alpha_host_firewall.sh --status
  sudo scripts/remote_alpha_host_firewall.sh --probe
  sudo scripts/remote_alpha_host_firewall.sh --rollback
  scripts/remote_alpha_host_firewall.sh --render
  scripts/remote_alpha_host_firewall.sh --help

Modes:
  --plan      Default. Read-only: show the settings, host facts, inbound SSH
              connections, listening sockets and what the firewall does to
              each, the rendered ruleset, and every check --apply makes.
  --apply     Run the checks, arm a rollback timer, then load the ruleset.
              The previous rules come back after ROLLBACK_SECONDS unless
              --confirm runs from an SSH connection opened after --apply.
  --confirm   From a new SSH connection: install the ruleset and the
              es-host-firewall.service unit so the rules load at every boot,
              then cancel the rollback timer.
  --status    Read-only: report whether the installed rules are loaded and
              unchanged, the unit state, a pending rollback and the drop
              counters. Exit 0 only when installed and unchanged.
  --probe     Start two short-lived containers from PROBE_IMAGE and check
              from inside one of them that Vault, DNS and the internet work
              and that the box's LAN services, the LAN gateway and the other
              container are unreachable. Checks the drop counters moved.
  --rollback  Remove both tables, the unit and the installed files.
  --render    Print the ruleset for the current settings and exit.

Settings:
  The editable settings block at the top of
  scripts/internal/remote_alpha_host_firewall.sh, or environment variables of
  the same names (REMOTE_ALPHA_HOST_FIREWALL_*). SERVICE_CALLERS has no
  default and must be set.

Scope:
  Changes only the nftables tables inet and bridge es_host_firewall, the
  files under /etc/execution-substrate/host-firewall, the unit
  /etc/systemd/system/es-host-firewall.service and a transient
  es-host-firewall-rollback timer. It does not touch Docker's, ufw's or any
  other rules, sshd, Vault, Nomad or ES. It reads no secrets.

Non-claims:
  Not egress lanes (a container still reaches the whole internet), not a
  per-run network grant, not Docker or Nomad hardening, not sshd hardening.
EOF
}

remote_alpha_host_firewall_internal_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P
}

remote_alpha_host_firewall_py() {
  python3 -I -B "$(remote_alpha_host_firewall_internal_dir)/remote_alpha_host_firewall.py" "$@"
}

# Prints an error. Callers return their own status after it.
remote_alpha_host_firewall_die() {
  printf 'error: %s\n' "$*" >&2
}

remote_alpha_host_firewall_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    remote_alpha_host_firewall_die "this mode must run as root (sudo)"
    return 1
  fi
}

remote_alpha_host_firewall_require_commands() {
  local name
  for name in "$@"; do
    if ! command -v "${name}" >/dev/null 2>&1; then
      remote_alpha_host_firewall_die "${name} is required"
      return 1
    fi
  done
}

remote_alpha_host_firewall_validate_numbers() {
  if [[ ! "${REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS}" =~ ^[0-9]{2,4}$ ]] \
    || (( REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS < 60 || REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS > 1800 )); then
    remote_alpha_host_firewall_die "REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS must be 60 to 1800"
    return 1
  fi
  local path
  for path in "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR}" "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" "${REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR}"; do
    if [[ ! "${path}" =~ ^/[A-Za-z0-9_./-]+$ || "${path}" == *"/../"* || "${path}" == */.. ]]; then
      remote_alpha_host_firewall_die "${path} is not a plain absolute path"
      return 1
    fi
  done
}

remote_alpha_host_firewall_ruleset_path() {
  printf '%s/es-host-firewall.nft\n' "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR}"
}

remote_alpha_host_firewall_listing_path() {
  printf '%s/es-host-firewall.listing\n' "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR}"
}

# Prints the kernel's stateless listing of both tables (empty when absent).
remote_alpha_host_firewall_live_listing() {
  local family
  for family in inet bridge; do
    if nft list table "${family}" "${remote_alpha_host_firewall_table}" >/dev/null 2>&1; then
      nft -s list table "${family}" "${remote_alpha_host_firewall_table}"
    fi
  done
}

# A rollback is pending while its transient timer waits to fire. An elapsed
# or missing timer is not pending.
remote_alpha_host_firewall_rollback_pending() {
  [[ "$(systemctl show -p SubState --value "${remote_alpha_host_firewall_rollback_unit}.timer" 2>/dev/null)" == "waiting" ]]
}

remote_alpha_host_firewall_ssh_connections() {
  ss -H -t -n state established 2>/dev/null || true
}

remote_alpha_host_firewall_print_host_facts() {
  printf '== host facts ==\n'
  printf 'interfaces with IPv4 addresses:\n'
  ip -o -4 addr show 2>/dev/null | remote_alpha_host_firewall_py bridge-check || true
  printf 'default IPv4 route: %s\n' "$(ip -4 route show default 2>/dev/null | head -n 1)"
  if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    printf 'nftables.service: enabled'
    if grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset' "${REMOTE_ALPHA_HOST_FIREWALL_NFTABLES_CONF}" 2>/dev/null; then
      printf ' and %s flushes the whole ruleset: restarting nftables.service would also drop these rules and Docker'"'"'s; --status reports it\n' "${REMOTE_ALPHA_HOST_FIREWALL_NFTABLES_CONF}"
    else
      printf '\n'
    fi
  else
    printf 'nftables.service: not enabled\n'
  fi
  if command -v ufw >/dev/null 2>&1; then
    printf 'ufw: %s\n' "$(ufw status 2>/dev/null | head -n 1)"
  else
    printf 'ufw: not installed\n'
  fi
  if command -v iptables >/dev/null 2>&1; then
    printf 'iptables: %s\n' "$(iptables -V 2>/dev/null)"
  fi
  if [[ -d /sys/module/br_netfilter ]]; then
    printf 'br_netfilter: loaded\n'
  else
    printf 'br_netfilter: not loaded (the bridge table still isolates the listed bridge subnets)\n'
  fi
  if nft list table inet "${remote_alpha_host_firewall_table}" >/dev/null 2>&1; then
    printf 'table inet %s: loaded\n' "${remote_alpha_host_firewall_table}"
  else
    printf 'table inet %s: not loaded\n' "${remote_alpha_host_firewall_table}"
  fi
  if [[ -f "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" ]]; then
    printf 'unit %s: installed, %s\n' "${remote_alpha_host_firewall_unit}" "$(systemctl is-enabled "${remote_alpha_host_firewall_unit}" 2>/dev/null || true)"
  else
    printf 'unit %s: not installed\n' "${remote_alpha_host_firewall_unit}"
  fi
  if remote_alpha_host_firewall_rollback_pending; then
    printf 'rollback timer: PENDING (an earlier --apply awaits --confirm)\n'
  else
    printf 'rollback timer: none\n'
  fi
}

# Runs every check that --apply needs. Prints a line per check. Writes the
# rendered ruleset to "$1". Returns 0 only when every check passed.
remote_alpha_host_firewall_checks() {
  local candidate=$1
  local failed=0 ephemeral_low

  printf '== checks ==\n'
  if ! remote_alpha_host_firewall_py render >"${candidate}"; then
    printf 'render: FAIL\n'
    return 1
  fi
  printf 'render: pass (sha256 %s)\n' "$(sha256sum "${candidate}" | awk '{print $1}')"

  if nft -c -f "${candidate}" >/dev/null 2>"${candidate}.nft-check"; then
    printf 'nft -c (kernel accepts the ruleset): pass\n'
  else
    printf 'nft -c (kernel accepts the ruleset): FAIL\n'
    sed 's/^/  /' "${candidate}.nft-check"
    failed=1
  fi
  rm -f "${candidate}.nft-check"

  if ip -o -4 addr show 2>/dev/null | remote_alpha_host_firewall_py bridge-check >/dev/null; then
    printf 'container bridge holds the Vault address and is isolated: pass\n'
  else
    printf 'container bridge holds the Vault address and is isolated: FAIL (see host facts)\n'
    failed=1
  fi

  printf 'inbound SSH connections:\n'
  if remote_alpha_host_firewall_ssh_connections | remote_alpha_host_firewall_py ssh-peers; then
    printf 'current SSH peers stay allowed: pass\n'
  else
    printf 'current SSH peers stay allowed: FAIL\n'
    failed=1
  fi

  ephemeral_low=$(awk '{print $1}' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo 32768)
  printf 'listening sockets and what the firewall does to them:\n'
  if ss -H -l -n -t -u -p 2>/dev/null | remote_alpha_host_firewall_py listeners "${ephemeral_low}"; then
    printf 'every newly blocked listener is accepted: pass\n'
  else
    printf 'every newly blocked listener is accepted: FAIL\n'
    failed=1
  fi

  if remote_alpha_host_firewall_rollback_pending; then
    printf 'no earlier apply awaiting confirm: FAIL (run --confirm or --rollback first)\n'
    failed=1
  else
    printf 'no earlier apply awaiting confirm: pass\n'
  fi
  return "${failed}"
}

remote_alpha_host_firewall_plan() {
  local work candidate status=0
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft ip ss systemctl python3 sha256sum || return 1
  work=$(mktemp -d)
  candidate="${work}/candidate.nft"

  printf 'Remote Alpha host firewall: plan (read-only; nothing is changed)\n'
  printf '== settings ==\n'
  remote_alpha_host_firewall_py describe || { rm -rf "${work}"; return 2; }
  remote_alpha_host_firewall_print_host_facts
  remote_alpha_host_firewall_checks "${candidate}" || status=1
  if [[ -s "${candidate}" ]]; then
    printf '== ruleset ==\n'
    cat "${candidate}"
  fi
  if [[ "${status}" -eq 0 ]]; then
    printf 'RESULT: ready to apply\n'
  else
    printf 'RESULT: NOT ready to apply (see the FAIL lines)\n'
  fi
  rm -rf "${work}"
  return "${status}"
}

remote_alpha_host_firewall_apply() {
  local run_dir candidate rollback applied peers nft_path at work
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft ip ss systemctl systemd-run python3 sha256sum install || return 1
  run_dir="${REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR}"
  candidate="${run_dir}/candidate.nft"
  rollback="${run_dir}/rollback.nft"
  applied="${run_dir}/applied.listing"
  peers="${run_dir}/ssh-peers-at-apply"

  printf 'Remote Alpha host firewall: apply\n'
  remote_alpha_host_firewall_py describe || return 2
  work=$(mktemp -d)
  if ! remote_alpha_host_firewall_checks "${work}/candidate.nft"; then
    rm -rf "${work}"
    printf 'RESULT: not applied; nothing was changed\n'
    return 1
  fi
  # Only now, with no apply pending, replace the records of an earlier one.
  install -d -m 0700 -o root -g root "${run_dir}"
  rm -f "${candidate}" "${rollback}" "${applied}" "${peers}"
  mv "${work}/candidate.nft" "${candidate}"
  rm -rf "${work}"

  # The rollback file restores exactly what is loaded now: the current
  # tables if they exist, otherwise no tables.
  {
    printf 'table inet %s\ndelete table inet %s\n' "${remote_alpha_host_firewall_table}" "${remote_alpha_host_firewall_table}"
    printf 'table bridge %s\ndelete table bridge %s\n' "${remote_alpha_host_firewall_table}" "${remote_alpha_host_firewall_table}"
    remote_alpha_host_firewall_live_listing
  } >"${rollback}"
  chmod 0600 "${rollback}" "${candidate}"
  if ! nft -c -f "${rollback}" >/dev/null 2>&1; then
    remote_alpha_host_firewall_die "the rollback file for the current rules does not load; nothing was changed"
    return 1
  fi

  remote_alpha_host_firewall_ssh_connections | remote_alpha_host_firewall_py ssh-peer-list >"${peers}"

  # Arm the rollback before loading, so a lockout can never outlive the timer.
  nft_path=$(command -v nft)
  systemctl reset-failed "${remote_alpha_host_firewall_rollback_unit}.service" "${remote_alpha_host_firewall_rollback_unit}.timer" >/dev/null 2>&1 || true
  if ! systemd-run --quiet --collect --unit="${remote_alpha_host_firewall_rollback_unit}" \
    --description="Roll back an unconfirmed es-host-firewall apply" \
    --on-active="${REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS}s" \
    --timer-property=AccuracySec=1s \
    "${nft_path}" -f "${rollback}"; then
    remote_alpha_host_firewall_die "could not arm the rollback timer; nothing was changed"
    return 1
  fi
  if ! remote_alpha_host_firewall_rollback_pending; then
    remote_alpha_host_firewall_die "the rollback timer is not active after arming it; nothing was changed"
    return 1
  fi

  if ! nft -f "${candidate}"; then
    systemctl stop "${remote_alpha_host_firewall_rollback_unit}.timer" >/dev/null 2>&1 || true
    remote_alpha_host_firewall_die "nft refused the ruleset; the transaction changed nothing"
    return 1
  fi
  remote_alpha_host_firewall_live_listing >"${applied}"
  at=$(date -u -d "+${REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "in ${REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS} s")
  printf 'Loaded tables inet and bridge %s.\n' "${remote_alpha_host_firewall_table}"
  printf 'ROLLBACK at %s unless confirmed. Open a NEW SSH connection to the box and run --confirm with the same settings.\n' "${at}"
  printf 'RESULT: applied, awaiting confirm\n'
}

remote_alpha_host_firewall_install_file() {
  local source=$1 target=$2
  local tmp
  tmp=$(mktemp "${target}.XXXXXX")
  cat "${source}" >"${tmp}"
  chmod 0644 "${tmp}"
  chown root:root "${tmp}"
  mv -f "${tmp}" "${target}"
}

remote_alpha_host_firewall_confirm() {
  local run_dir candidate rollback applied peers rendered work ruleset_path listing_path backup_dir nft_path
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft ss systemctl python3 install || return 1
  run_dir="${REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR}"
  candidate="${run_dir}/candidate.nft"
  rollback="${run_dir}/rollback.nft"
  applied="${run_dir}/applied.listing"
  peers="${run_dir}/ssh-peers-at-apply"
  ruleset_path=$(remote_alpha_host_firewall_ruleset_path)
  listing_path=$(remote_alpha_host_firewall_listing_path)

  printf 'Remote Alpha host firewall: confirm\n'
  if ! remote_alpha_host_firewall_rollback_pending; then
    remote_alpha_host_firewall_die "no apply is awaiting confirm (no waiting rollback timer); nothing was changed"
    return 1
  fi
  if [[ ! -f "${candidate}" || ! -f "${rollback}" || ! -f "${applied}" || ! -f "${peers}" ]]; then
    remote_alpha_host_firewall_die "the apply records under ${run_dir} are missing; nothing was changed"
    return 1
  fi
  work=$(mktemp -d)
  rendered="${work}/rendered.nft"
  if ! remote_alpha_host_firewall_py render >"${rendered}" || ! cmp -s "${rendered}" "${candidate}"; then
    rm -rf "${work}"
    remote_alpha_host_firewall_die "the current settings do not render the applied ruleset; confirm with the same settings as --apply. Nothing was changed"
    return 1
  fi
  if [[ "${REMOTE_ALPHA_HOST_FIREWALL_CONFIRM_WITHOUT_NEW_SSH}" == "1" ]]; then
    printf 'new SSH connection check: skipped (REMOTE_ALPHA_HOST_FIREWALL_CONFIRM_WITHOUT_NEW_SSH=1)\n'
  elif ! remote_alpha_host_firewall_ssh_connections | remote_alpha_host_firewall_py new-ssh-peer "${peers}"; then
    rm -rf "${work}"
    remote_alpha_host_firewall_die "confirm needs an SSH connection opened after --apply, to prove SSH still works; nothing was changed"
    return 1
  fi

  # Stop the timer first, so it cannot fire half way through the install.
  # From here on a failure restores the previous rules itself.
  systemctl stop "${remote_alpha_host_firewall_rollback_unit}.timer" >/dev/null 2>&1 || true
  if remote_alpha_host_firewall_rollback_pending; then
    rm -rf "${work}"
    remote_alpha_host_firewall_die "could not stop the rollback timer; it will restore the previous rules. Nothing was installed"
    return 1
  fi
  if ! remote_alpha_host_firewall_live_listing | cmp -s - "${applied}"; then
    nft -f "${rollback}" || true
    rm -rf "${work}"
    remote_alpha_host_firewall_die "the loaded tables changed since --apply (or the rollback already ran); restored the rules from before --apply. Nothing was installed"
    return 1
  fi

  backup_dir="${work}/previous"
  mkdir -p "${backup_dir}"
  if [[ -f "${ruleset_path}" ]]; then cp -p "${ruleset_path}" "${backup_dir}/ruleset"; fi
  if [[ -f "${listing_path}" ]]; then cp -p "${listing_path}" "${backup_dir}/listing"; fi
  if [[ -f "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" ]]; then cp -p "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" "${backup_dir}/unit"; fi

  nft_path=$(command -v nft)
  if ! {
    install -d -m 0755 -o root -g root "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR}" \
      && remote_alpha_host_firewall_install_file "${candidate}" "${ruleset_path}" \
      && remote_alpha_host_firewall_py render-unit "${ruleset_path}" "${nft_path}" >"${work}/unit" \
      && remote_alpha_host_firewall_install_file "${work}/unit" "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" \
      && systemctl daemon-reload \
      && systemctl enable --quiet "${remote_alpha_host_firewall_unit}" \
      && systemctl restart "${remote_alpha_host_firewall_unit}" \
      && remote_alpha_host_firewall_live_listing | cmp -s - "${applied}" \
      && remote_alpha_host_firewall_install_file "${applied}" "${listing_path}"
  }; then
    printf 'install failed; restoring the previous files and the rules from before --apply\n' >&2
    if [[ -f "${backup_dir}/ruleset" ]]; then cp -p "${backup_dir}/ruleset" "${ruleset_path}"; else rm -f "${ruleset_path}"; fi
    if [[ -f "${backup_dir}/listing" ]]; then cp -p "${backup_dir}/listing" "${listing_path}"; else rm -f "${listing_path}"; fi
    if [[ -f "${backup_dir}/unit" ]]; then
      cp -p "${backup_dir}/unit" "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}"
    else
      systemctl disable --quiet "${remote_alpha_host_firewall_unit}" >/dev/null 2>&1 || true
      rm -f "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    nft -f "${rollback}" || printf 'error: nft could not restore the rules from before --apply\n' >&2
    rm -rf "${work}"
    return 1
  fi

  rm -f "${candidate}" "${rollback}" "${applied}" "${peers}"
  rm -rf "${work}"
  printf 'Installed %s and %s (enabled). Rollback timer cancelled.\n' "${ruleset_path}" "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}"
  printf 'RESULT: confirmed\n'
}

remote_alpha_host_firewall_status() {
  local ruleset_path listing_path status=0 work
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft systemctl python3 || return 1
  ruleset_path=$(remote_alpha_host_firewall_ruleset_path)
  listing_path=$(remote_alpha_host_firewall_listing_path)
  printf 'Remote Alpha host firewall: status (read-only)\n'
  if remote_alpha_host_firewall_rollback_pending; then
    printf 'rollback timer: PENDING (an apply awaits --confirm)\n'
    status=3
  fi
  if [[ ! -f "${ruleset_path}" || ! -f "${listing_path}" ]]; then
    printf 'installed ruleset: none\n'
    [[ "${status}" -eq 0 ]] && status=1
  else
    printf 'installed ruleset: %s (sha256 %s)\n' "${ruleset_path}" "$(sha256sum "${ruleset_path}" | awk '{print $1}')"
    if remote_alpha_host_firewall_live_listing | cmp -s - "${listing_path}"; then
      printf 'loaded tables: match the installed ruleset\n'
    else
      printf 'loaded tables: DIFFER from the installed ruleset (missing, edited or replaced)\n'
      [[ "${status}" -eq 0 ]] && status=1
    fi
    work=$(mktemp -d)
    if remote_alpha_host_firewall_py render >"${work}/rendered.nft" 2>/dev/null && cmp -s "${work}/rendered.nft" "${ruleset_path}"; then
      printf 'current settings: render the installed ruleset\n'
    else
      printf 'current settings: do not render the installed ruleset (settings or host resolvers changed; --plan shows the new one)\n'
    fi
    rm -rf "${work}"
  fi
  if systemctl is-enabled --quiet "${remote_alpha_host_firewall_unit}" 2>/dev/null; then
    printf 'unit %s: enabled\n' "${remote_alpha_host_firewall_unit}"
  else
    printf 'unit %s: NOT enabled\n' "${remote_alpha_host_firewall_unit}"
    [[ "${status}" -eq 0 ]] && status=1
  fi
  if systemctl is-enabled --quiet nftables.service 2>/dev/null \
    && grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset' "${REMOTE_ALPHA_HOST_FIREWALL_NFTABLES_CONF}" 2>/dev/null; then
    printf 'warning: nftables.service is enabled and flushes the whole ruleset when restarted\n'
  fi
  if nft list table inet "${remote_alpha_host_firewall_table}" >/dev/null 2>&1; then
    printf 'drop counters:\n'
    nft list counters table inet "${remote_alpha_host_firewall_table}" 2>/dev/null | awk '/counter /{name=$2} /packets/{print "  " name " " $0}' | sed 's/[[:space:]]\+/ /g'
    nft list counters table bridge "${remote_alpha_host_firewall_table}" 2>/dev/null | awk '/counter /{name=$2} /packets/{print "  " name " " $0}' | sed 's/[[:space:]]\+/ /g'
  fi
  case "${status}" in
    0) printf 'RESULT: installed and unchanged\n' ;;
    3) printf 'RESULT: apply awaiting confirm\n' ;;
    *) printf 'RESULT: not installed or changed\n' ;;
  esac
  return "${status}"
}

remote_alpha_host_firewall_rollback() {
  local ruleset_path listing_path work
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft systemctl || return 1
  ruleset_path=$(remote_alpha_host_firewall_ruleset_path)
  listing_path=$(remote_alpha_host_firewall_listing_path)
  printf 'Remote Alpha host firewall: rollback (remove)\n'
  systemctl stop "${remote_alpha_host_firewall_rollback_unit}.timer" >/dev/null 2>&1 || true
  if [[ -f "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}" ]]; then
    systemctl disable --quiet "${remote_alpha_host_firewall_unit}" >/dev/null 2>&1 || true
    rm -f "${REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH}"
    systemctl daemon-reload
    systemctl reset-failed "${remote_alpha_host_firewall_unit}" >/dev/null 2>&1 || true
  fi
  work=$(mktemp -d)
  printf 'table inet %s\ndelete table inet %s\ntable bridge %s\ndelete table bridge %s\n' \
    "${remote_alpha_host_firewall_table}" "${remote_alpha_host_firewall_table}" \
    "${remote_alpha_host_firewall_table}" "${remote_alpha_host_firewall_table}" >"${work}/remove.nft"
  if ! nft -f "${work}/remove.nft"; then
    rm -rf "${work}"
    remote_alpha_host_firewall_die "nft could not remove the tables"
    return 1
  fi
  rm -rf "${work}"
  rm -f "${ruleset_path}" "${listing_path}"
  rmdir "${REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR}" 2>/dev/null || true
  rm -rf "${REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR}"
  if [[ -n "$(remote_alpha_host_firewall_live_listing)" ]]; then
    remote_alpha_host_firewall_die "the tables are still loaded after removal"
    return 1
  fi
  printf 'RESULT: removed (tables, unit and installed files)\n'
}

remote_alpha_host_firewall_counter_value() {
  local family=$1 name=$2
  nft list counter "${family}" "${remote_alpha_host_firewall_table}" "${name}" 2>/dev/null \
    | awk '/packets/{for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}'
}

remote_alpha_host_firewall_probe() {
  local image gateway work label a b pid_a ip_b status=0 before after name family
  remote_alpha_host_firewall_require_root || return 1
  remote_alpha_host_firewall_require_commands nft ip docker nsenter python3 || return 1
  image="${REMOTE_ALPHA_HOST_FIREWALL_PROBE_IMAGE}"
  if [[ -z "${image}" || ! "${image}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]]; then
    remote_alpha_host_firewall_die "REMOTE_ALPHA_HOST_FIREWALL_PROBE_IMAGE must name a local image that contains sleep"
    return 1
  fi
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    remote_alpha_host_firewall_die "image ${image} is not present locally; the probe never pulls"
    return 1
  fi
  if ! nft list table inet "${remote_alpha_host_firewall_table}" >/dev/null 2>&1; then
    remote_alpha_host_firewall_die "table inet ${remote_alpha_host_firewall_table} is not loaded; nothing to probe"
    return 1
  fi
  gateway="${REMOTE_ALPHA_HOST_FIREWALL_PROBE_LAN_GATEWAY}"
  if [[ "${gateway}" == "auto" ]]; then
    gateway=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "via") {print $(i + 1); exit}}')
    [[ -n "${gateway}" ]] || gateway="-"
  fi

  label="es-host-firewall-probe-$$"
  a="${label}-a"
  b="${label}-b"
  work=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "docker rm -f '${a}' '${b}' >/dev/null 2>&1 || true; rm -rf '${work}'; trap - RETURN" RETURN

  for name in "${a}" "${b}"; do
    if ! docker run -d --rm --pull=never --network bridge --name "${name}" \
      --label es-host-firewall-probe=1 --entrypoint sleep "${image}" 300 >/dev/null; then
      remote_alpha_host_firewall_die "could not start probe container ${name}"
      return 1
    fi
  done
  pid_a=$(docker inspect -f '{{.State.Pid}}' "${a}")
  ip_b=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${b}")
  if [[ ! "${pid_a}" =~ ^[0-9]+$ || "${pid_a}" == "0" || -z "${ip_b}" ]]; then
    remote_alpha_host_firewall_die "could not read the probe containers' PID and address"
    return 1
  fi

  if ! remote_alpha_host_firewall_py probe-plan "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_LAN_ADDRESS}" "${gateway}" "${ip_b}" \
    "/proc/${pid_a}/root/etc/resolv.conf" "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_DNS_NAME}" \
    "${REMOTE_ALPHA_HOST_FIREWALL_PROBE_INTERNET_PORT}" >"${work}/plan.json"; then
    return 1
  fi

  declare -A before_counts=()
  for name in container_to_host container_to_private; do
    before_counts["inet:${name}"]=$(remote_alpha_host_firewall_counter_value inet "${name}")
  done
  before_counts["bridge:container_to_container"]=$(remote_alpha_host_firewall_counter_value bridge container_to_container)

  printf 'Remote Alpha host firewall: probe from container %s (image %s)\n' "${a}" "${image}"
  if ! nsenter -t "${pid_a}" -n python3 -I -B "$(remote_alpha_host_firewall_internal_dir)/remote_alpha_host_firewall.py" probe "${work}/plan.json"; then
    status=1
  fi

  printf 'drop counters that must have moved:\n'
  for key in "inet:container_to_host" "inet:container_to_private" "bridge:container_to_container"; do
    family=${key%%:*}
    name=${key#*:}
    if [[ "${name}" == "container_to_private" && "${gateway}" == "-" ]]; then
      continue
    fi
    before=${before_counts[${key}]:-0}
    after=$(remote_alpha_host_firewall_counter_value "${family}" "${name}")
    if [[ -n "${after}" && "${after}" =~ ^[0-9]+$ && "${after}" -gt "${before:-0}" ]]; then
      printf '  PASS %s %s: %s -> %s\n' "${family}" "${name}" "${before}" "${after}"
    else
      printf '  FAIL %s %s: %s -> %s\n' "${family}" "${name}" "${before}" "${after:-?}"
      status=1
    fi
  done
  if [[ "${status}" -eq 0 ]]; then
    printf 'RESULT: probe passed\n'
  else
    printf 'RESULT: probe FAILED\n'
  fi
  return "${status}"
}

remote_alpha_host_firewall_main() {
  local mode="plan"
  if [[ $# -gt 1 ]]; then
    remote_alpha_host_firewall_die "give at most one mode; see --help"
    return 2
  fi
  case "${1:-}" in
    ""|--plan) mode="plan" ;;
    --apply) mode="apply" ;;
    --confirm) mode="confirm" ;;
    --status) mode="status" ;;
    --probe) mode="probe" ;;
    --rollback) mode="rollback" ;;
    --render) mode="render" ;;
    --help|-h)
      remote_alpha_host_firewall_usage
      return 0
      ;;
    *)
      remote_alpha_host_firewall_die "unknown argument: $1; settings are environment variables, see --help"
      return 2
      ;;
  esac
  remote_alpha_host_firewall_defaults
  remote_alpha_host_firewall_validate_numbers || return 2
  remote_alpha_host_firewall_require_commands python3 || return 1
  case "${mode}" in
    render) remote_alpha_host_firewall_py render ;;
    plan) remote_alpha_host_firewall_plan ;;
    apply) remote_alpha_host_firewall_apply ;;
    confirm) remote_alpha_host_firewall_confirm ;;
    status) remote_alpha_host_firewall_status ;;
    probe) remote_alpha_host_firewall_probe ;;
    rollback) remote_alpha_host_firewall_rollback ;;
  esac
}
