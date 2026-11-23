"""Remote Alpha host firewall: settings validation, ruleset rendering, host
analysis and container probes.

This file is run only by scripts/internal/remote_alpha_host_firewall.sh, as
``python3 -I -B remote_alpha_host_firewall.py <subcommand>``. It reads its
settings from REMOTE_ALPHA_HOST_FIREWALL_* environment variables, which the
shell script fills from its editable settings block. It never changes the host:
every effect (nft, systemctl, systemd-run, docker) is run by the shell script.

The contract is documented in
.docs/system_overview/remote_supported_host_alpha.md, section
"Remote Alpha Host Firewall".
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time

SCHEMA = "execution-substrate.remote-alpha.host-firewall.v1"
TABLE = "es_host_firewall"
UNIT_NAME = "es-host-firewall.service"

# Destinations a workload container must never reach directly. IPv4: "this"
# network, RFC 1918 private ranges, shared address space (carrier-grade NAT,
# also used by mesh VPNs), loopback, link-local, IETF protocol assignments,
# benchmarking, multicast and reserved space. IPv6: loopback, IPv4-mapped,
# unique local, link-local and multicast.
BLOCKED_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
BLOCKED_V6 = (
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

IFNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,14}\*?$|^[A-Za-z0-9_.-]{15}$")
LISTENER_TOKEN_RE = re.compile(r"^(tcp|udp)/([0-9]{1,5})$")

COUNTERS_INET = (
    "container_to_private",
    "container_to_host",
    "into_container",
    "lan_to_host",
    "invalid_in",
)
COUNTERS_BRIDGE = ("container_to_container",)


class SettingsError(Exception):
    pass


def env(name, default=None):
    value = os.environ.get("REMOTE_ALPHA_HOST_FIREWALL_" + name)
    if value is None:
        if default is None:
            raise SettingsError(f"REMOTE_ALPHA_HOST_FIREWALL_{name} is not set")
        return default
    return value


def words(value):
    return [item for item in value.replace(",", " ").split() if item]


def parse_port(name, raw):
    if not re.fullmatch(r"[0-9]{1,5}", raw or ""):
        raise SettingsError(f"{name}: {raw!r} is not a port number")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise SettingsError(f"{name}: {port} is outside 1-65535")
    return port


def parse_networks(name, raw, required):
    networks = []
    for item in words(raw):
        if not re.fullmatch(r"[0-9A-Fa-f:./]+", item):
            raise SettingsError(f"{name}: {item!r} is not an address or network")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            raise SettingsError(
                f"{name}: {item!r} is not an address or network with host bits zero"
            ) from None
        if network.prefixlen == 0:
            raise SettingsError(f"{name}: {item!r} would match every address")
        if network not in networks:
            networks.append(network)
    if required and not networks:
        raise SettingsError(f"{name} must name at least one address or network")
    return networks


def parse_address(name, raw):
    if not re.fullmatch(r"[0-9A-Fa-f:.]+", raw or ""):
        raise SettingsError(f"{name}: {raw!r} is not an IP address")
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        raise SettingsError(f"{name}: {raw!r} is not an IP address") from None


def parse_ifnames(name, raw):
    names = []
    for item in words(raw):
        if not IFNAME_RE.fullmatch(item):
            raise SettingsError(
                f"{name}: {item!r} is not an interface name (at most 15 characters "
                "of letters, digits, '_', '.', '-', optionally ending in '*')"
            )
        if item not in names:
            names.append(item)
    if not names:
        raise SettingsError(f"{name} must name at least one interface")
    return names


def is_loopback(address):
    return address.is_loopback or (
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None
        and address.ipv4_mapped.is_loopback
    )


def read_nameservers(path):
    servers = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1].split("%", 1)[0])
    except FileNotFoundError:
        return None
    return servers


def auto_dns_servers():
    """Return (servers, source) the way Docker picks resolvers for containers
    on its default bridge. daemon.json "dns" wins. Otherwise Docker reads
    /etc/resolv.conf, or systemd-resolved's upstream list when /etc/resolv.conf
    names only the stub 127.0.0.53; it then drops loopback resolvers, and
    IPv6 resolvers unless daemon.json enables IPv6. With none left Docker
    falls back to public resolvers, which need no exception here."""
    daemon_json = env("DOCKER_DAEMON_JSON", "/etc/docker/daemon.json")
    try:
        with open(daemon_json, encoding="utf-8") as handle:
            config = json.load(handle)
    except FileNotFoundError:
        config = {}
    except (OSError, ValueError) as exc:
        raise SettingsError(f"cannot read {daemon_json}: {exc.__class__.__name__}") from None
    if not isinstance(config, dict):
        raise SettingsError(f"{daemon_json}: not a JSON object")
    if config.get("dns"):
        dns = config["dns"]
        if not isinstance(dns, list) or not all(isinstance(item, str) for item in dns):
            raise SettingsError(f"{daemon_json}: \"dns\" is not a list of strings")
        return dns, daemon_json
    ipv6 = config.get("ipv6") is True
    path = env("RESOLV_CONF", "/etc/resolv.conf")
    servers = read_nameservers(path)
    if servers == ["127.0.0.53"]:
        path = env("SYSTEMD_RESOLV_CONF", "/run/systemd/resolve/resolv.conf")
        servers = read_nameservers(path)
    if not servers:
        return [], "none (Docker falls back to public resolvers)"
    kept = []
    dropped_ipv6 = False
    for item in servers:
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            continue
        if is_loopback(address):
            continue
        if address.version == 6 and not ipv6:
            dropped_ipv6 = True
            continue
        kept.append(item)
    if not kept:
        return [], f"none usable in {path} (Docker falls back to public resolvers)"
    source = path + (", IPv6 resolvers dropped as Docker does without IPv6" if dropped_ipv6 else "")
    return kept, source


def load_settings():
    settings = {}
    settings["ssh_port"] = parse_port("SSH_PORT", env("SSH_PORT"))
    settings["ssh_sources"] = parse_networks("SSH_SOURCES", env("SSH_SOURCES"), True)
    settings["service_ports"] = []
    for raw in words(env("SERVICE_PORTS")):
        port = parse_port("SERVICE_PORTS", raw)
        if port not in settings["service_ports"]:
            settings["service_ports"].append(port)
    if not settings["service_ports"]:
        raise SettingsError("SERVICE_PORTS must name at least one port")
    if settings["ssh_port"] in settings["service_ports"]:
        raise SettingsError("SERVICE_PORTS must not contain SSH_PORT")
    settings["service_callers"] = parse_networks(
        "SERVICE_CALLERS", env("SERVICE_CALLERS"), True
    )
    settings["vault_address"] = parse_address("VAULT_ADDRESS", env("VAULT_ADDRESS"))
    settings["vault_port"] = parse_port("VAULT_PORT", env("VAULT_PORT"))
    settings["container_interfaces"] = parse_ifnames(
        "CONTAINER_INTERFACES", env("CONTAINER_INTERFACES")
    )
    settings["container_bridge_subnets"] = parse_networks(
        "CONTAINER_BRIDGE_SUBNETS", env("CONTAINER_BRIDGE_SUBNETS"), True
    )
    for network in settings["container_bridge_subnets"]:
        if network.version != 4:
            raise SettingsError("CONTAINER_BRIDGE_SUBNETS takes IPv4 networks only")
    raw_dns = env("CONTAINER_DNS_SERVERS").strip()
    if raw_dns == "auto":
        servers, source = auto_dns_servers()
        settings["dns_source"] = source
        raw_dns = " ".join(servers)
    else:
        settings["dns_source"] = "REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS"
    dns = []
    for item in words(raw_dns):
        address = parse_address("CONTAINER_DNS_SERVERS", item)
        if is_loopback(address):
            raise SettingsError(
                "CONTAINER_DNS_SERVERS: a loopback resolver is not reachable from a container"
            )
        if address not in dns:
            dns.append(address)
    settings["dns_servers"] = dns
    accepted = []
    for item in words(env("ACCEPT_BLOCKED_LISTENERS", "")):
        match = LISTENER_TOKEN_RE.fullmatch(item)
        if not match:
            raise SettingsError(
                f"ACCEPT_BLOCKED_LISTENERS: {item!r} is not of the form tcp/PORT or udp/PORT"
            )
        parse_port("ACCEPT_BLOCKED_LISTENERS", match.group(2))
        accepted.append(f"{match.group(1)}/{int(match.group(2))}")
    settings["accept_blocked_listeners"] = accepted
    return settings


def nft_set(items):
    return "{ " + ", ".join(str(item) for item in items) + " }"


def split_versions(networks):
    return (
        [item for item in networks if item.version == 4],
        [item for item in networks if item.version == 6],
    )


def render(settings):
    lines = []
    add = lines.append
    ports = nft_set(settings["service_ports"])
    exact_ifnames = [name for name in settings["container_interfaces"] if not name.endswith("*")]
    wildcard_ifnames = [name for name in settings["container_interfaces"] if name.endswith("*")]

    def iif_matches():
        matches = []
        if exact_ifnames:
            matches.append("iifname " + nft_set(f'"{name}"' for name in exact_ifnames))
        matches.extend(f'iifname "{name}"' for name in wildcard_ifnames)
        return matches

    def oif_matches():
        matches = []
        if exact_ifnames:
            matches.append("oifname " + nft_set(f'"{name}"' for name in exact_ifnames))
        matches.extend(f'oifname "{name}"' for name in wildcard_ifnames)
        return matches

    add("#!/usr/sbin/nft -f")
    add("# Managed by Execution-Substrate scripts/remote_alpha_host_firewall.sh.")
    add(f"# Schema: {SCHEMA}")
    add("# Do not edit by hand. Change the settings and run the script again;")
    add("# --status reports any difference between this file and the kernel.")
    add("#")
    add("# Settings:")
    add(f"#   ssh_port = {settings['ssh_port']}")
    add(f"#   ssh_sources = {' '.join(map(str, settings['ssh_sources']))}")
    add(f"#   service_ports = {' '.join(map(str, settings['service_ports']))}")
    add(f"#   service_callers = {' '.join(map(str, settings['service_callers']))}")
    add(f"#   vault = {settings['vault_address']} tcp/{settings['vault_port']}")
    add(f"#   container_interfaces = {' '.join(settings['container_interfaces'])}")
    add(
        "#   container_bridge_subnets = "
        + " ".join(map(str, settings["container_bridge_subnets"]))
    )
    add(
        "#   container_dns_servers = "
        + (" ".join(map(str, settings["dns_servers"])) or "(none)")
        + f" (from {settings['dns_source']})"
    )
    add("")
    add("# Replace both tables in one transaction. The empty declarations make the")
    add("# deletes succeed when a table does not exist yet. Nothing outside these")
    add("# two tables is touched: Docker's and any other rules stay as they are.")
    add(f"table inet {TABLE}")
    add(f"delete table inet {TABLE}")
    add(f"table bridge {TABLE}")
    add(f"delete table bridge {TABLE}")
    add("")
    add(f"table inet {TABLE} {{")
    for name in COUNTERS_INET:
        add(f"\tcounter {name} {{")
        add("\t}")
        add("")
    add("\t# Inbound to the box. Default deny: only loopback, replies, the listed")
    add("\t# LAN services and Vault for containers are accepted. A drop here is")
    add("\t# final even when another table accepts the packet.")
    add("\tchain input {")
    add("\t\ttype filter hook input priority filter - 10; policy drop;")
    add('\t\tiifname "lo" accept')
    add('\t\tct state invalid counter name "invalid_in" drop')
    add("\t\tct state { established, related } accept")
    for match in iif_matches():
        add(f"\t\t{match} goto container_to_host")
    add("\t\tgoto lan_to_host")
    add("\t}")
    add("")
    add("\t# Containers may reach exactly one service on the box: Vault.")
    add("\tchain container_to_host {")
    vault_family = "ip" if settings["vault_address"].version == 4 else "ip6"
    add(
        f"\t\t{vault_family} daddr {settings['vault_address']} "
        f"tcp dport {settings['vault_port']} accept"
    )
    add('\t\tcounter name "container_to_host" drop')
    add("\t}")
    add("")
    add("\t# Everything else that arrives: the home LAN.")
    add("\tchain lan_to_host {")
    add(
        "\t\ticmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
    )
    add("\t\ticmp type echo-request limit rate 10/second accept")
    add(
        "\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, "
        "parameter-problem, nd-router-advert, nd-neighbor-solicit, "
        "nd-neighbor-advert, mld-listener-query } accept"
    )
    add("\t\ticmpv6 type echo-request limit rate 10/second accept")
    add("\t\tudp sport 67 udp dport 68 accept")
    add("\t\tip6 saddr fe80::/10 udp sport 547 udp dport 546 accept")
    ssh_v4, ssh_v6 = split_versions(settings["ssh_sources"])
    if ssh_v4:
        add(f"\t\tip saddr {nft_set(ssh_v4)} tcp dport {settings['ssh_port']} accept")
    if ssh_v6:
        add(f"\t\tip6 saddr {nft_set(ssh_v6)} tcp dport {settings['ssh_port']} accept")
    callers_v4, callers_v6 = split_versions(settings["service_callers"])
    if callers_v4:
        add(f"\t\tip saddr {nft_set(callers_v4)} tcp dport {ports} accept")
    if callers_v6:
        add(f"\t\tip6 saddr {nft_set(callers_v6)} tcp dport {ports} accept")
    add('\t\tlimit rate 6/minute log prefix "es-host-firewall lan drop: "')
    add('\t\tcounter name "lan_to_host" drop')
    add("\t}")
    add("")
    add("\t# Routed traffic. Container egress is checked by destination; new")
    add("\t# connections into containers are allowed only through Docker's")
    add("\t# published-port DNAT. Other forwarded traffic is left to Docker.")
    add("\tchain forward {")
    add("\t\ttype filter hook forward priority filter - 10; policy accept;")
    for match in iif_matches():
        add(f"\t\t{match} goto container_egress")
    for match in oif_matches():
        add(f'\t\t{match} ct state new ct status != dnat counter name "into_container" drop')
    add("\t}")
    add("")
    add("\t# Containers reach the internet, the listed resolvers on port 53, and")
    add("\t# nothing private: not the home LAN, not other containers.")
    add("\tchain container_egress {")
    dns_v4, dns_v6 = split_versions(settings["dns_servers"])
    for family, servers in (("ip", dns_v4), ("ip6", dns_v6)):
        if servers:
            add(f"\t\t{family} daddr {nft_set(servers)} udp dport 53 accept")
            add(f"\t\t{family} daddr {nft_set(servers)} tcp dport 53 accept")
    add(f'\t\tip daddr {nft_set(BLOCKED_V4)} counter name "container_to_private" drop')
    add(f'\t\tip6 daddr {nft_set(BLOCKED_V6)} counter name "container_to_private" drop')
    add("\t}")
    add("}")
    add("")
    add("# Containers on the same bridge talk at layer 2 and do not pass the inet")
    add("# forward hook unless br_netfilter is loaded. This table blocks that path")
    add("# whatever the br_netfilter state. Traffic to the bridge's own address")
    add("# is local delivery, not bridge forwarding, so Vault stays reachable.")
    add(f"table bridge {TABLE} {{")
    for name in COUNTERS_BRIDGE:
        add(f"\tcounter {name} {{")
        add("\t}")
        add("")
    add("\tchain forward {")
    add("\t\ttype filter hook forward priority filter - 10; policy accept;")
    for network in settings["container_bridge_subnets"]:
        add(
            f"\t\tether type ip ip saddr {network} ip daddr {network} "
            'counter name "container_to_container" drop'
        )
    add("\t}")
    add("}")
    return "\n".join(lines) + "\n"


def render_unit(ruleset_path, nft_path):
    return "\n".join(
        [
            "# Managed by Execution-Substrate scripts/remote_alpha_host_firewall.sh.",
            f"# Schema: {SCHEMA}",
            "[Unit]",
            "Description=Execution Substrate Remote Alpha host firewall (nftables tables "
            f"inet and bridge {TABLE})",
            "Documentation=https://github.com/evo-agi/Execution-Substrate/blob/trunk_dev/"
            ".docs/system_overview/remote_supported_host_alpha.md",
            "DefaultDependencies=no",
            "Wants=network-pre.target",
            "Before=network-pre.target docker.service nomad.service shutdown.target",
            "After=nftables.service",
            "Conflicts=shutdown.target",
            f"RequiresMountsFor={os.path.dirname(ruleset_path)}",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "StandardInput=null",
            f"ExecStart={nft_path} -f {ruleset_path}",
            f"ExecReload={nft_path} -f {ruleset_path}",
            "",
            "[Install]",
            "WantedBy=sysinit.target",
            "",
        ]
    )


def cmd_render(_args):
    settings = load_settings()
    sys.stdout.write(render(settings))


def cmd_render_unit(args):
    if len(args) != 2:
        raise SettingsError("render-unit needs RULESET_PATH NFT_PATH")
    for value in args:
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or "/../" in value:
            raise SettingsError(f"render-unit: {value!r} is not a plain absolute path")
    sys.stdout.write(render_unit(args[0], args[1]))


def cmd_describe(_args):
    settings = load_settings()
    text = render(settings)
    print(f"schema: {SCHEMA}")
    print(f"ruleset_sha256: {hashlib.sha256(text.encode('utf-8')).hexdigest()}")
    print(f"ssh: tcp/{settings['ssh_port']} from {' '.join(map(str, settings['ssh_sources']))}")
    print(
        "services: tcp/"
        + ",".join(map(str, settings["service_ports"]))
        + " from "
        + " ".join(map(str, settings["service_callers"]))
    )
    print(f"vault for containers: {settings['vault_address']} tcp/{settings['vault_port']}")
    print(
        "container dns servers: "
        + (" ".join(map(str, settings["dns_servers"])) or "(none)")
        + f" (from {settings['dns_source']})"
    )
    print(f"container interfaces: {' '.join(settings['container_interfaces'])}")
    print(
        "container bridge subnets: "
        + " ".join(map(str, settings["container_bridge_subnets"]))
    )
    print(
        "accepted blocked listeners: "
        + (" ".join(settings["accept_blocked_listeners"]) or "(none)")
    )


def parse_ss_address(text):
    """Split an ss local address column into (address or None for any, port)."""
    host, _, port = text.rpartition(":")
    if not port.isdigit():
        return None, None
    host = host.strip("[]")
    host = host.split("%", 1)[0]
    if host in ("*", "0.0.0.0", "::", ""):
        return None, int(port)
    try:
        return ipaddress.ip_address(host), int(port)
    except ValueError:
        return "unparsed:" + host, int(port)


def scope_is_loopback(text):
    host = text.rpartition(":")[0]
    return "%lo" in host


def cmd_listeners(args):
    """Classify listening sockets (``ss -H -l -n -t -u -p`` output on stdin)
    by who can reach them once the ruleset is loaded. Exit 0 when every
    socket that becomes unreachable from the LAN is accepted in
    ACCEPT_BLOCKED_LISTENERS, else 3."""
    settings = load_settings()
    ephemeral_low = 32768
    if args:
        try:
            ephemeral_low = int(args[0])
        except ValueError:
            raise SettingsError("listeners: ephemeral port floor is not a number") from None
    vault = settings["vault_address"]
    unaccepted = []
    rows = []
    seen = set()
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 5:
            continue
        proto = fields[0]
        if proto not in ("tcp", "udp"):
            continue
        state = fields[1]
        if proto == "tcp" and state != "LISTEN":
            continue
        local = fields[4]
        process = " ".join(fields[6:]) if len(fields) > 6 else ""
        match = re.search(r'users:\(\("([^"]+)"', process)
        owner = match.group(1) if match else "?"
        address, port = parse_ss_address(local)
        if port is None:
            continue
        key = (proto, local)
        if key in seen:
            continue
        seen.add(key)
        token = f"{proto}/{port}"
        if scope_is_loopback(local) or (
            isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            and is_loopback(address)
        ):
            verdict = "loopback only (unchanged)"
        elif proto == "tcp" and port == settings["ssh_port"]:
            verdict = "LAN: from " + " ".join(map(str, settings["ssh_sources"])) + "; containers: blocked"
        elif proto == "tcp" and port in settings["service_ports"]:
            verdict = "LAN: from " + " ".join(map(str, settings["service_callers"])) + "; containers: blocked"
        elif proto == "tcp" and port == settings["vault_port"] and address == vault:
            verdict = "containers only (Vault); LAN: blocked"
        elif proto == "udp" and port in (68, 546):
            verdict = "DHCP client replies only"
        elif proto == "udp" and port >= ephemeral_low:
            verdict = "ephemeral client socket (replies only)"
        elif token in settings["accept_blocked_listeners"]:
            verdict = "BLOCKED from LAN and containers (accepted in settings)"
        else:
            verdict = "BLOCKED from LAN and containers (NOT accepted)"
            unaccepted.append(token)
        rows.append((proto, local, owner, verdict))
    for proto, local, owner, verdict in sorted(rows):
        print(f"  {proto:<4} {local:<40} {owner:<20} {verdict}")
    if unaccepted:
        tokens = " ".join(sorted(set(unaccepted)))
        print(
            "listeners that would become unreachable and are not accepted: "
            f"{tokens}. Add them to REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS "
            "after checking nobody needs them, or allow them in the settings."
        )
        return 3
    return 0


def cmd_ssh_peers(args):
    """Check that every peer of an established inbound SSH connection
    (``ss -H -t -n state established`` lines on stdin, local port SSH_PORT)
    is inside SSH_SOURCES. Prints the peers. Exit 4 when one is not."""
    settings = load_settings()
    outside = []
    peers = []
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 4:
            continue
        # With "state established" ss omits the State column:
        # Recv-Q Send-Q Local:Port Peer:Port [Process]
        local, peer = fields[2], fields[3]
        _, local_port = parse_ss_address(local)
        if local_port != settings["ssh_port"]:
            continue
        address, port = parse_ss_address(peer)
        if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            continue
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        peers.append(f"{address}:{port}")
        if is_loopback(address):
            continue
        if not any(address in network for network in settings["ssh_sources"] if network.version == address.version):
            outside.append(str(address))
    for peer in peers:
        print(f"  ssh peer {peer}")
    if not peers:
        print("  no inbound SSH connection (not run over SSH)")
    if outside:
        print(
            "these SSH peers are outside REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES and "
            "could not open a new SSH connection after apply: "
            + " ".join(sorted(set(outside)))
        )
        return 4
    return 0


def cmd_new_ssh_peer(args):
    """Exit 0 when stdin (current established SSH connections, ss format)
    holds a peer address:port that is not in the file args[0] (the list
    recorded at apply), else 5."""
    if len(args) != 1:
        raise SettingsError("new-ssh-peer needs the recorded peer file")
    settings = load_settings()
    with open(args[0], encoding="utf-8") as handle:
        recorded = {line.strip() for line in handle if line.strip()}
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 4:
            continue
        _, local_port = parse_ss_address(fields[2])
        if local_port != settings["ssh_port"]:
            continue
        if fields[3] not in recorded:
            print(f"  new ssh connection from {fields[3]}")
            return 0
    print("  no SSH connection opened after apply was found")
    return 5


def cmd_ssh_peer_list(_args):
    settings = load_settings()
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 4:
            continue
        _, local_port = parse_ss_address(fields[2])
        if local_port == settings["ssh_port"]:
            print(fields[3])
    return 0


# ---------------------------------------------------------------------------
# Probe, run inside a container's network namespace (nsenter -n) with the
# host's python3. It only opens sockets; it writes nothing.
# ---------------------------------------------------------------------------


def tcp_attempt(host, port, timeout):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return "connected"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as exc:
        return "error:" + (exc.strerror or exc.__class__.__name__).replace(" ", "_")
    finally:
        sock.close()


def dns_query(server, name, timeout):
    query_id = int(time.time() * 1000) & 0xFFFF
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")
    ) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return "timeout", []
    except OSError as exc:
        return "error:" + (exc.strerror or exc.__class__.__name__).replace(" ", "_"), []
    finally:
        sock.close()
    if len(data) < 12:
        return "short_reply", []
    reply_id, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if reply_id != query_id or flags & 0x000F != 0:
        return f"rcode_{flags & 0x000F}", []
    addresses = []
    offset = 12
    # Skip the question.
    while offset < len(data) and data[offset] != 0:
        if data[offset] & 0xC0 == 0xC0:
            offset += 1
            break
        offset += data[offset] + 1
    offset += 5
    for _ in range(ancount):
        if offset >= len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(data[offset : offset + 4]))
        offset += rdlength
    return ("answer" if addresses else "no_address"), addresses


def cmd_probe(args):
    """Run the probe plan given as a JSON file (args[0]). Prints one line per
    probe and exits 0 when every probe met its expectation, else 6."""
    if len(args) != 1:
        raise SettingsError("probe needs the plan file")
    with open(args[0], encoding="utf-8") as handle:
        plan = json.load(handle)
    timeout = float(plan.get("timeout", 3))
    failures = 0
    resolved = []
    for probe in plan["probes"]:
        kind = probe["kind"]
        if kind == "dns":
            outcome = "no_resolver"
            for server in probe["servers"]:
                outcome, addresses = dns_query(server, probe["name"], timeout)
                if addresses:
                    resolved = addresses
                    break
            ok = outcome == "answer"
            detail = f"{probe['name']} via {' '.join(probe['servers']) or '(none)'}"
        elif kind == "tcp_resolved":
            if not resolved:
                outcome, ok = "nothing_resolved", False
            else:
                outcome = tcp_attempt(resolved[0], probe["port"], timeout)
                ok = outcome == probe["expect"]
            detail = f"{resolved[0] if resolved else '?'}:{probe['port']}"
        else:
            outcome = tcp_attempt(probe["host"], probe["port"], timeout)
            ok = outcome == probe["expect"]
            detail = f"{probe['host']}:{probe['port']}"
        if not ok:
            failures += 1
        expect = probe.get("expect", "answer")
        print(
            f"  {'PASS' if ok else 'FAIL'} {probe['label']:<28} {detail:<28} "
            f"expected {expect}, got {outcome}"
        )
    return 0 if failures == 0 else 6


def ifname_matches(name, patterns):
    for pattern in patterns:
        if pattern.endswith("*"):
            if name.startswith(pattern[:-1]):
                return True
        elif name == pattern:
            return True
    return False


def cmd_bridge_check(_args):
    """Read ``ip -o -4 addr show`` on stdin. Report every interface with an
    IPv4 address as container side or LAN side, and whether container
    bridges are isolated at layer 2. Exit 7 unless the interface that holds
    VAULT_ADDRESS is a container interface whose subnet is listed in
    CONTAINER_BRIDGE_SUBNETS."""
    settings = load_settings()
    vault = settings["vault_address"]
    vault_ok = False
    vault_seen = False
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        name = fields[1].split("@", 1)[0]
        try:
            interface = ipaddress.ip_interface(fields[3])
        except ValueError:
            continue
        if name == "lo":
            continue
        container = ifname_matches(name, settings["container_interfaces"])
        isolated = interface.network in settings["container_bridge_subnets"]
        holds_vault = interface.ip == vault
        side = "container side" if container else "LAN side (inbound default deny)"
        extra = ""
        if container:
            extra = (
                "; containers isolated from each other at layer 2"
                if isolated
                else "; NOT isolated at layer 2 (inet forward rule only, needs br_netfilter)"
            )
        if holds_vault:
            vault_seen = True
            vault_ok = container and isolated
            extra += "; holds the Vault address"
        print(f"  {name:<16} {interface.with_prefixlen:<20} {side}{extra}")
    if not vault_seen:
        print(
            f"  no interface holds the Vault address {vault}: containers could not reach Vault"
        )
        return 7
    if not vault_ok:
        print(
            "  the interface that holds the Vault address must be a container interface "
            "listed in CONTAINER_INTERFACES with its subnet in CONTAINER_BRIDGE_SUBNETS"
        )
        return 7
    return 0


def cmd_probe_plan(args):
    """Print the probe plan as JSON. args: LAN_ADDRESS GATEWAY PEER_IP
    RESOLV_CONF DNS_NAME INTERNET_PORT. GATEWAY may be '-' to skip the LAN
    gateway probe."""
    if len(args) != 6:
        raise SettingsError(
            "probe-plan needs LAN_ADDRESS GATEWAY PEER_IP RESOLV_CONF DNS_NAME INTERNET_PORT"
        )
    settings = load_settings()
    lan_address = str(parse_address("PROBE lan address", args[0]))
    gateway = None if args[1] == "-" else str(parse_address("PROBE gateway", args[1]))
    peer = str(parse_address("PROBE peer container", args[2]))
    resolv_conf = args[3]
    dns_name = args[4]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", dns_name):
        raise SettingsError(f"PROBE_DNS_NAME: {dns_name!r} is not a host name")
    internet_port = parse_port("PROBE_INTERNET_PORT", args[5])
    servers = read_nameservers(resolv_conf) or []
    vault = str(settings["vault_address"])
    probes = [
        {"label": "vault", "kind": "tcp", "host": vault, "port": settings["vault_port"], "expect": "connected"},
    ]
    for port in settings["service_ports"]:
        probes.append({"label": f"box lan tcp/{port}", "kind": "tcp", "host": lan_address, "port": port, "expect": "timeout"})
    probes.append({"label": f"box lan ssh", "kind": "tcp", "host": lan_address, "port": settings["ssh_port"], "expect": "timeout"})
    probes.append({"label": "box bridge ssh", "kind": "tcp", "host": vault, "port": settings["ssh_port"], "expect": "timeout"})
    if gateway:
        probes.append({"label": "lan gateway tcp/80", "kind": "tcp", "host": gateway, "port": 80, "expect": "timeout"})
    probes.append({"label": "other container tcp/9", "kind": "tcp", "host": peer, "port": 9, "expect": "timeout"})
    probes.append({"label": "dns", "kind": "dns", "name": dns_name, "servers": servers, "expect": "answer"})
    probes.append({"label": f"internet tcp/{internet_port}", "kind": "tcp_resolved", "port": internet_port, "expect": "connected"})
    json.dump({"timeout": 3, "probes": probes}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


COMMANDS = {
    "bridge-check": cmd_bridge_check,
    "probe-plan": cmd_probe_plan,
    "render": cmd_render,
    "render-unit": cmd_render_unit,
    "describe": cmd_describe,
    "listeners": cmd_listeners,
    "ssh-peers": cmd_ssh_peers,
    "ssh-peer-list": cmd_ssh_peer_list,
    "new-ssh-peer": cmd_new_ssh_peer,
    "probe": cmd_probe,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print("usage: remote_alpha_host_firewall.py " + "|".join(COMMANDS), file=sys.stderr)
        return 2
    try:
        result = COMMANDS[argv[1]](argv[2:])
    except SettingsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return result or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
