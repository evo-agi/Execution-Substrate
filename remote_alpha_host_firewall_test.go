package executionsubstrate_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests for scripts/remote_alpha_host_firewall.sh and its internal files.
// The contract is .docs/system_overview/remote_supported_host_alpha.md,
// section "Remote Alpha Host Firewall".

func remoteAlphaHostFirewallScript() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_host_firewall.sh")
}

// hostFirewallBaseEnv returns the process environment without any
// REMOTE_ALPHA_HOST_FIREWALL_* value, with fakeBin (when set) first on PATH,
// plus the fixed test settings and then extra.
func hostFirewallBaseEnv(t *testing.T, fakeBin string, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	settings := map[string]string{
		"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS":       "192.168.1.23/32",
		"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS": "192.168.1.1",
		"REMOTE_ALPHA_HOST_FIREWALL_DOCKER_DAEMON_JSON":    filepath.Join(dir, "absent-daemon.json"),
		"REMOTE_ALPHA_HOST_FIREWALL_RESOLV_CONF":           filepath.Join(dir, "absent-resolv.conf"),
		"REMOTE_ALPHA_HOST_FIREWALL_SYSTEMD_RESOLV_CONF":   filepath.Join(dir, "absent-systemd-resolv.conf"),
		"REMOTE_ALPHA_HOST_FIREWALL_NFTABLES_CONF":         filepath.Join(dir, "absent-nftables.conf"),
		"REMOTE_ALPHA_HOST_FIREWALL_SETTINGS_FILE":         filepath.Join(dir, "absent-settings.env"),
	}
	for key, value := range hostFirewallSSHDFixture(t, dir) {
		settings[key] = value
	}
	for _, entry := range extra {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("bad env entry %q", entry)
		}
		settings[key] = value
	}
	var env []string
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "REMOTE_ALPHA_HOST_FIREWALL_") {
			continue
		}
		if key == "PATH" && fakeBin != "" {
			value = fakeBin + string(os.PathListSeparator) + value
		}
		env = append(env, key+"="+value)
	}
	for key, value := range settings {
		env = append(env, key+"="+value)
	}
	return env
}

// hostFirewallSSHDFixture writes a small sshd configuration tree shaped like
// Ubuntu's (sshd_config includes sshd_config.d/*.conf first, and a later
// drop-in turns passwords on) and returns the settings that point at it.
// sshd_config itself turns keyboard-interactive login and X11 forwarding on,
// so every check sees the drop-in's own values win.
func hostFirewallSSHDFixture(t *testing.T, dir string) map[string]string {
	t.Helper()
	sshdDir := filepath.Join(dir, "ssh")
	dropInDir := filepath.Join(sshdDir, "sshd_config.d")
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(sshdDir, "sshd_config")
	writeFile(t, config, []byte("Include "+dropInDir+"/*.conf\nKbdInteractiveAuthentication yes\nX11Forwarding yes\nUsePAM yes\n"), 0o644)
	writeFile(t, filepath.Join(dropInDir, "50-cloud-init.conf"), []byte("PasswordAuthentication yes\n"), 0o644)
	return map[string]string{
		"REMOTE_ALPHA_HOST_FIREWALL_SSHD_CONFIG":  config,
		"REMOTE_ALPHA_HOST_FIREWALL_SSHD_DROP_IN": filepath.Join(dropInDir, "00-execution-substrate-host-access.conf"),
		"REMOTE_ALPHA_HOST_FIREWALL_SSHD_SERVICE": "ssh.service",
	}
}

// hostFirewallFakeSSHD emulates sshd -t and -T for the tests that do not
// need the real sshd: first value wins, Include globs are expanded in place,
// a Match Address block (exact addresses only) ends at the end of its file.
// FAKE_SSHD_T_FAIL makes -t fail; FAKE_SSHD_WRONG_FOR=<config> makes -T on
// that config report passwords on for every address.
const hostFirewallFakeSSHD = `#!/bin/bash
mode="" config="" spec=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|-T) mode=$1; shift ;;
    -f) config=$2; shift 2 ;;
    -C) spec=$2; shift 2 ;;
    *) shift ;;
  esac
done
if [[ "$mode" == "-t" ]]; then
  [[ -n "${FAKE_SSHD_T_FAIL:-}" ]] && { echo "fake sshd: bad configuration" >&2; exit 1; }
  exit 0
fi
addr=${spec##*addr=}
expand() {
  local line g
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^Include[[:space:]]+(.*)$ ]]; then
      for g in ${BASH_REMATCH[1]}; do [[ -f "$g" ]] && expand "$g"; done
    else
      printf '%s\n' "$line"
    fi
  done <"$1"
  echo "#END-OF-FILE"
}
declare -A global=() inmatch=()
in_match=0 matched=0
while IFS= read -r line; do
  [[ "$line" == "#END-OF-FILE" ]] && { in_match=0; continue; }
  line="${line#"${line%%[![:space:]]*}"}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  key=${line%%[[:space:]]*}; key=${key,,}; value=${line#*[[:space:]]}; value=${value,,}
  if [[ "$key" == match ]]; then
    in_match=1; matched=0
    IFS=, read -ra nets <<<"${value#address }"
    for n in "${nets[@]}"; do [[ "$n" == "$addr" || "$n" == "$addr/32" || "$n" == "$addr/128" ]] && matched=1; done
    continue
  fi
  if (( in_match )); then
    (( matched )) && [[ -z "${inmatch[$key]+x}" ]] && inmatch[$key]=$value
    continue
  fi
  [[ -z "${global[$key]+x}" ]] && global[$key]=$value
done < <(expand "$config")
for k in passwordauthentication kbdinteractiveauthentication x11forwarding; do
  v=${inmatch[$k]:-${global[$k]:-yes}}
  [[ -n "${FAKE_SSHD_WRONG_FOR:-}" && "$config" == "$FAKE_SSHD_WRONG_FOR" && "$k" == passwordauthentication ]] && v=yes
  echo "$k $v"
done
`

func runHostFirewall(t *testing.T, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("/bin/bash", append([]string{remoteAlphaHostFirewallScript()}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run host firewall %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func runHostFirewallPython(t *testing.T, env []string, stdin string, args ...string) (string, int) {
	t.Helper()
	// Through the shell file, so the Python sees the same settings defaults
	// as the script does.
	internal := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_host_firewall.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\nremote_alpha_host_firewall_defaults\nremote_alpha_host_firewall_py \"$@\"\n", internal)
	cmd := exec.Command("/bin/bash", append([]string{"-c", script, "host-firewall-py"}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	output, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run host firewall python %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return string(output), code
}

func TestRemoteAlphaHostFirewallRenderMatchesGolden(t *testing.T) {
	stdout, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--render")
	if code != 0 {
		t.Fatalf("render exit %d\nstderr=%s", code, stderr)
	}
	golden := mustRead(t, filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_host_firewall", "ruleset.golden.nft"))
	if stdout != golden {
		t.Fatalf("rendered ruleset differs from testdata/remote_alpha_host_firewall/ruleset.golden.nft\n--- got ---\n%s", stdout)
	}

	unit, code := runHostFirewallPython(t, hostFirewallBaseEnv(t, ""), "", "render-unit", "/etc/execution-substrate/host-firewall/es-host-firewall.nft", "/usr/sbin/nft")
	if code != 0 {
		t.Fatalf("render-unit exit %d: %s", code, unit)
	}
	goldenUnit := mustRead(t, filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_host_firewall", "es-host-firewall.service.golden"))
	if unit != goldenUnit {
		t.Fatalf("rendered unit differs from testdata/remote_alpha_host_firewall/es-host-firewall.service.golden\n--- got ---\n%s", unit)
	}
}

func TestRemoteAlphaHostFirewallRulesetInvariants(t *testing.T) {
	stdout, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, "",
		"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=192.168.1.23 2001:db8::23",
		"REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES=192.168.1.0/24",
	), "--render")
	if code != 0 {
		t.Fatalf("render exit %d\nstderr=%s", code, stderr)
	}
	assertContainsAll(t, "ruleset", stdout,
		// Only our two tables are replaced, in one transaction.
		"table inet es_host_firewall\ndelete table inet es_host_firewall\ntable bridge es_host_firewall\ndelete table bridge es_host_firewall\n",
		// Inbound default deny, loopback first.
		"type filter hook input priority filter - 10; policy drop;\n\t\tiifname \"lo\" accept",
		// Containers reach only Vault on the box.
		"ip daddr 172.17.0.1 tcp dport 8200 accept\n\t\tcounter name \"container_to_host\" drop",
		// LAN callers: IPv4 and IPv6 forms of the setting, exact host addresses.
		"ip saddr { 192.168.1.23/32 } tcp dport { 8444, 8445 } accept",
		"ip6 saddr { 2001:db8::23/128 } tcp dport { 8444, 8445 } accept",
		"ip saddr { 192.168.1.0/24 } tcp dport 22 accept",
		// Private destinations are dropped for container egress.
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
		"fc00::/7", "fe80::/10",
		// Invalid packets are dropped before anything is accepted, and echo
		// requests are rate-limited.
		"ct state invalid counter name \"invalid_in\" drop",
		"icmp type echo-request limit rate 10/second accept",
		// Layer-2 isolation of the Vault bridge: IPv4 by destination only
		// (a forged source does not help), and no IPv6 between bridge ports.
		"ether type ip ip daddr 172.17.0.0/16 counter name \"container_to_container\" drop\n\t\tether type ip6 counter name \"container_to_container\" drop\n",
		// Nothing new is forwarded into a container, published ports included.
		"oifname { \"docker0\", \"nomad\" } ct state new counter name \"into_container\" drop",
		// The box's own connections to Vault keep the bridge address as their
		// source: an identity snat, before Docker's masquerade (srcnat), as
		// the last chain of the inet table.
		"\tchain host_to_vault_source {\n\t\ttype nat hook postrouting priority srcnat - 10; policy accept;\n"+
			"\t\toifname \"lo\" ip saddr 172.17.0.1 ip daddr 172.17.0.1 tcp dport 8200 counter name \"host_to_vault_source_kept\" snat ip to 172.17.0.1\n\t}\n}\n",
	)
	assertContainsNone(t, "ruleset", stdout,
		"flush ruleset",
		"ip6 saddr { fe80::/10 } tcp dport 22",
		"policy drop;\n\t\tiifname \"docker0\"",
		"ip saddr 172.17.0.0/16 ip daddr 172.17.0.0/16",
		"ct status",
	)
	// The invalid-state drop comes before replies are accepted.
	input := stdout[strings.Index(stdout, "type filter hook input"):]
	if invalid, accept := strings.Index(input, "ct state invalid"), strings.Index(input, "ct state { established, related } accept"); invalid < 0 || accept < 0 || invalid > accept {
		t.Fatalf("the invalid-state drop must precede the reply accept: invalid=%d accept=%d", invalid, accept)
	}
	// The only address rewrite is the identity snat for the box's own
	// connections to Vault.
	var rules []string
	for _, line := range strings.Split(stdout, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			rules = append(rules, trimmed)
		}
	}
	nat := 0
	for _, rule := range rules {
		for _, statement := range []string{"masquerade", "dnat to", "redirect", "snat to", "dnat ip", "dnat ip6"} {
			if strings.Contains(rule, statement) {
				t.Errorf("unexpected address rewrite %q in rule %q", statement, rule)
			}
		}
		if strings.Contains(rule, " snat ") {
			nat++
		}
	}
	if nat != 1 {
		t.Fatalf("exactly one snat rule (the identity snat for the box's Vault connections), got %d", nat)
	}

	// An IPv6 Vault address renders the same rules for ip6.
	v6, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS=fd00:17::1"), "--render")
	if code != 0 {
		t.Fatalf("render with an IPv6 Vault address: exit %d\nstderr=%s", code, stderr)
	}
	assertContainsAll(t, "ruleset with an IPv6 Vault address", v6,
		"ip6 daddr fd00:17::1 tcp dport 8200 accept",
		"oifname \"lo\" ip6 saddr fd00:17::1 ip6 daddr fd00:17::1 tcp dport 8200 counter name \"host_to_vault_source_kept\" snat ip6 to [fd00:17::1]",
	)
	// The DNS exception comes before the private-range drop.
	dnsIndex := strings.Index(stdout, "ip daddr { 192.168.1.1 } udp dport 53 accept")
	dropIndex := strings.Index(stdout, "counter name \"container_to_private\" drop")
	if dnsIndex < 0 || dropIndex < 0 || dnsIndex > dropIndex {
		t.Fatalf("DNS exception must precede the private-range drop: dns=%d drop=%d", dnsIndex, dropIndex)
	}
}

// TestRemoteAlphaHostFirewallHostVaultSource checks the source check against
// a local listener standing in for Vault: kept when Vault sees its own
// address, unknown when nothing listens or the address is not local. The
// rewritten case needs a NAT rule and runs in the real-kernel lab.
func TestRemoteAlphaHostFirewallHostVaultSource(t *testing.T) {
	for _, c := range []struct{ name, network, address string }{
		{"ipv4", "tcp4", "127.0.0.1"},
		{"ipv6", "tcp6", "::1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if runtime.GOOS != "linux" {
				t.Skip("reads /proc/net/tcp; the box is Linux")
			}
			listener, err := net.Listen(c.network, net.JoinHostPort(c.address, "0"))
			if err != nil {
				if c.name == "ipv6" {
					t.Skipf("no IPv6 loopback here (%v): the /proc/net/tcp6 path is not exercised", err)
				}
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
				}
			}()
			env := hostFirewallBaseEnv(t, "",
				"REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS="+c.address,
				fmt.Sprintf("REMOTE_ALPHA_HOST_FIREWALL_VAULT_PORT=%d", port),
			)
			output, code := runHostFirewallPython(t, env, "", "host-vault-source")
			if code != 0 || strings.TrimSpace(output) != "host to Vault source: kept (Vault sees "+c.address+")" {
				t.Fatalf("with a listener: exit %d\n%s", code, output)
			}
			_ = listener.Close()
			output, code = runHostFirewallPython(t, env, "", "host-vault-source")
			if code != 9 || !strings.Contains(output, fmt.Sprintf("host to Vault source: unknown (no connection to %s:%d: ConnectionRefusedError)", c.address, port)) {
				t.Fatalf("without a listener: exit %d\n%s", code, output)
			}
		})
	}
	// 192.0.2.1 (TEST-NET-1) is not an address of this host: nothing is tried.
	output, code := runHostFirewallPython(t, hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS=192.0.2.1"), "", "host-vault-source")
	if code != 9 || strings.TrimSpace(output) != "host to Vault source: unknown (192.0.2.1 is not an address of this host)" {
		t.Fatalf("with a non-local Vault address: exit %d\n%s", code, output)
	}
}

func TestRemoteAlphaHostFirewallRejectsInvalidSettings(t *testing.T) {
	cases := []struct {
		name  string
		env   []string
		error string
	}{
		{"callers unset", []string{"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS="}, "SERVICE_CALLERS must name at least one"},
		{"callers whole internet", []string{"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=0.0.0.0/0"}, "would match every address"},
		{"callers injection", []string{"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=192.168.1.23;flush"}, "is not an address or network"},
		{"callers host bits", []string{"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=192.168.1.23/24"}, "host bits zero"},
		{"ssh sources empty", []string{"REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES= "}, "SSH_SOURCES must name at least one"},
		{"service port is ssh", []string{"REMOTE_ALPHA_HOST_FIREWALL_SERVICE_PORTS=22 8445"}, "must not contain SSH_PORT"},
		{"port out of range", []string{"REMOTE_ALPHA_HOST_FIREWALL_VAULT_PORT=70000"}, "outside 1-65535"},
		{"interface with quote", []string{"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_INTERFACES=docker0 eth\"0"}, "is not an interface name"},
		{"interface too long", []string{"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_INTERFACES=abcdefghijklmnop"}, "is not an interface name"},
		{"interface star inside", []string{"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_INTERFACES=br*x"}, "is not an interface name"},
		{"bridge subnet ipv6", []string{"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_BRIDGE_SUBNETS=fd00::/64"}, "IPv4 networks only"},
		{"dns loopback", []string{"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS=127.0.0.53"}, "loopback resolver"},
		{"vault network", []string{"REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS=172.17.0.1/16"}, "is not an IP address"},
		{"accept token", []string{"REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS=tcp:5353"}, "tcp/PORT or udp/PORT"},
		{"rollback too short", []string{"REMOTE_ALPHA_HOST_FIREWALL_ROLLBACK_SECONDS=5"}, "ROLLBACK_SECONDS must be 60 to 1800"},
		{"state dir relative", []string{"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR=etc/x"}, "is not a plain absolute path"},
		{"state dir dotdot", []string{"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR=/etc/../tmp"}, "is not a plain absolute path"},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			stdout, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, "", tc.env...), "--render")
			if code != 2 {
				t.Fatalf("expected exit 2, got %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.error) {
				t.Fatalf("expected error containing %q, got %q", tc.error, stderr)
			}
			if strings.TrimSpace(stdout) != "" {
				t.Fatalf("a refused render must print no ruleset, got %q", stdout)
			}
		})
	}
}

func TestRemoteAlphaHostFirewallSettingsFile(t *testing.T) {
	dir := t.TempDir()
	settingsFile := filepath.Join(dir, "settings.env")
	// Base env without SERVICE_CALLERS, so the file has to supply it.
	env := func(extra ...string) []string {
		all := hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_SETTINGS_FILE="+settingsFile)
		kept := all[:0]
		for _, entry := range all {
			if !strings.HasPrefix(entry, "REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=") {
				kept = append(kept, entry)
			}
		}
		return append(kept, extra...)
	}

	// Without the file and without the variable, SERVICE_CALLERS is missing.
	if _, stderr, code := runHostFirewall(t, env(), "--render"); code != 2 || !strings.Contains(stderr, "SERVICE_CALLERS") {
		t.Fatalf("expected refusal without SERVICE_CALLERS, got exit %d: %s", code, stderr)
	}

	// The file supplies the host's values; comments, blank lines, quoted and
	// unquoted values are accepted.
	writeFile(t, settingsFile, []byte("# Devices that may reach ES and AGS.\nSERVICE_CALLERS=\"192.168.1.210/32 192.168.1.211\"\n\n  # indented comment\nSERVICE_PORTS=8444 8445\n"), 0o644)
	stdout, stderr, code := runHostFirewall(t, env(), "--render")
	if code != 0 {
		t.Fatalf("render with settings file: exit %d: %s", code, stderr)
	}
	assertContainsAll(t, "settings file values", stdout,
		"ip saddr { 192.168.1.210/32, 192.168.1.211/32 } tcp dport { 8444, 8445 } accept",
	)

	// A non-empty environment variable wins over the file.
	stdout, _, code = runHostFirewall(t, env("REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=192.168.1.99/32"), "--render")
	if code != 0 || !strings.Contains(stdout, "ip saddr { 192.168.1.99/32 } tcp dport") || strings.Contains(stdout, "192.168.1.210") {
		t.Fatalf("expected the environment to win over the file, got exit %d\n%s", code, stdout)
	}

	// Refusals: the file is parsed, never sourced.
	marker := filepath.Join(dir, "sourced-marker")
	for _, tc := range []struct {
		name, content, want string
	}{
		{"unknown name", "SERVICE_CALLERS=192.168.1.210/32\nSTATE_DIR=/tmp\n", "unknown setting STATE_DIR"},
		{"set twice", "SERVICE_CALLERS=192.168.1.210/32\nSERVICE_CALLERS=192.168.1.0/24\n", "SERVICE_CALLERS is set twice"},
		{"not an assignment", "SERVICE_CALLERS 192.168.1.210/32\n", "expected NAME="},
		{"command substitution", "SERVICE_CALLERS=\"$(touch " + marker + ")\"\n", "not allowed"},
		{"backquote", "SERVICE_CALLERS=`touch " + marker + "`\n", "not allowed"},
		{"inner quote", "SERVICE_CALLERS=\"192.168.1.210/32\" \"x\"\n", "not allowed"},
		{"single quotes", "SERVICE_CALLERS='192.168.1.210/32'\n", "not allowed"},
		{"backslash", "SERVICE_CALLERS=192.168.1.210/32\\\n", "not allowed"},
		{"lower case name", "service_callers=192.168.1.210/32\n", "expected NAME="},
	} {
		writeFile(t, settingsFile, []byte(tc.content), 0o644)
		_, stderr, code := runHostFirewall(t, env(), "--render")
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: expected exit 2 with %q, got exit %d: %s", tc.name, tc.want, code, stderr)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("a settings file value was executed")
	}

	// A symlink is refused.
	target := filepath.Join(dir, "target.env")
	writeFile(t, target, []byte("SERVICE_CALLERS=192.168.1.210/32\n"), 0o644)
	if err := os.Remove(settingsFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, settingsFile); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runHostFirewall(t, env(), "--render"); code != 2 || !strings.Contains(stderr, "not a regular file") {
		t.Fatalf("expected symlink refusal, got exit %d: %s", code, stderr)
	}
	if err := os.Remove(settingsFile); err != nil {
		t.Fatal(err)
	}

	// Run as root, the file must belong to root and not be group or world
	// writable.
	if os.Geteuid() == 0 {
		writeFile(t, settingsFile, []byte("SERVICE_CALLERS=192.168.1.210/32\n"), 0o664)
		if err := os.Chmod(settingsFile, 0o664); err != nil {
			t.Fatal(err)
		}
		if _, stderr, code := runHostFirewall(t, env(), "--render"); code != 2 || !strings.Contains(stderr, "must belong to root and not be writable") {
			t.Fatalf("expected refusal of a group-writable settings file, got exit %d: %s", code, stderr)
		}
		if err := os.Chmod(settingsFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(settingsFile, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, stderr, code := runHostFirewall(t, env(), "--render"); code != 2 || !strings.Contains(stderr, "must belong to root") {
			t.Fatalf("expected refusal of a settings file owned by another user, got exit %d: %s", code, stderr)
		}
	}
}

// TestRemoteAlphaHostFirewallSSHDDropInWithRealSSHD checks the rendered
// sshd drop-in against the real sshd's own evaluation (sshd -T), in a
// configuration tree shaped like Ubuntu's where a later drop-in and
// sshd_config itself turn passwords and X11 forwarding on. It needs sshd and
// ssh-keygen and skips itself without them;
// .github/ci/environment-only-tests.txt lists it.
func TestRemoteAlphaHostFirewallSSHDDropInWithRealSSHD(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		if _, statErr := os.Stat("/usr/sbin/sshd"); statErr != nil {
			t.Skip("needs sshd (openssh-server) to check the drop-in against the real sshd")
		}
		sshd = "/usr/sbin/sshd"
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("needs ssh-keygen to make a host key for sshd -t")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: sshd -t checks its privilege separation setup")
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		t.Fatalf("sshd -t needs /run/sshd: %v", err)
	}
	dir := t.TempDir()
	fixture := hostFirewallSSHDFixture(t, dir)
	config := fixture["REMOTE_ALPHA_HOST_FIREWALL_SSHD_CONFIG"]
	dropIn := fixture["REMOTE_ALPHA_HOST_FIREWALL_SSHD_DROP_IN"]
	hostKey := filepath.Join(dir, "host_ed25519")
	if output, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, output)
	}
	writeFile(t, config, []byte(mustRead(t, config)+"HostKey "+hostKey+"\n"), 0o644)
	sshdBin := filepath.Dir(sshd)

	env := hostFirewallBaseEnv(t, "",
		"REMOTE_ALPHA_HOST_FIREWALL_SSH_PASSWORD_SOURCES=192.168.1.210/32",
		"REMOTE_ALPHA_HOST_FIREWALL_SSHD_CONFIG="+config,
		"REMOTE_ALPHA_HOST_FIREWALL_SSHD_DROP_IN="+dropIn,
	)
	for i, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			env[i] = entry + string(os.PathListSeparator) + sshdBin
		}
	}
	internal := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_host_firewall.sh")
	run := func(call string) (string, int) {
		t.Helper()
		script := fmt.Sprintf("source %q\nremote_alpha_host_firewall_defaults\n%s\n", internal, call)
		cmd := exec.Command("/bin/bash", "-c", script)
		cmd.Dir = executionSubstrateRepoRoot
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(output), code
	}

	// Before: the fixture lets passwords and X11 in from everywhere.
	if output, code := run("remote_alpha_host_firewall_sshd_check " + config); code == 0 || !strings.Contains(output, "FAIL  from 192.0.2.1") {
		t.Fatalf("without the drop-in sshd must allow passwords elsewhere: %d\n%s", code, output)
	}

	// The plan-time simulation, with the drop-in not installed yet.
	candidate := filepath.Join(dir, "candidate-sshd.conf")
	output, code := run("remote_alpha_host_firewall_sshd_checks " + candidate)
	if code != 0 {
		t.Fatalf("simulated sshd checks: %d\n%s", code, output)
	}
	assertContainsAll(t, "simulated sshd checks", output,
		"sshd -t (configuration valid): pass",
		"pass  from 192.168.1.210",
		"pass  from 192.0.2.1",
		"pass  from 2001:db8::1",
		"pass  from 192.168.1.1",
		"pass  from fe80::1",
	)

	// Installed where it belongs, sshd agrees.
	writeFile(t, dropIn, []byte(mustRead(t, candidate)), 0o644)
	output, code = run("remote_alpha_host_firewall_sshd_check " + config)
	if code != 0 {
		t.Fatalf("installed drop-in: %d\n%s", code, output)
	}
	assertContainsAll(t, "installed drop-in", output,
		"pass  from 192.168.1.210                password yes, keyboard-interactive no, X11 no",
		"pass  from 192.0.2.1                    password no, keyboard-interactive no, X11 no",
	)

	// A drop-in that sorts before ours wins in sshd; the check notices.
	earlier := filepath.Join(filepath.Dir(dropIn), "00-aaa.conf")
	writeFile(t, earlier, []byte("PasswordAuthentication yes\n"), 0o644)
	if output, code := run("remote_alpha_host_firewall_sshd_check " + config); code == 0 || !strings.Contains(output, "FAIL  from 192.0.2.1") {
		t.Fatalf("an earlier drop-in turning passwords on must fail the check: %d\n%s", code, output)
	}
	if err := os.Remove(earlier); err != nil {
		t.Fatal(err)
	}

	// Without any password source, passwords are off everywhere.
	env = append(env, "REMOTE_ALPHA_HOST_FIREWALL_SSH_PASSWORD_SOURCES= ")
	output, code = run("remote_alpha_host_firewall_py render-sshd >" + dropIn + " && remote_alpha_host_firewall_sshd_check " + config)
	if code != 0 || strings.Contains(output, "password yes") || strings.Contains(mustRead(t, dropIn), "Match") {
		t.Fatalf("keys-only drop-in: %d\n%s\n%s", code, output, mustRead(t, dropIn))
	}
}

func TestRemoteAlphaHostFirewallAutoDNSFollowsDockerResolverChoice(t *testing.T) {
	dir := t.TempDir()
	daemonJSON := filepath.Join(dir, "daemon.json")
	resolvConf := filepath.Join(dir, "resolv.conf")
	systemdConf := filepath.Join(dir, "systemd-resolv.conf")
	writeFile(t, resolvConf, []byte("nameserver 127.0.0.53\noptions edns0 trust-ad\n"), 0o644)
	writeFile(t, systemdConf, []byte("nameserver 192.168.1.1\nnameserver fe80::1%wlp2s0\n"), 0o644)
	base := []string{
		"REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_DNS_SERVERS=auto",
		"REMOTE_ALPHA_HOST_FIREWALL_RESOLV_CONF=" + resolvConf,
		"REMOTE_ALPHA_HOST_FIREWALL_SYSTEMD_RESOLV_CONF=" + systemdConf,
		"REMOTE_ALPHA_HOST_FIREWALL_DOCKER_DAEMON_JSON=" + daemonJSON,
	}

	// systemd-resolved stub only in resolv.conf: the upstream list is used,
	// without its IPv6 resolvers because the default bridge has no IPv6.
	stdout, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 {
		t.Fatalf("render exit %d: %s", code, stderr)
	}
	assertContainsAll(t, "systemd upstream", stdout,
		"ip daddr { 192.168.1.1 } udp dport 53 accept",
		"(from "+systemdConf+", IPv6 resolvers dropped as Docker does without IPv6)",
	)
	if strings.Contains(stdout, "fe80::1 }") {
		t.Fatalf("IPv6 resolver must be dropped without Docker IPv6:\n%s", stdout)
	}

	// With IPv6 enabled in daemon.json, Docker keeps IPv6 resolvers.
	writeFile(t, daemonJSON, []byte(`{"ipv6": true}`), 0o644)
	stdout, _, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 || !strings.Contains(stdout, "ip6 daddr { fe80::1 } udp dport 53 accept") {
		t.Fatalf("expected IPv6 resolver with Docker IPv6, got exit %d\n%s", code, stdout)
	}
	if err := os.Remove(daemonJSON); err != nil {
		t.Fatal(err)
	}

	// Docker switches to systemd-resolved's list only when 127.0.0.53 is the
	// sole resolver. Another loopback resolver leaves nothing usable.
	writeFile(t, resolvConf, []byte("nameserver 127.0.0.1\n"), 0o644)
	stdout, _, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 || strings.Contains(stdout, "dport 53") || !strings.Contains(stdout, "container_dns_servers = (none)") {
		t.Fatalf("expected no DNS exception for a loopback-only resolv.conf, got exit %d\n%s", code, stdout)
	}

	// A non-loopback resolver in resolv.conf wins over systemd-resolved.
	writeFile(t, resolvConf, []byte("nameserver 127.0.0.53\nnameserver 192.168.1.2\n"), 0o644)
	stdout, _, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 || !strings.Contains(stdout, "ip daddr { 192.168.1.2 } udp dport 53 accept") || strings.Contains(stdout, "192.168.1.1 }") {
		t.Fatalf("expected resolv.conf resolver only, got exit %d\n%s", code, stdout)
	}

	// daemon.json "dns" wins over both.
	writeFile(t, daemonJSON, []byte(`{"dns": ["10.0.0.53"]}`), 0o644)
	stdout, _, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 || !strings.Contains(stdout, "ip daddr { 10.0.0.53 } udp dport 53 accept") {
		t.Fatalf("expected daemon.json resolver, got exit %d\n%s", code, stdout)
	}

	// Nothing usable: no DNS exception at all (Docker uses public resolvers).
	if err := os.Remove(daemonJSON); err != nil {
		t.Fatal(err)
	}
	writeFile(t, resolvConf, []byte("nameserver 127.0.0.53\n"), 0o644)
	if err := os.Remove(systemdConf); err != nil {
		t.Fatal(err)
	}
	stdout, _, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 0 || strings.Contains(stdout, "dport 53") || !strings.Contains(stdout, "container_dns_servers = (none)") {
		t.Fatalf("expected no DNS exception, got exit %d\n%s", code, stdout)
	}

	// A broken daemon.json is refused, not ignored.
	writeFile(t, daemonJSON, []byte(`{"dns": `), 0o644)
	_, stderr, code = runHostFirewall(t, hostFirewallBaseEnv(t, "", base...), "--render")
	if code != 2 || !strings.Contains(stderr, "cannot read") {
		t.Fatalf("expected refusal of unreadable daemon.json, got exit %d: %s", code, stderr)
	}
}

const hostFirewallSampleListeners = `tcp LISTEN 0 4096 127.0.0.1:4646 0.0.0.0:* users:(("nomad",pid=1,fd=22))
tcp LISTEN 0 4096 172.17.0.1:8200 0.0.0.0:* users:(("vault",pid=2,fd=10))
tcp LISTEN 0 4096 192.168.1.156:8444 0.0.0.0:* users:(("ags",pid=3,fd=3))
tcp LISTEN 0 4096 192.168.1.156:8445 0.0.0.0:* users:(("es",pid=4,fd=6))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=5,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=5,fd=4))
tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=6,fd=15))
tcp LISTEN 0 5 0.0.0.0:5900 0.0.0.0:* users:(("vnc",pid=7,fd=3))
udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=8,fd=12))
udp UNCONN 0 0 192.168.1.156%wlp2s0:68 0.0.0.0:* users:(("NetworkManager",pid=9,fd=24))
udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:(("chronyd",pid=10,fd=5))
tcp ESTAB 0 0 192.168.1.156:22 192.168.1.23:50000 users:(("sshd",pid=11,fd=4))
`

func TestRemoteAlphaHostFirewallListenerClassification(t *testing.T) {
	output, code := runHostFirewallPython(t, hostFirewallBaseEnv(t, ""), hostFirewallSampleListeners, "listeners", "32768")
	if code != 3 {
		t.Fatalf("expected exit 3 for unaccepted listeners, got %d\n%s", code, output)
	}
	assertContainsAll(t, "listener classes", output,
		"127.0.0.1:4646", "loopback only (unchanged)",
		"containers only (Vault); LAN: blocked",
		"192.168.1.156:8445", "LAN: from 192.168.1.23/32; containers: blocked",
		"LAN: from 192.168.1.0/24 fe80::/10; containers: blocked",
		"DHCP client replies only",
		"ephemeral range: taken as a client socket (replies only); a service here would be BLOCKED",
		"BLOCKED from LAN and containers (NOT accepted)",
		"not accepted: tcp/5900 udp/5353",
	)
	if strings.Contains(output, "50000") {
		t.Fatalf("an established connection is not a listener:\n%s", output)
	}

	output, code = runHostFirewallPython(t, hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS=tcp/5900 udp/5353"), hostFirewallSampleListeners, "listeners", "32768")
	if code != 0 {
		t.Fatalf("expected exit 0 once accepted, got %d\n%s", code, output)
	}
	assertContainsAll(t, "accepted listeners", output, "BLOCKED from LAN and containers (accepted in settings)")
}

func TestRemoteAlphaHostFirewallSSHPeerChecks(t *testing.T) {
	env := hostFirewallBaseEnv(t, "")
	inside := "0 0 192.168.1.156:22 192.168.1.23:50000\n0 0 192.168.1.156:8445 10.9.9.9:40000\n0 0 [::ffff:192.168.1.156]:22 [::ffff:192.168.1.40]:50001\n0 0 127.0.0.1:22 127.0.0.1:50002\n"
	output, code := runHostFirewallPython(t, env, inside, "ssh-peers")
	if code != 0 {
		t.Fatalf("expected peers inside SSH_SOURCES to pass, got %d\n%s", code, output)
	}
	assertContainsAll(t, "ssh peers", output, "ssh peer 192.168.1.23:50000", "ssh peer 192.168.1.40:50001")
	if strings.Contains(output, "10.9.9.9") {
		t.Fatalf("a connection to another port is not an SSH peer:\n%s", output)
	}

	outside := inside + "0 0 192.168.1.156:22 10.20.30.40:50003\n"
	output, code = runHostFirewallPython(t, env, outside, "ssh-peers")
	if code != 4 || !strings.Contains(output, "outside REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES") || !strings.Contains(output, "10.20.30.40") {
		t.Fatalf("expected refusal for a peer outside SSH_SOURCES, got %d\n%s", code, output)
	}

	output, code = runHostFirewallPython(t, env, "", "ssh-peers")
	if code != 0 || !strings.Contains(output, "not run over SSH") {
		t.Fatalf("expected pass without SSH connections, got %d\n%s", code, output)
	}

	recorded := filepath.Join(t.TempDir(), "peers")
	writeFile(t, recorded, []byte("192.168.1.23:50000\n"), 0o600)
	output, code = runHostFirewallPython(t, env, "0 0 192.168.1.156:22 192.168.1.23:50000\n", "new-ssh-peer", recorded)
	if code != 5 {
		t.Fatalf("the connection that ran --apply must not count as new, got %d\n%s", code, output)
	}
	output, code = runHostFirewallPython(t, env, "0 0 192.168.1.156:22 192.168.1.23:50000\n0 0 192.168.1.156:22 192.168.1.23:50010\n", "new-ssh-peer", recorded)
	if code != 0 || !strings.Contains(output, "192.168.1.23:50010") {
		t.Fatalf("a connection opened after --apply must count as new, got %d\n%s", code, output)
	}
	// A new loopback connection, or one from outside SSH_SOURCES, proves
	// nothing about the operator's path through the firewall.
	for _, line := range []string{"0 0 127.0.0.1:22 127.0.0.1:41000\n", "0 0 [::1]:22 [::1]:41001\n", "0 0 192.168.1.156:22 10.20.30.40:41002\n"} {
		output, code = runHostFirewallPython(t, env, "0 0 192.168.1.156:22 192.168.1.23:50000\n"+line, "new-ssh-peer", recorded)
		if code != 5 {
			t.Fatalf("%q must not count as a new SSH connection, got %d\n%s", line, code, output)
		}
	}
	// Loopback stays out even when SSH_SOURCES names it: the settings
	// accept a loopback network, and the loopback check is its own rule.
	withLoopback := hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_SSH_SOURCES=192.168.1.0/24 127.0.0.0/8 ::1/128")
	output, code = runHostFirewallPython(t, withLoopback, "0 0 192.168.1.156:22 192.168.1.23:50000\n0 0 192.168.1.156:22 192.168.1.23:50011\n", "new-ssh-peer", recorded)
	if code != 0 || !strings.Contains(output, "192.168.1.23:50011") {
		t.Fatalf("with loopback in SSH_SOURCES, a LAN connection opened after --apply must still count, got %d\n%s", code, output)
	}
	for _, line := range []string{"0 0 127.0.0.1:22 127.0.0.1:41000\n", "0 0 [::1]:22 [::1]:41001\n", "0 0 [::ffff:127.0.0.1]:22 [::ffff:127.0.0.1]:41003\n"} {
		output, code = runHostFirewallPython(t, withLoopback, "0 0 192.168.1.156:22 192.168.1.23:50000\n"+line, "new-ssh-peer", recorded)
		if code != 5 {
			t.Fatalf("%q must not count as a new SSH connection even with loopback in SSH_SOURCES, got %d\n%s", line, code, output)
		}
	}
}

func TestRemoteAlphaHostFirewallBridgeCheck(t *testing.T) {
	env := hostFirewallBaseEnv(t, "")
	addrs := "1: lo    inet 127.0.0.1/8 scope host lo\n2: wlp2s0    inet 192.168.1.156/24 brd 192.168.1.255 scope global wlp2s0\n3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n9: br-abc123    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-abc123\n"
	output, code := runHostFirewallPython(t, env, addrs, "bridge-check")
	if code != 0 {
		t.Fatalf("expected pass, got %d\n%s", code, output)
	}
	assertContainsAll(t, "bridge check", output,
		"wlp2s0", "LAN side (inbound default deny)",
		"docker0", "containers isolated from each other at layer 2; holds the Vault address",
		"br-abc123", "NOT isolated at layer 2",
	)
	output, code = runHostFirewallPython(t, hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_CONTAINER_BRIDGE_SUBNETS=172.18.0.0/16"), addrs, "bridge-check")
	if code != 7 {
		t.Fatalf("expected refusal when the Vault bridge is not isolated, got %d\n%s", code, output)
	}
	output, code = runHostFirewallPython(t, env, "2: wlp2s0    inet 192.168.1.156/24 scope global wlp2s0\n", "bridge-check")
	if code != 7 || !strings.Contains(output, "no interface holds the Vault address") {
		t.Fatalf("expected refusal without the Vault address, got %d\n%s", code, output)
	}
}

func TestRemoteAlphaHostFirewallBridgesAndContainerIPv6(t *testing.T) {
	env := hostFirewallBaseEnv(t, "")
	links := "3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default \\    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff\n" +
		"9: br-abc123: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \\    link/ether 02:42:ac:12:00:01 brd ff:ff:ff:ff:ff:ff\n"
	output, code := runHostFirewallPython(t, env, links, "bridges")
	if code != 0 || !strings.Contains(output, "bridge docker0") || !strings.Contains(output, "bridge br-abc123") {
		t.Fatalf("container bridges must pass, got %d\n%s", code, output)
	}
	output, code = runHostFirewallPython(t, env, links+"12: virbr0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT \\    link/ether 52:54:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", "bridges")
	if code != 10 || !strings.Contains(output, "bridge virbr0") || !strings.Contains(output, "NOT a container interface") {
		t.Fatalf("a bridge that is not a container interface must be refused, got %d\n%s", code, output)
	}

	global := "2: wlp2s0    inet6 2001:db8:1::156/64 scope global dynamic mngtmpaddr \\       valid_lft 86000sec preferred_lft 14000sec\n"
	output, code = runHostFirewallPython(t, env, global, "container-ipv6")
	if code != 0 {
		t.Fatalf("IPv6 on the LAN interface is fine, got %d\n%s", code, output)
	}
	for _, line := range []string{
		"3: docker0    inet6 fd00:dead:beef::1/64 scope global \\       valid_lft forever preferred_lft forever\n",
		"9: br-abc123    inet6 2001:db8:2::1/64 scope global \\       valid_lft forever preferred_lft forever\n",
	} {
		output, code = runHostFirewallPython(t, env, global+line, "container-ipv6")
		if code != 11 || !strings.Contains(output, "container interface with IPv6") {
			t.Fatalf("a container interface with IPv6 must be refused (%q), got %d\n%s", line, code, output)
		}
	}
}

func TestRemoteAlphaHostFirewallArgumentsAndRoot(t *testing.T) {
	stdout, _, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--help")
	if code != 0 {
		t.Fatalf("--help exit %d", code)
	}
	assertContainsAll(t, "usage", stdout,
		"--plan", "--apply", "--confirm", "--status", "--probe", "--rollback", "--render",
		"SERVICE_CALLERS has no", "default and must be set",
		"Changes only the nftables tables inet and bridge es_host_firewall",
		"an open SSH connection from outside SSH_SOURCES",
		"bridge that is not a container interface",
		"container\n              interface with a global or unique-local IPv6 address",
		"never confirmed or rolled back",
		"From a new SSH connection from SSH_SOURCES (loopback does not",
		"records of an earlier --apply in\n              RUN_DIR",
		"(/var/lib/es-host-firewall\n  by default",
		"Not egress lanes",
	)
	if _, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--apply", "--confirm"); code != 2 || !strings.Contains(stderr, "at most one mode") {
		t.Fatalf("two modes must be refused, got %d: %s", code, stderr)
	}
	if _, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--service-callers=1.2.3.4"); code != 2 || !strings.Contains(stderr, "unknown argument") {
		t.Fatalf("unknown argument must be refused, got %d: %s", code, stderr)
	}

	fakeBin := t.TempDir()
	writeExecutable(t, fakeBin, "id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 1000; exit 0; fi\nexec /usr/bin/id \"$@\"\n")
	for _, mode := range []string{"--plan", "--apply", "--confirm", "--status", "--probe", "--rollback"} {
		_, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, fakeBin), mode)
		if code != 1 || !strings.Contains(stderr, "must run as root") {
			t.Fatalf("%s without root: expected exit 1 and a root error, got %d: %s", mode, code, stderr)
		}
	}
	if _, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, fakeBin), "--render"); code != 0 {
		t.Fatalf("--render must work without root, got %d: %s", code, stderr)
	}
}

// hostFirewallFakes installs fake root-only commands that record every call.
// The fake nft keeps a "loaded" copy of the last ruleset it loaded and lists
// it in place of the kernel; the fake systemd-run records the rollback
// command; the fake systemctl keeps the timer and unit state in files.
func hostFirewallFakes(t *testing.T, ssEstablished string) (string, string) {
	t.Helper()
	fakeBin := t.TempDir()
	state := t.TempDir()
	log := filepath.Join(state, "calls.log")
	writeExecutable(t, fakeBin, "id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexec /usr/bin/id \"$@\"\n")
	writeExecutable(t, fakeBin, "install", fmt.Sprintf("#!/bin/sh\necho \"install $*\" >>%q\nexit 0\n", log))
	writeExecutable(t, fakeBin, "chown", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, fakeBin, "sshd", hostFirewallFakeSSHD)
	writeExecutable(t, fakeBin, "nft", fmt.Sprintf(`#!/bin/bash
state=%q
echo "nft $*" >>%q
if [[ "$1" == "-c" ]]; then [[ -n "${FAKE_NFT_CHECK_FAIL:-}" ]] && { echo "check failed" >&2; exit 1; }; exit 0; fi
if [[ "$1" == "-f" ]]; then
  if grep -q "^table inet es_host_firewall {" "$2"; then cp "$2" "$state/loaded"; else rm -f "$state/loaded"; fi
  exit 0
fi
if [[ "$1" == "list" && "$2" == "table" ]]; then [[ -f "$state/loaded" ]]; exit; fi
if [[ "$1" == "-s" && "$2" == "list" ]]; then
  [[ -f "$state/loaded" ]] || exit 1
  if [[ "$4" == "inet" ]]; then sed -n '/^table inet es_host_firewall {/,/^}/p' "$state/loaded"; else sed -n '/^table bridge es_host_firewall {/,/^}/p' "$state/loaded"; fi
  exit 0
fi
exit 0
`, state, log))
	writeExecutable(t, fakeBin, "systemd-run", fmt.Sprintf(`#!/bin/bash
echo "systemd-run $*" >>%q
cmd=()
for arg in "$@"; do case "$arg" in --*) ;; *) cmd+=("$arg") ;; esac; done
printf '%%q ' "${cmd[@]}" >%q/rollback-command
echo waiting >%q/timer
`, log, state, state))
	writeExecutable(t, fakeBin, "systemctl", fmt.Sprintf(`#!/bin/bash
state=%q
echo "systemctl $*" >>%q
case "$1" in
  show) cat "$state/timer" 2>/dev/null || echo dead ;;
  stop) echo dead >"$state/timer" ;;
  is-enabled) [[ "$*" == *es-host-firewall.service* && -f "$state/enabled" ]] ;;
  enable) touch "$state/enabled" ;;
  disable) rm -f "$state/enabled" ;;
  restart) nft -f "$(sed -n 's/^ExecStart=[^ ]* -f //p' "$FAKE_UNIT_PATH")" ;;
  *) exit 0 ;;
esac
`, state, log))
	writeExecutable(t, fakeBin, "ss", fmt.Sprintf(`#!/bin/bash
echo "ss $*" >>%q
if [[ "$*" == *"state established"* ]]; then cat %q 2>/dev/null; exit 0; fi
printf 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=5,fd=3))\n'
`, log, filepath.Join(state, "established")))
	// The fake ip: one docker0 bridge with the Vault address; FAKE_IP_BRIDGES
	// and FAKE_IP_V6 add lines to the bridge list and the IPv6 address list.
	writeExecutable(t, fakeBin, "ip", `#!/bin/bash
case "$*" in
  *"link show type bridge"*) printf '3: docker0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP mode DEFAULT\n'; [[ -n "${FAKE_IP_BRIDGES:-}" ]] && printf '%s\n' "$FAKE_IP_BRIDGES" ;;
  *"-6 addr show"*) [[ -n "${FAKE_IP_V6:-}" ]] && printf '%s\n' "$FAKE_IP_V6" ;;
  *"addr show"*) printf '3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n' ;;
esac
exit 0
`)
	writeFile(t, filepath.Join(state, "established"), []byte(ssEstablished), 0o644)
	return fakeBin, state
}

func readCalls(t *testing.T, state string) string {
	t.Helper()
	return readIfExists(filepath.Join(state, "calls.log"))
}

func TestRemoteAlphaHostFirewallApplyConfirmRollbackOrderWithFakes(t *testing.T) {
	fakeBin, state := hostFirewallFakes(t, "0 0 192.168.1.156:22 192.168.1.23:50000\n")
	root := t.TempDir()
	unitPath := filepath.Join(root, "systemd", "es-host-firewall.service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	env := hostFirewallBaseEnv(t, fakeBin,
		"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR="+filepath.Join(root, "state"),
		"REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR="+filepath.Join(root, "run"),
		"REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH="+unitPath,
		"REMOTE_ALPHA_HOST_FIREWALL_SSH_PASSWORD_SOURCES=192.168.1.23/32",
		"FAKE_UNIT_PATH="+unitPath,
	)
	envValue := func(key string) string {
		for _, entry := range env {
			if k, v, _ := strings.Cut(entry, "="); k == key {
				return v
			}
		}
		t.Fatalf("no %s in env", key)
		return ""
	}
	dropIn := envValue("REMOTE_ALPHA_HOST_FIREWALL_SSHD_DROP_IN")
	sshdConfig := envValue("REMOTE_ALPHA_HOST_FIREWALL_SSHD_CONFIG")
	for _, dir := range []string{filepath.Join(root, "state"), filepath.Join(root, "run")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Plan changes nothing.
	stdout, stderr, code := runHostFirewall(t, env, "--plan")
	if code != 0 || !strings.Contains(stdout, "RESULT: ready to apply") {
		t.Fatalf("plan: exit %d\n%s\n%s", code, stdout, stderr)
	}
	calls := readCalls(t, state)
	assertContainsNone(t, "plan calls", calls, "nft -f", "systemd-run", "systemctl stop", "systemctl enable", "systemctl restart", "systemctl reload", "install ")
	assertContainsAll(t, "plan sshd checks", stdout,
		"includes "+filepath.Dir(dropIn)+"/*.conf: pass",
		"no other Match blocks in the sshd configuration: pass",
		"pass  from 192.168.1.23",
		"password yes",
		"pass  from 192.0.2.1",
		"== sshd drop-in "+dropIn+" ==",
		"Match Address 192.168.1.23/32",
		"host to Vault source: ",
	)
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Fatalf("plan must not write the sshd drop-in, stat err=%v", err)
	}

	// An sshd configuration the script cannot reason about stops plan.
	otherMatch := filepath.Join(filepath.Dir(dropIn), "60-other.conf")
	writeFile(t, otherMatch, []byte("Match User backup\n\tPasswordAuthentication yes\n"), 0o644)
	if stdout, _, code := runHostFirewall(t, env, "--plan"); code != 1 || !strings.Contains(stdout, "no other Match blocks in the sshd configuration: FAIL") {
		t.Fatalf("plan with another Match block: exit %d\n%s", code, stdout)
	}
	if err := os.Remove(otherMatch); err != nil {
		t.Fatal(err)
	}
	// An invalid sshd configuration stops plan.
	if stdout, _, code := runHostFirewall(t, append(append([]string{}, env...), "FAKE_SSHD_T_FAIL=1"), "--plan"); code != 1 || !strings.Contains(stdout, "sshd -t (configuration valid): FAIL") {
		t.Fatalf("plan with invalid sshd configuration: exit %d\n%s", code, stdout)
	}

	// A failing kernel check stops apply before any effect.
	failEnv := append(append([]string{}, env...), "FAKE_NFT_CHECK_FAIL=1")
	stdout, _, code = runHostFirewall(t, failEnv, "--apply")
	if code != 1 || !strings.Contains(stdout, "RESULT: not applied; nothing was changed") {
		t.Fatalf("apply with failing check: exit %d\n%s", code, stdout)
	}
	assertContainsNone(t, "failed apply calls", readCalls(t, state), "nft -f", "systemd-run")

	// Confirm without an apply is refused.
	if _, stderr, code := runHostFirewall(t, env, "--confirm"); code != 1 || !strings.Contains(stderr, "no apply is awaiting confirm") {
		t.Fatalf("confirm without apply: exit %d: %s", code, stderr)
	}

	// Apply arms the rollback before it loads the ruleset.
	if err := os.WriteFile(filepath.Join(state, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runHostFirewall(t, env, "--apply")
	if code != 0 || !strings.Contains(stdout, "RESULT: applied, awaiting confirm") {
		t.Fatalf("apply: exit %d\n%s\n%s", code, stdout, stderr)
	}
	calls = readCalls(t, state)
	runIndex := strings.Index(calls, "systemd-run")
	loadIndex := strings.Index(calls, "nft -f "+filepath.Join(root, "run", "candidate.nft"))
	if runIndex < 0 || loadIndex < 0 || runIndex > loadIndex {
		t.Fatalf("the rollback timer must be armed before the ruleset loads:\n%s", calls)
	}
	assertContainsAll(t, "apply timer", calls, "--on-active=180s", "--collect", "--unit=es-host-firewall-rollback")
	rollbackCommand := readIfExists(filepath.Join(state, "rollback-command"))
	if !strings.Contains(rollbackCommand, filepath.Join(root, "run", "rollback.sh")) {
		t.Fatalf("rollback command must run the rollback script, got %q", rollbackCommand)
	}
	rollbackScript := mustRead(t, filepath.Join(root, "run", "rollback.sh"))
	assertContainsAll(t, "rollback script", rollbackScript,
		"-f '"+filepath.Join(root, "run", "rollback.nft")+"'",
		"-f '"+dropIn+"'",
		"is-active --quiet 'ssh.service'",
		"reload 'ssh.service'",
	)
	sshdIndex := strings.Index(calls, "systemctl reload ssh.service")
	if sshdIndex < 0 || sshdIndex < runIndex {
		t.Fatalf("sshd must reload after the rollback timer is armed:\n%s", calls)
	}
	renderedDropIn, _ := runHostFirewallPython(t, env, "", "render-sshd")
	if got := mustRead(t, dropIn); got != renderedDropIn {
		t.Fatalf("apply must install the rendered sshd drop-in, got:\n%s", got)
	}
	rollbackFile := mustRead(t, filepath.Join(root, "run", "rollback.nft"))
	if rollbackFile != "table inet es_host_firewall\ndelete table inet es_host_firewall\ntable bridge es_host_firewall\ndelete table bridge es_host_firewall\n" {
		t.Fatalf("with no earlier tables the rollback file must only remove ours, got:\n%s", rollbackFile)
	}

	// A second apply while one awaits confirm is refused.
	if stdout, _, code := runHostFirewall(t, env, "--apply"); code != 1 || !strings.Contains(stdout, "no earlier apply awaiting confirm: FAIL") {
		t.Fatalf("second apply: exit %d\n%s", code, stdout)
	}

	// Confirm from the connection that applied is refused.
	if _, stderr, code := runHostFirewall(t, env, "--confirm"); code != 1 || !strings.Contains(stderr, "SSH connection opened after --apply") {
		t.Fatalf("confirm without a new SSH connection: exit %d: %s", code, stderr)
	}
	// Confirm with different settings is refused.
	otherEnv := append(append([]string{}, env...), "REMOTE_ALPHA_HOST_FIREWALL_SERVICE_CALLERS=192.168.1.24/32")
	if _, stderr, code := runHostFirewall(t, otherEnv, "--confirm"); code != 1 || !strings.Contains(stderr, "do not render the applied ruleset") {
		t.Fatalf("confirm with other settings: exit %d: %s", code, stderr)
	}

	// A new SSH connection allows confirm, which stops the timer before it
	// installs the files.
	writeFile(t, filepath.Join(state, "established"), []byte("0 0 192.168.1.156:22 192.168.1.23:50000\n0 0 192.168.1.156:22 192.168.1.23:50010\n"), 0o644)
	if err := os.WriteFile(filepath.Join(state, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runHostFirewall(t, env, "--confirm")
	if code != 0 || !strings.Contains(stdout, "RESULT: confirmed") {
		t.Fatalf("confirm: exit %d\n%s\n%s", code, stdout, stderr)
	}
	calls = readCalls(t, state)
	stopIndex := strings.Index(calls, "systemctl stop es-host-firewall-rollback.timer")
	enableIndex := strings.Index(calls, "systemctl enable --quiet es-host-firewall.service")
	if stopIndex < 0 || enableIndex < 0 || stopIndex > enableIndex {
		t.Fatalf("confirm must stop the timer before installing:\n%s", calls)
	}
	installed := mustRead(t, filepath.Join(root, "state", "es-host-firewall.nft"))
	rendered, _, _ := runHostFirewall(t, env, "--render")
	if installed != rendered {
		t.Fatal("the installed ruleset must be the rendered one")
	}
	unit := mustRead(t, unitPath)
	assertContainsAll(t, "unit", unit, "ExecStart=", "-f "+filepath.Join(root, "state", "es-host-firewall.nft"), "WantedBy=sysinit.target", "Before=network-pre.target docker.service nomad.service")
	for _, path := range []string{"candidate.nft", "rollback.nft", "applied.listing"} {
		if _, err := os.Stat(filepath.Join(root, "run", path)); !os.IsNotExist(err) {
			t.Fatalf("confirm must remove %s, stat err=%v", path, err)
		}
	}

	// Status: installed and unchanged.
	stdout, _, code = runHostFirewall(t, env, "--status")
	if code != 0 || !strings.Contains(stdout, "RESULT: installed and unchanged") || !strings.Contains(stdout, "host to Vault source: ") {
		t.Fatalf("status: exit %d\n%s", code, stdout)
	}
	// Drift: the sshd drop-in edited by hand.
	writeFile(t, dropIn, []byte(renderedDropIn+"PasswordAuthentication yes\n"), 0o644)
	stdout, _, code = runHostFirewall(t, env, "--status")
	if code != 1 || !strings.Contains(stdout, "DIFFERS from the current settings") {
		t.Fatalf("status after sshd drift: exit %d\n%s", code, stdout)
	}
	writeFile(t, dropIn, []byte(renderedDropIn), 0o644)
	// Drift: sshd itself no longer does what the drop-in says.
	stdout, _, code = runHostFirewall(t, append(append([]string{}, env...), "FAKE_SSHD_WRONG_FOR="+sshdConfig), "--status")
	if code != 1 || !strings.Contains(stdout, "FAIL  from 192.0.2.1") {
		t.Fatalf("status with sshd granting passwords elsewhere: exit %d\n%s", code, stdout)
	}

	// Drift: the loaded tables change behind the script's back.
	loaded := filepath.Join(state, "loaded")
	writeFile(t, loaded, []byte(strings.Replace(mustRead(t, loaded), "tcp dport 8200 accept", "tcp dport 8201 accept", 1)), 0o644)
	stdout, _, code = runHostFirewall(t, env, "--status")
	if code != 1 || !strings.Contains(stdout, "loaded tables: DIFFER") {
		t.Fatalf("status after drift: exit %d\n%s", code, stdout)
	}

	// Rollback removes tables, unit and files.
	stdout, stderr, code = runHostFirewall(t, env, "--rollback")
	if code != 0 || !strings.Contains(stdout, "RESULT: removed") {
		t.Fatalf("rollback: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, path := range []string{unitPath, filepath.Join(root, "state", "es-host-firewall.nft"), loaded, dropIn} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("rollback must remove %s, stat err=%v", path, err)
		}
	}

	// If sshd does not do what the installed drop-in says, apply undoes
	// itself at once: tables, drop-in and the timer.
	if err := os.WriteFile(filepath.Join(state, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// (install is faked here, so recreate the run directory --rollback removed.)
	if err := os.MkdirAll(filepath.Join(root, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	wrongEnv := append(append([]string{}, env...), "FAKE_SSHD_WRONG_FOR="+sshdConfig)
	stdout, stderr, code = runHostFirewall(t, wrongEnv, "--apply")
	if code != 1 || !strings.Contains(stderr, "sshd does not do what the drop-in says; restored the state from before --apply") {
		t.Fatalf("apply with sshd disagreeing: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, path := range []string{dropIn, loaded} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("a self-undone apply must leave no %s, stat err=%v", path, err)
		}
	}
	if timer := strings.TrimSpace(readIfExists(filepath.Join(state, "timer"))); timer != "dead" {
		t.Fatalf("a self-undone apply must stop the timer, got %q", timer)
	}
	assertContainsNone(t, "self-undone apply", readCalls(t, state), "systemctl reload ssh.service\nsystemctl reload")
}

// TestRemoteAlphaHostFirewallApplyRefusesSSHPeerOutsideSources: an SSH
// connection from outside SSH_SOURCES would be cut by the new rules, so
// --plan and --apply refuse before any effect.
func TestRemoteAlphaHostFirewallApplyRefusesSSHPeerOutsideSources(t *testing.T) {
	fakeBin, state := hostFirewallFakes(t, "0 0 192.168.1.156:22 10.9.9.9:50000\n")
	root := t.TempDir()
	env := hostFirewallBaseEnv(t, fakeBin,
		"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR="+filepath.Join(root, "state"),
		"REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR="+filepath.Join(root, "run"),
		"REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH="+filepath.Join(root, "es-host-firewall.service"),
	)
	for _, mode := range []string{"--plan", "--apply"} {
		stdout, _, code := runHostFirewall(t, env, mode)
		if code != 1 || !strings.Contains(stdout, "current SSH peers stay allowed: FAIL") || !strings.Contains(stdout, "10.9.9.9") {
			t.Fatalf("%s with an SSH peer outside SSH_SOURCES: exit %d\n%s", mode, code, stdout)
		}
	}
	assertContainsNone(t, "calls", readCalls(t, state), "nft -f", "systemd-run", "systemctl reload")
}

// TestRemoteAlphaHostFirewallApplyRefusesOtherBridgesAndContainerIPv6: the
// bridge table's IPv6 rule covers every bridge, and container IPv6 would
// reach the LAN's IPv6 prefix, so --plan and --apply refuse both.
func TestRemoteAlphaHostFirewallApplyRefusesOtherBridgesAndContainerIPv6(t *testing.T) {
	fakeBin, state := hostFirewallFakes(t, "0 0 192.168.1.156:22 192.168.1.23:50000\n")
	root := t.TempDir()
	base := hostFirewallBaseEnv(t, fakeBin,
		"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR="+filepath.Join(root, "state"),
		"REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR="+filepath.Join(root, "run"),
		"REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH="+filepath.Join(root, "es-host-firewall.service"),
	)
	stdout, _, code := runHostFirewall(t, base, "--plan")
	if code != 0 || !strings.Contains(stdout, "every bridge is a container interface: pass") || !strings.Contains(stdout, "no container interface has IPv6: pass") {
		t.Fatalf("plan with only docker0: exit %d\n%s", code, stdout)
	}
	// br_netfilter is read from its sysctl file, which exists whether it is
	// a module or built in.
	want := "br_netfilter: not active"
	if _, err := os.Stat("/proc/sys/net/bridge/bridge-nf-call-iptables"); err == nil {
		want = "br_netfilter: active (bridged traffic also passes the inet rules: iptables "
	}
	if !strings.Contains(stdout, want) {
		t.Fatalf("plan must report br_netfilter from /proc/sys/net/bridge (want %q):\n%s", want, stdout)
	}
	cases := []struct{ name, env, fail string }{
		{"other_bridge", "FAKE_IP_BRIDGES=12: virbr0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT", "every bridge is a container interface: FAIL"},
		{"container_ipv6", "FAKE_IP_V6=3: docker0    inet6 fd00:dead:beef::1/64 scope global", "no container interface has IPv6: FAIL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := append(append([]string{}, base...), tc.env)
			for _, mode := range []string{"--plan", "--apply"} {
				stdout, _, code := runHostFirewall(t, env, mode)
				if code != 1 || !strings.Contains(stdout, tc.fail) {
					t.Fatalf("%s: exit %d\n%s", mode, code, stdout)
				}
			}
			assertContainsNone(t, "calls", readCalls(t, state), "nft -f", "systemd-run", "systemctl reload")
		})
	}
}

// TestRemoteAlphaHostFirewallUnconfirmedApplyRecords: rollback.sh (what the
// timer runs) puts back a drop-in that existed before --apply and clears the
// unconfirmed marker; an apply whose timer vanished (a reboot inside the
// confirm window) leaves the marker, which --status reports and --plan and
// --apply refuse until --rollback.
func TestRemoteAlphaHostFirewallUnconfirmedApplyRecords(t *testing.T) {
	fakeBin, state := hostFirewallFakes(t, "0 0 192.168.1.156:22 192.168.1.23:50000\n")
	root := t.TempDir()
	unitPath := filepath.Join(root, "systemd", "es-host-firewall.service")
	runDir := filepath.Join(root, "run")
	for _, dir := range []string{filepath.Dir(unitPath), filepath.Join(root, "state"), runDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := hostFirewallBaseEnv(t, fakeBin,
		"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR="+filepath.Join(root, "state"),
		"REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR="+runDir,
		"REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH="+unitPath,
		"FAKE_UNIT_PATH="+unitPath,
	)
	var dropIn string
	for _, entry := range env {
		if k, v, _ := strings.Cut(entry, "="); k == "REMOTE_ALPHA_HOST_FIREWALL_SSHD_DROP_IN" {
			dropIn = v
		}
	}
	// A drop-in from an earlier confirmed apply (other settings).
	previous := "# Managed by Execution-Substrate scripts/remote_alpha_host_firewall.sh.\n# earlier settings\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nX11Forwarding no\n"
	writeFile(t, dropIn, []byte(previous), 0o644)
	marker := filepath.Join(runDir, "unconfirmed")

	stdout, stderr, code := runHostFirewall(t, env, "--apply")
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if mustRead(t, dropIn) == previous {
		t.Fatal("apply must install the new drop-in")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("apply must leave the unconfirmed marker: %v", err)
	}
	rollbackScript := mustRead(t, filepath.Join(runDir, "rollback.sh"))
	assertContainsAll(t, "rollback script", rollbackScript, "-p '"+filepath.Join(runDir, "sshd-previous.conf")+"' '"+dropIn+"'", "-f '"+marker+"'")

	// The timer fires: the previous drop-in is back and the marker is gone.
	if output, err := exec.Command("/bin/sh", filepath.Join(runDir, "rollback.sh")).CombinedOutput(); err != nil {
		t.Fatalf("rollback.sh: %v\n%s", err, output)
	}
	writeFile(t, filepath.Join(state, "timer"), []byte("dead\n"), 0o644)
	if got := mustRead(t, dropIn); got != previous {
		t.Fatalf("rollback.sh must put the previous drop-in back, got:\n%s", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("rollback.sh must remove the unconfirmed marker, stat err=%v", err)
	}
	if stdout, _, code := runHostFirewall(t, env, "--plan"); code != 0 || !strings.Contains(stdout, "no earlier apply awaiting confirm: pass") {
		t.Fatalf("plan after a rollback: exit %d\n%s", code, stdout)
	}

	// Apply again, then the timer vanishes without running (a reboot).
	if stdout, stderr, code := runHostFirewall(t, env, "--apply"); code != 0 {
		t.Fatalf("second apply: exit %d\n%s\n%s", code, stdout, stderr)
	}
	writeFile(t, filepath.Join(state, "timer"), []byte("dead\n"), 0o644)
	stdout, _, code = runHostFirewall(t, env, "--status")
	if code != 1 || !strings.Contains(stdout, "unconfirmed apply: an --apply of ") || !strings.Contains(stdout, "run --rollback, then --apply again") {
		t.Fatalf("status with an unconfirmed apply left behind: exit %d\n%s", code, stdout)
	}
	for _, mode := range []string{"--plan", "--apply"} {
		stdout, _, code := runHostFirewall(t, env, mode)
		if code != 1 || !strings.Contains(stdout, "no earlier apply awaiting confirm: FAIL (an earlier --apply was never confirmed and its rollback timer is gone") {
			t.Fatalf("%s with an unconfirmed apply left behind: exit %d\n%s", mode, code, stdout)
		}
	}
	if _, stderr, code := runHostFirewall(t, env, "--confirm"); code != 1 || !strings.Contains(stderr, "no apply is awaiting confirm") {
		t.Fatalf("confirm after the timer vanished: exit %d: %s", code, stderr)
	}
	if stdout, stderr, code := runHostFirewall(t, env, "--rollback"); code != 0 {
		t.Fatalf("rollback: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("--rollback must remove the unconfirmed marker, stat err=%v", err)
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if stdout, _, code := runHostFirewall(t, env, "--plan"); code != 0 {
		t.Fatalf("plan after --rollback: exit %d\n%s", code, stdout)
	}
}

// ---------------------------------------------------------------------------
// Real-kernel tests. They need root, iproute2 and nft, build a small network
// of namespaces (a "box" with a docker0 bridge and two containers, a LAN with
// a router, the operator Mac and another device, and an "internet" host),
// load the rendered ruleset into the box namespace, and check real traffic.
// They skip themselves without root; .github/ci/environment-only-tests.txt
// lists them.
// ---------------------------------------------------------------------------

type hostFirewallLab struct {
	t      *testing.T
	prefix string
	names  map[string]string
	// ipv6 is true when the kernel has IPv6 (some sandboxes boot with
	// ipv6.disable=1); the IPv6 checks run only then, as a visible subtest.
	ipv6 bool
}

func requireHostFirewallLab(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	// A root CI step may run with PATH=/usr/bin:/bin; nft and ip live in
	// /usr/sbin. Add the sbin directories for the test and the scripts.
	t.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+"/usr/sbin"+string(os.PathListSeparator)+"/sbin")
	for _, tool := range []string{"ip", "nft", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("running as root but %s is missing: install it to run this real-kernel test", tool)
		}
	}
}

func (l *hostFirewallLab) run(args ...string) string {
	l.t.Helper()
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func (l *hostFirewallLab) ns(name string) string { return l.names[name] }

func newHostFirewallLab(t *testing.T) *hostFirewallLab {
	t.Helper()
	requireHostFirewallLab(t)
	l := &hostFirewallLab{t: t, prefix: fmt.Sprintf("esfw%d", os.Getpid()%100000), names: map[string]string{}}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		l.ipv6 = true
	}
	for _, name := range []string{"box", "c1", "c2", "lan", "wan"} {
		l.names[name] = l.prefix + name
	}
	t.Cleanup(func() {
		for _, ns := range l.names {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, name := range []string{"box", "c1", "c2", "lan", "wan"} {
		l.run("ip", "netns", "add", l.ns(name))
		l.run("ip", "-n", l.ns(name), "link", "set", "lo", "up")
	}
	box := l.ns("box")
	lan := l.ns("lan")
	// The LAN interface comes first, as on the box (Docker creates docker0
	// after the network cards): when Docker's masquerade rule rewrites a
	// connection that leaves through lo, the kernel picks the first
	// interface's global address, the LAN address.
	l.run("ip", "link", "add", "wlp2s0", "netns", box, "type", "veth", "peer", "name", "lan0", "netns", lan)
	l.run("ip", "-n", box, "addr", "add", "192.168.1.156/24", "dev", "wlp2s0")
	l.run("ip", "-n", box, "link", "set", "wlp2s0", "up")
	l.run("ip", "-n", box, "link", "add", "docker0", "type", "bridge")
	l.run("ip", "-n", box, "addr", "add", "172.17.0.1/16", "dev", "docker0")
	l.run("ip", "-n", box, "link", "set", "docker0", "up")
	for i, c := range []string{"c1", "c2"} {
		ns := l.ns(c)
		hostSide := fmt.Sprintf("veth%d", i+1)
		l.run("ip", "link", "add", "eth0", "netns", ns, "type", "veth", "peer", "name", hostSide, "netns", box)
		l.run("ip", "-n", box, "link", "set", hostSide, "master", "docker0", "up")
		l.run("ip", "-n", ns, "addr", "add", fmt.Sprintf("172.17.0.%d/16", i+2), "dev", "eth0")
		l.run("ip", "-n", ns, "link", "set", "eth0", "up")
		l.run("ip", "-n", ns, "route", "add", "default", "via", "172.17.0.1")
	}
	for _, addr := range []string{"192.168.1.1/24", "192.168.1.23/24", "192.168.1.50/24"} {
		l.run("ip", "-n", lan, "addr", "add", addr, "dev", "lan0")
	}
	l.run("ip", "-n", lan, "link", "set", "lan0", "up")
	// IPv6 on the LAN link, as on the box: a global prefix (the ISP's, which
	// may be reachable from the internet) and link-local addresses. nodad
	// makes the addresses usable at once.
	if l.ipv6 {
		for _, addr := range []string{"2001:db8:1::156/64", "fe80::156/64"} {
			l.run("ip", "-n", box, "addr", "add", addr, "dev", "wlp2s0", "nodad")
		}
		for _, addr := range []string{"2001:db8:1::1/64", "2001:db8:1::23/64", "2001:db8:1::50/64", "fe80::23/64"} {
			l.run("ip", "-n", lan, "addr", "add", addr, "dev", "lan0", "nodad")
		}
	}
	l.run("ip", "-n", box, "route", "add", "default", "via", "192.168.1.1")
	l.run("ip", "netns", "exec", box, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	wan := l.ns("wan")
	l.run("ip", "link", "add", "wan0", "netns", lan, "type", "veth", "peer", "name", "wan1", "netns", wan)
	l.run("ip", "-n", lan, "addr", "add", "198.51.100.1/24", "dev", "wan0")
	l.run("ip", "-n", lan, "link", "set", "wan0", "up")
	l.run("ip", "-n", wan, "addr", "add", "198.51.100.10/24", "dev", "wan1")
	l.run("ip", "-n", wan, "addr", "add", "203.0.113.10/24", "dev", "wan1")
	l.run("ip", "-n", wan, "link", "set", "wan1", "up")
	l.run("ip", "-n", wan, "route", "add", "default", "via", "198.51.100.1")
	l.run("ip", "-n", lan, "route", "add", "203.0.113.0/24", "via", "198.51.100.10")
	l.run("ip", "-n", lan, "route", "add", "172.17.0.0/16", "via", "192.168.1.156")
	l.run("ip", "netns", "exec", lan, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return l
}

// hostFirewallLabServer is a python helper that listens on TCP (keeping
// connections open until the peer closes) and answers DNS A queries on UDP.
const hostFirewallLabServer = `
import socket, sys, threading
def hold(conn):
    try:
        while conn.recv(1024):
            pass
    except OSError:
        pass
    conn.close()
for spec in sys.argv[1:]:
    proto, host, port = spec.split(",")
    if proto == "tcp":
        s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if ":" in host:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind((host, int(port)))
        s.listen(16)
        def accept(s=s):
            while True:
                conn, _ = s.accept()
                threading.Thread(target=hold, args=(conn,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, int(port)))
        def answer(s=s):
            while True:
                data, peer = s.recvfrom(4096)
                end = 12
                while data[end] != 0:
                    end += data[end] + 1
                end += 5
                s.sendto(data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00" + data[12:end]
                         + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 10]), peer)
        threading.Thread(target=answer, daemon=True).start()
print("ready", flush=True)
sys.stdin.read()
`

func (l *hostFirewallLab) serve(name string, specs ...string) {
	l.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", l.ns(name), "python3", "-I", "-c", hostFirewallLabServer}, specs...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		l.t.Fatalf("lab server in %s did not start: %q %v", name, line, err)
	}
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
}

const hostFirewallLabProbe = `
import socket, struct, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
src = sys.argv[4] if len(sys.argv) > 4 else None
if kind == "tcp":
    family, _, _, _, target = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(1.5)
    if src:
        s.bind(socket.getaddrinfo(src, 0, family, socket.SOCK_STREAM)[0][4])
    try:
        s.connect(target); print("connected")
    except socket.timeout:
        print("timeout")
    except ConnectionRefusedError:
        print("refused")
    except OSError as exc:
        print("error", exc.errno)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    s.sendto(struct.pack(">HHHHHH", 7, 0x100, 1, 0, 0, 0) + b"\x06github\x03com\x00" + struct.pack(">HH", 1, 1), (host, port))
    try:
        s.recvfrom(512); print("answer")
    except socket.timeout:
        print("timeout")
`

func (l *hostFirewallLab) probe(name, kind, host string, port int, src string) string {
	l.t.Helper()
	args := []string{"netns", "exec", l.ns(name), "python3", "-I", "-c", hostFirewallLabProbe, kind, host, fmt.Sprint(port)}
	if src != "" {
		args = append(args, src)
	}
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("probe %s %s %s:%d: %v\n%s", name, kind, host, port, err, output)
	}
	return strings.TrimSpace(string(output))
}

// hostVaultSource runs the script's source check inside the box namespace,
// with the test settings (Vault at 172.17.0.1 tcp/8200, as in the lab).
func (l *hostFirewallLab) hostVaultSource() (string, int) {
	l.t.Helper()
	internal := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_host_firewall.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\nremote_alpha_host_firewall_defaults\nremote_alpha_host_firewall_py host-vault-source\n", internal)
	cmd := exec.Command("ip", "netns", "exec", l.ns("box"), "/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = hostFirewallBaseEnv(l.t, "")
	output, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		l.t.Fatal(err)
	}
	return string(output), code
}

func (l *hostFirewallLab) counter(family, name string) string {
	l.t.Helper()
	output := l.run("ip", "netns", "exec", l.ns("box"), "nft", "list", "counter", family, "es_host_firewall", name)
	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "packets" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	l.t.Fatalf("no packets field in counter %s %s:\n%s", family, name, output)
	return ""
}

func (l *hostFirewallLab) startLabServers() {
	if l.ipv6 {
		// sshd and the unlisted service listen on both families, as on the box.
		l.serve("box", "tcp,192.168.1.156,8445", "tcp,192.168.1.156,8444", "tcp,2001:db8:1::156,8445", "tcp,::,22", "tcp,172.17.0.1,8200", "tcp,::,5900")
		l.serve("lan", "tcp,192.168.1.1,80", "udp,192.168.1.1,53", "tcp,192.168.1.1,53", "tcp,2001:db8:1::1,80")
	} else {
		l.serve("box", "tcp,192.168.1.156,8445", "tcp,192.168.1.156,8444", "tcp,0.0.0.0,22", "tcp,172.17.0.1,8200", "tcp,0.0.0.0,5900")
		l.serve("lan", "tcp,192.168.1.1,80", "udp,192.168.1.1,53", "tcp,192.168.1.1,53")
	}
	l.serve("wan", "tcp,203.0.113.10,443")
	l.serve("c2", "tcp,0.0.0.0,9", "tcp,0.0.0.0,8080")
}

type hostFirewallExpectation struct {
	from, kind, host string
	port             int
	src, want        string
}

func (l *hostFirewallLab) expectAll(label string, expectations []hostFirewallExpectation) {
	l.t.Helper()
	for _, e := range expectations {
		if got := l.probe(e.from, e.kind, e.host, e.port, e.src); got != e.want {
			l.t.Errorf("%s: %s %s %s:%d src=%q: want %s, got %s", label, e.from, e.kind, e.host, e.port, e.src, e.want, got)
		}
	}
}

// expectIPv6 runs IPv6 expectations as a subtest that is skipped, visibly,
// when the kernel has no IPv6.
func (l *hostFirewallLab) expectIPv6(label string, expectations []hostFirewallExpectation) {
	l.t.Helper()
	parent := l.t
	parent.Run("ipv6 "+label, func(t *testing.T) {
		if !l.ipv6 {
			t.Skip("kernel without IPv6 (/proc/sys/net/ipv6 missing): IPv6 traffic not exercised here")
		}
		l.t = t
		defer func() { l.t = parent }()
		l.expectAll(label, expectations)
	})
}

func TestRemoteAlphaHostFirewallRealKernelTraffic(t *testing.T) {
	l := newHostFirewallLab(t)
	l.startLabServers()

	// Without the firewall every path is open: the finding this closes.
	l.expectAll("without firewall", []hostFirewallExpectation{
		{"c1", "tcp", "192.168.1.1", 80, "", "connected"},
		{"c1", "tcp", "192.168.1.156", 8445, "", "connected"},
		{"c1", "tcp", "172.17.0.3", 9, "", "connected"},
		{"lan", "tcp", "192.168.1.156", 8445, "192.168.1.50", "connected"},
		{"lan", "tcp", "172.17.0.1", 8200, "192.168.1.50", "connected"},
	})
	l.expectIPv6("without firewall", []hostFirewallExpectation{
		{"lan", "tcp", "2001:db8:1::156", 22, "2001:db8:1::50", "connected"},
		{"lan", "tcp", "2001:db8:1::156", 8445, "2001:db8:1::50", "connected"},
	})

	// Docker's masquerade rule, as on the box: everything from the bridge
	// subnet that leaves through another interface. The box's own
	// connection to the bridge address leaves through lo, so Vault sees the
	// box's LAN address: a Vault role limited to the bridge subnet refuses
	// the box. Everything above still works with it.
	dockerNAT := filepath.Join(t.TempDir(), "docker-nat.nft")
	writeFile(t, dockerNAT, []byte("table ip docker_like_nat {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n"+
		"\t\tip saddr 172.17.0.0/16 oifname != \"docker0\" masquerade\n\t}\n}\n"), 0o600)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-f", dockerNAT)
	if output, code := l.hostVaultSource(); code != 8 || !strings.Contains(output, "host to Vault source: REWRITTEN (Vault sees 192.168.1.156, not 172.17.0.1;") {
		t.Fatalf("with Docker's masquerade and no firewall the source must be rewritten: exit %d\n%s", code, output)
	}
	l.expectAll("with Docker's masquerade, without firewall", []hostFirewallExpectation{
		{"c1", "tcp", "192.168.1.1", 80, "", "connected"},
		{"c1", "tcp", "203.0.113.10", 443, "", "connected"},
		{"box", "tcp", "172.17.0.1", 8200, "", "connected"},
	})

	ruleset, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--render")
	if code != 0 {
		t.Fatalf("render: %d %s", code, stderr)
	}
	path := filepath.Join(t.TempDir(), "ruleset.nft")
	writeFile(t, path, []byte(ruleset), 0o600)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-c", "-f", path)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-f", path)
	// Loading twice is an atomic replace, not an error.
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-f", path)
	// The kernel also accepts the IPv6 form of the source chain.
	v6, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, "", "REMOTE_ALPHA_HOST_FIREWALL_VAULT_ADDRESS=fd00:17::1"), "--render")
	if code != 0 {
		t.Fatalf("render with an IPv6 Vault address: %d %s", code, stderr)
	}
	v6Path := filepath.Join(t.TempDir(), "ruleset-v6.nft")
	writeFile(t, v6Path, []byte(v6), 0o600)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-c", "-f", v6Path)

	// With the firewall, Vault sees the box's own connections from the
	// bridge address, Docker's rule notwithstanding.
	if output, code := l.hostVaultSource(); code != 0 || strings.TrimSpace(output) != "host to Vault source: kept (Vault sees 172.17.0.1)" {
		t.Fatalf("with the firewall the source must be kept: exit %d\n%s", code, output)
	}

	l.expectAll("with firewall", []hostFirewallExpectation{
		// From a container: Vault, the resolver and the internet work.
		{"c1", "tcp", "172.17.0.1", 8200, "", "connected"},
		{"c1", "udp", "192.168.1.1", 53, "", "answer"},
		{"c1", "tcp", "192.168.1.1", 53, "", "connected"},
		{"c1", "tcp", "203.0.113.10", 443, "", "connected"},
		// The box's LAN services, SSH and other ports are unreachable.
		{"c1", "tcp", "192.168.1.156", 8445, "", "timeout"},
		{"c1", "tcp", "192.168.1.156", 8444, "", "timeout"},
		{"c1", "tcp", "192.168.1.156", 22, "", "timeout"},
		{"c1", "tcp", "172.17.0.1", 22, "", "timeout"},
		{"c1", "tcp", "172.17.0.1", 5900, "", "timeout"},
		// The LAN (router admin page) and the other container are unreachable.
		{"c1", "tcp", "192.168.1.1", 80, "", "timeout"},
		{"c1", "tcp", "172.17.0.3", 9, "", "timeout"},
		{"c1", "tcp", "172.17.0.3", 8080, "", "timeout"},
		// From the LAN: the Mac reaches ES and AGS; another device does not.
		{"lan", "tcp", "192.168.1.156", 8445, "192.168.1.23", "connected"},
		{"lan", "tcp", "192.168.1.156", 8444, "192.168.1.23", "connected"},
		{"lan", "tcp", "192.168.1.156", 8445, "192.168.1.50", "timeout"},
		{"lan", "tcp", "192.168.1.156", 8444, "192.168.1.50", "timeout"},
		// SSH stays open to the LAN; an unlisted service is closed.
		{"lan", "tcp", "192.168.1.156", 22, "192.168.1.50", "connected"},
		{"lan", "tcp", "192.168.1.156", 22, "192.168.1.23", "connected"},
		{"lan", "tcp", "192.168.1.156", 5900, "192.168.1.23", "timeout"},
		// Vault and containers are not reachable from the LAN, even through
		// a route to the bridge subnet.
		{"lan", "tcp", "172.17.0.1", 8200, "192.168.1.23", "timeout"},
		{"lan", "tcp", "172.17.0.3", 8080, "192.168.1.50", "timeout"},
		// The box itself still reaches its own services.
		{"box", "tcp", "192.168.1.156", 8445, "", "connected"},
		{"box", "tcp", "172.17.0.1", 8200, "", "connected"},
	})
	// A published port (Docker-style DNAT to a container) is not reachable
	// from the LAN or from a public source: no new connection into a
	// container is forwarded.
	dnat := filepath.Join(t.TempDir(), "dnat.nft")
	writeFile(t, dnat, []byte("table ip docker_like_dnat {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"+
		"\t\tiifname \"wlp2s0\" tcp dport 18080 dnat to 172.17.0.3:8080\n\t}\n}\n"), 0o600)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-f", dnat)
	l.expectAll("published port", []hostFirewallExpectation{
		{"lan", "tcp", "192.168.1.156", 18080, "192.168.1.23", "timeout"},
		{"wan", "tcp", "192.168.1.156", 18080, "198.51.100.10", "timeout"},
	})

	// IPv6: the global address (which may be reachable from the internet)
	// takes no new connections, SSH included; SSH over link-local stays
	// open; neighbour discovery and replies to the box's own connections
	// still work.
	l.expectIPv6("with firewall", []hostFirewallExpectation{
		{"lan", "tcp", "2001:db8:1::156", 22, "2001:db8:1::50", "timeout"},
		{"lan", "tcp", "2001:db8:1::156", 22, "2001:db8:1::23", "timeout"},
		{"lan", "tcp", "2001:db8:1::156", 8445, "2001:db8:1::23", "timeout"},
		{"lan", "tcp", "2001:db8:1::156", 5900, "2001:db8:1::23", "timeout"},
		{"lan", "tcp", "fe80::156%lan0", 22, "fe80::23%lan0", "connected"},
		{"lan", "tcp", "fe80::156%lan0", 5900, "fe80::23%lan0", "timeout"},
		{"box", "tcp", "2001:db8:1::1", 80, "", "connected"},
	})

	for _, c := range []struct{ family, name string }{
		{"inet", "container_to_private"},
		{"inet", "container_to_host"},
		{"inet", "into_container"},
		{"inet", "lan_to_host"},
		{"inet", "host_to_vault_source_kept"},
		{"bridge", "container_to_container"},
	} {
		if got := l.counter(c.family, c.name); got == "0" {
			t.Errorf("counter %s %s did not move", c.family, c.name)
		}
	}

	// The rendered rules must survive an unrelated table with an accept-all
	// policy: a drop in our table is final.
	other := filepath.Join(t.TempDir(), "other.nft")
	writeFile(t, other, []byte("table inet other {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\taccept\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\taccept\n\t}\n}\n"), 0o600)
	l.run("ip", "netns", "exec", l.ns("box"), "nft", "-f", other)
	l.expectAll("with an accept-all table beside it", []hostFirewallExpectation{
		{"c1", "tcp", "192.168.1.1", 80, "", "timeout"},
		{"lan", "tcp", "192.168.1.156", 8445, "192.168.1.50", "timeout"},
		{"c1", "tcp", "172.17.0.1", 8200, "", "connected"},
	})
}

// hostFirewallLabL2Receiver counts, on eth0 of its namespace, raw frames
// that carry a marker: IPv4 (0x0800) and IPv6 (0x86dd) separately. It works
// below the namespace's IP stack, so it needs no IPv6 in the kernel.
const hostFirewallLabL2Receiver = `
import socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(("eth0", 0))
s.settimeout(0.2)
print("ready", flush=True)
counts = {"ipv4": 0, "ipv6": 0}
deadline = time.monotonic() + float(sys.argv[1])
while time.monotonic() < deadline:
    try:
        frame, address = s.recvfrom(2048)
    except socket.timeout:
        continue
    # Count arriving frames only, not what this namespace sends (such as an
    # ICMP error that quotes the marker).
    if address[2] == socket.PACKET_OUTGOING or b"ESFWL2MARK" not in frame:
        continue
    kind = {b"\x08\x00": "ipv4", b"\x86\xdd": "ipv6"}.get(frame[12:14])
    if kind:
        counts[kind] += 1
print("ipv4=%d ipv6=%d" % (counts["ipv4"], counts["ipv6"]), flush=True)
`

// hostFirewallLabL2Sender writes, from eth0 of its namespace, an IPv4/UDP
// frame with a forged source address and an IPv6/UDP frame between
// link-local addresses, both to the destination MAC address given.
const hostFirewallLabL2Sender = `
import socket, struct, sys
dst_mac = bytes.fromhex(sys.argv[1].replace(":", ""))
forged, target = socket.inet_aton(sys.argv[2]), socket.inet_aton(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth0", 0))
src_mac = s.getsockname()[4]
payload = b"ESFWL2MARK"
udp = struct.pack(">HHHH", 40000, 9999, 8 + len(payload), 0) + payload
header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, forged, target)
total = sum(struct.unpack(">10H", header))
total = (total & 0xFFFF) + (total >> 16)
checksum = ~((total & 0xFFFF) + (total >> 16)) & 0xFFFF
header = header[:10] + struct.pack(">H", checksum) + header[12:]
ipv6 = struct.pack(">IHBB16s16s", 6 << 28, len(udp), 17, 64,
                   socket.inet_pton(socket.AF_INET6, "fe80::2"), socket.inet_pton(socket.AF_INET6, "fe80::3"))
for _ in range(3):
    s.send(dst_mac + src_mac + b"\x08\x00" + header + udp)
    s.send(dst_mac + src_mac + b"\x86\xdd" + ipv6 + udp)
print("sent", flush=True)
`

// l2Probe sends the two raw frames from c1 to c2 and returns what c2 saw.
func (l *hostFirewallLab) l2Probe() string {
	l.t.Helper()
	link := l.run("ip", "-n", l.ns("c2"), "-o", "link", "show", "eth0")
	fields := strings.Fields(link)
	mac := ""
	for i, field := range fields {
		if field == "link/ether" && i+1 < len(fields) {
			mac = fields[i+1]
		}
	}
	if mac == "" {
		l.t.Fatalf("no MAC address for c2 eth0:\n%s", link)
	}
	receiver := exec.Command("ip", "netns", "exec", l.ns("c2"), "python3", "-I", "-c", hostFirewallLabL2Receiver, "2.5")
	stdout, err := receiver.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	receiver.Stderr = os.Stderr
	if err := receiver.Start(); err != nil {
		l.t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		_ = receiver.Process.Kill()
		_ = receiver.Wait()
		l.t.Fatalf("layer-2 receiver did not start: %q %v", line, err)
	}
	l.run("ip", "netns", "exec", l.ns("c1"), "python3", "-I", "-c", hostFirewallLabL2Sender, mac, "203.0.113.99", "172.17.0.3")
	result, _ := reader.ReadString('\n')
	if err := receiver.Wait(); err != nil {
		l.t.Fatalf("layer-2 receiver: %v", err)
	}
	return strings.TrimSpace(result)
}

// TestRemoteAlphaHostFirewallRealKernelBridgeIsolation turns br_netfilter's
// bridge calls off in the box namespace, so the inet rules never see frames
// between two containers on docker0 and only the bridge table stands between
// them, then sends a forged-source IPv4 frame and an IPv6 frame from one
// container to the other.
func TestRemoteAlphaHostFirewallRealKernelBridgeIsolation(t *testing.T) {
	l := newHostFirewallLab(t)
	box := l.ns("box")
	if _, err := os.Stat("/proc/sys/net/bridge/bridge-nf-call-iptables"); err == nil {
		for _, key := range []string{"bridge-nf-call-iptables", "bridge-nf-call-ip6tables", "bridge-nf-call-arptables"} {
			l.run("ip", "netns", "exec", box, "sysctl", "-qw", "net.bridge."+key+"=0")
		}
	}
	if got := l.l2Probe(); got != "ipv4=3 ipv6=3" {
		t.Fatalf("without the firewall both frames must arrive (the lab can see them), got %q", got)
	}
	ruleset, stderr, code := runHostFirewall(t, hostFirewallBaseEnv(t, ""), "--render")
	if code != 0 {
		t.Fatalf("render: %d %s", code, stderr)
	}
	path := filepath.Join(t.TempDir(), "ruleset.nft")
	writeFile(t, path, []byte(ruleset), 0o600)
	l.run("ip", "netns", "exec", box, "nft", "-f", path)
	if got := l.l2Probe(); got != "ipv4=0 ipv6=0" {
		t.Fatalf("with the firewall neither a forged-source IPv4 frame nor an IPv6 frame may pass between containers, got %q", got)
	}
	if got := l.counter("bridge", "container_to_container"); got != "6" {
		t.Fatalf("the bridge counter must count the six dropped frames, got %s", got)
	}
	// Containers still reach Vault, DNS and the internet: frames to the
	// bridge's own address are local delivery, not bridge forwarding.
	l.startLabServers()
	l.expectAll("bridge isolation, br_netfilter calls off", []hostFirewallExpectation{
		{"c1", "tcp", "172.17.0.1", 8200, "", "connected"},
		{"c1", "udp", "192.168.1.1", 53, "", "answer"},
		{"c1", "tcp", "203.0.113.10", 443, "", "connected"},
		{"c1", "tcp", "172.17.0.3", 9, "", "timeout"},
	})
}

func TestRemoteAlphaHostFirewallRealKernelApplyConfirmRollback(t *testing.T) {
	l := newHostFirewallLab(t)
	l.startLabServers()
	box := l.ns("box")

	// Real nft, ss and ip in the box namespace; fake systemctl and
	// systemd-run that keep state in files, so no host unit is touched.
	fakeBin := t.TempDir()
	state := t.TempDir()
	root := t.TempDir()
	unitPath := filepath.Join(root, "es-host-firewall.service")
	writeExecutable(t, fakeBin, "sshd", hostFirewallFakeSSHD)
	writeExecutable(t, fakeBin, "systemd-run", fmt.Sprintf(`#!/bin/bash
cmd=()
for arg in "$@"; do case "$arg" in --*) ;; *) cmd+=("$arg") ;; esac; done
printf '%%q ' "${cmd[@]}" >%q/rollback-command
echo waiting >%q/timer
`, state, state))
	writeExecutable(t, fakeBin, "systemctl", fmt.Sprintf(`#!/bin/bash
state=%q
case "$1" in
  show) cat "$state/timer" 2>/dev/null || echo dead ;;
  stop) echo dead >"$state/timer" ;;
  is-enabled) [[ "$*" == *es-host-firewall.service* && -f "$state/enabled" ]] ;;
  enable) touch "$state/enabled" ;;
  disable) rm -f "$state/enabled" ;;
  restart) nft -f "$(sed -n 's/^ExecStart=[^ ]* -f //p' %q)" ;;
  *) exit 0 ;;
esac
`, state, unitPath))
	env := hostFirewallBaseEnv(t, fakeBin,
		"REMOTE_ALPHA_HOST_FIREWALL_STATE_DIR="+filepath.Join(root, "state"),
		"REMOTE_ALPHA_HOST_FIREWALL_RUN_DIR="+filepath.Join(root, "run"),
		"REMOTE_ALPHA_HOST_FIREWALL_UNIT_PATH="+unitPath,
	)
	inBox := func(env []string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command("ip", append([]string{"netns", "exec", box, "/bin/bash", remoteAlphaHostFirewallScript()}, args...)...)
		cmd.Env = env
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return stdout.String(), stderr.String(), code
	}

	// The lab's VNC-like listener on 5900 would become unreachable: plan and
	// apply refuse until it is accepted.
	stdout, _, code := inBox(env, "--plan")
	if code != 1 || !strings.Contains(stdout, "not accepted: tcp/5900") {
		t.Fatalf("plan must refuse an unaccepted listener: %d\n%s", code, stdout)
	}
	if stdout, _, code := inBox(env, "--apply"); code != 1 || !strings.Contains(stdout, "nothing was changed") {
		t.Fatalf("apply must refuse an unaccepted listener: %d\n%s", code, stdout)
	}
	if got := l.probe("c1", "tcp", "192.168.1.1", 80, ""); got != "connected" {
		t.Fatalf("a refused apply must change nothing, got %s", got)
	}

	env = append(env, "REMOTE_ALPHA_HOST_FIREWALL_ACCEPT_BLOCKED_LISTENERS=tcp/5900")
	stdout, stderr, code := inBox(env, "--plan")
	if code != 0 || !strings.Contains(stdout, "nft -c (kernel accepts the ruleset): pass") {
		t.Fatalf("plan: %d\n%s\n%s", code, stdout, stderr)
	}

	// Apply, then let the "timer" fire: the box returns to no tables.
	stdout, stderr, code = inBox(env, "--apply")
	if code != 0 {
		t.Fatalf("apply: %d\n%s\n%s", code, stdout, stderr)
	}
	if got := l.probe("c1", "tcp", "192.168.1.1", 80, ""); got != "timeout" {
		t.Fatalf("applied rules must block the LAN, got %s", got)
	}
	rollbackCommand := strings.TrimSpace(readIfExists(filepath.Join(state, "rollback-command")))
	l.run("ip", "netns", "exec", box, "/bin/bash", "-c", rollbackCommand)
	writeFile(t, filepath.Join(state, "timer"), []byte("dead\n"), 0o644)
	if got := l.probe("c1", "tcp", "192.168.1.1", 80, ""); got != "connected" {
		t.Fatalf("the rollback must restore the state before apply, got %s", got)
	}
	if out := l.run("ip", "netns", "exec", box, "nft", "list", "tables"); strings.Contains(out, "es_host_firewall") {
		t.Fatalf("the rollback must remove our tables:\n%s", out)
	}
	if _, stderr, code := inBox(env, "--confirm"); code != 1 || !strings.Contains(stderr, "no apply is awaiting confirm") {
		t.Fatalf("confirm after the rollback fired: %d %s", code, stderr)
	}

	// Apply again, hold an SSH-like connection opened after apply, confirm.
	if stdout, stderr, code := inBox(env, "--apply"); code != 0 {
		t.Fatalf("second apply: %d\n%s\n%s", code, stdout, stderr)
	}
	if _, stderr, code := inBox(env, "--confirm"); code != 1 || !strings.Contains(stderr, "SSH connection opened after --apply") {
		t.Fatalf("confirm without a new SSH connection: %d %s", code, stderr)
	}
	holder := exec.Command("ip", "netns", "exec", l.ns("lan"), "python3", "-I", "-c",
		"import socket,sys\ns=socket.create_connection(('192.168.1.156',22),source_address=('192.168.1.23',0))\nprint('up',flush=True)\nsys.stdin.read()")
	holderIn, _ := holder.StdinPipe()
	holderOut, _ := holder.StdoutPipe()
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holderIn.Close(); _ = holder.Wait() }()
	if line, _ := bufio.NewReader(holderOut).ReadString('\n'); strings.TrimSpace(line) != "up" {
		t.Fatalf("SSH-like connection from the Mac failed after apply: %q", line)
	}
	time.Sleep(200 * time.Millisecond)
	stdout, stderr, code = inBox(env, "--confirm")
	if code != 0 || !strings.Contains(stdout, "RESULT: confirmed") {
		t.Fatalf("confirm: %d\n%s\n%s", code, stdout, stderr)
	}
	stdout, _, code = inBox(env, "--status")
	if code != 0 || !strings.Contains(stdout, "RESULT: installed and unchanged") || !strings.Contains(stdout, "lan_to_host") ||
		!strings.Contains(stdout, "host to Vault source: kept (Vault sees 172.17.0.1)") || !strings.Contains(stdout, "host_to_vault_source_kept") {
		t.Fatalf("status: %d\n%s", code, stdout)
	}

	// Drift: a rule added behind the script's back is reported.
	l.run("ip", "netns", "exec", box, "nft", "insert", "rule", "inet", "es_host_firewall", "input", "accept")
	if stdout, _, code := inBox(env, "--status"); code != 1 || !strings.Contains(stdout, "DIFFER") {
		t.Fatalf("status after drift: %d\n%s", code, stdout)
	}
	// Reloading the installed file (what the unit does at boot) repairs it.
	l.run("ip", "netns", "exec", box, "nft", "-f", filepath.Join(root, "state", "es-host-firewall.nft"))
	if stdout, _, code := inBox(env, "--status"); code != 0 {
		t.Fatalf("status after reload: %d\n%s", code, stdout)
	}

	// Rollback removes everything; traffic is as before the firewall.
	if stdout, stderr, code := inBox(env, "--rollback"); code != 0 {
		t.Fatalf("rollback: %d\n%s\n%s", code, stdout, stderr)
	}
	if got := l.probe("c1", "tcp", "192.168.1.1", 80, ""); got != "connected" {
		t.Fatalf("after rollback the LAN is reachable again, got %s", got)
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("rollback must remove the unit, stat err=%v", err)
	}
}

// TestRemoteAlphaHostFirewallDocsContract pins the documented contract of
// the host firewall (PLANS.md slice and the system-overview section) to the
// behaviour the tests above check.
func TestRemoteAlphaHostFirewallDocsContract(t *testing.T) {
	plans := compactDocSection(t, mustRead(t, "PLANS.md"), "## Current Remote Alpha Host Network Boundary Slice", "## Future ES Privilege-Boundary Design Track")
	assertContainsAll(t, "PLANS.md host network boundary slice", plans,
		"INF-01 (containers reach the home LAN), INF-13 (ES and AGS listeners open to the whole LAN) and INF-23",
		"`scripts/remote_alpha_host_firewall.sh`",
		"It owns only the nftables tables `inet es_host_firewall` and `bridge es_host_firewall`",
		"It never touches Docker's, ufw's or other rules, other sshd files, Vault, Nomad or ES, and reads no secrets.",
		"an identity snat ahead of Docker's masquerade rule",
		"It is the ruleset's only address rewrite.",
		"`/etc/execution-substrate/host-firewall/settings.env`",
		"`--apply` arms an automatic rollback that only `--confirm` from an SSH connection opened after `--apply` cancels.",
	)

	section := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "## Remote Alpha Host Firewall", "## Non-Goals")
	assertContainsAll(t, "host firewall docs section", section,
		"`execution-substrate.remote-alpha.host-firewall.v1`",
		"`testdata/remote_alpha_host_firewall/ruleset.golden.nft`",
		"input, default drop, at priority `filter - 10`",
		"from container interfaces (`CONTAINER_INTERFACES`, default `docker0 br-* nomad`): only `VAULT_ADDRESS:VAULT_PORT` (default `172.17.0.1:8200`)",
		"no new connection into a container is forwarded, published ports (Docker DNAT) included",
		"cannot reach each other at layer 2, whatever the `br_netfilter` state and whatever source address a container writes (the IPv4 rule matches the destination only), and no IPv6 frame passes from one bridge port to another.",
		"`--apply` refuses while a bridge exists that is not a container interface",
		"no container interface has a global or unique-local IPv6 address",
		"The new connection must come from an address inside `SSH_SOURCES` and not from loopback",
		"under `/var/lib/es-host-firewall`. They are on disk so that an apply cut short by a reboot (which also ends the timer) stays visible",
		"`/proc/sys/net/bridge/bridge-nf-call-iptables`, which exists whether it is a module or built in",
		"a real UDP service on such a port is blocked like any other unlisted listener",
		"the bound CIDR limits by network, not by workload",
		"one turns `br_netfilter` off in the lab and sends forged-source IPv4 and raw IPv6 frames between two containers, which must not arrive",
		"chain `host_to_vault_source` (nat, postrouting, priority `srcnat - 10`) applies an identity snat",
		"the workload role's `token_bound_cidrs` (`172.17.0.0/16`, P0q-R1) refuses the box's own workload-auth check with a plain 403",
		"an `accept` would not do this. It is the only address rewrite in the ruleset",
		"(`host_to_vault_source_kept`)",
		"`SERVICE_CALLERS` has no default.",
		"`SSH_PASSWORD_SOURCES` (default empty: keys only) must lie inside `SSH_SOURCES`",
		"`PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `X11Forwarding no`, then `Match Address <SSH_PASSWORD_SOURCES>`",
		"a `Match` block in an included file ends at the end of that file",
		"`ROLLBACK_SECONDS`, default 180",
		"`REMOTE_ALPHA_HOST_FIREWALL_CONFIRM_WITHOUT_NEW_SSH=1`",
		"Vault must see the box's own connections from `VAULT_ADDRESS`",
		"it opens a TCP connection to `VAULT_ADDRESS:VAULT_PORT`, sends nothing, and reads the accepted side of that connection from `/proc/net/tcp`",
		"`sudo bash scripts/remote_alpha_host_firewall.sh --rollback`",
		"the source check reports `REWRITTEN` to the LAN address without the firewall and `kept` with it",
		"Non-claims: not egress lanes",
	)
}
