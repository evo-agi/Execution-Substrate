package app_test

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// supportedNomadClientOptions is the client options map of the supported
// Nomad configuration: only the Docker driver is enabled.
const supportedNomadClientOptions = `  options = {
    "driver.allowlist" = "docker"
  }`

// supportedNomadClientNetworkInterface pins the node's host network to
// loopback in the supported Nomad configuration. ES jobs ask for no ports, so
// they need only a host-mode network to exist; loopback exists on Wi-Fi and on
// a cable alike, while a wired-port pin leaves none when the cable is out and
// no pin leaves Nomad unable to start without a default route.
const supportedNomadClientNetworkInterface = `  network_interface = "lo"`

// nomadNetworkInterfaceSetting matches every network_interface setting in a
// Nomad config, wherever it stands.
var nomadNetworkInterfaceSetting = regexp.MustCompile(`(?m)^\s*network_interface\s*=`)

// supportedNomadDockerPluginBlock is the Docker plugin block of the supported
// Nomad configuration, byte for byte as scripts/70_linux_setup.sh and
// .examples/config/nomad.hcl write it. Every real Nomad these tests start
// uses it, so the integration tests run ES jobs under the supported limits:
// no privileged containers and only the capabilities ES's runtime helper uses
// (audit INF-02). Removing any one of the seven capabilities fails the real
// Nomad and Docker submit tests on Nomad 2.1.1.
const supportedNomadDockerPluginBlock = `plugin "docker" {
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
`

// supportedNomadDockerPluginBlockWithTaskNameLabel adds the task-name label
// the installed-source witness profile needs, and nothing else.
func supportedNomadDockerPluginBlockWithTaskNameLabel() string {
	return strings.Replace(supportedNomadDockerPluginBlock, "  config {\n", "  config {\n    extra_labels = [\"task_name\"]\n", 1)
}

// supportedNomadDockerPluginAgentConfig is the Docker plugin entry an agent
// running the supported block reports in /v1/agent/self (Nomad 2.1.1 shape,
// reduced to the fields the checks read).
func supportedNomadDockerPluginAgentConfig() []map[string]any {
	return []map[string]any{{
		"Name": "docker",
		"Config": map[string]any{
			"allow_privileged": false,
			"allow_caps":       []string{"chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"},
			"volumes":          map[string]any{"enabled": true},
			"gc":               map[string]any{"image": false},
		},
	}}
}

// supportedNomadTLSAgentConfig is the TLSConfig an agent running the
// supported tls block reports in /v1/agent/self (Nomad 2.1.1 and 2.0.0 agree),
// reduced to the fields the posture check reads.
func supportedNomadTLSAgentConfig() map[string]any {
	return map[string]any{
		"EnableHTTP":           true,
		"EnableRPC":            true,
		"TLSMinVersion":        "tls13",
		"VerifyServerHostname": true,
		"RPCUpgradeMode":       false,
	}
}

// supportedNomadAgentStats is the stats block an agent that encrypts its
// gossip reports in /v1/agent/self, reduced to the field the posture check
// reads. Nomad reports stats.serf.encrypted as a string.
func supportedNomadAgentStats() map[string]any {
	return map[string]any{"serf": map[string]any{"encrypted": "true"}}
}

// extractNomadBlock returns the top-level block that starts with header, up
// to and including its closing brace at the start of a line.
func extractNomadBlock(t *testing.T, text string, header string) string {
	t.Helper()
	start := strings.Index(text, "\n"+header+" {\n")
	if start < 0 || strings.Count(text, "\n"+header+" {\n") != 1 {
		t.Fatalf("expected exactly one %s block", header)
	}
	start++
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s block is not closed", header)
	}
	return text[start : start+end+3]
}

// The supported setup script, the example configuration and the test Nomad
// agents carry the same Docker limits and the same tls block, so CI proves
// what hosts run.
func TestSupportedNomadDockerLimitsMatchSetupExampleAndTests(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	for rel, tlsDir := range map[string]string{
		filepath.Join("scripts", "70_linux_setup.sh"):     "${NOMAD_TLS_DIR}",
		filepath.Join(".examples", "config", "nomad.hcl"): "/etc/nomad.d/tls",
	} {
		body, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if got := extractNomadBlock(t, text, `plugin "docker"`); got != supportedNomadDockerPluginBlock {
			t.Fatalf("%s Docker plugin block differs from the tested one:\n%s", rel, got)
		}
		if got := extractNomadBlock(t, text, "tls"); got != supportedNomadTLSBlock(tlsDir) {
			t.Fatalf("%s tls block differs from the tested one:\n%s", rel, got)
		}
		client := extractNomadBlock(t, text, "client")
		if !strings.Contains(client, supportedNomadClientOptions+"\n") {
			t.Fatalf("%s client block does not enable only the Docker driver:\n%s", rel, client)
		}
		// Wi-Fi or cable: the host network comes from loopback, never from a
		// named wired or wireless port.
		if len(nomadNetworkInterfaceSetting.FindAllString(text, -1)) != 1 || !strings.Contains(client, "\n"+supportedNomadClientNetworkInterface+"\n") {
			t.Fatalf("%s client block does not pin the host network to loopback, and only there:\n%s", rel, client)
		}
		for _, stale := range []string{`"docker.cleanup.image"`, `"docker.volumes.enabled"`, "allow_privileged = true", `"raw_exec"`} {
			if strings.Contains(text, stale) {
				t.Fatalf("%s still names %s", rel, stale)
			}
		}
	}

	witness := supportedNomadDockerPluginBlockWithTaskNameLabel()
	if strings.Count(witness, `extra_labels = ["task_name"]`) != 1 || strings.Replace(witness, "    extra_labels = [\"task_name\"]\n", "", 1) != supportedNomadDockerPluginBlock {
		t.Fatal("the witness profile changes more than the task-name label")
	}
}

// The setup script's qualify step reads each ready node's detail with the
// qualify token and, like bring-up readiness, refuses a node without a
// host-mode network: a client pinned to a wired port whose cable is out has
// only a bridge network, and Nomad cannot place any ES job there.
func TestLinuxSetupQualifyRequiresAHostNetwork(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const opener = `python3 -I - <<'PY' "${NOMAD_HTTP_ADDR}" "${leader_path}" "${agent_path}" "${nodes_path}"` + "\n"
	text := string(body)
	if strings.Count(text, opener) != 1 {
		t.Fatalf("70_linux_setup.sh holds %d qualify programs, want 1", strings.Count(text, opener))
	}
	program := text[strings.Index(text, opener)+len(opener):]
	end := strings.Index(program, "\nPY\n")
	if end < 0 {
		t.Fatal("the qualify program does not end")
	}
	program = program[:end+1]

	const qualifyToken = "9d934051-6f7e-4a81-b2c3-d4e5f6a7b8c9"
	const encryptedAgent = `{"config":{"DevMode":false},"stats":{"serf":{"encrypted":"true"}}}`
	for _, test := range []struct {
		name     string
		agent    string
		networks any
		want     string
		refused  bool
	}{
		{"loopback host network", encryptedAgent, fakeNomadLoopbackHostNetworks, "mode=non-dev gossip=encrypted ready_nodes=1 schedulable_nodes=1 fixture:cpu.totalcompute=4000", false},
		{"bridge network only", encryptedAgent, []map[string]any{{"Mode": "bridge", "Device": "nomad"}},
			"nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network; fixture=no-host-network", true},
		{"no networks reported", encryptedAgent, nil,
			"nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network; fixture=no-host-network", true},
		// Red-team RT60-1: the keyring the setup writes takes effect only
		// when Nomad starts, so qualification asks the running agent.
		{"gossip not encrypted", `{"config":{"DevMode":false},"stats":{"serf":{"encrypted":"false"}}}`, fakeNomadLoopbackHostNetworks,
			"nomad: the agent does not encrypt its gossip", true},
		{"no serf stats", `{"config":{"DevMode":false}}`, fakeNomadLoopbackHostNetworks,
			"nomad: the agent does not encrypt its gossip", true},
		{"stats not an object", `{"config":{"DevMode":false},"stats":["serf"]}`, fakeNomadLoopbackHostNetworks,
			"nomad: the agent does not encrypt its gossip", true},
		{"serf stats not an object", `{"config":{"DevMode":false},"stats":{"serf":"true"}}`, fakeNomadLoopbackHostNetworks,
			"nomad: the agent does not encrypt its gossip", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, material := startNomadTLSStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/node/node-1" || r.Header.Get("X-Nomad-Token") != qualifyToken {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"Attributes":    map[string]any{"cpu.totalcompute": "4000"},
					"Drivers":       map[string]any{"docker": map[string]any{"Healthy": true}},
					"NodeResources": map[string]any{"Networks": test.networks},
				})
			}))
			dir := t.TempDir()
			files := map[string]string{
				"leader.json": `"127.0.0.1:4647"`,
				"agent.json":  test.agent,
				"nodes.json":  `[{"ID":"node-1","Name":"fixture","Status":"ready"}]`,
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("python3", "-I", "-", server.URL,
				filepath.Join(dir, "leader.json"), filepath.Join(dir, "agent.json"), filepath.Join(dir, "nodes.json"))
			command.Dir = dir
			command.Stdin = strings.NewReader(program)
			command.Env = []string{"PATH=" + os.Getenv("PATH"), "NOMAD_TOKEN=" + qualifyToken, "NOMAD_CACERT=" + material.caFile}
			output, err := command.CombinedOutput()
			if (err != nil) != test.refused || !strings.Contains(string(output), test.want) {
				t.Fatalf("qualify on a node with %s: %v output=%s", test.name, err, output)
			}
		})
	}
}

// Nomad runs as root, so its config and data directories belong to root
// (audit INF-16), and the config is not world-readable.
func TestLinuxSetupKeepsNomadConfigAndDataRootOwned(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		`sudo install -d -o root -g root -m 0755 "${NOMAD_CONFIG_DIR}"`,
		`sudo install -d -o root -g root -m 0700 "${NOMAD_DATA_DIR}"`,
		`sudo chown root:root "${NOMAD_CONFIG_PATH}"`,
		`sudo chmod 0640 "${NOMAD_CONFIG_PATH}"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("70_linux_setup.sh is missing %q", want)
		}
	}
	if strings.Contains(text, "nomad:nomad") || strings.Contains(text, "-o nomad") {
		t.Fatal("70_linux_setup.sh still gives the nomad account a Nomad config or data path")
	}
}

func runNomadRuntimePostureCheck(t *testing.T, agentSelf any) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent-self.json")
	var body []byte
	if raw, ok := agentSelf.(string); ok {
		body = []byte(raw)
	} else {
		body = mustMarshalJSON(t, agentSelf)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source scripts/internal/nomad_acl.sh; nomad_runtime_posture_check "$1"`, "posture", path)
	cmd.Dir = executionPlatformRepoRoot(t)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

const supportedNomadPostureLine = "nomad: drivers=docker docker_privileged=refused docker_caps=chown,dac_override,fowner,kill,setgid,setpcap,setuid tls=1.3 gossip=encrypted"

// The posture check accepts the supported agent and refuses each loosening of
// the driver allowlist or the Docker plugin limits.
func TestNomadRuntimePostureCheckRefusesLoosenedDockerLimits(t *testing.T) {
	agent := func(edit func(config map[string]any, plugin map[string]any)) map[string]any {
		plugins := supportedNomadDockerPluginAgentConfig()
		config := map[string]any{
			"Client":    map[string]any{"Enabled": true, "Options": map[string]any{"driver.allowlist": "docker"}},
			"Plugins":   plugins,
			"TLSConfig": supportedNomadTLSAgentConfig(),
		}
		if edit != nil {
			edit(config, plugins[0]["Config"].(map[string]any))
		}
		return map[string]any{"config": config, "stats": supportedNomadAgentStats()}
	}
	gossip := func(serf any) map[string]any {
		document := agent(nil)
		if serf == nil {
			delete(document, "stats")
		} else {
			document["stats"] = map[string]any{"serf": serf}
		}
		return document
	}
	if output, err := runNomadRuntimePostureCheck(t, agent(nil)); err != nil || output != supportedNomadPostureLine {
		t.Fatalf("supported agent refused: %v %s", err, output)
	}
	for _, test := range []struct {
		name  string
		agent any
		want  string
	}{
		{"exec also enabled", agent(func(c, _ map[string]any) {
			c["Client"].(map[string]any)["Options"] = map[string]any{"driver.allowlist": "docker,exec"}
		}), "enable only the Docker driver"},
		{"no allowlist", agent(func(c, _ map[string]any) { c["Client"] = map[string]any{"Enabled": true} }), "enable only the Docker driver"},
		{"no plugin block", agent(func(c, _ map[string]any) { delete(c, "Plugins") }), `explicit plugin "docker" block`},
		{"privileged allowed", agent(func(_, p map[string]any) { p["allow_privileged"] = true }), "refuse privileged containers"},
		{"privileged unset", agent(func(_, p map[string]any) { delete(p, "allow_privileged") }), "refuse privileged containers"},
		{"extra capability", agent(func(_, p map[string]any) {
			p["allow_caps"] = []string{"chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap", "sys_admin"}
		}), "allow only capabilities ES's runtime helper uses"},
		{"Docker default capabilities", agent(func(_, p map[string]any) { delete(p, "allow_caps") }), "allow only capabilities ES's runtime helper uses"},
		{"empty capability list", agent(func(_, p map[string]any) { p["allow_caps"] = []string{} }), "allow only capabilities ES's runtime helper uses"},
		{"plain HTTP", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["EnableHTTP"] = false }), "TLS 1.3 only"},
		{"plain RPC", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["EnableRPC"] = false }), "TLS 1.3 only"},
		{"TLS 1.2 allowed", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["TLSMinVersion"] = "tls12" }), "TLS 1.3 only"},
		{"TLS version unset", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["TLSMinVersion"] = "" }), "TLS 1.3 only"},
		{"server names not verified", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["VerifyServerHostname"] = false }), "TLS 1.3 only"},
		{"RPC upgrade mode", agent(func(c, _ map[string]any) { c["TLSConfig"].(map[string]any)["RPCUpgradeMode"] = true }), "TLS 1.3 only"},
		{"no TLS settings", agent(func(c, _ map[string]any) { delete(c, "TLSConfig") }), "TLS 1.3 only"},
		{"gossip not encrypted", gossip(map[string]any{"encrypted": "false"}), "must encrypt its gossip"},
		{"gossip encryption as a boolean", gossip(map[string]any{"encrypted": true}), "must encrypt its gossip"},
		{"no serf stats", gossip(map[string]any{}), "must encrypt its gossip"},
		{"no stats", gossip(nil), "must encrypt its gossip"},
		{"stats not an object", func() map[string]any { document := agent(nil); document["stats"] = []any{"serf"}; return document }(), "must encrypt its gossip"},
		{"serf stats not an object", gossip("true"), "must encrypt its gossip"},
		{"unreadable answer", "{not json", "the agent configuration could not be read"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := runNomadRuntimePostureCheck(t, test.agent)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("posture check did not refuse with %q: err=%v output=%s", test.want, err, output)
			}
		})
	}
}

// On a real Nomad started with the supported limits, the posture check
// passes, the node offers only the Docker driver, and ES's own token cannot
// get a privileged container, an extra capability or another driver. Those
// three are all the limits refuse. Host bind mounts as container root, host
// networking, host devices, security_opt (seccomp=unconfined) and, on Nomad
// 2.0.0, the host PID, IPC and user namespaces still run (audit INF-02);
// the configuration docs record them. Nomad 2.1.1 (the CI pin) refuses the
// three host-namespace modes. The host-namespace rows below pin whichever
// side the running Nomad is on.
func TestRealNomadOffersOnlyTheLimitedDockerDriver(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{})
	// startACLTestNomad waits only for a leader; the drivers are read from
	// the registered client node.
	harness.waitReady(t)
	esToken := readNomadTokenFile(t, harness.esTokenFile)
	observerToken := readNomadTokenFile(t, harness.observerTokenFile)

	status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/agent/self", observerToken, nil)
	if status != http.StatusOK {
		t.Fatalf("observer could not read the agent: HTTP %d %s", status, body)
	}
	if output, err := runNomadRuntimePostureCheck(t, body); err != nil || output != supportedNomadPostureLine {
		t.Fatalf("real agent posture: %v %s", err, output)
	}
	// The fixtures the other checks use must have the real agent's shape for
	// every field those checks read.
	var agentSelf struct {
		Config struct {
			Plugins   []map[string]any `json:"Plugins"`
			TLSConfig map[string]any   `json:"TLSConfig"`
			Version   struct {
				Version string `json:"Version"`
			} `json:"Version"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(body), &agentSelf); err != nil {
		t.Fatalf("decode agent self: %v", err)
	}
	if agentSelf.Config.Version.Version == "" {
		t.Fatalf("real agent reports no version: %s", body)
	}
	// Nomad 2.0 runs the host PID, IPC and user namespace modes that
	// Nomad 2.1 refuses.
	hostNamespacesOpen := strings.HasPrefix(agentSelf.Config.Version.Version, "2.0.")
	for field, want := range supportedNomadTLSAgentConfig() {
		if got := agentSelf.Config.TLSConfig[field]; string(mustMarshalJSON(t, got)) != string(mustMarshalJSON(t, want)) {
			t.Fatalf("real agent TLSConfig.%s = %s, fixture has %s", field, mustMarshalJSON(t, got), mustMarshalJSON(t, want))
		}
	}
	var realDocker map[string]any
	for _, plugin := range agentSelf.Config.Plugins {
		if plugin["Name"] == "docker" {
			realDocker, _ = plugin["Config"].(map[string]any)
		}
	}
	fixture := supportedNomadDockerPluginAgentConfig()[0]["Config"].(map[string]any)
	for field, want := range fixture {
		got := realDocker[field]
		if nested, ok := want.(map[string]any); ok {
			// Nomad 2.1 reports a nested block as an object, Nomad 2.0
			// (the version on the box) as a list holding one object.
			if list, isList := got.([]any); isList && len(list) == 1 {
				got = list[0]
			}
			gotNested, isMap := got.(map[string]any)
			if !isMap {
				t.Fatalf("real agent Docker plugin %s = %s, want an object", field, mustMarshalJSON(t, got))
			}
			for key, value := range nested {
				if string(mustMarshalJSON(t, gotNested[key])) != string(mustMarshalJSON(t, value)) {
					t.Fatalf("real agent Docker plugin %s.%s = %s, fixture has %s", field, key, mustMarshalJSON(t, gotNested[key]), mustMarshalJSON(t, value))
				}
			}
			continue
		}
		if string(mustMarshalJSON(t, got)) != string(mustMarshalJSON(t, want)) {
			t.Fatalf("real agent Docker plugin %s = %s, fixture has %s", field, mustMarshalJSON(t, got), mustMarshalJSON(t, want))
		}
	}

	status, body = nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/nodes", observerToken, nil)
	var nodes []struct {
		ID string `json:"ID"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &nodes) != nil || len(nodes) != 1 {
		t.Fatalf("list nodes: HTTP %d %s", status, body)
	}
	status, body = nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/node/"+nodes[0].ID, observerToken, nil)
	var node struct {
		Drivers map[string]struct {
			Detected bool `json:"Detected"`
			Healthy  bool `json:"Healthy"`
		} `json:"Drivers"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &node) != nil {
		t.Fatalf("read node: HTTP %d %s", status, body)
	}
	for name, driver := range node.Drivers {
		if name != "docker" && (driver.Detected || driver.Healthy) {
			t.Fatalf("node offers driver %s", name)
		}
	}
	if docker := node.Drivers["docker"]; !docker.Detected || !docker.Healthy {
		t.Fatal("node does not offer a healthy Docker driver")
	}

	// The supported client config pins the node's host network to loopback,
	// and the operators' placement check passes on it: ES's job shapes
	// (network mode none and bridge, no Nomad network block) plan with ES's
	// token in ES's namespace.
	esConfig := filepath.Join(t.TempDir(), "es.json")
	if err := os.WriteFile(esConfig, mustMarshalJSON(t, map[string]any{"nomad": map[string]any{"datacenter": "dc1"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runNomadACLTool(t, "placement", "--addr", harness.addr, "--ca-file", harness.tls.caFile, "--es-token-file", harness.esTokenFile,
		"--observer-token-file", harness.observerTokenFile, "--es-config", esConfig, "--wait-seconds", "30"); err != nil ||
		!strings.Contains(output, "nomad placement: ok (host-mode network on ") {
		t.Fatalf("placement check on the supported client config: %v output=%s", err, output)
	}

	job := func(id string, driver string, config map[string]any) []byte {
		return mustMarshalJSON(t, map[string]any{"Job": map[string]any{
			"ID": id, "Name": id, "Type": "batch", "Namespace": nomadACLNamespace, "Datacenters": []string{"dc1"},
			"TaskGroups": []map[string]any{{
				"Name": "probe", "Count": 1,
				"RestartPolicy":    map[string]any{"Attempts": 0, "Mode": "fail"},
				"ReschedulePolicy": map[string]any{"Attempts": 0, "Unlimited": false},
				"Tasks": []map[string]any{{
					"Name": "probe", "Driver": driver, "Config": config,
					"Resources": map[string]any{"CPU": 100, "MemoryMB": 64},
				}},
			}},
		}})
	}
	type dockerLimitCase struct {
		id, driver string
		config     map[string]any
		taskEvent  string
	}
	refusals := []dockerLimitCase{
		{"limit-privileged", "docker", map[string]any{"image": "alpine:3.20", "command": "/bin/true", "privileged": true}, "Docker privileged mode is disabled on this Nomad agent"},
		{"limit-capability", "docker", map[string]any{"image": "alpine:3.20", "command": "/bin/true", "cap_add": []string{"sys_admin"}}, "driver does not allow the following capabilities: sys_admin"},
		{"limit-exec", "exec", map[string]any{"command": "/bin/true"}, ""},
		{"limit-raw-exec", "raw_exec", map[string]any{"command": "/bin/true"}, ""},
	}
	// The host-namespace modes: refused on Nomad 2.1, run on Nomad 2.0, as
	// the configuration docs say.
	var hostNamespaceRuns []dockerLimitCase
	for _, mode := range []string{"pid_mode", "ipc_mode", "userns_mode"} {
		hostMode := dockerLimitCase{
			id: "host-" + strings.TrimSuffix(mode, "_mode"), driver: "docker",
			config:    map[string]any{"image": "alpine:3.20", "command": "/bin/true", mode: "host"},
			taskEvent: `cannot apply "` + mode + `" configuration`,
		}
		if hostNamespacesOpen {
			hostNamespaceRuns = append(hostNamespaceRuns, hostMode)
		} else {
			refusals = append(refusals, hostMode)
		}
	}
	for _, refusal := range append(append([]dockerLimitCase{}, refusals...), hostNamespaceRuns...) {
		status, body := nomadRawRequest(t, http.MethodPost, harness.addr+"/v1/jobs?namespace="+nomadACLNamespace, esToken, job(refusal.id, refusal.driver, refusal.config))
		if status != http.StatusOK {
			t.Fatalf("register %s: HTTP %d %s", refusal.id, status, body)
		}
		id := refusal.id
		t.Cleanup(func() {
			_, _ = nomadRawRequest(t, http.MethodDelete, harness.addr+"/v1/job/"+id+"?namespace="+nomadACLNamespace+"&purge=true", harness.managementToken, nil)
		})
	}
	for _, refusal := range refusals {
		deadline := time.Now().Add(30 * time.Second)
		for {
			if refusal.taskEvent != "" {
				_, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/job/"+refusal.id+"/allocations?namespace="+nomadACLNamespace, esToken, nil)
				var allocations []struct {
					ClientStatus string `json:"ClientStatus"`
					TaskStates   map[string]struct {
						Events []struct {
							DisplayMessage string `json:"DisplayMessage"`
						} `json:"Events"`
					} `json:"TaskStates"`
				}
				_ = json.Unmarshal([]byte(body), &allocations)
				refused := false
				for _, allocation := range allocations {
					if allocation.ClientStatus == "complete" {
						t.Fatalf("%s ran", refusal.id)
					}
					for _, state := range allocation.TaskStates {
						for _, event := range state.Events {
							refused = refused || strings.Contains(event.DisplayMessage, refusal.taskEvent)
						}
					}
				}
				if refused {
					break
				}
			} else {
				_, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/job/"+refusal.id+"/evaluations?namespace="+nomadACLNamespace, esToken, nil)
				var evaluations []struct {
					FailedTGAllocs map[string]struct {
						ConstraintFiltered map[string]int `json:"ConstraintFiltered"`
					} `json:"FailedTGAllocs"`
				}
				_ = json.Unmarshal([]byte(body), &evaluations)
				missing := false
				for _, evaluation := range evaluations {
					for _, failed := range evaluation.FailedTGAllocs {
						missing = missing || failed.ConstraintFiltered["missing drivers"] > 0
					}
				}
				if missing {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s was not refused by the Docker limits within 30s", refusal.id)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	for _, run := range hostNamespaceRuns {
		deadline := time.Now().Add(60 * time.Second)
		for {
			_, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/job/"+run.id+"/allocations?namespace="+nomadACLNamespace, esToken, nil)
			var allocations []struct {
				ClientStatus string `json:"ClientStatus"`
			}
			_ = json.Unmarshal([]byte(body), &allocations)
			ran := false
			for _, allocation := range allocations {
				if allocation.ClientStatus == "failed" {
					t.Fatalf("%s failed on Nomad %s, which the configuration docs say runs it: %s", run.id, agentSelf.Config.Version.Version, body)
				}
				ran = ran || allocation.ClientStatus == "complete"
			}
			if ran {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not run on Nomad %s within 60s: %s", run.id, agentSelf.Config.Version.Version, body)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}
