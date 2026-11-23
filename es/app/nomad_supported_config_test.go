package app_test

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// supportedNomadClientOptions is the client options map of the supported
// Nomad configuration: only the Docker driver is enabled.
const supportedNomadClientOptions = `  options = {
    "driver.allowlist" = "docker"
  }`

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
// agents carry the same Docker limits, so CI proves what hosts run.
func TestSupportedNomadDockerLimitsMatchSetupExampleAndTests(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	for _, rel := range []string{filepath.Join("scripts", "70_linux_setup.sh"), filepath.Join(".examples", "config", "nomad.hcl")} {
		body, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if got := extractNomadBlock(t, text, `plugin "docker"`); got != supportedNomadDockerPluginBlock {
			t.Fatalf("%s Docker plugin block differs from the tested one:\n%s", rel, got)
		}
		client := extractNomadBlock(t, text, "client")
		if !strings.Contains(client, supportedNomadClientOptions+"\n") {
			t.Fatalf("%s client block does not enable only the Docker driver:\n%s", rel, client)
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

const supportedNomadPostureLine = "nomad: drivers=docker docker_privileged=refused docker_caps=chown,dac_override,fowner,kill,setgid,setpcap,setuid"

// The posture check accepts the supported agent and refuses each loosening of
// the driver allowlist or the Docker plugin limits.
func TestNomadRuntimePostureCheckRefusesLoosenedDockerLimits(t *testing.T) {
	agent := func(edit func(config map[string]any, plugin map[string]any)) map[string]any {
		plugins := supportedNomadDockerPluginAgentConfig()
		config := map[string]any{
			"Client":  map[string]any{"Enabled": true, "Options": map[string]any{"driver.allowlist": "docker"}},
			"Plugins": plugins,
		}
		if edit != nil {
			edit(config, plugins[0]["Config"].(map[string]any))
		}
		return map[string]any{"config": config}
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
// 2.0.0, the host PID namespace still run (audit INF-02); the configuration
// docs record them.
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
			Plugins []map[string]any `json:"Plugins"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(body), &agentSelf); err != nil {
		t.Fatalf("decode agent self: %v", err)
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
	refusals := []struct {
		id, driver string
		config     map[string]any
		taskEvent  string
	}{
		{"limit-privileged", "docker", map[string]any{"image": "alpine:3.20", "command": "/bin/true", "privileged": true}, "Docker privileged mode is disabled on this Nomad agent"},
		{"limit-capability", "docker", map[string]any{"image": "alpine:3.20", "command": "/bin/true", "cap_add": []string{"sys_admin"}}, "driver does not allow the following capabilities: sys_admin"},
		{"limit-exec", "exec", map[string]any{"command": "/bin/true"}, ""},
		{"limit-raw-exec", "raw_exec", map[string]any{"command": "/bin/true"}, ""},
	}
	for _, refusal := range refusals {
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
}
