package app_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func runWorkloadEgressLine(t *testing.T, esConfigPath string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; workload_egress_line "$ES_CONFIG"`)
	cmd.Dir = executionPlatformRepoRoot(t)
	cmd.Env = append(os.Environ(), "ES_CONFIG="+esConfigPath)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Readiness reports the temporary compatibility edge of the workload grants
// contract (.docs/execution_lifecycle/contracts.md, section 5B): while any
// grant rule gives the lane unrestricted, workload_egress_unrestricted=true.
func TestReadinessReportsWorkloadEgressUnrestricted(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	for _, example := range []struct {
		file  string
		rules string
	}{
		{"es.json", "2"},
		{"es.operator_and_control_plane.json", "4"},
		{"es.configured_literal_policy_demo.json", "2"},
	} {
		output, err := runWorkloadEgressLine(t, filepath.Join(repoRoot, ".examples", "config", example.file))
		if err != nil || !strings.HasPrefix(output, "workload_egress_unrestricted=true ("+example.rules+" workload grant rule(s) give the egress lane unrestricted") {
			t.Errorf("%s: %v %q", example.file, err, output)
		}
	}

	rootDir := t.TempDir()
	for name, config := range map[string]any{
		"no admission policy": map[string]any{"http": map[string]any{}},
		"no grants":           map[string]any{"admission_policy": map[string]any{}},
		"no rules":            map[string]any{"admission_policy": map[string]any{"workload_grants": map[string]any{}}},
		"rules without a lane": map[string]any{"admission_policy": map[string]any{"workload_grants": map[string]any{
			"rules": []any{map[string]any{"id": "no-network"}},
		}}},
	} {
		path := writeJSONConfigFile(t, rootDir, strings.ReplaceAll(name, " ", "-")+".json", config)
		output, err := runWorkloadEgressLine(t, path)
		if err != nil || strings.TrimSpace(output) != "workload_egress_unrestricted=false (no workload grant rule gives the egress lane unrestricted)" {
			t.Errorf("%s: %v %q", name, err, output)
		}
	}

	path := writeJSONConfigFile(t, rootDir, "rules-not-a-list.json", map[string]any{
		"admission_policy": map[string]any{"workload_grants": map[string]any{"rules": "unrestricted"}},
	})
	if output, err := runWorkloadEgressLine(t, path); err == nil || !strings.Contains(output, "admission_policy.workload_grants.rules must be a list") {
		t.Errorf("rules that are not a list: %v %q", err, output)
	}
}

// The health check prints the line in its own section whenever it has ES's
// configuration.
func TestHealthCheckPrintsTheWorkloadEgressLine(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "10_health_check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		`print_check_section "workload grants"`,
		`workload_egress_line "${ES_CONFIG}"`,
		`echo "workload_egress_unrestricted: skipped (ES_CONFIG is not set)"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scripts/10_health_check.sh lacks %q", want)
		}
	}
}

// ES and the readiness line read the same es.json the same way: for every
// file ES starts with, the line reports the lane unrestricted exactly when
// ES's rules give it, and a file ES refuses for a repeated key or a key in
// another letter case is refused by the line too. (Red-team of ES PR #73,
// RT73-1, and audit 10, F4: encoding/json folds letter case and merges
// repeated keys, Python lets the last one win, so the two used to disagree.)
func TestReadinessLineAndESReadTheSameConfigurationTheSameWay(t *testing.T) {
	example, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), ".examples", "config", "es.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(example, &base); err != nil {
		t.Fatal(err)
	}
	delete(base, "admission_policy")
	keyID := base["verification"].(map[string]any)["provenance"].(map[string]any)["key_id"].(string)
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	withPolicy := func(policy string) string {
		return strings.TrimSuffix(strings.TrimSpace(string(encoded)), "}") + ", " + policy + "}"
	}
	lanes := `"egress_lanes": [{"name": "unrestricted", "reaches_workload_vault": true}]`
	rule := `{"id": "operator-default", "publisher_principal": "spiffe://execution.internal/operator/local", "caller_principal": "spiffe://execution.internal/operator/local", "signer_key_id": "` + keyID +
		`", "artifact_type": "static-script", "runtime_profile": "static-script/default"`
	granting := rule + `, "egress_lane": "unrestricted"}`
	longS, kelvin := string(rune(0x17f)), string(rune(0x212a))

	rootDir := t.TempDir()
	for i, test := range []struct {
		name       string
		policy     string
		esStarts   bool
		lineGrants bool
	}{
		{"exact keys, granting", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}}`, true, true},
		{"exact keys, no lane", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `}]}}`, true, false},
		{"escaped key that decodes exactly", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "egress_lane": "unrestricted"}]}}`, true, true},
		{"rule key Egress_Lane", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "Egress_Lane": "unrestricted"}]}}`, false, false},
		{"rule key EGRESS_LANE", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "EGRESS_LANE": "unrestricted"}]}}`, false, false},
		{"egress_lane empty, then Egress_Lane", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "egress_lane": "", "Egress_Lane": "unrestricted"}]}}`, false, false},
		{"key RULES", `"admission_policy": {"workload_grants": {` + lanes + `, "RULES": [` + granting + `]}}`, false, false},
		{"key Admission_Policy", `"Admission_Policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}}`, false, false},
		{"admission_policy twice, the second empty", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}}, "admission_policy": {}`, false, false},
		{"workload_grants twice, the second empty", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}, "workload_grants": {}}`, false, false},
		{"rules twice, the second without egress_lane", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `], "rules": [` + rule + `}]}}`, false, false},
		{"long s in egress_lane", `"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "egre` + longS + `s_lane": "unrestricted"}]}}`, false, false},
		{"Kelvin sign in workload_grants", `"admission_policy": {"wor` + kelvin + `load_grants": {` + lanes + `, "rules": [` + granting + `]}}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(rootDir, fmt.Sprintf("es-%d.json", i))
			if err := os.WriteFile(path, []byte(withPolicy(test.policy)), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, loadErr := esconfig.Load(path)
			if (loadErr == nil) != test.esStarts {
				t.Fatalf("ES load: %v, want ES to start=%t", loadErr, test.esStarts)
			}
			output, lineErr := runWorkloadEgressLine(t, path)
			if !test.esStarts {
				if lineErr == nil || !strings.Contains(output, "ES refuses such a file") {
					t.Fatalf("ES refuses the file (%v), the line printed %q (%v)", loadErr, output, lineErr)
				}
				return
			}
			esGrants := false
			if cfg.AdmissionPolicy != nil && cfg.AdmissionPolicy.WorkloadGrants != nil {
				for _, rule := range cfg.AdmissionPolicy.WorkloadGrants.Rules {
					esGrants = esGrants || rule.EgressLane == esconfig.WorkloadEgressLaneUnrestricted
				}
			}
			lineGrants := strings.HasPrefix(output, "workload_egress_unrestricted=true")
			if lineErr != nil || esGrants != test.lineGrants || lineGrants != esGrants {
				t.Fatalf("ES gives unrestricted=%t, the line printed %q (%v)", esGrants, output, lineErr)
			}
		})
	}
}
