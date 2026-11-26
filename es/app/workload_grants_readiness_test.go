package app_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
