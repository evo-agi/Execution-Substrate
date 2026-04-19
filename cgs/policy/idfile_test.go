package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/cgs/policy"
)

func TestLoadParsesExplicitSubjectGrammar(t *testing.T) {
	t.Parallel()

	set := loadPolicy(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://execution.internal/service/execution"
  role: "worker"
}

subject "bot_test_privileged" {
  type: "script"
  principal: "spiffe://execution.internal/script/bot_test_privileged"
  role: "worker"
}
`)

	serviceType, serviceID, ok := set.SubjectFromWorkload(policy.Workload{
		Type:               "service",
		WorkloadIdentityID: "spiffe://execution.internal/service/execution",
	})
	if !ok || serviceType != "service" || serviceID != "execution" {
		t.Fatalf("unexpected service subject mapping: type=%q id=%q ok=%v", serviceType, serviceID, ok)
	}

	scriptType, scriptID, ok := set.SubjectFromWorkload(policy.Workload{
		Type:               "script",
		WorkloadIdentityID: "spiffe://execution.internal/script/bot_test_privileged",
	})
	if !ok || scriptType != "script" || scriptID != "bot_test_privileged" {
		t.Fatalf("unexpected script subject mapping: type=%q id=%q ok=%v", scriptType, scriptID, ok)
	}
}

func TestLoadRejectsLegacyLocationDerivedGrammar(t *testing.T) {
	t.Parallel()

	_, err := policy.Load(writePolicyFile(t, `
service_id {
  services.execution.ExecutionServer: "execution"
}
`))
	if err == nil || !strings.Contains(err.Error(), "invalid subject declaration") {
		t.Fatalf("expected legacy grammar rejection, got %v", err)
	}
}

func TestValidateWorkloadRejectsTypePrincipalMismatch(t *testing.T) {
	t.Parallel()

	set := loadPolicy(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://execution.internal/service/execution"
  role: "worker"
}
`)

	err := set.ValidateWorkload(policy.Workload{
		Type:               "script",
		WorkloadIdentityID: "spiffe://execution.internal/service/execution",
	})
	if err == nil || !strings.Contains(err.Error(), "workload.type does not match workload.workload_identity_id") {
		t.Fatalf("expected type mismatch error, got %v", err)
	}
}

func loadPolicy(t *testing.T, contents string) *policy.Set {
	t.Helper()

	set, err := policy.Load(writePolicyFile(t, contents))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return set
}

func writePolicyFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "id.conf")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}
