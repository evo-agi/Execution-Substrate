package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validWorkloadGrantsConfig() *WorkloadGrantsConfig {
	reaches := true
	return &WorkloadGrantsConfig{
		EgressLanes: []WorkloadEgressLaneConfig{{Name: WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}},
		Rules: []WorkloadGrantRuleConfig{
			{
				ID:                 "operator-default",
				PublisherPrincipal: "spiffe://execution.internal/operator/local",
				CallerPrincipal:    "spiffe://execution.internal/operator/local",
				SignerKeyID:        "test-key",
				ArtifactType:       "static-script",
				RuntimeProfile:     WorkloadGrantRuntimeProfileDefault,
				EgressLane:         WorkloadEgressLaneUnrestricted,
			},
			{
				ID:                 "cp-codex",
				PublisherPrincipal: "spiffe://execution.internal/service/control-plane",
				CallerPrincipal:    "spiffe://execution.internal/service/control-plane",
				SignerKeyID:        "test-key",
				ArtifactType:       "static-script",
				RuntimeProfile:     WorkloadGrantRuntimeProfileControlPlaneNormalShell,
				EgressLane:         WorkloadEgressLaneUnrestricted,
			},
		},
	}
}

func configWithWorkloadGrants(grants *WorkloadGrantsConfig) Config {
	cfg := validTestConfig()
	cfg.Authorization.AllowedSPIFFEPathPrefixes = []string{"operator/local", "service/control-plane"}
	cfg.AdmissionPolicy = &AdmissionPolicyConfig{WorkloadGrants: grants}
	return cfg
}

func TestWorkloadGrantsValidConfigurationValidates(t *testing.T) {
	if err := configWithWorkloadGrants(validWorkloadGrantsConfig()).Validate(); err != nil {
		t.Fatalf("valid workload grants: %v", err)
	}
	// No lanes and no rules is valid: it admits only runs without network.
	if err := configWithWorkloadGrants(&WorkloadGrantsConfig{}).Validate(); err != nil {
		t.Fatalf("empty workload grants: %v", err)
	}
	// A rule may grant nothing; it then admits only runs without network.
	grants := validWorkloadGrantsConfig()
	grants.Rules[0].EgressLane = ""
	if err := configWithWorkloadGrants(grants).Validate(); err != nil {
		t.Fatalf("rule without a lane: %v", err)
	}
}

func TestWorkloadGrantsLoadFromJSONAndRefuseIdentityFieldsUntilIdentitiesLand(t *testing.T) {
	grants := `"admission_policy": {"workload_grants": {
    "egress_lanes": [{"name": "unrestricted", "reaches_workload_vault": true}],
    "rules": [{"id": "operator-default", "publisher_principal": "spiffe://execution.internal/operator/local",
      "caller_principal": "spiffe://execution.internal/operator/local", "signer_key_id": "test-key", "artifact_type": "static-script", "runtime_profile": "static-script/default",
      "egress_lane": "unrestricted"}]}},
  "workload_vault_auth"`
	raw := strings.Replace(validTestConfigJSON(), `"workload_vault_auth"`, grants, 1)
	cfg, err := Load(writeTempConfig(t, raw))
	if err != nil {
		t.Fatalf("load config with workload grants: %v", err)
	}
	if cfg.AdmissionPolicy == nil || cfg.AdmissionPolicy.WorkloadGrants == nil || len(cfg.AdmissionPolicy.WorkloadGrants.Rules) != 1 {
		t.Fatalf("workload grants not loaded: %#v", cfg.AdmissionPolicy)
	}

	// Named workload identities land with WI-3. Until then the identity
	// fields are unknown keys, which ES config refuses.
	for name, replace := range map[string][2]string{
		"workload_identities": {`"egress_lanes"`, `"workload_identities": ["codex-agent"], "egress_lanes"`},
		"workload_identity":   {`"egress_lane": "unrestricted"}`, `"egress_lane": "unrestricted", "workload_identity": "codex-agent"}`},
		"mode":                {`"egress_lanes"`, `"mode": "disabled", "egress_lanes"`},
	} {
		changed := strings.Replace(raw, replace[0], replace[1], 1)
		if changed == raw {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := Load(writeTempConfig(t, changed)); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: Load error = %v, want an unknown field refusal", name, err)
		}
	}
}

func TestWorkloadGrantsRefuseInvalidConfiguration(t *testing.T) {
	falseValue := false
	cases := map[string]struct {
		change func(*WorkloadGrantsConfig)
		want   string
	}{
		"lane other than unrestricted": {func(g *WorkloadGrantsConfig) { g.EgressLanes[0].Name = "codex-api" }, "only egress lane until egress lanes land"},
		"unrestricted not reaching vault": {func(g *WorkloadGrantsConfig) {
			g.EgressLanes[0].ReachesWorkloadVault = &falseValue
		}, "only egress lane until egress lanes land"},
		"lane without reaches_workload_vault": {func(g *WorkloadGrantsConfig) { g.EgressLanes[0].ReachesWorkloadVault = nil }, "reaches_workload_vault is required"},
		"duplicate lane": {func(g *WorkloadGrantsConfig) {
			g.EgressLanes = append(g.EgressLanes, g.EgressLanes[0])
		}, "egress_lanes[1].name must be unique"},
		"bad lane name":    {func(g *WorkloadGrantsConfig) { g.EgressLanes[0].Name = "Unrestricted" }, "must be 1 to 63 characters"},
		"lane name hyphen": {func(g *WorkloadGrantsConfig) { g.EgressLanes[0].Name = "-x" }, "must be 1 to 63 characters"},
		"empty lane name":  {func(g *WorkloadGrantsConfig) { g.EgressLanes[0].Name = "" }, "egress_lanes[0].name is required"},
		"rule lane not listed": {func(g *WorkloadGrantsConfig) {
			g.EgressLanes = nil
		}, "rules[0].egress_lane must name a lane listed"},
		"duplicate rule ID": {func(g *WorkloadGrantsConfig) { g.Rules[1].ID = g.Rules[0].ID }, "rules[1].id must be unique"},
		"unsafe rule ID":    {func(g *WorkloadGrantsConfig) { g.Rules[0].ID = "not safe" }, "rules[0].id may contain only"},
		"duplicate match": {func(g *WorkloadGrantsConfig) {
			g.Rules[1] = g.Rules[0]
			g.Rules[1].ID = "other"
		}, "at most one rule may match a run"},
		"missing principal":   {func(g *WorkloadGrantsConfig) { g.Rules[0].PublisherPrincipal = "" }, "publisher_principal is required"},
		"principal path only": {func(g *WorkloadGrantsConfig) { g.Rules[0].PublisherPrincipal = "operator/local" }, "publisher_principal must be a caller SPIFFE ID"},
		"principal foreign": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = "spiffe://other.internal/operator/local"
		}, "publisher_principal must be a caller SPIFFE ID"},
		"principal padded": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = " spiffe://execution.internal/operator/local"
		}, "publisher_principal must not contain leading or trailing whitespace"},
		"principal non-canonical scheme": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = "SPIFFE://execution.internal/operator/local"
		}, "publisher_principal must be a caller SPIFFE ID"},
		// No caller allowlist admits a one-segment caller, so AGS never
		// signs for one and ES is never called by one (red-team 11, OBS-5).
		"principal of one segment": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = "spiffe://execution.internal/operator"
		}, "publisher_principal must be a caller SPIFFE ID in trust domain execution.internal with at least 2 path segments"},
		"missing caller":     {func(g *WorkloadGrantsConfig) { g.Rules[0].CallerPrincipal = "" }, "caller_principal is required"},
		"caller path only":   {func(g *WorkloadGrantsConfig) { g.Rules[0].CallerPrincipal = "operator/local" }, "caller_principal must be a caller SPIFFE ID"},
		"caller padded":      {func(g *WorkloadGrantsConfig) { g.Rules[0].CallerPrincipal += "\t" }, "caller_principal must not contain leading or trailing whitespace"},
		"caller one segment": {func(g *WorkloadGrantsConfig) { g.Rules[0].CallerPrincipal = "spiffe://execution.internal/operator" }, "caller_principal must be a caller SPIFFE ID"},
		"caller foreign": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].CallerPrincipal = "spiffe://other.internal/operator/local"
		}, "caller_principal must be a caller SPIFFE ID"},
		"caller ES does not admit": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].CallerPrincipal = "spiffe://execution.internal/user/claude"
		}, "rules[0].caller_principal must be a caller authorization.allowed_spiffe_path_prefixes admits"},
		"caller above an allowed prefix": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].CallerPrincipal = "spiffe://execution.internal/service/control"
		}, "rules[0].caller_principal must be a caller authorization.allowed_spiffe_path_prefixes admits"},
		"missing signer":    {func(g *WorkloadGrantsConfig) { g.Rules[0].SignerKeyID = "" }, "signer_key_id is required"},
		"padded signer":     {func(g *WorkloadGrantsConfig) { g.Rules[0].SignerKeyID = "test-key " }, "signer_key_id must not contain leading or trailing whitespace"},
		"missing type":      {func(g *WorkloadGrantsConfig) { g.Rules[0].ArtifactType = "" }, "artifact_type is required"},
		"invisible in type": {func(g *WorkloadGrantsConfig) { g.Rules[0].ArtifactType = "static​-script" }, "artifact_type must contain only printable non-control text"},
		"control in type":   {func(g *WorkloadGrantsConfig) { g.Rules[0].ArtifactType = "static\x00script" }, "artifact_type must contain only printable non-control text"},
		"invalid utf8 type": {func(g *WorkloadGrantsConfig) { g.Rules[0].ArtifactType = "static\xffscript" }, "artifact_type must be valid UTF-8 text"},
		"long type": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].ArtifactType = strings.Repeat("a", MaxWorkloadGrantMatchValueBytes+1)
		}, "artifact_type must not exceed"},
		"unknown profile":     {func(g *WorkloadGrantsConfig) { g.Rules[0].RuntimeProfile = "static-script/other" }, "runtime_profile must be"},
		"profile case":        {func(g *WorkloadGrantsConfig) { g.Rules[0].RuntimeProfile = "Static-Script/Default" }, "runtime_profile must be"},
		"empty profile":       {func(g *WorkloadGrantsConfig) { g.Rules[0].RuntimeProfile = "" }, "runtime_profile must be"},
		"invalid rule lane":   {func(g *WorkloadGrantsConfig) { g.Rules[0].EgressLane = "Unrestricted" }, "rules[0].egress_lane must be 1 to 63 characters"},
		"padded rule lane":    {func(g *WorkloadGrantsConfig) { g.Rules[0].EgressLane = "unrestricted " }, "rules[0].egress_lane must be 1 to 63 characters"},
		"signer not verified": {func(g *WorkloadGrantsConfig) { g.Rules[0].SignerKeyID = "other-key" }, "rules[0].signer_key_id must be verification.provenance.key_id"},
		"too many rules": {func(g *WorkloadGrantsConfig) {
			g.Rules = nil
			for i := 0; i <= MaxWorkloadGrantRules; i++ {
				g.Rules = append(g.Rules, WorkloadGrantRuleConfig{
					ID: fmt.Sprintf("rule-%d", i), PublisherPrincipal: fmt.Sprintf("spiffe://execution.internal/operator/p%d", i),
					CallerPrincipal: "spiffe://execution.internal/operator/local", SignerKeyID: "test-key", ArtifactType: "static-script", RuntimeProfile: WorkloadGrantRuntimeProfileDefault,
				})
			}
		}, "must not contain more than 32 rules"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			grants := validWorkloadGrantsConfig()
			tc.change(grants)
			err := configWithWorkloadGrants(grants).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "admission_policy.workload_grants") {
				t.Fatalf("Validate() = %v, want the error to name admission_policy.workload_grants", err)
			}
		})
	}
}

// ES verifies evidence against the trimmed verification.provenance.key_id,
// so a rule naming the trimmed key matches that evidence and validates.
func TestWorkloadGrantSignerKeyIsComparedWithTheTrimmedProvenanceKey(t *testing.T) {
	cfg := configWithWorkloadGrants(validWorkloadGrantsConfig())
	cfg.Verification.Provenance.KeyID = " " + cfg.Verification.Provenance.KeyID + " "
	if err := cfg.Validate(); err != nil {
		t.Fatalf("padded provenance key: %v", err)
	}
}

func TestWorkloadGrantsAtTheRuleLimitValidate(t *testing.T) {
	grants := validWorkloadGrantsConfig()
	grants.Rules = nil
	for i := 0; i < MaxWorkloadGrantRules; i++ {
		grants.Rules = append(grants.Rules, WorkloadGrantRuleConfig{
			ID: fmt.Sprintf("rule-%d", i), PublisherPrincipal: fmt.Sprintf("spiffe://execution.internal/operator/p%d", i),
			CallerPrincipal: "spiffe://execution.internal/operator/local", SignerKeyID: "test-key", ArtifactType: "static-script", RuntimeProfile: WorkloadGrantRuntimeProfileDefault,
			EgressLane: WorkloadEgressLaneUnrestricted,
		})
	}
	if err := configWithWorkloadGrants(grants).Validate(); err != nil {
		t.Fatalf("%d rules: %v", MaxWorkloadGrantRules, err)
	}
}

func writeTempConfig(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "es.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// The lane unrestricted is a temporary compatibility edge whose removal
// condition is egress lanes (WI-4,
// .docs/execution_lifecycle/contracts.md, section 5B). This test is its
// machine trigger: while ES accepts unrestricted, it fails once ES accepts
// any other lane, whatever shape that lane takes. It pins the lane type to
// its two fields, so a lane that needs any further field (what it may
// reach, a proxy, a network) fails it, and it probes other lane names with
// both reaches_workload_vault values, as Go values and as JSON with and
// without extra keys. (Audit 10 F3 and red-team RT73-3: probing one lane
// shape let a lane with an extra field land without the trigger noticing.)
func TestUnrestrictedLaneIsRefusedOnceAnotherLaneIsAccepted(t *testing.T) {
	if err := configWithWorkloadGrants(validWorkloadGrantsConfig()).Validate(); err != nil {
		// The temporary lane is gone: nothing left to trigger.
		return
	}
	const remove = "egress lanes are landing, so remove the temporary lane %q (ES must refuse it) in the same change"

	lane := reflect.TypeOf(WorkloadEgressLaneConfig{})
	var fields []string
	for i := 0; i < lane.NumField(); i++ {
		fields = append(fields, lane.Field(i).Name+" "+lane.Field(i).Type.String()+" "+string(lane.Field(i).Tag))
	}
	if want := []string{`Name string json:"name"`, `ReachesWorkloadVault *bool json:"reaches_workload_vault"`}; !reflect.DeepEqual(fields, want) {
		t.Fatalf("an egress lane now has the fields %q, not %q, and ES still accepts %q: "+remove, fields, want, WorkloadEgressLaneUnrestricted, WorkloadEgressLaneUnrestricted)
	}
	if rule, ok := reflect.TypeOf(WorkloadGrantRuleConfig{}).FieldByName("EgressLane"); !ok || rule.Type.Kind() != reflect.String {
		t.Fatalf("a rule's EgressLane is no longer a lane name, and ES still accepts %q: "+remove, WorkloadEgressLaneUnrestricted, WorkloadEgressLaneUnrestricted)
	}

	names := []string{"vault-only", "codex-api", "filtered", "default", "none", "bridge", "restricted", "internet",
		"Unrestricted", "unrestricted ", "unrestricted-v2"}
	for _, name := range names {
		for _, reaches := range []bool{true, false} {
			reaches := reaches
			other := &WorkloadGrantsConfig{EgressLanes: []WorkloadEgressLaneConfig{{Name: name, ReachesWorkloadVault: &reaches}}}
			if configWithWorkloadGrants(other).Validate() == nil {
				t.Errorf("ES accepts the lane %q (reaches_workload_vault=%t) and still accepts %q: "+remove, name, reaches, WorkloadEgressLaneUnrestricted, WorkloadEgressLaneUnrestricted)
			}
			for _, extra := range []string{"", `, "allowed_hosts": ["api.openai.com"]`, `, "allowed_destinations": ["10.0.0.1/32"]`,
				`, "proxy": "http://127.0.0.1:3128"`, `, "network": "codex"`} {
				raw := strings.Replace(validTestConfigJSON(), `"workload_vault_auth"`, fmt.Sprintf(`"admission_policy": {"workload_grants": {
    "egress_lanes": [{"name": %q, "reaches_workload_vault": %t%s}], "rules": []}},
  "workload_vault_auth"`, name, reaches, extra), 1)
				if _, err := Load(writeTempConfig(t, raw)); err == nil {
					t.Errorf("ES loads the lane %q (reaches_workload_vault=%t%s) and still accepts %q: "+remove, name, reaches, extra, WorkloadEgressLaneUnrestricted, WorkloadEgressLaneUnrestricted)
				}
			}
		}
	}
	reaches := false
	if configWithWorkloadGrants(&WorkloadGrantsConfig{EgressLanes: []WorkloadEgressLaneConfig{{Name: WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}}}).Validate() == nil {
		t.Errorf("ES accepts %q with reaches_workload_vault=false", WorkloadEgressLaneUnrestricted)
	}
}

// A rule names its caller as well as its publisher, and a caller that the
// caller allowlist admits only through a prefix is named exactly: the rule
// for operator/local does not cover operator/local/x (red-team 11, RT73-4).
func TestWorkloadGrantRulesNameTheirCallerExactly(t *testing.T) {
	grants := validWorkloadGrantsConfig()
	grants.Rules[0].CallerPrincipal = "spiffe://execution.internal/operator/local/x"
	if err := configWithWorkloadGrants(grants).Validate(); err != nil {
		t.Fatalf("a caller the allowlist admits through its prefix: %v", err)
	}
	other := grants.Rules[0]
	other.ID = "operator-default-local"
	other.CallerPrincipal = "spiffe://execution.internal/operator/local"
	grants.Rules = append(grants.Rules, other)
	if err := configWithWorkloadGrants(grants).Validate(); err != nil {
		t.Fatalf("the same publisher with two callers is two rules: %v", err)
	}
	if grants.Rules[0].MatchKey() == grants.Rules[2].MatchKey() {
		t.Fatal("rules for two callers have the same match key")
	}
	if key := grants.Rules[2].MatchKey(); key != [5]string{other.PublisherPrincipal, other.CallerPrincipal, other.SignerKeyID, other.ArtifactType, other.RuntimeProfile} {
		t.Fatalf("match key order = %q", key)
	}
}
