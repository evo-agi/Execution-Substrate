package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
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
		// Workload identities are never callers (WI-3a), so AGS never signs
		// for one and ES is never called by one.
		"principal is a workload identity": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = "spiffe://execution.internal/workload/codex-agent"
		}, "rules[0].publisher_principal must not be a workload identity"},
		"principal is a workload identity in another letter case": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].PublisherPrincipal = "spiffe://execution.internal/WorkLoad/codex-agent"
		}, "rules[0].publisher_principal must not be a workload identity"},
		"caller is a workload identity": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].CallerPrincipal = "spiffe://execution.internal/workload/codex-agent"
		}, "rules[0].caller_principal must not be a workload identity"},
		"caller is a workload identity in another letter case": {func(g *WorkloadGrantsConfig) {
			g.Rules[0].CallerPrincipal = "spiffe://execution.internal/WORKLOAD/codex-agent"
		}, "rules[0].caller_principal must not be a workload identity"},
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

// The second half of the unrestricted lane's machine trigger, with
// TestUnrestrictedLaneIsRefusedOnceAnotherLaneIsAccepted. That test pins the
// lane type's fields and tries lane names it makes up; a second lane that ES
// accepts by a built-in name, with no new field, would pass it unless the
// name were one of those. A built-in name has to be written in ES's own
// source, so this test takes its candidate names from there: every string
// literal in every non-test Go file under es/, whole, trimmed and split into
// words. While ES accepts the temporary lane, it must accept no other lane
// named by any of them. (Red-team 2 of ES PR #73, RT73B-3.)
func TestNoLaneNameInESSourceIsAcceptedWhileUnrestrictedStillIs(t *testing.T) {
	if err := configWithWorkloadGrants(validWorkloadGrantsConfig()).Validate(); err != nil {
		// The temporary lane is gone: nothing left to trigger.
		return
	}
	candidates := map[string]bool{}
	files := 0
	walkErr := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Errorf("%s: cannot read the string literal %s: %v", path, literal.Value, err)
				return true
			}
			// A literal can be a whole name or hold one among other words.
			candidates[value] = true
			candidates[strings.TrimSpace(value)] = true
			for _, word := range strings.FieldsFunc(value, func(r rune) bool {
				return !(r == '-' || r == '_' || r == '.' || r == '/' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
			}) {
				candidates[word] = true
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	// Controls: the scan read ES's source, and it found the lane it knows.
	if files < 20 || len(candidates) < 500 {
		t.Fatalf("control: the scan read %d files and %d candidate names; it no longer reads ES's source", files, len(candidates))
	}
	if !candidates[WorkloadEgressLaneUnrestricted] {
		t.Fatalf("control: the scan did not find %q, the one lane name ES has", WorkloadEgressLaneUnrestricted)
	}

	var accepted []string
	for name := range candidates {
		if name == WorkloadEgressLaneUnrestricted {
			continue
		}
		for _, reaches := range []bool{true, false} {
			reaches := reaches
			other := &WorkloadGrantsConfig{EgressLanes: []WorkloadEgressLaneConfig{{Name: name, ReachesWorkloadVault: &reaches}}}
			if configWithWorkloadGrants(other).Validate() == nil {
				accepted = append(accepted, strconv.Quote(name)+" reaches_workload_vault="+strconv.FormatBool(reaches))
			}
		}
	}
	sort.Strings(accepted)
	for _, lane := range accepted {
		t.Errorf("ES accepts the lane %s and still accepts %q: egress lanes are landing, so remove the temporary lane (ES must refuse it) in the same change", lane, WorkloadEgressLaneUnrestricted)
	}
	t.Logf("tried %d names from %d source files under es/", len(candidates), files)
}

// The third part of the unrestricted lane's machine trigger. The other two
// try lane names, as made-up names and as names written in ES's source; a
// later change could instead accept a lane whose name is listed somewhere
// else in the configuration, beside the lanes or under another section (a
// catalogue of networks, say). So this test puts each candidate name into
// every list of names in the configuration, one list at a time, and checks
// that ES still accepts no lane by that name. It finds the lists by
// reflection, so a list added later is tried too. (Re-audit 18 of ES PR #73,
// L-1.)
func TestNoConfigurationListAdmitsAnotherLaneWhileUnrestrictedStillIs(t *testing.T) {
	if err := configWithWorkloadGrants(validWorkloadGrantsConfig()).Validate(); err != nil {
		// The temporary lane is gone: nothing left to trigger.
		return
	}
	template := configWithWorkloadGrants(validWorkloadGrantsConfig())
	var slots []configSlot
	collectConfigSlots(reflect.ValueOf(&template).Elem(), nil, "", &slots)

	// Controls: the walk reaches nested sections and the lists ES has today.
	seen := map[string]bool{}
	for _, slot := range slots {
		seen[slot.name] = true
	}
	for _, want := range []string{".Authorization.AllowedSPIFFEPathPrefixes", ".AdmissionPolicy.WorkloadGrants.EgressLanes", ".AdmissionPolicy.WorkloadGrants.Rules"} {
		if !seen[want] {
			t.Fatalf("control: the walk did not reach %s; it found %d lists", want, len(slots))
		}
	}

	names := []string{"vault-only", "codex-api", "filtered", "default", "none", "bridge", "restricted", "internet",
		"Unrestricted", "unrestricted ", "unrestricted-v2"}
	var accepted []string
	for _, slot := range slots {
		for _, name := range names {
			for _, reaches := range []bool{true, false} {
				for _, shape := range []string{"only that lane", "beside unrestricted", "beside unrestricted, used by a rule"} {
					cfg := configWithWorkloadGrants(validWorkloadGrantsConfig())
					grants := cfg.AdmissionPolicy.WorkloadGrants
					reaches := reaches
					other := WorkloadEgressLaneConfig{Name: name, ReachesWorkloadVault: &reaches}
					switch shape {
					case "only that lane":
						grants.EgressLanes, grants.Rules = []WorkloadEgressLaneConfig{other}, nil
					case "beside unrestricted":
						grants.EgressLanes = append(grants.EgressLanes, other)
					default:
						grants.EgressLanes = append(grants.EgressLanes, other)
						grants.Rules[0].EgressLane = name
					}
					if !slot.add(reflect.ValueOf(&cfg).Elem(), name) {
						continue
					}
					if cfg.Validate() == nil {
						accepted = append(accepted, fmt.Sprintf("%q (reaches_workload_vault=%t, %s) once %s lists it", name, reaches, shape, slot.name))
					}
				}
			}
		}
	}
	sort.Strings(accepted)
	for _, lane := range accepted {
		t.Errorf("ES accepts the lane %s, and still accepts %q: egress lanes are landing, so remove the temporary lane (ES must refuse it) in the same change", lane, WorkloadEgressLaneUnrestricted)
	}
	t.Logf("tried %d names in %d configuration lists", len(names), len(slots))
}

// configSlot is one list in the configuration that a name can be added to:
// a slice of strings, a map keyed by strings, or a slice of structs (a new
// element with every string field set to the name).
type configSlot struct {
	name string
	path []int
}

// collectConfigSlots records every list reachable from value through struct
// fields, pointers and slice elements. A nil pointer to a section is walked
// as an empty section, and add creates it.
func collectConfigSlots(value reflect.Value, path []int, name string, slots *[]configSlot) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			collectConfigSlots(value.Elem(), path, name, slots)
		} else if value.Type().Elem().Kind() == reflect.Struct {
			collectConfigSlots(reflect.New(value.Type().Elem()).Elem(), path, name, slots)
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				collectConfigSlots(value.Field(i), append(append([]int(nil), path...), i), name+"."+value.Type().Field(i).Name, slots)
			}
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.String || value.Type().Elem().Kind() == reflect.Struct {
			*slots = append(*slots, configSlot{name: name, path: append([]int(nil), path...)})
		}
		for i := 0; i < value.Len(); i++ {
			collectConfigSlots(value.Index(i), append(append([]int(nil), path...), -1-i), fmt.Sprintf("%s[%d]", name, i), slots)
		}
	case reflect.Map:
		if value.Type().Key().Kind() == reflect.String {
			*slots = append(*slots, configSlot{name: name, path: append([]int(nil), path...)})
		}
	}
}

// add puts name into the slot's list in root, a fresh configuration built
// the same way as the one the slot was found in. It reports whether it could.
func (s configSlot) add(root reflect.Value, name string) bool {
	value := root
	for _, step := range s.path {
		for value.Kind() == reflect.Pointer {
			if value.IsNil() {
				value.Set(reflect.New(value.Type().Elem()))
			}
			value = value.Elem()
		}
		if step >= 0 {
			value = value.Field(step)
		} else {
			if value.Kind() != reflect.Slice || -1-step >= value.Len() {
				return false
			}
			value = value.Index(-1 - step)
		}
	}
	switch value.Kind() {
	case reflect.Slice:
		element := reflect.New(value.Type().Elem()).Elem()
		if element.Kind() == reflect.String {
			element.SetString(name)
		} else {
			setStringFields(element, name)
		}
		value.Set(reflect.Append(value, element))
	case reflect.Map:
		if value.IsNil() {
			value.Set(reflect.MakeMap(value.Type()))
		}
		key := reflect.New(value.Type().Key()).Elem()
		key.SetString(name)
		element := reflect.New(value.Type().Elem()).Elem()
		setStringFields(element, name)
		value.SetMapIndex(key, element)
	default:
		return false
	}
	return true
}

func setStringFields(value reflect.Value, name string) {
	switch value.Kind() {
	case reflect.String:
		value.SetString(name)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				setStringFields(value.Field(i), name)
			}
		}
	}
}

// The last part of the unrestricted lane's machine trigger looks at use, not
// at configuration: a lane does nothing until code reads it, and realizing
// lanes (WI-4) has to read the lane a run was granted. Today nothing does.
// ES admission computes the decision and drops it, and only the grant code
// itself reads a lane. So, while ES still accepts the temporary lane, this
// test fails when, in any non-test Go file of the module:
//   - a call of decideWorkloadGrants keeps the decision instead of dropping
//     it into _;
//   - the decision's or a rule's egressLane is read outside
//     workloadGrantsFromConfig and decide in es/admission/workload_grants.go;
//   - a lane field of the configuration (EgressLane, EgressLanes,
//     ReachesWorkloadVault) is read anywhere but the two validation methods
//     in es/config (WorkloadGrantsConfig.Validate and
//     WorkloadGrantRuleConfig.validate) and workloadGrantsFromConfig, so a
//     new reader in es/config itself fails too (re-check 21, N-1);
//   - the grant types gain a field, or decide or decideWorkloadGrants return
//     something else.
//
// Identity grants (WI-3) will keep the decision too. Then this test fails
// early, and that change narrows it to lane reads. (Re-audit 18 of ES PR #73,
// L-1.)
func TestNoCodeUsesAnEgressLaneWhileUnrestrictedStillIs(t *testing.T) {
	if err := configWithWorkloadGrants(validWorkloadGrantsConfig()).Validate(); err != nil {
		// The temporary lane is gone: nothing left to trigger.
		return
	}
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format+"; ES still accepts the temporary lane %q: if egress lanes are landing, remove it (ES must refuse it) in the same change", append(args, WorkloadEgressLaneUnrestricted)...)
	}

	pinFields := func(value any, want ...string) {
		t.Helper()
		typ := reflect.TypeOf(value)
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, typ.Field(i).Name+" "+string(typ.Field(i).Tag))
		}
		if !reflect.DeepEqual(got, want) {
			fail("%s now has the fields %q, not %q", typ.Name(), got, want)
		}
	}
	pinFields(AdmissionPolicyConfig{},
		`ConfiguredStaticScriptLiteralDeny json:"configured_static_script_literal_deny,omitempty"`,
		`WorkloadGrants json:"workload_grants,omitempty"`)
	pinFields(WorkloadGrantsConfig{}, `EgressLanes json:"egress_lanes"`, `Rules json:"rules"`)
	pinFields(WorkloadGrantRuleConfig{}, `ID json:"id"`, `PublisherPrincipal json:"publisher_principal"`,
		`CallerPrincipal json:"caller_principal"`, `SignerKeyID json:"signer_key_id"`, `ArtifactType json:"artifact_type"`,
		`RuntimeProfile json:"runtime_profile"`, `EgressLane json:"egress_lane,omitempty"`)

	const grantFile = "es/admission/workload_grants.go"
	laneReaders := map[string]bool{"workloadGrantsFromConfig": true, "workloadGrants.decide": true}
	configuredLaneReaders := map[string]bool{
		"es/config/workload_grants.go WorkloadGrantsConfig.Validate":    true,
		"es/config/workload_grants.go WorkloadGrantRuleConfig.validate": true,
		grantFile + " workloadGrantsFromConfig":                         true,
	}
	configuredLaneReads := 0
	var decisionCalls, droppedDecisions, laneReads int
	files := 0
	pinned := map[string]bool{}
	walkErr := filepath.WalkDir("../..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if base := entry.Name(); path != "../.." && (strings.HasPrefix(base, ".") || base == "testdata" || base == "vendor" || base == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, "../../"))
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, decl := range parsed.Decls {
			function, _ := decl.(*ast.FuncDecl)
			name := ""
			if function != nil {
				name = function.Name.Name
				if function.Recv != nil && len(function.Recv.List) == 1 {
					name = types.ExprString(function.Recv.List[0].Type) + "." + name
				}
			}
			if rel == grantFile {
				pinGrantDeclaration(t, decl, pinned, fail)
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.AssignStmt:
					if len(node.Rhs) == 1 && isCallOf(node.Rhs[0], "decideWorkloadGrants") {
						if blank, ok := node.Lhs[0].(*ast.Ident); ok && blank.Name == "_" {
							droppedDecisions++
						}
					}
				case *ast.CallExpr:
					if isCallOf(node, "decideWorkloadGrants") {
						decisionCalls++
					}
				case *ast.SelectorExpr:
					switch node.Sel.Name {
					case "egressLane":
						if rel != grantFile || !laneReaders[name] {
							fail("%s reads egressLane", fset.PositionFor(node.Pos(), false))
						} else {
							laneReads++
						}
					case "EgressLane", "EgressLanes", "ReachesWorkloadVault":
						if !configuredLaneReaders[rel+" "+name] {
							fail("%s reads the configured lane field %s in %s", fset.PositionFor(node.Pos(), false), node.Sel.Name, name)
						} else {
							configuredLaneReads++
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	// Controls: the walk read the module, found today's one call and the
	// grant code's own lane reads.
	if files < 100 || decisionCalls == 0 || laneReads < 3 || configuredLaneReads < 5 {
		t.Fatalf("control: read %d files, %d calls of decideWorkloadGrants, %d lane reads in the grant code, %d configured lane reads in validation and the grant code; the walk no longer reads the module", files, decisionCalls, laneReads, configuredLaneReads)
	}
	for _, name := range []string{"workloadGrantDecision", "workloadGrantRule", "workloadGrants", "decide", "decideWorkloadGrants"} {
		if !pinned[name] {
			fail("%s is no longer declared in %s", name, grantFile)
		}
	}
	if droppedDecisions != decisionCalls {
		fail("%d of %d calls of decideWorkloadGrants keep the decision", decisionCalls-droppedDecisions, decisionCalls)
	}
}

func isCallOf(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name == name
	case *ast.Ident:
		return fun.Name == name
	}
	return false
}

// pinGrantDeclaration pins the fields of the admission grant types and what
// decide and decideWorkloadGrants return. It records each name it pinned in
// seen.
func pinGrantDeclaration(t *testing.T, decl ast.Decl, seen map[string]bool, fail func(string, ...any)) {
	t.Helper()
	fieldsOf := func(list *ast.FieldList) []string {
		var out []string
		for _, field := range list.List {
			for _, name := range field.Names {
				out = append(out, name.Name+" "+types.ExprString(field.Type))
			}
			if len(field.Names) == 0 {
				out = append(out, types.ExprString(field.Type))
			}
		}
		return out
	}
	switch decl := decl.(type) {
	case *ast.GenDecl:
		for _, spec := range decl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			want, pinned := grantTypeFields[typeSpec.Name.Name]
			if !pinned {
				continue
			}
			seen[typeSpec.Name.Name] = true
			var got []string
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				got = fieldsOf(structType.Fields)
			}
			if !reflect.DeepEqual(got, want) {
				fail("%s now has the fields %q, not %q", typeSpec.Name.Name, got, want)
			}
		}
	case *ast.FuncDecl:
		if decl.Name.Name != "decide" && decl.Name.Name != "decideWorkloadGrants" {
			return
		}
		seen[decl.Name.Name] = true
		if got := fieldsOf(decl.Type.Results); !reflect.DeepEqual(got, []string{"workloadGrantDecision", "*Error"}) {
			fail("%s now returns %q", decl.Name.Name, got)
		}
	}
}

// grantTypeFields are the fields of the admission grant types today.
var grantTypeFields = map[string][]string{
	"workloadGrantDecision": {"ruleID string", "egressLane string"},
	"workloadGrantRule":     {"id string", "match [5]string", "egressLane string"},
	"workloadGrants":        {"rules []workloadGrantRule"},
}
