package config

import (
	"strings"
	"testing"
)

// ES refuses a configuration that encoding/json would read differently from
// a reader that matches keys exactly and lets the last repeated key win (the
// readiness line, jq, a person). Red-team of ES PR #73, RT73-1: without
// this, a second empty admission_policy or a second rules list without
// egress_lane removed a grant for every other reader and kept it in ES.
func TestLoadRefusesRepeatedKeysAndKeysNotSpelledExactly(t *testing.T) {
	lanes := `"egress_lanes": [{"name": "unrestricted", "reaches_workload_vault": true}]`
	rule := `{"id": "operator-default", "publisher_principal": "spiffe://execution.internal/operator/local",
      "caller_principal": "spiffe://execution.internal/operator/local", "signer_key_id": "test-key", "artifact_type": "static-script", "runtime_profile": "static-script/default"`
	granting := rule + `, "egress_lane": "unrestricted"}`
	longS, kelvin := string(rune(0x17f)), string(rune(0x212a))
	withPolicy := func(policy string) string {
		return strings.Replace(validTestConfigJSON(), `"workload_vault_auth"`, policy+"\n  \"workload_vault_auth\"", 1)
	}

	raw := withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}},`)
	cfg, err := Load(writeTempConfig(t, raw))
	if err != nil || len(cfg.AdmissionPolicy.WorkloadGrants.Rules) != 1 || cfg.AdmissionPolicy.WorkloadGrants.Rules[0].EgressLane != WorkloadEgressLaneUnrestricted {
		t.Fatalf("control: exact keys: %+v, %v", cfg.AdmissionPolicy, err)
	}
	escaped := strings.Replace(raw, `"egress_lane": "unrestricted"`, `"\u0065gress_lane": "unrestricted"`, 1)
	if escaped == raw || !strings.Contains(escaped, `\u0065gress_lane`) {
		t.Fatal("control: the escaped document is not escaped")
	}
	if cfg, err := Load(writeTempConfig(t, escaped)); err != nil || cfg.AdmissionPolicy.WorkloadGrants.Rules[0].EgressLane != WorkloadEgressLaneUnrestricted {
		t.Fatalf("control: an escaped key that decodes to the exact spelling: %+v, %v", cfg.AdmissionPolicy, err)
	}

	for name, test := range map[string]struct{ raw, want string }{
		"rule key Egress_Lane": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "Egress_Lane": "unrestricted"}]}},`),
			`admission_policy.workload_grants.rules[0]: the key "Egress_Lane" must be spelled exactly "egress_lane"`},
		"rule key EGRESS_LANE": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "EGRESS_LANE": "unrestricted"}]}},`),
			`the key "EGRESS_LANE" must be spelled exactly "egress_lane"`},
		"egress_lane empty, then Egress_Lane": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "egress_lane": "", "Egress_Lane": "unrestricted"}]}},`),
			`the key "Egress_Lane" must be spelled exactly "egress_lane"`},
		"key RULES": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "RULES": [` + granting + `]}},`),
			`admission_policy.workload_grants: the key "RULES" must be spelled exactly "rules"`},
		"key Admission_Policy": {withPolicy(`"Admission_Policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}},`),
			`the top level: the key "Admission_Policy" must be spelled exactly "admission_policy"`},
		"admission_policy twice, the second empty": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}}, "admission_policy": {},`),
			`the top level: the key "admission_policy" appears more than once`},
		"workload_grants twice, the second empty": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `]}, "workload_grants": {}},`),
			`admission_policy: the key "workload_grants" appears more than once`},
		"rules twice, the second without egress_lane": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `], "rules": [` + rule + `}]}},`),
			`admission_policy.workload_grants: the key "rules" appears more than once`},
		"long s in egress_lane": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "egre` + longS + `s_lane": "unrestricted"}]}},`),
			`must be spelled exactly "egress_lane"`},
		"Kelvin sign in workload_grants": {withPolicy(`"admission_policy": {"wor` + kelvin + `load_grants": {` + lanes + `, "rules": [` + granting + `]}},`),
			`must be spelled exactly "workload_grants"`},
		"repeated key spelled with an escape": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + granting + `], "\u0072ules": []}},`),
			`the key "rules" appears more than once`},
		"case variant spelled with an escape": {withPolicy(`"admission_policy": {"workload_grants": {` + lanes + `, "rules": [` + rule + `, "\u0045gress_lane": "unrestricted"}]}},`),
			`the key "Egress_lane" must be spelled exactly "egress_lane"`},
		"top-level key in capitals": {strings.Replace(validTestConfigJSON(), `"http"`, `"HTTP"`, 1),
			`the key "HTTP" must be spelled exactly "http"`},
		"repeated key outside the admission policy": {strings.Replace(validTestConfigJSON(), `"workload_vault_auth"`, `"authorization": {"allowed_spiffe_path_prefixes": ["user/x"]}, "workload_vault_auth"`, 1),
			`the top level: the key "authorization" appears more than once`},
		"repeated key in a lane": {withPolicy(`"admission_policy": {"workload_grants": {"egress_lanes": [{"name": "unrestricted", "reaches_workload_vault": true, "name": "unrestricted"}], "rules": []}},`),
			`admission_policy.workload_grants.egress_lanes[0]: the key "name" appears more than once`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, test.raw))
			if err == nil || !strings.HasPrefix(err.Error(), "decode config: ") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}
