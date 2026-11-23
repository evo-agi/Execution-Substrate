package policy_test

import (
	"strings"
	"testing"

	"execution-substrate/cgs/policy"
)

// A subject principal is matched against the authenticated caller's SPIFFE
// ID, and caller authentication accepts only conforming SPIFFE IDs in the
// trust domain execution.internal, in their exact form. id.conf refuses
// every other principal at load, so no subject loads that no caller could
// ever present.
func TestLoadRefusesPrincipalsThatNoAuthenticatedCallerCanPresent(t *testing.T) {
	t.Parallel()

	for _, principal := range []string{
		"spiffe://other.internal/service/execution",
		"spiffe://execution.internal.evil/service/execution",
		"spiffe://evil.execution.internal/service/execution",
		"spiffe://execution.internal:443/service/execution",
		"spiffe://user@execution.internal/service/execution",
		"spiffe://EXECUTION.INTERNAL/service/execution",
		"SPIFFE://execution.internal/service/execution",
		"spiffe://execution.internal/service/execution/",
		"spiffe://execution.internal//service/execution",
		"spiffe://execution.internal/service//execution",
		"spiffe://execution.internal/service/./execution",
		"spiffe://execution.internal/service/execution?x=1",
		"spiffe://execution.internal/service/execution#x",
		"spiffe://execution.internal/service/%65xecution",
		" spiffe://execution.internal/service/execution",
		"spiffe://execution.internal/service/execution ",
	} {
		_, err := policy.Load(writePolicyFile(t, `
subject "execution" {
  type: "service"
  principal: "`+principal+`"
  role: "worker"
}
`))
		if err == nil || !strings.Contains(err.Error(), "subject execution principal must be a conforming SPIFFE ID with a path in trust domain execution.internal") {
			t.Errorf("principal %q: error %v", principal, err)
		}
	}
}

func TestLoadAcceptsPrincipalsInTheTrustDomain(t *testing.T) {
	t.Parallel()

	set := loadPolicy(t, `
subject "execution" {
  type: "service"
  principal: "spiffe://execution.internal/service/execution"
  role: "worker"
}

subject "bot_test-privileged.2" {
  type: "script"
  principal: "spiffe://execution.internal/script/bot_test-privileged.2"
  role: "worker"
}
`)
	for _, workload := range []policy.Workload{
		{Type: "service", WorkloadIdentityID: "spiffe://execution.internal/service/execution"},
		{Type: "script", WorkloadIdentityID: "spiffe://execution.internal/script/bot_test-privileged.2"},
	} {
		if _, _, ok := set.SubjectFromWorkload(workload); !ok {
			t.Errorf("subject for %q not loaded", workload.WorkloadIdentityID)
		}
	}
}
