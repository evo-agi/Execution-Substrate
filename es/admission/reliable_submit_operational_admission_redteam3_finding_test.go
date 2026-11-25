package admission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// redTeam3NomadTemplate reports whether Nomad's client would evaluate part of
// s instead of passing it on as written. The client decodes every string of a
// task's driver configuration as an HCL template: "${" opens an interpolation
// and "%{" a directive unless the opening character is doubled ("$${", "%%{").
func redTeam3NomadTemplate(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if (s[i] == '$' || s[i] == '%') && s[i+1] == '{' && (i == 0 || s[i-1] != s[i]) {
			return true
		}
	}
	return false
}

// FINDING (holds at PR #12 4416699; report 28-redteam.md, RT28-1). The
// behaviour is older than PR #12: it comes from the shared job builder and the
// request validation on trunk_dev, and the private handoff inherits it.
//
// The caller's argv is judged by admission, bound into the plan and compared
// by validateOperationalPlan exactly as the caller wrote it. It is then placed
// in the Nomad job's Config.args unchanged. Nomad's client does not run it as
// written: it evaluates "${...}" and "%{...}" in every driver configuration
// string with the task's environment, the node's attributes and metadata and
// a set of functions (Nomad v2.1.1, client/allocrunner/taskrunner
// task_runner.go runDriver and helper/pluginutils/hclutils util.go
// ParseHclInterface). So the argv that runs is not the argv that was
// admitted: a caller can have node attributes, node metadata and task
// environment values written into the arguments of a governed artifact, can
// spell an argument so that a literal comparison of the argv never sees it,
// and can submit an argv that Nomad refuses to start after ES has accepted it.
//
// The test passes once ES either refuses such an argv before it sends
// anything, or sends it in a form Nomad passes on as written.
func TestRedTeamPR12HeadCallerArgvIsNotEvaluatedByNomad(t *testing.T) {
	for i, argv := range [][]string{
		{"${attr.unique.hostname}"},
		{"plain", `${env["NOMAD_ALLOC_ID"]}`},
		{`${lower("DENIED-LITERAL")}`},
		{"%{ if true }x%{ endif }"},
		{"unterminated ${"},
	} {
		t.Run(fmt.Sprintf("argv %d", i), func(t *testing.T) {
			f := makeOperationalFixture(t, "", argv...)
			out := f.submit()
			f.receiver.mu.Lock()
			job, posts := bytes.Clone(f.receiver.job), f.receiver.posts
			f.receiver.mu.Unlock()
			if job == nil {
				// Refused before the POST: nothing of the caller's reached Nomad.
				if posts != 0 || out.kind == operationalAccepted {
					t.Fatalf("no job was received, yet posts=%d result=%s", posts, operationalResultText(out))
				}
				return
			}
			var sent struct {
				TaskGroups []struct {
					Tasks []struct {
						Config struct {
							Args []string `json:"args"`
						}
					}
				}
			}
			if err := json.Unmarshal(job, &sent); err != nil || len(sent.TaskGroups) != 1 || len(sent.TaskGroups[0].Tasks) != 1 {
				t.Fatalf("job shape: %v", err)
			}
			for _, arg := range sent.TaskGroups[0].Tasks[0].Config.Args {
				if redTeam3NomadTemplate(arg) {
					t.Fatalf("the job sent to Nomad carries the caller's argument %q, which Nomad's client evaluates instead of passing on (result %s)",
						arg, operationalResultText(out))
				}
			}
		})
	}
}

// FINDING (holds at PR #12 4416699; report 28-redteam.md, RT28-2).
//
// The delivery parser accepts a request of up to 262,144 bytes with up to
// 100 arguments of 65,536 bytes each. The provider can only project a job
// whose JSON is at most 65,536 bytes, and it measures that on Go's
// HTML-escaped encoding, where each of '<', '>', '&' and each control byte
// takes six bytes. The projection first runs after the claim is stored and
// its run is assigned. A request whose job is larger is therefore admitted,
// takes one of the four claim slots and one of the 32 reservations, gets a
// run, and can never go further: every later delivery and every recovery
// answers OperationalIntegrity, under any generation. Four such requests
// leave the domain refusing every new claim with OperationalCapacity. On the
// fixture the largest single argument that completes is about 62,290 plain
// bytes or 10,382 escaped ones; the exact figure moves by a few bytes with
// the length of the staging path.
//
// The test passes once such a request either completes or is refused before
// it takes a claim and a reservation.
func TestRedTeamPR12HeadRequestTooLargeForAJobTakesNoClaim(t *testing.T) {
	for name, argv := range map[string][]any{
		"one argument of 65536 bytes":         {strings.Repeat("a", 65536)},
		"one argument of 12000 escaped bytes": {strings.Repeat("<", 12000)},
		"one hundred arguments of 2000 bytes": redTeam3Repeat(strings.Repeat("a", 2000), 100),
		"one argument of 12000 control bytes": {strings.Repeat("\x01", 12000)},
		"one argument of 63000 bytes":         {strings.Repeat("a", 63000)},
		"one argument of 10500 escaped bytes": {strings.Repeat("&", 10500)},
	} {
		t.Run(name, func(t *testing.T) {
			f := makeOperationalFixture(t, "", "alpha")
			f.raw = redTeam3RequestVariant(t, f, func(_, invocation map[string]any) { invocation["argv"] = argv })
			out := f.submit()
			state := operationalPrestageStateAt(t, f)
			if out.kind == operationalAccepted && state.Posts == 1 && state.Receipt {
				return
			}
			if state.Claims != 0 || state.Grants != 0 || state.Posts != 0 {
				t.Fatalf("a request whose job the provider cannot project took a claim and a reservation and cannot go on: %s state=%+v",
					operationalResultText(out), state)
			}
		})
	}
}
