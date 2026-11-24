package admission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// redTeam31Rewritten pairs request strings that hold no "${", no "%{" and no
// NUL byte with what a workload receives when Nomad's client has decoded them
// as part of a task's driver configuration. The client parses every string of
// that configuration as an HCL template and makes a cty string of it. The
// template scanner drops a UTF-8 byte order mark at the start of its input,
// and cty normalizes strings to Unicode Normalization Form C: Nomad v2.1.1
// helper/pluginutils/hclutils util.go ParseHclInterface; hcl v2.20.2-nomad-1
// json/structure.go expression.Value, hclsyntax/scan_tokens.rl scanTokens
// (stripUTF8BOM) and hclsyntax/parser_template.go parseExpr
// (cty.StringVal(tok.Val)); go-cty v1.19.0 cty/value_init.go StringVal and
// cty/ctystrings/normalize.go (norm.NFC.String).
var redTeam31Rewritten = []struct{ written, received string }{
	{"\ufeff--flag", "--flag"},  // a leading byte order mark is removed
	{"cafe\u0301", "caf\u00e9"}, // e and a combining acute accent become one letter
	{"\u212a", "K"},             // KELVIN SIGN becomes the Latin capital K
	{"\u037e", ";"},             // GREEK QUESTION MARK becomes a semicolon
	{"\u1fef", "`"},             // GREEK VARIA becomes a grave accent
	{"a\u0302\u0323", "\u1ead"}, // marks in another order become one letter
}

// redTeam31SentConfig returns the arguments and the mount targets of the one
// task of job, which is the "Job" member of a registration.
func redTeam31SentConfig(t *testing.T, job []byte) (args, targets []string) {
	t.Helper()
	var sent struct {
		TaskGroups []struct {
			Tasks []struct {
				Config struct {
					Args   []string `json:"args"`
					Mounts []struct {
						Target string `json:"target"`
					} `json:"mounts"`
				}
			}
		}
	}
	if err := json.Unmarshal(job, &sent); err != nil || len(sent.TaskGroups) != 1 || len(sent.TaskGroups[0].Tasks) != 1 {
		t.Fatalf("job shape: %v", err)
	}
	for _, mount := range sent.TaskGroups[0].Tasks[0].Config.Mounts {
		targets = append(targets, mount.Target)
	}
	return sent.TaskGroups[0].Tasks[0].Config.Args, targets
}

// FINDING (holds at draft PR #40 fd399a1; report 31-redteam-recheck.md,
// RC31-1). The behaviour is older than PR #12 and than the repair; the repair
// added the sentence it contradicts ("so the workload receives exactly the
// strings ES admitted", .docs/execution_lifecycle/contracts.md).
//
// An argument that begins with a byte order mark, or that is not in
// Normalization Form C, passes nomadPassesAsWritten, is judged by the
// admission policy, bound and recorded as the caller wrote it, and is placed
// in Config.args unchanged. Nomad's client hands the workload the argument
// without the mark and in NFC. So the argv that runs is still not always the
// argv that was admitted: with an invisible mark in front, any argument at
// all differs from the one a policy that reads invocation_argv compares it
// with, and the workload receives it without the mark; a ";", a "`" or a "K"
// can be written as another character that becomes it; and a file name
// written in decomposed form names another file inside the workload.
//
// The test passes once ES either refuses such an argument before it sends
// anything, or sends the form the workload will receive.
func TestRedTeamRecheck31NomadDoesNotRewriteAdmittedArguments(t *testing.T) {
	for i, sample := range redTeam31Rewritten {
		t.Run(fmt.Sprintf("ordinary path sample %d", i), func(t *testing.T) {
			fixture, payload := nomadStringsFixture(t, "", "")
			request := fixture.prepareRequest()
			request.Invocation.Argv = []string{"plain", sample.written}
			_, err, bodies := nomadStringsSubmit(t, fixture, payload, request)
			if err != nil {
				if err.Status != http.StatusBadRequest || err.Code != codeInvalidRequest || len(bodies) != 0 {
					t.Fatalf("Submit with argument %+q: error %+v posts %d", sample.written, err, len(bodies))
				}
				return
			}
			if len(bodies) != 1 {
				t.Fatalf("Submit with argument %+q reached Nomad %d times", sample.written, len(bodies))
			}
			var registration struct{ Job json.RawMessage }
			if err := json.Unmarshal(bodies[0], &registration); err != nil {
				t.Fatal(err)
			}
			args, _ := redTeam31SentConfig(t, registration.Job)
			if last := args[len(args)-1]; last != sample.received {
				t.Fatalf("the job sent to Nomad carries the caller's argument %+q, which Nomad's client hands to the workload as %+q", last, sample.received)
			}
		})
		t.Run(fmt.Sprintf("private path sample %d", i), func(t *testing.T) {
			f := makeOperationalFixture(t, "", sample.written)
			out := f.submit()
			state := operationalPrestageStateAt(t, f)
			f.receiver.mu.Lock()
			job := bytes.Clone(f.receiver.job)
			f.receiver.mu.Unlock()
			if job == nil {
				if out.kind == operationalAccepted || state.Claims != 0 || state.Grants != 0 || state.Posts != 0 {
					t.Fatalf("no job was received, yet %s state=%+v", operationalResultText(out), state)
				}
				return
			}
			args, _ := redTeam31SentConfig(t, job)
			if last := args[len(args)-1]; last != sample.received {
				t.Fatalf("the job sent to Nomad carries the caller's argument %+q, which Nomad's client hands to the workload as %+q (result %s)",
					last, sample.received, operationalResultText(out))
			}
		})
	}
}

// FINDING (same report, RC31-1, mount targets). Two mount targets that differ
// only in their normalization form pass the overlap check as different paths
// and reach Config.mounts as two binds. Nomad's client normalizes both, so the
// container is asked for two mounts at one path, or for one mount inside the
// other, after ES has answered that the run was submitted.
//
// The test passes once such a pair is refused before anything is sent.
func TestRedTeamRecheck31MountTargetsStayDistinctForNomad(t *testing.T) {
	for name, pair := range map[string][2]string{
		"same path after normalization":   {"/caf\u00e9", "/cafe\u0301"},
		"nested path after normalization": {"/caf\u00e9", "/cafe\u0301/inner"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, payload := nomadStringsFixture(t, "", "")
			request := fixture.prepareRequest()
			source := MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest}
			request.Invocation.Mounts = []RuntimeMount{
				{Source: source, TargetPath: runtimeMountRoot + pair[0], ReadOnly: true},
				{Source: source, TargetPath: runtimeMountRoot + pair[1], ReadOnly: true},
			}
			result, err, bodies := nomadStringsSubmit(t, fixture, payload, request)
			if err == nil || result.Submitted || len(bodies) != 0 {
				t.Fatalf("mount targets %+q and %+q, which are one path or nested paths once Nomad has normalized them, were submitted: result %+v error %+v posts %d",
					pair[0], pair[1], result, err, len(bodies))
			}
		})
	}
}

// FINDING (same report, RC31-2). Not caused by the repair: it is another way
// to the end state that the repair of RT28-2 closes for size.
//
// ES accepts resources.memory_mb from 1. Nomad v2.1.1 refuses to register a
// task with less than 10 MB (nomad/structs/structs.go, MinResources and
// Resources.MeetsMinResources: "minimum MemoryMB value is 10"). On the private
// path such a request takes one of the four claim slots and a reservation, is
// staged, gets its durable marker and its one POST, and Nomad refuses the
// POST: the claim then answers as ambiguous for good. On the ordinary path it
// is staged and answered with 503 instead of 400.
//
// The test passes once a request that Nomad refuses for its memory is refused
// before the private path stores a claim and before the ordinary path sends
// anything.
func TestRedTeamRecheck31MemoryBelowNomadMinimumIsRefusedFirst(t *testing.T) {
	const nomadMinimumMemoryMB = 10
	for _, memory := range []int{1, 9} {
		t.Run(fmt.Sprintf("private path memory_mb %d", memory), func(t *testing.T) {
			f := makeOperationalFixture(t, "", "alpha")
			f.raw = redTeam3RequestVariant(t, f, func(outer, _ map[string]any) {
				outer["resources"] = map[string]any{"cpu": 1, "memory_mb": memory}
			})
			out := f.submit()
			if state := operationalPrestageStateAt(t, f); out.kind == operationalAccepted || state.Claims != 0 || state.Grants != 0 || state.Posts != 0 {
				t.Fatalf("a request with %d MB, below Nomad's minimum of %d, took a claim and was sent: %s state=%+v",
					memory, nomadMinimumMemoryMB, operationalResultText(out), state)
			}
		})
		t.Run(fmt.Sprintf("ordinary path memory_mb %d", memory), func(t *testing.T) {
			fixture, payload := nomadStringsFixture(t, "", "")
			request := fixture.prepareRequest()
			request.Resources = &ExecutionResources{CPU: 1, MemoryMB: memory}
			_, err, bodies := nomadStringsSubmit(t, fixture, payload, request)
			if err == nil || err.Status != http.StatusBadRequest || err.Code != codeInvalidRequest || len(bodies) != 0 {
				t.Fatalf("Submit with %d MB, below Nomad's minimum of %d: error %+v posts %d, want 400 %s and no POST",
					memory, nomadMinimumMemoryMB, err, len(bodies), codeInvalidRequest)
			}
		})
	}
}
