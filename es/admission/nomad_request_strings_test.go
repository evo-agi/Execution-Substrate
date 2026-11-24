package admission

// Report 28-redteam.md, RT28-1: Nomad's client evaluates "${...}" and
// "%{...}" in the strings of a task's driver configuration and replaces
// "${name}" in environment and meta values. These tests pin that ES refuses a
// request string that would not reach the workload as written, on the
// ordinary path and on the private path, and that the strings it checks are
// exactly the request strings that reach the Nomad job.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// nomadEvaluatedSamples are request strings that Nomad v2.1.1 would not pass
// on as written: an interpolation, a function call, a directive, both escape
// forms (which Nomad rewrites to the opener), an unterminated opener that
// fails the task after ES accepted it, and a NUL byte that no process can
// receive.
var nomadEvaluatedSamples = []string{
	"${attr.unique.hostname}",
	`${lower("DENIED")}`,
	"%{ if true }x%{ endif }",
	"$${x}",
	"%%{x}",
	"unterminated ${",
	"nul\x00byte",
}

func TestNomadPassesAsWrittenRefusesTemplateOpenersAndNUL(t *testing.T) {
	for _, s := range append(append([]string{}, nomadEvaluatedSamples...), "${", "%{", "a${b}c", "x%{", "\x00", "${~x~}") {
		if nomadPassesAsWritten(s) {
			t.Errorf("nomadPassesAsWritten(%q) = true, want false", s)
		}
	}
	// Each of these reaches the workload as written: a lone "$" or "%", a
	// brace without an opener before it, an opener split by another
	// character, every other control byte, and non-ASCII text.
	for _, s := range []string{"", "plain", "$", "%", "{", "}", "{}", "$HOME", "100%", "%d", "$ {x}", "% {x}", "{$}", "{%}", "$ {x}",
		"\x01\x1f\x7f", "\t\n\r", "<&>", "é", " ", "x$", "x%"} {
		if !nomadPassesAsWritten(s) {
			t.Errorf("nomadPassesAsWritten(%q) = false, want true", s)
		}
	}
}

// nomadStringsFixture is a signed artifact whose evidence allows the
// environment key extraEnv as well as APP_MODE and names outputID.
func nomadStringsFixture(t *testing.T, extraEnv, outputID string) (preparedArtifactFixture, []byte) {
	t.Helper()
	fixture := newPreparedArtifactFixture(t)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	fixture = fixture.withPayload(t, payload)
	fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess = false
	if extraEnv != "" {
		runtime := &fixture.evidence.Claims.Admission.Execution.Runtime
		runtime.EnvironmentVariables = append(append([]string(nil), runtime.EnvironmentVariables...), extraEnv)
	}
	if outputID != "" {
		fixture.evidence.Claims.Admission.Authorization.Derivation.OutputID = outputID
	}
	resignPreparedArtifactFixture(t, &fixture)
	return fixture, payload
}

// nomadStringsSubmit submits request on a fresh Service for fixture and
// returns the result, the error and every body the synthetic Nomad received.
func nomadStringsSubmit(t *testing.T, fixture preparedArtifactFixture, payload []byte, request PrepareRequest) (SubmitResult, *Error, [][]byte) {
	t.Helper()
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, payload, nil))
	var bodies [][]byte
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		_, _ = w.Write([]byte(`{"EvalID":"eval-nomad-strings"}`))
	}))
	result, err := service.Submit(context.Background(), request)
	return result, err, bodies
}

func TestSubmitRefusesRequestStringsThatNomadWouldNotPassOnAsWritten(t *testing.T) {
	for _, field := range []struct {
		name, message string
		outputID      bool
		set           func(f preparedArtifactFixture, r *PrepareRequest, value string)
	}{
		{name: "argv", message: "invocation.argv " + nomadEvaluatedText,
			set: func(_ preparedArtifactFixture, r *PrepareRequest, value string) {
				r.Invocation.Argv = []string{"plain", value}
			}},
		{name: "env value", message: "invocation.env " + nomadEvaluatedText,
			set: func(_ preparedArtifactFixture, r *PrepareRequest, value string) {
				r.Invocation.Env = map[string]string{"APP_MODE": value}
			}},
		{name: "env key", message: "invocation.env " + nomadEvaluatedText,
			set: func(_ preparedArtifactFixture, r *PrepareRequest, value string) {
				r.Invocation.Env = map[string]string{"APP_MODE": "test", value: "x"}
			}},
		{name: "mount target", message: "mount target_path " + nomadEvaluatedText,
			set: func(f preparedArtifactFixture, r *PrepareRequest, value string) {
				r.Invocation.Mounts = []RuntimeMount{{Source: MountSource{ArtifactDigest: f.discovery.Artifact.ArtifactDigest},
					TargetPath: runtimeMountRoot + "/" + value, ReadOnly: true}}
			}},
		{name: "output id", message: "invocation.output_id " + nomadEvaluatedText, outputID: true,
			set: func(_ preparedArtifactFixture, r *PrepareRequest, value string) { r.Invocation.OutputID = value }},
	} {
		for i, value := range nomadEvaluatedSamples {
			t.Run(fmt.Sprintf("%s sample %d", field.name, i), func(t *testing.T) {
				outputID := ""
				if field.outputID {
					// The evidence names the same output, so the request is refused
					// for its text and not for a mismatch with the evidence.
					outputID = value
				}
				fixture, payload := nomadStringsFixture(t, "", outputID)
				request := fixture.prepareRequest()
				field.set(fixture, &request, value)
				_, err, bodies := nomadStringsSubmit(t, fixture, payload, request)
				if err == nil || err.Status != http.StatusBadRequest || err.Code != codeInvalidRequest || err.Message != field.message {
					t.Fatalf("Submit with %s %q: error %+v, want 400 %s %q", field.name, value, err, codeInvalidRequest, field.message)
				}
				if len(bodies) != 0 {
					t.Fatalf("Submit with %s %q reached Nomad %d times", field.name, value, len(bodies))
				}
			})
		}
	}
}

// nomadJobStrings returns every string of a decoded JSON value, keys
// included, with its path. Array indexes are written as [] and a key as {key}
// after the path of its object.
func nomadJobStrings(value any, path string, out map[string][]string) {
	switch v := value.(type) {
	case string:
		out[v] = append(out[v], path)
	case []any:
		for _, elem := range v {
			nomadJobStrings(elem, path+"[]", out)
		}
	case map[string]any:
		for key, elem := range v {
			out[key] = append(out[key], path+"{key}")
			nomadJobStrings(elem, path+"."+key, out)
		}
	}
}

// The request strings that reach the Nomad job are exactly the ones that
// validateInvocationAgainstManifest checks with nomadPassesAsWritten: the
// arguments, the environment keys and values, the mount targets and the output
// id. Every free-text member of the request carries its own marker, and the
// test finds where each marker lands. A change that places another request
// string in the job, an annotation for example, fails here until that string
// is checked too.
func TestSubmitPlacesOnlyTheCheckedRequestStringsInTheNomadJob(t *testing.T) {
	fixture, payload := nomadStringsFixture(t, "ZZMARK_ENV_KEY", "zzmark-output-id")
	request := fixture.prepareRequest()
	request.Invocation.Argv = []string{"zzmark-argv"}
	request.Invocation.Env = map[string]string{"ZZMARK_ENV_KEY": "zzmark-env-value"}
	request.Invocation.Mounts = []RuntimeMount{{Source: MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest},
		TargetPath: runtimeMountRoot + "/zzmark-mount", ReadOnly: true}}
	request.Invocation.Annotations = map[string]string{"zzmark-annotation-key": "zzmark-annotation-value"}
	result, err, bodies := nomadStringsSubmit(t, fixture, payload, request)
	if err != nil || !result.Submitted || len(bodies) != 1 {
		t.Fatalf("Submit with markers: result %+v error %+v posts %d", result, err, len(bodies))
	}
	var job any
	if err := json.Unmarshal(bodies[0], &job); err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	nomadJobStrings(job, "", found)
	got := map[string][]string{}
	for s, paths := range found {
		if strings.Contains(strings.ToLower(s), "zzmark") {
			sort.Strings(paths)
			got[s] = paths
		}
	}
	task := ".Job.TaskGroups[].Tasks[]"
	want := map[string][]string{
		"zzmark-argv":                    {task + ".Config.args[]"},
		"ZZMARK_ENV_KEY":                 {task + ".Env{key}"},
		"zzmark-env-value":               {task + ".Env.ZZMARK_ENV_KEY"},
		"/execution/mounts/zzmark-mount": {task + ".Config.mounts[].target"},
		"zzmark-output-id":               {task + ".Meta.output_id"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request strings in the Nomad job:\n got %v\nwant %v", got, want)
	}
}

// requestStringFields lists every member of t that holds a string, by path.
func requestStringFields(t reflect.Type, path string, out *[]string) {
	switch t.Kind() {
	case reflect.String:
		*out = append(*out, path)
	case reflect.Pointer:
		requestStringFields(t.Elem(), path, out)
	case reflect.Slice, reflect.Array:
		requestStringFields(t.Elem(), path+"[]", out)
	case reflect.Map:
		requestStringFields(t.Key(), path+"{key}", out)
		requestStringFields(t.Elem(), path+"{value}", out)
	case reflect.Struct:
		for i := range t.NumField() {
			field := t.Field(i)
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			requestStringFields(field.Type, name, out)
		}
	}
}

// Every string a caller can put in a request is classified for the Nomad job.
// A new string member fails here until someone decides which class it is in,
// and a member that reaches the job must be checked by nomadPassesAsWritten
// and listed in TestSubmitPlacesOnlyTheCheckedRequestStringsInTheNomadJob.
func TestEveryRequestStringIsClassifiedForTheNomadJob(t *testing.T) {
	const (
		checked = "reaches the job; nomadPassesAsWritten refuses it unless Nomad passes it on as written"
		digest  = "a labeled sha256 digest, which holds no template opener and no NUL byte"
		enum    = "one of a fixed set of values"
		absent  = "never placed in the job"
	)
	want := map[string]string{
		"SchemaVersion":                             absent,
		"Mode":                                      enum,
		"Invocation.SchemaVersion":                  absent,
		"Invocation.ArtifactDigest":                 digest,
		"Invocation.DerivationSpecDigest":           digest,
		"Invocation.OutputID":                       checked,
		"Invocation.Argv[]":                         checked,
		"Invocation.Env{key}":                       checked,
		"Invocation.Env{value}":                     checked,
		"Invocation.Mounts[].Source.ArtifactDigest": digest,
		"Invocation.Mounts[].TargetPath":            checked,
		"Invocation.Annotations{key}":               absent,
		"Invocation.Annotations{value}":             absent,
	}
	var got []string
	requestStringFields(reflect.TypeFor[PrepareRequest](), "", &got)
	var wantPaths []string
	for path := range want {
		wantPaths = append(wantPaths, path)
	}
	slices.Sort(got)
	slices.Sort(wantPaths)
	if !slices.Equal(got, wantPaths) {
		t.Fatalf("string members of PrepareRequest:\n got %v\nwant %v", got, wantPaths)
	}
}

// The private path resolves its request through the same validation before
// it stores anything, so a request string that Nomad would not pass on as
// written takes no claim, no reservation and no POST there either. The red
// team's test covers the arguments; this covers an environment value.
func TestOperationalHandoffRefusesAnEnvironmentValueThatNomadWouldEvaluate(t *testing.T) {
	for i, value := range nomadEvaluatedSamples {
		t.Run(fmt.Sprintf("sample %d", i), func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			f.raw = redTeam3RequestVariant(t, f, func(_, invocation map[string]any) {
				invocation["env"] = map[string]any{"APP_MODE": value}
			})
			out := f.submit()
			state := operationalPrestageStateAt(t, f)
			if out.kind == operationalAccepted || state.Claims != 0 || state.Grants != 0 || state.Posts != 0 {
				t.Fatalf("environment value %q: %s state=%+v", value, operationalResultText(out), state)
			}
		})
	}
}

// Report 31-redteam-recheck.md, RC31-1: Nomad's client drops a byte order
// mark at the start of a string of a task's driver configuration and rewrites
// the string to Unicode Normalization Form C. nomadKeepsDriverString keeps a
// string exactly when neither changes it, and when every code point in it is
// assigned in the Unicode version of ES's tables, so that a Nomad with tables
// of a later version leaves it unchanged too.
func TestNomadKeepsDriverStringRefusesWhatNomadWouldRewrite(t *testing.T) {
	if nomadNormalizationAssigned == nil {
		t.Fatalf("x/text has no table of code points assigned in Unicode %s", norm.Version)
	}
	for _, s := range []string{
		"",
		"--flag",
		"/execution/mounts/caf\u00e9", // a composed letter
		"\u1ead",                      // the composed form of a, U+0302, U+0323
		"\U0001f603",                  // an emoji of Unicode 6.0
		"\U0001fae8",                  // an emoji of Unicode 15.0, the version of ES's tables
		"\u2028",                      // LINE SEPARATOR
		"\ufffd",                      // REPLACEMENT CHARACTER
		"\ufb01",                      // a ligature that only compatibility forms fold
		"a\ufeff",                     // a byte order mark after the start
		"\x01\x1f\x7f\r",              // ASCII control bytes
	} {
		if !nomadKeepsDriverString(s) {
			t.Errorf("nomadKeepsDriverString(%+q) = false, want true", s)
		}
	}
	rewritten := []string{
		"\ufeff",     // a byte order mark alone
		"\u0378",     // never assigned
		"\ufffe",     // a noncharacter
		"\U0001fae9", // assigned in Unicode 16.0, after ES's tables
	}
	for _, pair := range redTeam31Rewritten {
		rewritten = append(rewritten, pair.written)
	}
	for _, s := range rewritten {
		if nomadKeepsDriverString(s) {
			t.Errorf("nomadKeepsDriverString(%+q) = true, want false", s)
		}
	}
}

// Report 31-redteam-recheck.md, RC31-2: Nomad v2.1.1 refuses a task with less
// than 10 MB of memory, so the request validation that both paths share
// refuses it first, and accepts the least Nomad registers.
func TestValidatePrepareRequestRefusesMemoryBelowNomadMinimum(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	for _, test := range []struct {
		memory int
		want   string
	}{
		{0, "resources.memory_mb must be at least 10, the least memory Nomad registers a task with"},
		{9, "resources.memory_mb must be at least 10, the least memory Nomad registers a task with"},
		{10, ""},
	} {
		request := fixture.prepareRequest()
		request.Resources = &ExecutionResources{CPU: 1, MemoryMB: test.memory}
		got := ""
		if err := validatePrepareRequest(&request); err != nil {
			got = err.Message
		}
		if got != test.want {
			t.Errorf("memory_mb %d: got %q, want %q", test.memory, got, test.want)
		}
	}
}
