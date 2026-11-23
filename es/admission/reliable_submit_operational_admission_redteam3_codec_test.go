package admission

// Red-team regression tests for PR #12 at 4416699 (report 28-redteam.md): the
// retained original between its writer and its readers.

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// redTeam3RequestVariant returns the fixture's request after edit changed its
// outer object or its invocation.
func redTeam3RequestVariant(t *testing.T, f *operationalFixture, edit func(outer, invocation map[string]any)) []byte {
	t.Helper()
	var outer map[string]any
	if err := json.Unmarshal(f.raw, &outer); err != nil {
		t.Fatal(err)
	}
	edit(outer, outer["invocation"].(map[string]any))
	raw, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func redTeam3Repeat(s string, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func redTeam3Entries(n, keyBytes, valueBytes int) map[string]any {
	out := map[string]any{}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("k%04d", i)
		out[key+strings.Repeat("k", max(keyBytes-len(key), 0))] = strings.Repeat("v", valueBytes)
	}
	return out
}

// redTeam3ExtremeRequests are requests at the edges of what the delivery
// parser accepts: counts and sizes at their limits, empty and absent members,
// and strings that are valid JSON and unusual as arguments.
func redTeam3ExtremeRequests(t *testing.T, f *operationalFixture) map[string][]byte {
	t.Helper()
	v := func(edit func(outer, invocation map[string]any)) []byte { return redTeam3RequestVariant(t, f, edit) }
	return map[string][]byte{
		"base":                     f.raw,
		"argv absent":              v(func(_, i map[string]any) { delete(i, "argv") }),
		"argv empty list":          v(func(_, i map[string]any) { i["argv"] = []any{} }),
		"argv 100 empty strings":   v(func(_, i map[string]any) { i["argv"] = redTeam3Repeat("", 100) }),
		"argv 100 of 2000 bytes":   v(func(_, i map[string]any) { i["argv"] = redTeam3Repeat(strings.Repeat("a", 2000), 100) }),
		"argv one of 65536":        v(func(_, i map[string]any) { i["argv"] = []any{strings.Repeat("a", 65536)} }),
		"argv three of 65536":      v(func(_, i map[string]any) { i["argv"] = redTeam3Repeat(strings.Repeat("a", 65536), 3) }),
		"argv control bytes":       v(func(_, i map[string]any) { i["argv"] = []any{"\x01\x1f\x7f"} }),
		"argv unicode":             v(func(_, i map[string]any) { i["argv"] = []any{"\U0001F603", " ", "�", "é"} }),
		"env absent":               v(func(_, i map[string]any) { delete(i, "env") }),
		"env empty map":            v(func(_, i map[string]any) { i["env"] = map[string]any{} }),
		"env value empty":          v(func(_, i map[string]any) { i["env"] = map[string]any{"APP_MODE": ""} }),
		"env value 60000 bytes":    v(func(_, i map[string]any) { i["env"] = map[string]any{"APP_MODE": strings.Repeat("e", 60000)} }),
		"annotations empty map":    v(func(_, i map[string]any) { i["annotations"] = map[string]any{} }),
		"annotations 128":          v(func(_, i map[string]any) { i["annotations"] = redTeam3Entries(128, 8, 8) }),
		"annotations 128 large":    v(func(_, i map[string]any) { i["annotations"] = redTeam3Entries(128, 1000, 500) }),
		"annotation empty key":     v(func(_, i map[string]any) { i["annotations"] = map[string]any{"": "x"} }),
		"annotation key 1024":      v(func(_, i map[string]any) { i["annotations"] = redTeam3Entries(1, 1024, 1) }),
		"annotation value 65536":   v(func(_, i map[string]any) { i["annotations"] = redTeam3Entries(1, 8, 65536) }),
		"profile empty":            v(func(_, i map[string]any) { i["annotations"] = map[string]any{runtimeProfileAnnotationKey: ""} }),
		"profile blank":            v(func(_, i map[string]any) { i["annotations"] = map[string]any{runtimeProfileAnnotationKey: " \t "} }),
		"mounts empty list":        v(func(_, i map[string]any) { i["mounts"] = []any{} }),
		"mode empty":               v(func(o, _ map[string]any) { o["mode"] = "" }),
		"mode async":               v(func(o, _ map[string]any) { o["mode"] = "async" }),
		"timeout 0":                v(func(o, _ map[string]any) { o["timeout_seconds"] = 0 }),
		"timeout 1":                v(func(o, _ map[string]any) { o["timeout_seconds"] = 1 }),
		"timeout largest":          v(func(o, _ map[string]any) { o["timeout_seconds"] = 2147483647 }),
		"resources smallest":       v(func(o, _ map[string]any) { o["resources"] = map[string]any{"cpu": 1, "memory_mb": 1} }),
		"resources largest":        v(func(o, _ map[string]any) { o["resources"] = map[string]any{"cpu": 2147483647, "memory_mb": 2147483647} }),
		"invocation schema empty":  v(func(_, i map[string]any) { i["schema_version"] = "" }),
		"invocation schema absent": v(func(_, i map[string]any) { delete(i, "schema_version") }),
		"everything large": v(func(o, i map[string]any) {
			i["argv"] = redTeam3Repeat(strings.Repeat("a", 900), 100)
			i["annotations"] = redTeam3Entries(128, 200, 600)
			i["env"] = map[string]any{"APP_MODE": strings.Repeat("e", 30000)}
			o["timeout_seconds"] = 5
			o["resources"] = map[string]any{"cpu": 100, "memory_mb": 64}
		}),
	}
}

// The composer writes the original once, before the claim exists; every later
// step reads it back through the verifier. Nothing checks the two against
// each other before the claim is stored, so an original that is written and
// then refused would cost one of the four claim slots and one reservation for
// good. For requests at the edges of what the parser accepts, whatever the
// composer writes the verifier reads back, the store's shape check accepts,
// and the retained qualification judges exactly as it judges the composed
// original.
func TestRedTeamPR12HeadEveryComposedOriginalReadsBack(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "", "alpha", "beta")
	caller, err := newSyntheticCallerFact(f.domain.caller.String())
	if err != nil {
		t.Fatal(err)
	}
	f.confirm()
	composed := 0
	for name, raw := range redTeam3ExtremeRequests(t, f) {
		delivery, err := parsePrivateReplayDelivery(raw, caller)
		if err != nil {
			t.Fatalf("%s: the delivery parser refuses a request the table holds as valid", name)
		}
		original, err := f.service.composeOperationalOriginal(ctx, delivery, f.domain.keys, f.domain.realm)
		if err != nil {
			t.Fatalf("%s: the composer refuses a request the table holds as valid", name)
		}
		composed++
		verified, err := verifyOperationalOriginal(original.wire, f.domain.keys, f.domain.realm)
		if err != nil {
			t.Fatalf("%s: the composer wrote an original of %d bytes that the verifier refuses", name, len(original.wire))
		}
		if _, err := reliablesubmit.MatchOperationalOriginal(delivery.refs.claimID, original.assessment.boundPlan, original.wire); err != nil {
			t.Fatalf("%s: the store's shape check refuses the composed original", name)
		}
		before := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm)
		after := f.service.qualifyOperationalRetained(ctx, verified, f.domain.realm)
		if before != reliablesubmit.OperationalReasonNone || after != before {
			t.Fatalf("%s: the composed original qualifies with reason %d, the one read back with %d", name, before, after)
		}
	}
	if composed < 30 {
		t.Fatalf("only %d requests were composed", composed)
	}
}

// The same through the store: large requests whose job still fits the
// provider's limit of 65,536 bytes are delivered, sealed, read back by every
// step and completed with exactly one POST.
func TestRedTeamPR12HeadLargeRequestsThatFitComplete(t *testing.T) {
	for name, edit := range map[string]func(outer, invocation map[string]any){
		"annotations 128 large": func(_, i map[string]any) { i["annotations"] = redTeam3Entries(128, 1000, 500) },
		"argv 100 of 500 bytes": func(_, i map[string]any) { i["argv"] = redTeam3Repeat(strings.Repeat("a", 500), 100) },
		"argv one of 60000":     func(_, i map[string]any) { i["argv"] = []any{strings.Repeat("a", 60000)} },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeOperationalFixture(t, "", "alpha", "beta")
			f.raw = redTeam3RequestVariant(t, f, edit)
			assertOperationalCompleted(t, f, f.submit(), name)
			assertOperationalCompleted(t, f, f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw), name+", delivered again")
		})
	}
}

// Tripwire (report 28-redteam.md, observation O-3). The retained request is
// tied to the bound plan only in the members validateOperationalPlan
// compares: argv, the two digests, the output id, the timeout, the resources
// and the runtime profile. Its env values, its mode and its other annotations
// are not tied. That is harmless while the policy context reads none of them.
// This test fails when the policy context gains a member, so that whoever
// adds an input derived from the request ties it to the bound plan first.
func TestRedTeamPR12HeadPolicyContextReadsOnlyTiedRequestMembers(t *testing.T) {
	want := []string{"InvocationArgv", "ArtifactDigest", "PayloadDigest", "PayloadByteCount", "ArtifactType",
		"RuntimeProfileName", "TargetPlatform", "NetworkAccess", "StaticScriptPayloadText", "StaticScriptPayloadTextPresent"}
	var got []string
	for i, typ := 0, reflect.TypeOf(AdmissionPolicyContext{}); i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the policy context changed: %v. Before a policy reads the request's env, mode or annotations, "+
			"validateOperationalPlan must compare that member with the bound plan (28-redteam.md, O-3).", got)
	}
	// What the context takes from the request today is tied: the argv and the
	// artifact digest directly, the profile through the trimmed annotation.
	request := PrepareRequest{Mode: "async", TimeoutSeconds: 9, Invocation: ArtifactInvocation{
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Argv: []string{"x"}, Env: map[string]string{"UNTIED": "value"},
		Annotations: map[string]string{"untied": "value"}}}
	policy := newAdmissionPolicyContext(request, preparedArtifact{})
	changed := request
	changed.Mode, changed.TimeoutSeconds = "", 0
	changed.Invocation.Env = map[string]string{"UNTIED": "other"}
	changed.Invocation.Annotations = map[string]string{"untied": "other"}
	if !reflect.DeepEqual(policy, newAdmissionPolicyContext(changed, preparedArtifact{})) {
		t.Fatal("the policy context depends on a request member that validateOperationalPlan does not tie to the bound plan")
	}
}
