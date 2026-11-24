package admission

// Red-team fuzz targets for PR #12 at 4416699 (report 28-redteam.md). The
// earlier targets cover the evidence record and the incoming delivery; these
// cover the provider's own JSON reader and renderer, the job template, and the
// retained scope-3 original as the store hands it back.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// redTeam3Standard decodes with the standard library, numbers kept as text.
func redTeam3Standard(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// redTeam3Plain turns the provider's value into the standard library's shape.
func redTeam3Plain(value any) any {
	switch v := value.(type) {
	case privateJSONNumber:
		return json.Number(string(v))
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = redTeam3Plain(v[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = redTeam3Plain(x)
		}
		return out
	default:
		return v
	}
}

// The provider reads what Nomad answers with its own JSON reader and compares
// canonical renderings. Whatever the reader accepts, the standard library
// accepts too and reads as the same value, and the canonical rendering is
// stable: it parses again to the same rendering and the same value. A
// difference between the two readers would let one answer mean two things.
func FuzzRedTeamPR12HeadParseOperationalJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `[]`, `null`, `0`, `-1`, `18446744073709551615`, `"😃"`, `{"a":[1,{"b":null}],"c":"\u0000\\"}`,
		`{"ID":"esoh-job-00","Meta":{"es_operational_correlation_v1":"aa"},"Stop":false}`, ` [ 1 , 2 ] `, `01`, `1.5`, `"\x7f"`, "\" \"", `{"a":1,"a":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := parseOperationalJSON(raw, 65536)
		if err != nil {
			return
		}
		standard, err := redTeam3Standard(raw)
		if err != nil {
			t.Fatalf("the provider's reader accepted what the standard library refuses (%v): %q", err, raw)
		}
		if !reflect.DeepEqual(redTeam3Plain(value), standard) {
			t.Fatalf("the two readers disagree on the value of %q", raw)
		}
		canonical := appendOperationalJSON(nil, value)
		again, err := parseOperationalJSON(canonical, 1<<20)
		if err != nil {
			t.Fatalf("the canonical rendering %q of %q does not parse", canonical, raw)
		}
		if second := appendOperationalJSON(nil, again); !bytes.Equal(second, canonical) {
			t.Fatalf("the canonical rendering is not stable: %q then %q", canonical, second)
		}
		rendered, err := redTeam3Standard(canonical)
		if err != nil || !reflect.DeepEqual(rendered, standard) {
			t.Fatalf("the canonical rendering %q changed the value of %q (%v)", canonical, raw, err)
		}
	})
}

// redTeam3Covers reports whether rendered carries every member of job
// unchanged at the same place.
func redTeam3Covers(rendered, job any) bool {
	switch j := job.(type) {
	case map[string]any:
		r, ok := rendered.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range j {
			x, ok := r[k]
			if !ok || !redTeam3Covers(x, v) {
				return false
			}
		}
		return true
	case []any:
		r, ok := rendered.([]any)
		if !ok || len(r) != len(j) {
			return false
		}
		for i := range j {
			if !redTeam3Covers(r[i], j[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(rendered, job)
	}
}

// The job template decides what the provider expects Nomad to hand back. For
// any template and any job, a rendering that succeeds carries every member of
// the job unchanged: a template can add literal defaults, never drop or
// replace what the job says.
func FuzzRedTeamPR12HeadRenderOperationalTemplate(f *testing.F) {
	f.Add([]byte(`{"ID":{"$job0":"/ID"},"Meta":{"$job0":"/Meta"},"Stop":false}`), []byte(`{"ID":"a","Meta":{"k":"v"}}`))
	f.Add([]byte(`{"TaskGroups":[{"Name":{"$job0":"/TaskGroups/0/Name"},"Tasks":[{"Config":{"args":{"$job0":"/TaskGroups/0/Tasks/0/Config/args"}}}]}]}`),
		[]byte(`{"TaskGroups":[{"Name":"g","Tasks":[{"Config":{"args":["${x}","b"]}}]}]}`))
	f.Add([]byte(`{"$job0":""}`), []byte(`"x"`))
	f.Add([]byte(`{"a":{"$job0":"/a"}}`), []byte(`{"a":{"b":1}}`))
	f.Fuzz(func(t *testing.T, templateRaw, jobRaw []byte) {
		template, err := parseOperationalJSON(templateRaw, 65536)
		if err != nil {
			return
		}
		job, err := parseOperationalJSON(jobRaw, 65536)
		if err != nil {
			return
		}
		rendered, err := renderOperationalTemplate(template, job, "")
		if err != nil {
			return
		}
		if !redTeam3Covers(rendered, job) {
			t.Fatalf("template %q dropped or replaced a member of job %q: %q", templateRaw, jobRaw, appendOperationalJSON(nil, rendered))
		}
		_ = appendOperationalJSON(nil, rendered)
	})
}

type redTeam3Original struct {
	wire   []byte
	keys   operationalOriginalKeys
	realm  operationalRealm
	claim  reliablesubmit.ClaimID
	plan   reliablesubmit.BoundPlan
	fields [][]byte
}

var (
	redTeam3OriginalOnce  sync.Once
	redTeam3OriginalValue redTeam3Original
)

// redTeam3ComposeOriginal composes the fixture's retained original once per
// process. The values it keeps do not depend on the fixture staying open.
func redTeam3ComposeOriginal(t *testing.T) redTeam3Original {
	t.Helper()
	redTeam3OriginalOnce.Do(func() {
		f := makeOperationalFixture(t, "", "alpha", "beta")
		caller, err := newSyntheticCallerFact(f.domain.caller.String())
		if err != nil {
			t.Fatal(err)
		}
		request, err := parsePrivateReplayDelivery(f.raw, caller)
		if err != nil {
			t.Fatal(err)
		}
		original, err := f.service.composeOperationalOriginal(context.Background(), request, f.domain.keys, f.domain.realm)
		if err != nil {
			t.Fatal(err)
		}
		redTeam3OriginalValue = redTeam3Original{wire: bytes.Clone(original.wire), keys: f.domain.keys, realm: f.domain.realm,
			claim: request.refs.claimID, plan: original.assessment.boundPlan,
			fields: operationalVectorFields(t, original.wire[14:], 11)}
	})
	if redTeam3OriginalValue.wire == nil {
		t.Fatal("the fixture's original could not be composed in this process")
	}
	return redTeam3OriginalValue
}

// redTeam3Edit applies an edit script to a copy of wire: groups of five bytes
// (operation, three bytes of offset, value). The first byte of the script
// says whether the aggregate length of the header is corrected afterwards, so
// that edits which change the size still reach the field reader.
func redTeam3Edit(wire, script []byte) []byte {
	out := bytes.Clone(wire)
	if len(script) == 0 {
		return out
	}
	fix := script[0]&1 == 1
	for rest := script[1:]; len(rest) >= 5 && len(out) > 0; rest = rest[5:] {
		offset := (int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])) % len(out)
		value := rest[4]
		switch rest[0] % 4 {
		case 0:
			out[offset] ^= value | 1
		case 1:
			out[offset] = value
		case 2:
			end := min(offset+int(value%8)+1, len(out))
			out = append(out[:offset], out[end:]...)
		case 3:
			out = append(out[:offset], append([]byte{value}, out[offset:]...)...)
		}
	}
	if fix && len(out) >= 14 {
		binary.BigEndian.PutUint32(out[10:14], uint32(len(out)-14))
	}
	return out
}

// The retained original reaches current admission again on every retry. This
// target edits the fixture's valid original and hands the result to the two
// readers production uses, the store's shape check and the admission's
// verifier. Neither panics. The verifier accepts only an exact canonical
// encoding, and an edited original it accepts leaves everything the effect is
// built from unchanged: the plan, the material, the binding, the image, the
// placement, the keys, the scope and the realm (fields 3 to 7 and 9 to 11)
// cannot be changed without the binding key.
//
// The three other fields are held elsewhere, which the single-bit scan of
// report 28-redteam.md measured: the claim identity (field 1) by the store's
// own comparison and digest, the evidence record (field 8) by the signature
// check of the retained qualification, and the retained request (field 2) by
// validateOperationalPlan for the members it compares.
func FuzzRedTeamPR12HeadVerifyOperationalOriginal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 20, 1})
	f.Add([]byte{1, 2, 0, 1, 0, 3})
	f.Add([]byte{1, 3, 0, 2, 0, 0, 0, 0, 0, 40, 7})
	f.Add([]byte{0, 1, 0, 0, 9, 2})
	f.Add([]byte{0x30, 0x30, 0x2e, 0x28, 0x30, 0x01})
	f.Fuzz(func(t *testing.T, script []byte) {
		original := redTeam3ComposeOriginal(t)
		wire := redTeam3Edit(original.wire, script)
		_, _ = reliablesubmit.MatchOperationalOriginal(original.claim, original.plan, wire)
		verified, err := verifyOperationalOriginal(wire, original.keys, original.realm)
		if err != nil {
			return
		}
		if !bytes.Equal(verified.wire, wire) {
			t.Fatal("the verifier accepted an encoding that is not the one it writes")
		}
		if bytes.Equal(wire, original.wire) {
			return
		}
		fields := operationalVectorFields(t, wire[14:], 11)
		for _, i := range []int{2, 3, 4, 5, 6, 8, 9, 10} {
			if !bytes.Equal(fields[i], original.fields[i]) {
				t.Fatalf("the verifier accepted an edited original whose field %d differs (script %x)", i+1, script)
			}
		}
	})
}
