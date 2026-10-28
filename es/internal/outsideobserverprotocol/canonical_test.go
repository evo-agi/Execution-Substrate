package outsideobserverprotocol

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCanonicalV2ExactAcceptedBytes(t *testing.T) {
	valid := []string{
		`{}`, `[]`, `null`, `true`, `false`, `0`, `-1`, `9007199254740993`,
		`9223372036854775808`, `"-0"`, `"1.0"`, `"1e2"`, `"\\u0061"`,
		`{"a":1,"b":2}`, `"<>&  "`, `"é"`, `"\b\t\n\f\r\u0000\u001f"`,
	}
	for _, raw := range valid {
		t.Run(raw, func(t *testing.T) {
			v, err := parseCanonicalV2([]byte(raw))
			if err != nil {
				t.Fatalf("valid canonical bytes refused: %v", err)
			}
			got, err := encodeCanonicalV2(v)
			if err != nil || !bytes.Equal(got, []byte(raw)) {
				t.Fatalf("round trip = %q, %v", got, err)
			}
		})
	}
	encoded, err := encodeCanonicalV2(map[string]any{"z": "<>&  ", "a": "\x00\b\t\n\f\r"})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":\"\\u0000\\b\\t\\n\\f\\r\",\"z\":\"<>&  \"}"
	if string(encoded) != want {
		t.Fatalf("encoder output %q != %q", encoded, want)
	}
}

func TestCanonicalV2Refusals(t *testing.T) {
	bad := [][]byte{
		{}, []byte(" "), []byte("{} "), []byte(" {}"), []byte("{}{}"),
		[]byte("\xef\xbb\xbf{}"), []byte{0xff}, []byte(`{"a":1,"a":2}`),
		[]byte(`{"b":1,"a":2}`), []byte(`{"a":1,"\u0061":2}`),
		[]byte(`-0`), []byte(`01`), []byte(`+1`), []byte(`1.0`),
		[]byte(`1e2`), []byte(`NaN`), []byte(`Infinity`),
		[]byte(`"\/"`), []byte(`"\u0041"`), []byte(`"\u00AF"`),
		[]byte(`"\ud800"`), []byte(`"\q"`), []byte(`"`),
		[]byte("²"), []byte("٢"), []byte("２"), []byte("-٢"),
		[]byte(strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129)),
		bytes.Repeat([]byte("x"), maxCanonicalBytes+1),
	}
	for i, raw := range bad {
		if _, err := parseCanonicalV2(raw); err == nil {
			t.Fatalf("bad case %d accepted", i)
		}
	}
}

func TestCanonicalV2AllByteStringsUpToTwo(t *testing.T) {
	// The independent oracle is the complete grammar possible at these lengths.
	count := 0
	for n := 0; n <= 2; n++ {
		limit := 1
		for i := 0; i < n; i++ {
			limit *= 256
		}
		for v := 0; v < limit; v++ {
			raw := make([]byte, n)
			for i, x := 0, v; i < n; i++ {
				raw[i] = byte(x)
				x >>= 8
			}
			want := false
			if n == 1 {
				want = raw[0] >= '0' && raw[0] <= '9'
			}
			if n == 2 {
				want = string(raw) == "{}" || string(raw) == "[]" || string(raw) == `""` ||
					(raw[0] == '-' && raw[1] >= '1' && raw[1] <= '9') ||
					(raw[0] >= '1' && raw[0] <= '9' && raw[1] >= '0' && raw[1] <= '9')
			}
			_, err := parseCanonicalV2(raw)
			if (err == nil) != want {
				t.Fatalf("length %d bytes %x acceptance=%v want=%v", n, raw, err == nil, want)
			}
			count++
		}
	}
	if count != 65793 {
		t.Fatalf("count=%d", count)
	}
}

func TestCanonicalV2DeterministicMalformedBytes(t *testing.T) {
	// This retained corpus specifically exercises the strict UTF-8 precheck.
	// The separate valid-UTF-8 corpus below reaches recursive grammar parsing.
	rng := rand.New(rand.NewSource(92820261027))
	for i := 0; i < 256; i++ {
		raw := []byte(`{"a":1}`)
		raw[rng.Intn(len(raw))] = byte(rng.Intn(256))
		raw = append(raw, 0xff)
		if _, err := parseCanonicalV2(raw); err == nil {
			t.Fatalf("malformed candidate %d accepted", i)
		}
	}
}

func TestCanonicalV2DeterministicValidUTF8MalformedGrammar(t *testing.T) {
	// Each bad/good pair is an independent literal grammar oracle. Every bad
	// value is valid UTF-8 and below the byte cap, so refusal cannot come from
	// either input precheck. The fixed-seed nested replay exercises the same
	// known-invalid forms at additional recursive positions.
	pairs := []struct{ name, bad, good string }{
		{"missing-colon", `{"a" 1}`, `{"a":1}`},
		{"trailing-object-comma", `{"a":1,}`, `{"a":1}`},
		{"missing-array-comma", `[1 2]`, `[1,2]`},
		{"trailing-array-comma", `[1,]`, `[1]`},
		{"wrong-delimiter", `{"a":[1}}`, `{"a":[1]}`},
		{"nested-array", `{"a":[{"b":1},]}`, `{"a":[{"b":1}]}`},
		{"nested-object", `{"a":{"b":1,}}`, `{"a":{"b":1}}`},
		{"bad-escape", `"\q"`, `"\\q"`},
		{"escaped-solidus", `"\/"`, `"/"`},
		{"nonshort-control", `"\u000a"`, `"\n"`},
		{"uppercase-control-hex", `"\u001F"`, `"\u001f"`},
		{"printable-unicode-escape", `"\u0041"`, `"A"`},
		{"literal-control", "\"a\nb\"", `"a\nb"`},
		{"leading-zero", `01`, `1`},
		{"negative-zero", `-0`, `0`},
		{"fraction", `1.0`, `"1.0"`},
		{"exponent", `1e2`, `"1e2"`},
		{"non-ascii-post-minus", `-٢`, `-2`},
		{"key-order", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"duplicate-key", `{"a":1,"a":2}`, `{"a":1,"b":2}`},
		{"escaped-key-collision", `{"a":1,"\u0061":2}`, `{"a":1,"b":2}`},
		{"trailing-space", `[] `, `[]`},
		{"trailing-value", `[][]`, `[]`},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			if !utf8.ValidString(pair.bad) || !utf8.ValidString(pair.good) {
				t.Fatal("fixture is not valid UTF-8")
			}
			if _, err := parseCanonicalV2([]byte(pair.bad)); err == nil {
				t.Fatalf("known malformed grammar accepted: %q", pair.bad)
			}
			if _, err := parseCanonicalV2([]byte(pair.good)); err != nil {
				t.Fatalf("valid neighboring grammar refused: %q: %v", pair.good, err)
			}
		})
	}
	rng := rand.New(rand.NewSource(92820261027))
	for i := 0; i < 256; i++ {
		raw := pairs[rng.Intn(len(pairs))].bad
		if i%2 == 0 {
			raw = "[" + raw + "]"
		}
		if !utf8.ValidString(raw) {
			t.Fatalf("valid-UTF-8 corpus case %d was invalid UTF-8", i)
		}
		if _, err := parseCanonicalV2([]byte(raw)); err == nil {
			t.Fatalf("valid-UTF-8 malformed corpus case %d accepted: %q", i, raw)
		}
	}
}

func TestCanonicalV2DepthAndByteBoundNeighbors(t *testing.T) {
	// A scalar at depth 128 is permitted; the same scalar at depth 129 is not.
	for _, tc := range []struct {
		depth int
		want  bool
	}{{128, true}, {129, false}} {
		raw := strings.Repeat("[", tc.depth) + "0" + strings.Repeat("]", tc.depth)
		_, err := parseCanonicalV2([]byte(raw))
		if (err == nil) != tc.want {
			t.Fatalf("depth %d accepted=%t want=%t: %v", tc.depth, err == nil, tc.want, err)
		}
	}
	// Both inputs are otherwise canonical JSON strings; the only difference
	// is the exact selected byte limit, including the two quote bytes.
	atLimit := []byte("\"" + strings.Repeat("a", 4_194_304-2) + "\"")
	overLimit := []byte("\"" + strings.Repeat("a", 4_194_304-1) + "\"")
	if len(atLimit) != 4_194_304 || len(overLimit) != 4_194_305 {
		t.Fatal("canonical byte-limit fixtures have wrong lengths")
	}
	if _, err := parseCanonicalV2(atLimit); err != nil {
		t.Fatalf("canonical input at byte limit refused: %v", err)
	}
	if _, err := parseCanonicalV2(overLimit); err == nil {
		t.Fatal("canonical input just over byte limit accepted")
	}
}
