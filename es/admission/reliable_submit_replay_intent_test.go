package admission

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func privateReplayJSON(t *testing.T, extraOuter string, extraInvocation string) []byte {
	t.Helper()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	return []byte(fmt.Sprintf(`{"schema_version":%q,"reliable_submit":{"contract":%q,"submit_key":%q},"invocation":{"artifact_digest":"sha256:a","derivation_spec_digest":"sha256:b","output_id":"o"%s}%s}`,
		reliableSubmitRequestSchemaV1, reliableSubmitContractV1, key, extraInvocation, extraOuter))
}

func privateReplayCaller(t *testing.T) syntheticCallerFact {
	t.Helper()
	caller, err := newSyntheticCallerFact("spiffe://synthetic.test/ns/one")
	if err != nil {
		t.Fatal(err)
	}
	return caller
}

func TestPrivateReplayStrictUnicodeDuplicateAndBounds(t *testing.T) {
	caller := privateReplayCaller(t)
	good := privateReplayJSON(t, ``, `,"env":{"é":"one","e\u0301":"two"}`)
	if _, err := parsePrivateReplayDelivery(good, caller); err != nil {
		t.Fatalf("distinct UTF-8 map keys: %v", err)
	}
	for name, raw := range map[string][]byte{
		"decoded duplicate":     privateReplayJSON(t, `,"schema_\u0076ersion":"v1"`, ``),
		"map decoded duplicate": privateReplayJSON(t, ``, `,"env":{"a":"one","\u0061":"two"}`),
		"unpaired high":         privateReplayJSON(t, ``, `,"env":{"a":"\uD800"}`),
		"unpaired low":          privateReplayJSON(t, ``, `,"env":{"a":"\uDC00"}`),
		"case alias":            privateReplayJSON(t, `,"Schema_Version":"v1"`, ``),
		"null":                  privateReplayJSON(t, `,"mode":null`, ``),
		"exponent":              privateReplayJSON(t, `,"timeout_seconds":1e2`, ``),
		"overflow":              privateReplayJSON(t, `,"timeout_seconds":2147483648`, ``),
		"negative zero":         privateReplayJSON(t, `,"timeout_seconds":-0`, ``),
		"leading zero":          privateReplayJSON(t, `,"timeout_seconds":01`, ``),
		"trailing":              append(privateReplayJSON(t, ``, ``), []byte(" true")...),
		"oversized":             bytes.Repeat([]byte{' '}, 262145),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePrivateReplayDelivery(raw, caller); err == nil {
				t.Fatal("invalid private JSON accepted")
			}
		})
	}
	invalidUTF8 := append(privateReplayJSON(t, ``, ``), 0xff)
	if _, err := parsePrivateReplayDelivery(invalidUTF8, caller); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestPrivateReplayIntentPresenceAndCanonicalOrder(t *testing.T) {
	caller := privateReplayCaller(t)
	first, err := parsePrivateReplayDelivery(privateReplayJSON(t, ``, `,"env":{"b":"2","a":"1"},"argv":[],"annotations":{"execution_substrate.runtime_profile":"  x  "}`), caller)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsePrivateReplayDelivery(privateReplayJSON(t, ``, `,"annotations":{"execution_substrate.runtime_profile":"x"},"argv":[],"env":{"a":"1","b":"2"}`), caller)
	if err != nil {
		t.Fatal(err)
	}
	e1, e2 := privateReplayEncoder{}, privateReplayEncoder{}
	one, two := e1.original(first.originalIntent), e2.original(second.originalIntent)
	if e1.err != nil || e2.err != nil || !bytes.Equal(one, two) {
		t.Fatal("canonical map order or source-owned profile trim drift")
	}
	sparse, err := parsePrivateReplayDelivery(privateReplayJSON(t, ``, ``), caller)
	if err != nil {
		t.Fatal(err)
	}
	withEmpty, err := parsePrivateReplayDelivery(privateReplayJSON(t, `,"mode":"","timeout_seconds":0`, `,"argv":[],"env":{},"annotations":{}`), caller)
	if err != nil {
		t.Fatal(err)
	}
	e3, e4 := privateReplayEncoder{}, privateReplayEncoder{}
	if bytes.Equal(e3.original(sparse.originalIntent), e4.original(withEmpty.originalIntent)) {
		t.Fatal("presence collapsed")
	}
	mountAbsent, err := parsePrivateReplayDelivery(privateReplayJSON(t, ``, `,"mounts":[{"source":{"artifact_digest":"a"},"target_path":"/execution/mounts/m"}]`), caller)
	if err != nil {
		t.Fatal(err)
	}
	mountFalse, err := parsePrivateReplayDelivery(privateReplayJSON(t, ``, `,"mounts":[{"source":{"artifact_digest":"a"},"target_path":"/execution/mounts/m","read_only":false}]`), caller)
	if err != nil {
		t.Fatal(err)
	}
	e5, e6 := privateReplayEncoder{}, privateReplayEncoder{}
	if bytes.Equal(e5.original(mountAbsent.originalIntent), e6.original(mountFalse.originalIntent)) {
		t.Fatal("nested mount presence collapsed")
	}
	if strings.Contains(fmt.Sprintf("%v", first), "sha256:a") {
		t.Fatal("delivery formatting leaked private intent")
	}
}
