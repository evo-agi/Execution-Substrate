package admission

// Report 28-redteam.md, RT28-2: a request whose job is too large to send must
// be refused before it takes a claim and a reservation.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// operationalArgvVariant is the fixture's request with argv set to one
// argument of n copies of c, under the submit key made of key. It is encoded
// without Go's HTML escaping, so that '<' takes one byte of the request as it
// may: the request bound is not the subject here.
func operationalArgvVariant(t *testing.T, f *operationalFixture, c string, n int, key byte) []byte {
	t.Helper()
	var outer map[string]any
	if err := json.Unmarshal(f.raw, &outer); err != nil {
		t.Fatal(err)
	}
	outer["invocation"].(map[string]any)["argv"] = []any{strings.Repeat(c, n)}
	outer["reliable_submit"].(map[string]any)["submit_key"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{key}, 32))
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(outer); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(raw.Bytes(), []byte("\n"))
}

// operationalFits composes raw as the handoff does before establishment and
// asks the provider whether its job fits. It stores nothing.
func operationalFits(t *testing.T, f *operationalFixture, raw []byte) bool {
	t.Helper()
	caller, err := newSyntheticCallerFact(f.domain.caller.String())
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.service.composeOperationalOriginal(context.Background(), delivery, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatal(err)
	}
	return f.domain.provider.fits(original.resolved)
}

// operationalLargestArgvThatFits bisects the largest number of copies of c,
// below high, that fit as one argument in f's job. The job holds paths under
// the fixture's temporary directories, whose names carry the test's name and a
// random number of digits, so a bound holds only for the fixture it was
// measured on.
func operationalLargestArgvThatFits(t *testing.T, f *operationalFixture, c string, high int) int {
	t.Helper()
	low := 1
	if !operationalFits(t, f, operationalArgvVariant(t, f, c, low, 0x41)) || operationalFits(t, f, operationalArgvVariant(t, f, c, high, 0x41)) {
		t.Fatalf("the bound is not between %d and %d copies of %q", low, high, c)
	}
	for high-low > 1 {
		mid := (low + high) / 2
		if operationalFits(t, f, operationalArgvVariant(t, f, c, mid, 0x41)) {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

// The largest single argument that fits, for a character that Go's
// encoding/json writes in one byte, one that it writes as a six-byte escape
// while the canonical encoding writes one byte, and one that both write in six.
// At that size the request completes with one POST, including the read of the
// job Nomad echoes; one byte more is refused as malformed before anything is
// stored. So the check before establishment and the projection after the run
// is assigned agree at the bound, and the bound is measured on encoding/json's
// form.
func TestOperationalJobBoundIsCheckedBeforeTheClaimAndAgreesWithTheProjection(t *testing.T) {
	ctx := context.Background()
	// high is above the bound and within the request's own bounds: a control
	// byte takes six bytes of the request too.
	chars := []struct {
		name, char string
		high       int
	}{{"plain", "a", 65536}, {"html", "<", 65536}, {"control", "\x01", 40000}}
	// encoding/json writes '<' and a control byte in six bytes each, so the
	// same number of each fits, and fewer than a fifth of the plain number.
	// The three bounds are measured on one fixture, so that its paths are the
	// same for each (audit 30, A30-1).
	shared := makeOperationalFixture(t, "", "alpha")
	largest := map[string]int{}
	for _, c := range chars {
		largest[c.name] = operationalLargestArgvThatFits(t, shared, c.char, c.high)
	}
	if largest["html"] != largest["control"] || largest["html"]*5 > largest["plain"] {
		t.Fatalf("largest arguments that fit: %v", largest)
	}
	for _, c := range chars {
		t.Run(c.name, func(t *testing.T) {
			f := makeOperationalFixture(t, "", "alpha")
			low := operationalLargestArgvThatFits(t, f, c.char, c.high)
			f.raw = operationalArgvVariant(t, f, c.char, low, 0x41)
			assertOperationalCompleted(t, f, f.submit(), "the largest argument that fits")
			before := operationalPrestageStateAt(t, f)
			out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, operationalArgvVariant(t, f, c.char, low+1, 0x42))
			after := operationalPrestageStateAt(t, f)
			if out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalMalformed || out.operation != 0 ||
				after.Claims != before.Claims || after.Grants != before.Grants || after.Posts != before.Posts || after.Revision != before.Revision {
				t.Fatalf("one byte more than fits: %s before=%+v after=%+v", operationalResultText(out), before, after)
			}
		})
	}
}

// Four requests too large for a job no longer fill the domain: none of them
// takes a claim, and an ordinary request after them completes.
func TestOperationalRequestsTooLargeForAJobLeaveTheDomainOpen(t *testing.T) {
	f := makeOperationalFixture(t, "", "alpha")
	ordinary := f.raw
	for key := byte(0x51); key < 0x55; key++ {
		out := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, operationalArgvVariant(t, f, "a", 65536, key))
		if state := operationalPrestageStateAt(t, f); out.reason != reliablesubmit.OperationalMalformed || state.Claims != 0 || state.Grants != 0 {
			t.Fatalf("request too large for a job: %s state=%+v", operationalResultText(out), state)
		}
	}
	f.raw = ordinary
	assertOperationalCompleted(t, f, f.submit(), "an ordinary request after four that are too large")
}
