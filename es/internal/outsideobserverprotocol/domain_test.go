package outsideobserverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestJournalSegmentIndependentVectorAndCore(t *testing.T) {
	nonce := "00000000000000000000000000000000"
	got, err := ComputeJournalSegmentID("stage-a", "source-1", 1, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const want = "3886338b508b748721cc033ca14cce2e07258c42265c10003357c99f72dc80fe"
	if got != want {
		t.Fatalf("segment=%s want=%s", got, want)
	}
	core := `{"endpoint_nonce":"00000000000000000000000000000000","epoch":1,"run_id":"stage-a","source_instance_id":"source-1"}`
	independent := sha256.Sum256(append([]byte("R6J-OBS-JOURNAL-SEGMENT/v1\x00"), []byte(core)...))
	if got != hex.EncodeToString(independent[:]) {
		t.Fatal("independent domain digest mismatch")
	}
	variants := []struct {
		run, source string
		epoch       int64
		nonce       string
	}{
		{"stage-b", "source-1", 1, nonce}, {"stage-a", "source-2", 1, nonce},
		{"stage-a", "source-1", 2, nonce}, {"stage-a", "source-1", 1, "10000000000000000000000000000000"},
	}
	for i, v := range variants {
		x, err := ComputeJournalSegmentID(v.run, v.source, v.epoch, v.nonce)
		if err != nil || x == got {
			t.Fatalf("core variant %d did not change digest: %s %v", i, x, err)
		}
	}
	// Non-core journal and receiver-session nonces are not arguments. A wider
	// journal identity has a different domain and canonical two-field core.
	widerCore := `{"journal_nonce":"11111111111111111111111111111111","session_binding_sha256":"` +
		"2222222222222222222222222222222222222222222222222222222222222222" + `"}`
	wider := sha256.Sum256(append([]byte("R6J-JOURNAL-IDENTITY/v2\x00"), []byte(widerCore)...))
	if got == hex.EncodeToString(wider[:]) {
		t.Fatal("segment aliased wider journal identity")
	}
	for _, bad := range []struct {
		run, source string
		epoch       int64
		nonce       string
	}{
		{"", "source-1", 1, nonce}, {"stage-a", "SOURCE-1", 1, nonce},
		{"stage-a", "source-1", 0, nonce}, {"stage-a", "source-1", 1, "ABC"},
	} {
		if _, err := ComputeJournalSegmentID(bad.run, bad.source, bad.epoch, bad.nonce); err == nil {
			t.Fatal("bad core accepted")
		}
	}
}
