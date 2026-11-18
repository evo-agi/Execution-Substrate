package reliablesubmit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func readPublicReplayLiteral(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	value, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestReplayCustodyFormatV1LiteralGolden(t *testing.T) {
	got, err := encodeReplayField(replayField{id: 1, state: 1, value: []byte("abc")})
	if err != nil {
		t.Fatalf("encode field: %v", err)
	}
	want := []byte{0, 1, 1, 0, 0, 0, 3, 'a', 'b', 'c'}
	if !bytes.Equal(got, want) {
		t.Fatalf("field bytes = %x, want %x", got, want)
	}
	absent, err := encodeReplayField(replayField{id: 2, state: 0})
	if err != nil {
		t.Fatalf("encode absent: %v", err)
	}
	if !bytes.Equal(absent, []byte{0, 2, 0, 0, 0, 0, 0}) {
		t.Fatalf("absent bytes = %x", absent)
	}
	if _, err := encodeReplayField(replayField{id: 2, state: 0, value: []byte{1}}); err == nil {
		t.Fatal("absent field accepted a value")
	}
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 17)
	payload := fixtureReplayPayload(t, record, keys)
	if literal := readPublicReplayLiteral(t, "replay_payload_v1.hex"); !bytes.Equal(payload, literal) {
		t.Fatal("full payload differs from independently calculated literal")
	}
	if _, err := parsePrivateReplayPayload(payload); err != nil {
		t.Fatal("literal payload framing failed")
	}
}

func TestReplayCustodyNestedFormatLiteralGolden(t *testing.T) {
	caller := bytes.Repeat([]byte{0x11}, 32)
	key := bytes.Repeat([]byte{0x22}, 32)
	identity, err := encodeReplayObject([]replayField{
		{id: 1, state: 1, value: caller},
		{id: 2, state: 1, value: key},
	})
	if err != nil {
		t.Fatalf("identity object: %v", err)
	}
	if len(identity) != 80 || !bytes.Equal(identity[:9], []byte{0, 2, 0, 1, 1, 0, 0, 0, 32}) {
		t.Fatalf("identity grammar mismatch: len=%d prefix=%x", len(identity), identity[:9])
	}
	if !bytes.Equal(identity[9:41], caller) || !bytes.Equal(identity[48:80], key) {
		t.Fatal("identity byte leaves mismatch")
	}
	if _, err := encodeReplayObject([]replayField{
		{id: 2, state: 1, value: key},
		{id: 1, state: 1, value: caller},
	}); err == nil {
		t.Fatal("out-of-order IDs accepted")
	}
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 17)
	payload := readPublicReplayLiteral(t, "replay_payload_v1.hex")
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, payload)
	if err != nil {
		t.Fatal(err)
	}
	var objectID [32]byte
	for i := range objectID {
		objectID[i] = 0x33
	}
	header, err := encodePrivateReplayHeader(record.claim, record.plan, keys, objectID, frozen.intentMAC, frozen.contextMAC, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if literal := readPublicReplayLiteral(t, "replay_header_v1.hex"); !bytes.Equal(header, literal) {
		t.Fatal("full header differs from independently calculated literal")
	}
	aad := append([]byte("ESRSAAD1"), header...)
	if literal := readPublicReplayLiteral(t, "replay_aad_v1.hex"); !bytes.Equal(aad, literal) {
		t.Fatal("full AAD differs from independently calculated literal")
	}
}

func TestReplayCustodyMountAuthorityFraming(t *testing.T) {
	mount, err := encodeReplayObject([]replayField{
		{id: 1, state: 1, value: []byte("a")},
		{id: 2, state: 1, value: []byte("b")},
		{id: 3, state: 1, value: []byte("c")},
		{id: 4, state: 1, value: []byte("/m")},
		{id: 5, state: 1, value: []byte{1}},
	})
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if len(mount) != 43 {
		t.Fatalf("mount len = %d, want 43", len(mount))
	}
	sequence := make([]byte, 6+len(mount))
	binary.BigEndian.PutUint16(sequence[:2], 1)
	binary.BigEndian.PutUint32(sequence[2:6], uint32(len(mount)))
	copy(sequence[6:], mount)
	outer, err := encodeReplayField(replayField{id: 9, state: 1, value: sequence})
	if err != nil {
		t.Fatalf("mount field: %v", err)
	}
	if len(sequence) != 49 || len(outer) != 56 ||
		!bytes.Equal(outer[:7], []byte{0, 9, 1, 0, 0, 0, 49}) {
		t.Fatalf("mount framing len=%d field=%x", len(outer), outer[:7])
	}
	authorityLeaves := [][]byte{
		[]byte("p"), {1}, []byte("/c"), []byte("v"), []byte("/s"),
		[]byte("f"), []byte("m"), []byte("u"), []byte("a"),
		[]byte("r"), []byte("j"), []byte("z"), {1}, {0},
	}
	fields := make([]replayField, len(authorityLeaves))
	for i, value := range authorityLeaves {
		fields[i] = replayField{id: uint16(i + 1), state: 1, value: value}
	}
	authority, err := encodeReplayObject(fields)
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	if len(authority) != 116 || !bytes.Equal(authority[:2], []byte{0, 14}) {
		t.Fatalf("authority framing len=%d", len(authority))
	}
}
