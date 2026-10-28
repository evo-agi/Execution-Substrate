package outsideobserverprotocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const testZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
const testOneHash = "1111111111111111111111111111111111111111111111111111111111111111"
const testNonce = "00000000000000000000000000000000"

func testJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v) // Independent standard-library fixture encoder; values are ASCII.
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testDomain(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func testPayload(kind string) map[string]any {
	switch kind {
	case "SupervisorStartedV1":
		return map[string]any{"schema": kind, "parent_pid": 1, "pid": 2, "process_group_id": 2,
			"proc_start_token": "42", "pid_namespace_device": 1, "pid_namespace_inode": 2,
			"mount_namespace_device": 3, "mount_namespace_inode": 4,
			"executable_sha256": testOneHash, "pidfd_bound": true,
			"execution_authority_digest": testOneHash}
	case "SupervisorExitObservedV1":
		return map[string]any{"schema": kind, "pid": 2, "proc_start_token": "42",
			"wait_code_kind": "exited", "exit_code": 0, "signal": nil, "core_dumped": false,
			"observed_by_pid": 1, "identity_match": true}
	case "SupervisorReapedV1":
		return map[string]any{"schema": kind, "pid": 2, "proc_start_token": "42",
			"pidfd_bound": true, "reap_count": 1, "wait_owner_pid": 1,
			"terminal_status_sha256": testOneHash}
	case "NamespaceDrainedV1":
		return map[string]any{"schema": kind, "supervisor_pid": 2, "term_signal_count": 0,
			"kill_signal_count": 0, "reaped_descendant_count": 0,
			"remaining_pids": []any{}, "waitid_all_result": "ECHILD"}
	case "SourceCompleteV1":
		return map[string]any{"schema": kind, "result_kind": "success",
			"supervisor_terminal_status_sha256": testOneHash, "supervisor_reaped_once": true,
			"namespace_drained": true, "last_nonfinal_record_hash": testZeroHash,
			"evidence_failure": false, "terminal_reason": "done"}
	}
	panic("unknown test payload")
}

func testFrame(t *testing.T, kind string) map[string]any {
	t.Helper()
	payload := testJSON(t, testPayload(kind))
	f := map[string]any{"schema": "EvidenceFrameV1", "version": 1, "run_id": "stage-a",
		"entry_digest": testOneHash, "permit_digest": testOneHash,
		"source_instance_id": "source-1", "epoch": 1, "sequence": 1,
		"producer_role": "es/outsideobserver", "qualified_clock_ref": "clock-1",
		"observed_time": 0, "previous_record_hash": testZeroHash,
		"payload_type": kind, "payload_length": len(payload),
		"payload_sha256": testDomain("R6J-OBS-PAYLOAD/v1", payload),
		"payload":        base64.RawURLEncoding.EncodeToString(payload)}
	f["record_hash"] = testDomain("R6J-OBS-RECORD/v1", testJSON(t, f))
	return f
}

func testAck() map[string]any {
	return map[string]any{"schema": "AckV1", "version": 1, "run_id": "stage-a",
		"source_instance_id": "source-1", "epoch": 1, "sequence": 1,
		"record_hash": testOneHash, "journal_segment_id": testOneHash,
		"durable_offset": 1, "source_state": "OPEN", "commit_id": testOneHash}
}

func testHeader(t *testing.T) map[string]any {
	t.Helper()
	core := map[string]any{"endpoint_nonce": testNonce, "entry_digest": testOneHash,
		"epoch": 1, "observer_session_nonce": testNonce,
		"observer_spiffe_id":                observerSPIFFEID,
		"permit_consumption_receipt_sha256": testOneHash, "permit_digest": testOneHash,
		"receiver_session_nonce": testNonce, "receiver_spiffe_id": receiverSPIFFEID,
		"run_id": "stage-a", "source_instance_id": "source-1"}
	session := testDomain("R6J-SESSION-BINDING/v2", testJSON(t, core))
	wider := testDomain("R6J-JOURNAL-IDENTITY/v2", testJSON(t,
		map[string]any{"journal_nonce": testNonce, "session_binding_sha256": session}))
	core["journal_nonce"] = testNonce
	core["session_binding_sha256"] = session
	core["journal_identity_sha256"] = wider
	core["schema"] = "JournalHeaderV2"
	core["version"] = 2
	return core
}

func testJournalFrame(t *testing.T) map[string]any {
	t.Helper()
	f := testFrame(t, "SupervisorStartedV1")
	raw := testJSON(t, f)
	return map[string]any{"schema": "JournalFrameV2", "version": 2,
		"evidence_record_hash": f["record_hash"], "exact_frame_bytes_b64url": base64.RawURLEncoding.EncodeToString(raw),
		"frame_length": len(raw), "frame_sha256": testDomain("R6J-JOURNAL-FRAME/v2", raw),
		"journal_identity_sha256": testOneHash, "payload_type": f["payload_type"],
		"session_binding_sha256": testOneHash, "source_sequence": 1,
		"transaction_kind": "EVIDENCE", "transaction_sequence": 1}
}

func testCommit(t *testing.T) map[string]any {
	t.Helper()
	c := map[string]any{"schema": "JournalCommitV2", "version": 2,
		"durable_offset_after_commit": 100, "evidence_record_hash": testOneHash,
		"frame_record_sha256": testOneHash, "journal_identity_sha256": testOneHash,
		"next_source_state": "OPEN", "previous_commit_hash": testZeroHash,
		"session_binding_sha256": testOneHash, "source_sequence": 1,
		"transaction_kind": "EVIDENCE", "transaction_payload_sha256": testOneHash,
		"transaction_sequence": 1}
	hash := testDomain("R6J-JOURNAL-COMMIT-HASH/v2", testJSON(t, c))
	decoded, _ := hex.DecodeString(hash)
	c["commit_hash"] = hash
	c["commit_id"] = testDomain("R6J-JOURNAL-COMMIT-ID/v2", decoded)
	return c
}

func testLimits() map[string]any {
	return map[string]any{"evidence_frame_max_bytes": 2162688,
		"evidence_payload_max_bytes": 2097152, "max_frames_per_session": 65536,
		"max_frames_per_source": 16384, "max_sources": 64,
		"per_source_aggregate_max_bytes": 16777216, "session_aggregate_max_bytes": 67108864}
}

func testObserverHello() map[string]any {
	return map[string]any{"schema": "ObserverHelloV1", "version": 1,
		"run_id": "stage-a", "entry_digest": testOneHash, "permit_digest": testOneHash,
		"permit_nonce": testNonce, "source_instance_id": "source-1", "epoch": 1,
		"observer_session_nonce": testNonce, "endpoint_nonce": testNonce,
		"observer_spiffe_id": observerSPIFFEID, "expected_receiver_spiffe_id": receiverSPIFFEID,
		"requested_limits": testLimits()}
}

func testReceiverHello() map[string]any {
	return map[string]any{"schema": "ReceiverHelloV1", "version": 1,
		"run_id": "stage-a", "entry_digest": testOneHash,
		"receiver_session_nonce": testNonce, "endpoint_nonce": testNonce,
		"receiver_spiffe_id": receiverSPIFFEID, "expected_observer_spiffe_id": observerSPIFFEID,
		"accepted_limits": testLimits()}
}

func TestEvidenceFrameSeventeenFieldsAndHashPreimage(t *testing.T) {
	f := testFrame(t, "SupervisorStartedV1")
	if len(f) != 17 {
		t.Fatalf("complete field count=%d", len(f))
	}
	got, err := ParseEvidenceFrameV1(testJSON(t, f))
	if err != nil || got.RecordHash != f["record_hash"] {
		t.Fatalf("complete frame refused: %v", err)
	}
	core := make(map[string]any, len(f)-1)
	for k, v := range f {
		if k != "record_hash" {
			core[k] = v
		}
	}
	if len(core) != 16 {
		t.Fatal("preimage not 16 fields")
	}
	if f["record_hash"] != testDomain("R6J-OBS-RECORD/v1", testJSON(t, core)) {
		t.Fatal("independent preimage mismatch")
	}
	if f["record_hash"] == testDomain("R6J-OBS-RECORD/v1", testJSON(t, f)) {
		t.Fatal("full frame used as preimage")
	}
	for key := range f {
		broken := make(map[string]any, len(f))
		for k, v := range f {
			if k != key {
				broken[k] = v
			}
		}
		if _, err := ParseEvidenceFrameV1(testJSON(t, broken)); err == nil {
			t.Fatalf("missing %s accepted", key)
		}
		typed := testFrame(t, "SupervisorStartedV1")
		typed[key] = []any{}
		if _, err := ParseEvidenceFrameV1(testJSON(t, typed)); err == nil {
			t.Errorf("wrong JSON kind for %s accepted", key)
		}
	}
	f["unknown"] = true
	if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
		t.Fatal("extra field accepted")
	}
}

func TestEverySelectedShapeClosedAndTyped(t *testing.T) {
	shapes := []struct {
		name   string
		object func(*testing.T) map[string]any
		parse  func([]byte) error
		ints   []string
	}{
		{"AckV1", func(*testing.T) map[string]any { return testAck() }, func(b []byte) error { _, e := ParseAckV1(b); return e }, []string{"version", "epoch", "sequence", "durable_offset"}},
		{"JournalHeaderV2", testHeader, func(b []byte) error { _, e := ParseJournalHeaderV2(b); return e }, []string{"version", "epoch"}},
		{"JournalFrameV2", testJournalFrame, func(b []byte) error { _, e := ParseJournalFrameV2(b); return e }, []string{"version", "frame_length", "source_sequence", "transaction_sequence"}},
		{"JournalCommitV2", testCommit, func(b []byte) error { _, e := ParseJournalCommitV2(b); return e }, []string{"version", "durable_offset_after_commit", "source_sequence", "transaction_sequence"}},
		{"ObserverHelloV1", func(*testing.T) map[string]any { return testObserverHello() }, func(b []byte) error { _, e := ParseObserverHelloV1(b); return e }, []string{"version", "epoch"}},
		{"ReceiverHelloV1", func(*testing.T) map[string]any { return testReceiverHello() }, func(b []byte) error { _, e := ParseReceiverHelloV1(b); return e }, []string{"version"}},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			obj := s.object(t)
			if err := s.parse(testJSON(t, obj)); err != nil {
				t.Fatalf("valid object refused: %v", err)
			}
			for key := range obj {
				copy := make(map[string]any, len(obj))
				for k, v := range obj {
					if k != key {
						copy[k] = v
					}
				}
				if err := s.parse(testJSON(t, copy)); err == nil {
					t.Errorf("missing %s accepted", key)
				}
				original := obj[key]
				obj[key] = []any{}
				if err := s.parse(testJSON(t, obj)); err == nil {
					t.Errorf("wrong JSON kind for %s accepted", key)
				}
				obj[key] = original
			}
			obj["unknown_field"] = "x"
			if err := s.parse(testJSON(t, obj)); err == nil {
				t.Error("extra field accepted")
			}
			delete(obj, "unknown_field")
			for _, key := range s.ints {
				orig := obj[key]
				obj[key] = true
				if err := s.parse(testJSON(t, obj)); err == nil {
					t.Errorf("boolean %s accepted", key)
				}
				obj[key] = orig
			}
		})
	}
}

func TestFiveEvidencePayloadsAndLocalRefusals(t *testing.T) {
	for _, kind := range []string{"SupervisorStartedV1", "SupervisorExitObservedV1", "SupervisorReapedV1", "NamespaceDrainedV1", "SourceCompleteV1"} {
		t.Run(kind, func(t *testing.T) {
			f := testFrame(t, kind)
			if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err != nil {
				t.Fatalf("valid payload refused: %v", err)
			}
			payload := testPayload(kind)
			for key := range payload {
				broken := make(map[string]any, len(payload))
				for k, v := range payload {
					if k != key {
						broken[k] = v
					}
				}
				setTestFramePayload(t, f, broken)
				if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
					t.Errorf("missing nested %s accepted", key)
				}
				typed := testPayload(kind)
				typed[key] = map[string]any{}
				setTestFramePayload(t, f, typed)
				if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
					t.Errorf("wrong nested JSON kind for %s accepted", key)
				}
			}
			payload["unknown"] = true
			setTestFramePayload(t, f, payload)
			if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
				t.Error("extra nested accepted")
			}
		})
	}
	wrongDispatch := testFrame(t, "SupervisorStartedV1")
	wrongDispatch["payload_type"] = "SupervisorReapedV1"
	delete(wrongDispatch, "record_hash")
	wrongDispatch["record_hash"] = testDomain("R6J-OBS-RECORD/v1", testJSON(t, wrongDispatch))
	if _, err := ParseEvidenceFrameV1(testJSON(t, wrongDispatch)); err == nil {
		t.Error("wrong selected payload dispatch accepted")
	}
	for _, tc := range []struct {
		kind, key string
		bad       any
	}{
		{"SupervisorStartedV1", "parent_pid", true}, {"SupervisorStartedV1", "pid", json.Number("4294967296")},
		{"SupervisorStartedV1", "process_group_id", 3}, {"SupervisorStartedV1", "pidfd_bound", false},
		{"SupervisorExitObservedV1", "signal", 2}, {"SupervisorExitObservedV1", "core_dumped", true},
		{"SupervisorExitObservedV1", "proc_start_token", "\x7f"},
		{"SupervisorReapedV1", "reap_count", true}, {"NamespaceDrainedV1", "remaining_pids", []int{2}},
		{"NamespaceDrainedV1", "term_signal_count", json.Number("9223372036854775808")},
		{"SourceCompleteV1", "evidence_failure", true}, {"SourceCompleteV1", "last_nonfinal_record_hash", testOneHash},
		{"SourceCompleteV1", "terminal_reason", "\x7f"},
	} {
		t.Run(tc.kind+"/"+tc.key, func(t *testing.T) {
			f := testFrame(t, tc.kind)
			p := testPayload(tc.kind)
			p[tc.key] = tc.bad
			setTestFramePayload(t, f, p)
			if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
				t.Fatal("contradictory payload accepted")
			}
		})
	}
}

func setTestFramePayload(t *testing.T, frame map[string]any, payload map[string]any) {
	t.Helper()
	raw := testJSON(t, payload)
	frame["payload"] = base64.RawURLEncoding.EncodeToString(raw)
	frame["payload_length"] = len(raw)
	frame["payload_sha256"] = testDomain("R6J-OBS-PAYLOAD/v1", raw)
	delete(frame, "record_hash")
	frame["record_hash"] = testDomain("R6J-OBS-RECORD/v1", testJSON(t, frame))
}

func TestLocalHashesBoundsAndBase64(t *testing.T) {
	f := testFrame(t, "SupervisorStartedV1")
	for _, key := range []string{"epoch", "sequence", "observed_time", "payload_length"} {
		orig := f[key]
		f[key] = true
		if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
			t.Errorf("boolean %s accepted", key)
		}
		f[key] = orig
	}
	for _, tc := range []struct {
		key string
		bad any
	}{
		{"epoch", json.Number("9223372036854775808")}, {"sequence", 16385},
		{"observed_time", json.Number("-9223372036854775809")}, {"payload_length", 2097153},
		{"payload", "Zh"}, {"payload", f["payload"].(string) + "="},
		{"payload_sha256", testZeroHash}, {"record_hash", testZeroHash},
	} {
		orig := f[tc.key]
		f[tc.key] = tc.bad
		if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err == nil {
			t.Errorf("bad %s accepted", tc.key)
		}
		f[tc.key] = orig
	}
	f["epoch"] = json.Number("9007199254740993")
	delete(f, "record_hash")
	f["record_hash"] = testDomain("R6J-OBS-RECORD/v1", testJSON(t, f))
	if _, err := ParseEvidenceFrameV1(testJSON(t, f)); err != nil {
		t.Fatalf("exact >2^53 token refused: %v", err)
	}
	a := testAck()
	for _, key := range []string{"epoch", "sequence", "durable_offset"} {
		orig := a[key]
		a[key] = json.Number("9223372036854775808")
		if _, err := ParseAckV1(testJSON(t, a)); err == nil {
			t.Errorf("overflow %s accepted", key)
		}
		a[key] = orig
	}
	a["sequence"] = 16385
	if _, err := ParseAckV1(testJSON(t, a)); err == nil {
		t.Error("Ack sequence overflow accepted")
	}
	h := testObserverHello()
	limits := h["requested_limits"].(map[string]any)
	limits["max_sources"] = true
	if _, err := ParseObserverHelloV1(testJSON(t, h)); err == nil {
		t.Error("boolean nested fixed limit accepted")
	}
	limits["max_sources"] = 64
	limits["unknown"] = 1
	if _, err := ParseObserverHelloV1(testJSON(t, h)); err == nil {
		t.Error("extra nested limit accepted")
	}
	if _, err := ParseEvidenceFrameV1([]byte(strings.Repeat("x", maxEvidenceFrameBytes+1))); err == nil {
		t.Error("oversize frame accepted")
	}
}

func TestJournalLocalSelfConsistencyDoesNotNeedHistory(t *testing.T) {
	h := testHeader(t)
	h["session_binding_sha256"] = testZeroHash
	if _, err := ParseJournalHeaderV2(testJSON(t, h)); err == nil {
		t.Error("wrong local session hash accepted")
	}
	j := testJournalFrame(t)
	j["frame_sha256"] = testZeroHash
	if _, err := ParseJournalFrameV2(testJSON(t, j)); err == nil {
		t.Error("wrong embedded frame hash accepted")
	}
	j = testJournalFrame(t)
	j["transaction_kind"] = "COMPLETE"
	if _, err := ParseJournalFrameV2(testJSON(t, j)); err == nil {
		t.Error("wrong local kind accepted")
	}
	c := testCommit(t)
	c["commit_id"] = testZeroHash
	if _, err := ParseJournalCommitV2(testJSON(t, c)); err == nil {
		t.Error("wrong split commit ID accepted")
	}
	c = testCommit(t)
	c["next_source_state"] = "COMPLETE"
	if _, err := ParseJournalCommitV2(testJSON(t, c)); err == nil {
		t.Error("wrong local state accepted")
	}
	for _, tc := range []struct {
		failure bool
		kind    string
	}{{false, "COMPLETE"}, {true, "ABORT"}} {
		frame := testFrame(t, "SourceCompleteV1")
		payload := testPayload("SourceCompleteV1")
		payload["result_kind"] = "supervisor_failure"
		payload["evidence_failure"] = tc.failure
		setTestFramePayload(t, frame, payload)
		raw := testJSON(t, frame)
		wrapper := testJournalFrame(t)
		wrapper["exact_frame_bytes_b64url"] = base64.RawURLEncoding.EncodeToString(raw)
		wrapper["frame_length"] = len(raw)
		wrapper["frame_sha256"] = testDomain("R6J-JOURNAL-FRAME/v2", raw)
		wrapper["evidence_record_hash"] = frame["record_hash"]
		wrapper["payload_type"] = "SourceCompleteV1"
		wrapper["transaction_kind"] = tc.kind
		if _, err := ParseJournalFrameV2(testJSON(t, wrapper)); err != nil {
			t.Errorf("non-success completion with evidence_failure=%t refused: %v", tc.failure, err)
		}
	}
}

const closeoutMaxI64 = int64(9_223_372_036_854_775_807)
const closeoutMinI64 = int64(-9_223_372_036_854_775_808)

func closeoutNumber(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func closeoutExpectField(t *testing.T, err error, field string) {
	t.Helper()
	want := "outside observer structural refusal: " + field
	if err == nil || err.Error() != want {
		t.Fatalf("want isolated %q refusal, got %v", field, err)
	}
}

// These fixture hashes use only encoding/json and crypto/sha256. They never
// call the production canonical encoder or hash-domain helper.
func closeoutRefreshRecordHash(t *testing.T, frame map[string]any) {
	t.Helper()
	core := make(map[string]any, len(frame)-1)
	for key, value := range frame {
		if key != "record_hash" {
			core[key] = value
		}
	}
	frame["record_hash"] = testDomain("R6J-OBS-RECORD/v1", testJSON(t, core))
}

func closeoutRefreshHeaderHashes(t *testing.T, header map[string]any) {
	t.Helper()
	core := map[string]any{}
	for _, key := range []string{"endpoint_nonce", "entry_digest", "epoch", "observer_session_nonce", "observer_spiffe_id", "permit_consumption_receipt_sha256", "permit_digest", "receiver_session_nonce", "receiver_spiffe_id", "run_id", "source_instance_id"} {
		core[key] = header[key]
	}
	session := testDomain("R6J-SESSION-BINDING/v2", testJSON(t, core))
	header["session_binding_sha256"] = session
	header["journal_identity_sha256"] = testDomain("R6J-JOURNAL-IDENTITY/v2", testJSON(t,
		map[string]any{"journal_nonce": header["journal_nonce"], "session_binding_sha256": session}))
}

func closeoutRefreshCommitHashes(t *testing.T, commit map[string]any) {
	t.Helper()
	core := make(map[string]any, len(commit)-2)
	for key, value := range commit {
		if key != "commit_hash" && key != "commit_id" {
			core[key] = value
		}
	}
	hash := testDomain("R6J-JOURNAL-COMMIT-HASH/v2", testJSON(t, core))
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	commit["commit_hash"] = hash
	commit["commit_id"] = testDomain("R6J-JOURNAL-COMMIT-ID/v2", decoded)
}

func closeoutShapeFixture(t *testing.T, shape string) map[string]any {
	t.Helper()
	switch shape {
	case "EvidenceFrameV1":
		return testFrame(t, "SupervisorStartedV1")
	case "AckV1":
		return testAck()
	case "JournalHeaderV2":
		return testHeader(t)
	case "JournalFrameV2":
		return testJournalFrame(t)
	case "JournalCommitV2":
		return testCommit(t)
	case "ObserverHelloV1":
		return testObserverHello()
	case "ReceiverHelloV1":
		return testReceiverHello()
	default:
		t.Fatalf("unknown closeout shape %q", shape)
		return nil
	}
}

func closeoutParseShape(shape string, raw []byte) error {
	switch shape {
	case "EvidenceFrameV1":
		_, err := ParseEvidenceFrameV1(raw)
		return err
	case "AckV1":
		_, err := ParseAckV1(raw)
		return err
	case "JournalHeaderV2":
		_, err := ParseJournalHeaderV2(raw)
		return err
	case "JournalFrameV2":
		_, err := ParseJournalFrameV2(raw)
		return err
	case "JournalCommitV2":
		_, err := ParseJournalCommitV2(raw)
		return err
	case "ObserverHelloV1":
		_, err := ParseObserverHelloV1(raw)
		return err
	case "ReceiverHelloV1":
		_, err := ParseReceiverHelloV1(raw)
		return err
	default:
		return structuralError("unknown test shape")
	}
}

func closeoutRefreshShapeHashes(t *testing.T, shape string, obj map[string]any) {
	t.Helper()
	switch shape {
	case "EvidenceFrameV1":
		closeoutRefreshRecordHash(t, obj)
	case "JournalHeaderV2":
		closeoutRefreshHeaderHashes(t, obj)
	case "JournalCommitV2":
		closeoutRefreshCommitHashes(t, obj)
	}
}

func closeoutSetJournalFrameSequence(t *testing.T, wrapper map[string]any, n int64) {
	t.Helper()
	frame := testFrame(t, "SupervisorStartedV1")
	frame["sequence"] = closeoutNumber(n)
	closeoutRefreshRecordHash(t, frame)
	raw := testJSON(t, frame)
	wrapper["source_sequence"] = closeoutNumber(n)
	wrapper["transaction_sequence"] = closeoutNumber(n)
	wrapper["exact_frame_bytes_b64url"] = base64.RawURLEncoding.EncodeToString(raw)
	wrapper["frame_length"] = len(raw)
	wrapper["frame_sha256"] = testDomain("R6J-JOURNAL-FRAME/v2", raw)
	wrapper["evidence_record_hash"] = frame["record_hash"]
}

func TestCloseoutSelectedTopLevelNumericKindAndBounds(t *testing.T) {
	// Independent selected-contract matrix: inclusive numeric ranges and fixed
	// numeric literals for all seven top-level schemas. Lengths have separate
	// decoded-byte relationships; their pure range neighbors are below.
	cases := []struct {
		shape, field  string
		min, max      int64
		lengthCoupled bool
	}{
		{"EvidenceFrameV1", "version", 1, 1, false},
		{"EvidenceFrameV1", "epoch", 1, closeoutMaxI64, false},
		{"EvidenceFrameV1", "sequence", 1, 16_384, false},
		{"EvidenceFrameV1", "observed_time", closeoutMinI64, closeoutMaxI64, false},
		{"EvidenceFrameV1", "payload_length", 0, 2_097_152, true},
		{"AckV1", "version", 1, 1, false},
		{"AckV1", "epoch", 1, closeoutMaxI64, false},
		{"AckV1", "sequence", 1, 16_384, false},
		{"AckV1", "durable_offset", 1, closeoutMaxI64, false},
		{"JournalHeaderV2", "version", 2, 2, false},
		{"JournalHeaderV2", "epoch", 1, closeoutMaxI64, false},
		{"JournalFrameV2", "version", 2, 2, false},
		{"JournalFrameV2", "frame_length", 1, 2_162_688, true},
		{"JournalFrameV2", "source_sequence", 1, 16_384, false},
		{"JournalFrameV2", "transaction_sequence", 1, 16_384, false},
		{"JournalCommitV2", "version", 2, 2, false},
		{"JournalCommitV2", "durable_offset_after_commit", 1, closeoutMaxI64, false},
		{"JournalCommitV2", "source_sequence", 1, 16_384, false},
		{"JournalCommitV2", "transaction_sequence", 1, 16_384, false},
		{"ObserverHelloV1", "version", 1, 1, false},
		{"ObserverHelloV1", "epoch", 1, closeoutMaxI64, false},
		{"ReceiverHelloV1", "version", 1, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.shape+"/"+tc.field, func(t *testing.T) {
			base := closeoutShapeFixture(t, tc.shape)
			if err := closeoutParseShape(tc.shape, testJSON(t, base)); err != nil {
				t.Fatalf("valid baseline refused: %v", err)
			}
			refuse := func(label string, value any) {
				t.Run(label, func(t *testing.T) {
					obj := closeoutShapeFixture(t, tc.shape)
					obj[tc.field] = value
					closeoutRefreshShapeHashes(t, tc.shape, obj)
					closeoutExpectField(t, closeoutParseShape(tc.shape, testJSON(t, obj)), tc.field)
				})
			}
			refuse("boolean-true", true)
			refuse("boolean-false", false)
			if tc.min == closeoutMinI64 {
				refuse("below-min", json.Number("-9223372036854775809"))
			} else {
				refuse("below-min", closeoutNumber(tc.min-1))
			}
			if tc.max == closeoutMaxI64 {
				refuse("above-max", json.Number("9223372036854775808"))
			} else {
				refuse("above-max", closeoutNumber(tc.max+1))
			}
			if tc.lengthCoupled {
				return
			}
			for _, edge := range []struct {
				name  string
				value int64
			}{{"at-min", tc.min}, {"at-max", tc.max}} {
				t.Run(edge.name, func(t *testing.T) {
					obj := closeoutShapeFixture(t, tc.shape)
					if tc.shape == "JournalFrameV2" && (tc.field == "source_sequence" || tc.field == "transaction_sequence") {
						closeoutSetJournalFrameSequence(t, obj, edge.value)
					} else if tc.shape == "JournalCommitV2" && (tc.field == "source_sequence" || tc.field == "transaction_sequence") {
						obj["source_sequence"] = closeoutNumber(edge.value)
						obj["transaction_sequence"] = closeoutNumber(edge.value)
					} else {
						obj[tc.field] = closeoutNumber(edge.value)
					}
					closeoutRefreshShapeHashes(t, tc.shape, obj)
					if err := closeoutParseShape(tc.shape, testJSON(t, obj)); err != nil {
						t.Fatalf("valid boundary %d refused: %v", edge.value, err)
					}
				})
			}
		})
	}
}

func TestCloseoutBothHelloLimitsObjects(t *testing.T) {
	// The seven literal values are copied from the selected wire contract, not
	// from parseLimits or the production ProtocolLimits type.
	limits := []struct {
		field string
		want  int64
	}{
		{"evidence_frame_max_bytes", 2_162_688},
		{"evidence_payload_max_bytes", 2_097_152},
		{"max_frames_per_session", 65_536},
		{"max_frames_per_source", 16_384},
		{"max_sources", 64},
		{"per_source_aggregate_max_bytes", 16_777_216},
		{"session_aggregate_max_bytes", 67_108_864},
	}
	for _, shape := range []struct{ name, nested string }{
		{"ObserverHelloV1", "requested_limits"},
		{"ReceiverHelloV1", "accepted_limits"},
	} {
		t.Run(shape.name, func(t *testing.T) {
			if err := closeoutParseShape(shape.name, testJSON(t, closeoutShapeFixture(t, shape.name))); err != nil {
				t.Fatalf("valid limits refused: %v", err)
			}
			for _, item := range limits {
				t.Run(item.field, func(t *testing.T) {
					for _, mutation := range []struct {
						name  string
						value any
					}{
						{"boolean-true", true}, {"boolean-false", false},
						{"below", closeoutNumber(item.want - 1)},
						{"above", closeoutNumber(item.want + 1)},
						{"int64-overflow", json.Number("9223372036854775808")},
					} {
						t.Run(mutation.name, func(t *testing.T) {
							obj := closeoutShapeFixture(t, shape.name)
							obj[shape.nested].(map[string]any)[item.field] = mutation.value
							closeoutExpectField(t, closeoutParseShape(shape.name, testJSON(t, obj)), item.field)
						})
					}
					obj := closeoutShapeFixture(t, shape.name)
					obj[shape.nested].(map[string]any)[item.field] = closeoutNumber(item.want)
					if err := closeoutParseShape(shape.name, testJSON(t, obj)); err != nil {
						t.Fatalf("exact selected limit refused: %v", err)
					}
				})
			}
			for _, mutation := range []struct {
				name   string
				change func(map[string]any)
			}{
				{"missing", func(m map[string]any) { delete(m, "max_sources") }},
				{"unknown", func(m map[string]any) { m["other"] = 1 }},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					obj := closeoutShapeFixture(t, shape.name)
					mutation.change(obj[shape.nested].(map[string]any))
					closeoutExpectField(t, closeoutParseShape(shape.name, testJSON(t, obj)), "nested field set")
				})
			}
		})
	}
}

func closeoutPayloadFixture(kind, branch string) map[string]any {
	payload := testPayload(kind)
	if kind == "SupervisorExitObservedV1" && branch == "signaled" {
		payload["wait_code_kind"] = "signaled"
		payload["exit_code"] = nil
		payload["signal"] = 1
	}
	if kind == "SourceCompleteV1" && branch == "failure" {
		payload["result_kind"] = "supervisor_failure"
	}
	return payload
}

func closeoutParsePayload(t *testing.T, kind string, payload map[string]any) error {
	t.Helper()
	frame := testFrame(t, kind)
	setTestFramePayload(t, frame, payload) // Rehash payload bytes, length, and frame record independently.
	_, err := ParseEvidenceFrameV1(testJSON(t, frame))
	return err
}

func TestCloseoutFivePayloadNumericKindAndBounds(t *testing.T) {
	// Every selected payload integer position appears once; SourceCompleteV1
	// has no integer position. Exit has a separate row for each branch number.
	cases := []struct {
		kind, branch, field string
		min, max            int64
	}{
		{"SupervisorStartedV1", "", "parent_pid", 1, 1},
		{"SupervisorStartedV1", "", "pid", 2, 4_294_967_295},
		{"SupervisorStartedV1", "", "process_group_id", 2, 4_294_967_295},
		{"SupervisorStartedV1", "", "pid_namespace_device", 0, closeoutMaxI64},
		{"SupervisorStartedV1", "", "pid_namespace_inode", 0, closeoutMaxI64},
		{"SupervisorStartedV1", "", "mount_namespace_device", 0, closeoutMaxI64},
		{"SupervisorStartedV1", "", "mount_namespace_inode", 0, closeoutMaxI64},
		{"SupervisorExitObservedV1", "exited", "pid", 2, 4_294_967_295},
		{"SupervisorExitObservedV1", "exited", "exit_code", 0, 255},
		{"SupervisorExitObservedV1", "signaled", "signal", 1, 64},
		{"SupervisorExitObservedV1", "exited", "observed_by_pid", 1, 1},
		{"SupervisorReapedV1", "", "pid", 2, 4_294_967_295},
		{"SupervisorReapedV1", "", "reap_count", 1, 1},
		{"SupervisorReapedV1", "", "wait_owner_pid", 1, 1},
		{"NamespaceDrainedV1", "", "supervisor_pid", 2, 4_294_967_295},
		{"NamespaceDrainedV1", "", "term_signal_count", 0, closeoutMaxI64},
		{"NamespaceDrainedV1", "", "kill_signal_count", 0, closeoutMaxI64},
		{"NamespaceDrainedV1", "", "reaped_descendant_count", 0, closeoutMaxI64},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.branch+"/"+tc.field, func(t *testing.T) {
			if err := closeoutParsePayload(t, tc.kind, closeoutPayloadFixture(tc.kind, tc.branch)); err != nil {
				t.Fatalf("valid payload refused: %v", err)
			}
			mutations := []struct {
				name  string
				value any
			}{
				{"boolean-true", true}, {"boolean-false", false},
				{"below", closeoutNumber(tc.min - 1)},
			}
			if tc.max == closeoutMaxI64 {
				mutations = append(mutations, struct {
					name  string
					value any
				}{"above", json.Number("9223372036854775808")})
			} else {
				mutations = append(mutations, struct {
					name  string
					value any
				}{"above", closeoutNumber(tc.max + 1)})
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					payload := closeoutPayloadFixture(tc.kind, tc.branch)
					payload[tc.field] = mutation.value
					closeoutExpectField(t, closeoutParsePayload(t, tc.kind, payload), tc.field)
				})
			}
			for _, edge := range []struct {
				name  string
				value int64
			}{{"at-min", tc.min}, {"at-max", tc.max}} {
				t.Run(edge.name, func(t *testing.T) {
					payload := closeoutPayloadFixture(tc.kind, tc.branch)
					payload[tc.field] = closeoutNumber(edge.value)
					if tc.kind == "SupervisorStartedV1" && (tc.field == "pid" || tc.field == "process_group_id") {
						payload["pid"] = closeoutNumber(edge.value)
						payload["process_group_id"] = closeoutNumber(edge.value)
					}
					if err := closeoutParsePayload(t, tc.kind, payload); err != nil {
						t.Fatalf("valid boundary %d refused: %v", edge.value, err)
					}
				})
			}
		})
	}
}

func TestCloseoutPayloadBooleanAndNullablePositions(t *testing.T) {
	booleans := []struct {
		kind, branch, field   string
		allowTrue, allowFalse bool
	}{
		{"SupervisorStartedV1", "", "pidfd_bound", true, false},
		{"SupervisorExitObservedV1", "exited", "core_dumped", false, true},
		{"SupervisorExitObservedV1", "signaled", "core_dumped", true, true},
		{"SupervisorExitObservedV1", "exited", "identity_match", true, false},
		{"SupervisorExitObservedV1", "signaled", "identity_match", true, false},
		{"SupervisorReapedV1", "", "pidfd_bound", true, false},
		{"SourceCompleteV1", "", "supervisor_reaped_once", true, false},
		{"SourceCompleteV1", "", "namespace_drained", true, false},
		{"SourceCompleteV1", "", "evidence_failure", false, true},
		{"SourceCompleteV1", "failure", "evidence_failure", true, true},
	}
	for _, tc := range booleans {
		t.Run(tc.kind+"/"+tc.branch+"/"+tc.field, func(t *testing.T) {
			for _, mutation := range []struct {
				name     string
				value    any
				accepted bool
			}{
				{"integer-zero", closeoutNumber(0), false},
				{"integer-one", closeoutNumber(1), false},
				{"boolean-true", true, tc.allowTrue},
				{"boolean-false", false, tc.allowFalse},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					payload := closeoutPayloadFixture(tc.kind, tc.branch)
					payload[tc.field] = mutation.value
					err := closeoutParsePayload(t, tc.kind, payload)
					if mutation.accepted && err != nil {
						t.Fatalf("valid boolean refused: %v", err)
					}
					if !mutation.accepted {
						closeoutExpectField(t, err, tc.field)
					}
				})
			}
		})
	}
	for _, tc := range []struct {
		branch, field string
		value         any
		accepted      bool
	}{
		{"exited", "exit_code", closeoutNumber(0), true},
		{"exited", "exit_code", closeoutNumber(255), true},
		{"exited", "exit_code", nil, false},
		{"exited", "signal", nil, true},
		{"exited", "signal", closeoutNumber(1), false},
		{"signaled", "exit_code", nil, true},
		{"signaled", "exit_code", closeoutNumber(0), false},
		{"signaled", "signal", closeoutNumber(1), true},
		{"signaled", "signal", closeoutNumber(64), true},
		{"signaled", "signal", nil, false},
	} {
		t.Run("SupervisorExitObservedV1/"+tc.branch+"/"+tc.field+"/"+strconv.FormatBool(tc.accepted)+"/"+string(testJSON(t, tc.value)), func(t *testing.T) {
			payload := closeoutPayloadFixture("SupervisorExitObservedV1", tc.branch)
			payload[tc.field] = tc.value
			err := closeoutParsePayload(t, "SupervisorExitObservedV1", payload)
			if tc.accepted && err != nil {
				t.Fatalf("valid conditional value refused: %v", err)
			}
			if !tc.accepted {
				closeoutExpectField(t, err, tc.field)
			}
		})
	}
}

func TestCloseoutSharedRangeSizeAndBase64Guards(t *testing.T) {
	for _, tc := range []struct {
		name     string
		min, max int64
	}{
		{"payload_length", 0, 2_097_152},
		{"frame_length", 1, 2_162_688},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, edge := range []struct {
				name, raw string
				accepted  bool
			}{
				{"below", strconv.FormatInt(tc.min-1, 10), false},
				{"at-min", strconv.FormatInt(tc.min, 10), true},
				{"at-max", strconv.FormatInt(tc.max, 10), true},
				{"above", strconv.FormatInt(tc.max+1, 10), false},
				{"int64-overflow", "9223372036854775808", false},
			} {
				t.Run(edge.name, func(t *testing.T) {
					_, err := intField(map[string]any{tc.name: canonicalInteger(edge.raw)}, tc.name, tc.min, tc.max)
					if edge.accepted && err != nil {
						t.Fatalf("valid boundary refused: %v", err)
					}
					if !edge.accepted {
						closeoutExpectField(t, err, tc.name)
					}
				})
			}
		})
	}
	for _, tc := range []struct {
		name, raw string
		max       int
		field     string
		accepted  bool
	}{
		{"at-byte-limit", `{"a":0}`, 7, "", true},
		{"just-over-byte-limit", `{"a":0}`, 6, "byte bound", false},
		{"missing-field", `{}`, 7, "field set", false},
		{"unknown-field", `{"a":0,"b":0}`, 13, "field set", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := exactObject([]byte(tc.raw), tc.max, "a")
			if tc.accepted && err != nil {
				t.Fatalf("valid canonical object refused: %v", err)
			}
			if !tc.accepted {
				closeoutExpectField(t, err, tc.field)
			}
		})
	}
	for _, tc := range []struct {
		name, value          string
		maxDecoded, maxChars int
		accepted             bool
	}{
		{"empty", "", 1, 2, true},
		{"exact-decoded-and-chars", "Zg", 1, 2, true},
		{"noncanonical-trailing-bits", "Zh", 1, 2, false},
		{"padding", "Zg=", 1, 4, false},
		{"invalid-character", "Zg+", 1, 4, false},
		{"decoded-overflow", "Zm8", 1, 3, false},
		{"character-overflow", "Zg", 1, 1, false},
	} {
		t.Run("base64/"+tc.name, func(t *testing.T) {
			decoded, err := base64Field(map[string]any{"payload": tc.value}, "payload", tc.maxDecoded, tc.maxChars)
			if tc.accepted {
				if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != tc.value {
					t.Fatalf("valid unpadded base64url refused or changed: %v", err)
				}
			} else {
				closeoutExpectField(t, err, "payload")
			}
		})
	}
	frame := testFrame(t, "SupervisorStartedV1")
	if err := closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)); err != nil {
		t.Fatalf("exact payload length baseline refused: %v", err)
	}
	frame["payload_length"] = closeoutNumber(int64(frame["payload_length"].(int) + 1))
	closeoutRefreshRecordHash(t, frame)
	closeoutExpectField(t, closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)), "payload_length")
	wrapper := testJournalFrame(t)
	wrapper["frame_length"] = closeoutNumber(int64(wrapper["frame_length"].(int) + 1))
	closeoutExpectField(t, closeoutParseShape("JournalFrameV2", testJSON(t, wrapper)), "frame_length")
}

func TestCloseoutIndependentHashesAndLocalBindings(t *testing.T) {
	frame := testFrame(t, "SupervisorStartedV1")
	frame["epoch"] = closeoutNumber(9_007_199_254_740_993)
	closeoutRefreshRecordHash(t, frame)
	if err := closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)); err != nil {
		t.Fatalf("rehash with exact >2^53 epoch refused: %v", err)
	}
	frame["payload_sha256"] = testZeroHash
	closeoutRefreshRecordHash(t, frame)
	closeoutExpectField(t, closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)), "payload_sha256")
	frame = testFrame(t, "SupervisorStartedV1")
	frame["record_hash"] = testZeroHash
	closeoutExpectField(t, closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)), "record_hash")

	header := testHeader(t)
	header["epoch"] = closeoutNumber(9_007_199_254_740_993)
	closeoutExpectField(t, closeoutParseShape("JournalHeaderV2", testJSON(t, header)), "session_binding_sha256")
	closeoutRefreshHeaderHashes(t, header)
	if err := closeoutParseShape("JournalHeaderV2", testJSON(t, header)); err != nil {
		t.Fatalf("rehash with exact >2^53 epoch refused: %v", err)
	}
	header["journal_identity_sha256"] = testZeroHash
	closeoutExpectField(t, closeoutParseShape("JournalHeaderV2", testJSON(t, header)), "journal_identity_sha256")

	wrapper := testJournalFrame(t)
	wrapper["frame_sha256"] = testZeroHash
	closeoutExpectField(t, closeoutParseShape("JournalFrameV2", testJSON(t, wrapper)), "frame_sha256")
	wrapper = testJournalFrame(t)
	wrapper["source_sequence"] = closeoutNumber(2)
	wrapper["transaction_sequence"] = closeoutNumber(2)
	closeoutExpectField(t, closeoutParseShape("JournalFrameV2", testJSON(t, wrapper)), "embedded frame binding")

	commit := testCommit(t)
	commit["source_sequence"] = closeoutNumber(2)
	commit["transaction_sequence"] = closeoutNumber(2)
	closeoutExpectField(t, closeoutParseShape("JournalCommitV2", testJSON(t, commit)), "commit_hash")
	closeoutRefreshCommitHashes(t, commit)
	if err := closeoutParseShape("JournalCommitV2", testJSON(t, commit)); err != nil {
		t.Fatalf("rehashed commit sequences refused: %v", err)
	}
	commit["commit_id"] = testZeroHash
	closeoutExpectField(t, closeoutParseShape("JournalCommitV2", testJSON(t, commit)), "commit_id")

	complete := closeoutPayloadFixture("SourceCompleteV1", "")
	complete["last_nonfinal_record_hash"] = testOneHash
	closeoutExpectField(t, closeoutParsePayload(t, "SourceCompleteV1", complete), "last_nonfinal_record_hash")
	started := closeoutPayloadFixture("SupervisorStartedV1", "")
	started["process_group_id"] = closeoutNumber(3)
	closeoutExpectField(t, closeoutParsePayload(t, "SupervisorStartedV1", started), "process_group_id")
}

func TestJournalFrameV2WrapperBindings(t *testing.T) {
	checkFixture := func(t *testing.T, baseline, wrapper map[string]any, changed string) EvidenceFrameV1 {
		t.Helper()
		if len(wrapper) != 12 || len(baseline) != 12 {
			t.Fatal("JournalFrameV2 fixture must have exactly 12 fields")
		}
		for key, want := range baseline {
			if key == changed {
				if reflect.DeepEqual(wrapper[key], want) {
					t.Fatalf("targeted outer field %s did not change", key)
				}
				continue
			}
			if !reflect.DeepEqual(wrapper[key], want) {
				t.Fatalf("unrelated outer field %s changed", key)
			}
		}
		encoded := wrapper["exact_frame_bytes_b64url"].(string)
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
			t.Fatalf("embedded bytes are not canonical base64url: %v", err)
		}
		if len(raw) != wrapper["frame_length"].(int) || wrapper["frame_sha256"] != testDomain("R6J-JOURNAL-FRAME/v2", raw) {
			t.Fatal("embedded frame length or independent digest changed")
		}
		embedded, err := ParseEvidenceFrameV1(raw)
		if err != nil {
			t.Fatalf("embedded frame is not independently valid: %v", err)
		}
		if embedded.RecordHash != baseline["evidence_record_hash"] || embedded.PayloadType != baseline["payload_type"] || embedded.Sequence != int64(baseline["source_sequence"].(int)) {
			t.Fatal("baseline wrapper does not match valid embedded frame")
		}
		return embedded
	}

	t.Run("matching-positive", func(t *testing.T) {
		baseline, wrapper := testJournalFrame(t), testJournalFrame(t)
		embedded := checkFixture(t, baseline, wrapper, "")
		parsed, err := ParseJournalFrameV2(testJSON(t, wrapper))
		if err != nil {
			t.Fatalf("matching wrapper refused: %v", err)
		}
		if parsed.EvidenceRecordHash != embedded.RecordHash || parsed.PayloadType != embedded.PayloadType || parsed.SourceSequence != embedded.Sequence || parsed.EmbeddedFrame.RecordHash != embedded.RecordHash || parsed.EmbeddedFrame.PayloadType != embedded.PayloadType || parsed.EmbeddedFrame.Sequence != embedded.Sequence {
			t.Fatal("parsed wrapper and embedded fields do not match fixture")
		}
	})
	t.Run("record-hash-mismatch", func(t *testing.T) {
		baseline, wrapper := testJournalFrame(t), testJournalFrame(t)
		wrapper["evidence_record_hash"] = testOneHash
		embedded := checkFixture(t, baseline, wrapper, "evidence_record_hash")
		if len(testOneHash) != 64 || wrapper["evidence_record_hash"] == embedded.RecordHash {
			t.Fatal("outer record hash is not a distinct valid hex64 value")
		}
		closeoutExpectField(t, closeoutParseShape("JournalFrameV2", testJSON(t, wrapper)), "embedded frame binding")
	})
	t.Run("payload-type-mismatch", func(t *testing.T) {
		baseline, wrapper := testJournalFrame(t), testJournalFrame(t)
		wrapper["payload_type"] = "SupervisorReapedV1"
		embedded := checkFixture(t, baseline, wrapper, "payload_type")
		if embedded.PayloadType != "SupervisorStartedV1" || wrapper["transaction_kind"] != "EVIDENCE" {
			t.Fatal("payload mismatch fixture lost its valid local kind")
		}
		closeoutExpectField(t, closeoutParseShape("JournalFrameV2", testJSON(t, wrapper)), "embedded frame binding")
	})
}

func TestEvidenceFrameV1InitialPreviousRecordHash(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sequence int
		previous string
		refuse   bool
	}{
		{"sequence-one-zero-positive", 1, testZeroHash, false},
		{"sequence-one-nonzero-refusal", 1, testOneHash, true},
		{"sequence-two-nonzero-positive", 2, testOneHash, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline, frame := testFrame(t, "SupervisorStartedV1"), testFrame(t, "SupervisorStartedV1")
			frame["sequence"] = tc.sequence
			frame["previous_record_hash"] = tc.previous
			originalRecordHash := frame["record_hash"]
			closeoutRefreshRecordHash(t, frame)
			if len(frame) != 17 || len(tc.previous) != 64 || tc.previous != strings.Repeat(string(tc.previous[0]), 64) {
				t.Fatal("frame or previous-record-hash fixture has wrong shape")
			}
			core := make(map[string]any, 16)
			for key, value := range frame {
				if key != "record_hash" {
					core[key] = value
				}
			}
			if len(core) != 16 || frame["record_hash"] != testDomain("R6J-OBS-RECORD/v1", testJSON(t, core)) {
				t.Fatal("independent 16-field record hash was not installed")
			}
			for key, want := range baseline {
				if key != "sequence" && key != "previous_record_hash" && key != "record_hash" && !reflect.DeepEqual(frame[key], want) {
					t.Fatalf("unrelated frame field %s changed", key)
				}
			}
			payload, err := base64.RawURLEncoding.DecodeString(frame["payload"].(string))
			if err != nil || len(payload) != frame["payload_length"].(int) || frame["payload_sha256"] != testDomain("R6J-OBS-PAYLOAD/v1", payload) {
				t.Fatalf("otherwise valid payload bytes/length/hash changed: %v", err)
			}
			if tc.refuse {
				if tc.sequence != 1 || tc.previous == testZeroHash || frame["record_hash"] == originalRecordHash {
					t.Fatal("sequence-one nonzero specimen did not refresh its record hash")
				}
				closeoutExpectField(t, closeoutParseShape("EvidenceFrameV1", testJSON(t, frame)), "initial previous_record_hash")
				return
			}
			parsed, err := ParseEvidenceFrameV1(testJSON(t, frame))
			if err != nil {
				t.Fatalf("structurally valid frame refused: %v", err)
			}
			if parsed.Sequence != int64(tc.sequence) || parsed.PreviousRecordHash != tc.previous || parsed.RecordHash != frame["record_hash"] {
				t.Fatal("parsed local fields differ from independently hashed fixture")
			}
		})
	}
}

func TestCloseoutPayloadTokenRules(t *testing.T) {
	// The selected Started token permits ASCII control bytes; later token
	// fields require printable ASCII. The JSON fixture encodes the control
	// byte canonically, so the field rule is the only differing guard.
	started := closeoutPayloadFixture("SupervisorStartedV1", "")
	started["proc_start_token"] = "\x01"
	if err := closeoutParsePayload(t, "SupervisorStartedV1", started); err != nil {
		t.Fatalf("Started ASCII control token refused: %v", err)
	}
	for _, kind := range []string{"SupervisorExitObservedV1", "SupervisorReapedV1"} {
		payload := closeoutPayloadFixture(kind, "")
		payload["proc_start_token"] = "\x01"
		closeoutExpectField(t, closeoutParsePayload(t, kind, payload), "proc_start_token")
	}
	for _, kind := range []string{"SupervisorStartedV1", "SupervisorExitObservedV1", "SupervisorReapedV1"} {
		for _, tc := range []struct {
			name, token string
			accepted    bool
		}{
			{"at-limit", strings.Repeat("a", 256), true},
			{"over-limit", strings.Repeat("a", 257), false},
			{"non-ascii", "é", false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				payload := closeoutPayloadFixture(kind, "")
				payload["proc_start_token"] = tc.token
				err := closeoutParsePayload(t, kind, payload)
				if tc.accepted && err != nil {
					t.Fatalf("valid token refused: %v", err)
				}
				if !tc.accepted {
					closeoutExpectField(t, err, "proc_start_token")
				}
			})
		}
	}
}
