package outsideobserverprotocol

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
)

const (
	maxEvidencePayloadBytes    = 2_097_152
	maxEvidenceFrameBytes      = 2_162_688
	maxJournalFrameBytes       = 2_884_158
	maxJournalFrameBase64Chars = 2_883_584
	maxAckBytes                = 16_384
	maxHelloBytes              = 65_536
	maxSelectedInteger         = int64(9_223_372_036_854_775_807)
	maxSequence                = int64(16_384)
	maxPID                     = int64(4_294_967_295)
	observerSPIFFEID           = "spiffe://governed-execution.local/es/r6j/outsideobserver"
	receiverSPIFFEID           = "spiffe://governed-execution.local/es/r6j/receiver"
)

func structuralError(field string) error {
	return fmt.Errorf("outside observer structural refusal: %s", field)
}

func exactObject(raw []byte, maxBytes int, fields ...string) (map[string]any, error) {
	if len(raw) > maxBytes {
		return nil, structuralError("byte bound")
	}
	v, err := parseCanonicalV2(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != len(fields) {
		return nil, structuralError("field set")
	}
	for _, key := range fields {
		if _, ok := obj[key]; !ok {
			return nil, structuralError("field set")
		}
	}
	return obj, nil
}

func exactNestedObject(v any, fields ...string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != len(fields) {
		return nil, structuralError("nested field set")
	}
	for _, key := range fields {
		if _, ok := obj[key]; !ok {
			return nil, structuralError("nested field set")
		}
	}
	return obj, nil
}

func stringField(obj map[string]any, key string) (string, error) {
	s, ok := obj[key].(string)
	if !ok {
		return "", structuralError(key)
	}
	return s, nil
}

func literalString(obj map[string]any, key, want string) error {
	s, err := stringField(obj, key)
	if err != nil || s != want {
		return structuralError(key)
	}
	return nil
}

func intField(obj map[string]any, key string, min, max int64) (int64, error) {
	token, ok := obj[key].(canonicalInteger)
	if !ok {
		return 0, structuralError(key)
	}
	value, err := strconv.ParseInt(string(token), 10, 64)
	if err != nil || value < min || value > max {
		return 0, structuralError(key)
	}
	return value, nil
}

func literalInt(obj map[string]any, key string, want int64) error {
	_, err := intField(obj, key, want, want)
	return err
}

func boolField(obj map[string]any, key string) (bool, error) {
	b, ok := obj[key].(bool)
	if !ok {
		return false, structuralError(key)
	}
	return b, nil
}

func literalBool(obj map[string]any, key string, want bool) error {
	b, err := boolField(obj, key)
	if err != nil || b != want {
		return structuralError(key)
	}
	return nil
}

func enumField(obj map[string]any, key string, allowed ...string) (string, error) {
	s, err := stringField(obj, key)
	if err != nil {
		return "", err
	}
	for _, v := range allowed {
		if s == v {
			return s, nil
		}
	}
	return "", structuralError(key)
}

func validASCIIID(s string) bool {
	if len(s) < 1 || len(s) > 128 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func asciiIDField(obj map[string]any, key string) (string, error) {
	s, err := stringField(obj, key)
	if err != nil || !validASCIIID(s) {
		return "", structuralError(key)
	}
	return s, nil
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lowerHexNibble(s[i]) < 0 {
			return false
		}
	}
	return true
}
func validHex32(s string) bool { return validHex(s, 32) }
func validHex64(s string) bool { return validHex(s, 64) }

func hexField(obj map[string]any, key string, n int) (string, error) {
	s, err := stringField(obj, key)
	if err != nil || !validHex(s, n) {
		return "", structuralError(key)
	}
	return s, nil
}

func asciiTextField(obj map[string]any, key string, max int, printable bool) (string, error) {
	s, err := stringField(obj, key)
	if err != nil || len(s) < 1 || len(s) > max {
		return "", structuralError(key)
	}
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f || (printable && (s[i] < 0x20 || s[i] > 0x7e)) {
			return "", structuralError(key)
		}
	}
	return s, nil
}

func base64Field(obj map[string]any, key string, maxDecoded, maxChars int) ([]byte, error) {
	s, err := stringField(obj, key)
	if err != nil || len(s) > maxChars {
		return nil, structuralError(key)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, structuralError(key)
		}
	}
	// The character bound prevents oversized allocations before decoding.
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(decoded) > maxDecoded || base64.RawURLEncoding.EncodeToString(decoded) != s {
		return nil, structuralError(key)
	}
	return decoded, nil
}

func b64Chars(maxBytes int) int { return (maxBytes/3)*4 + []int{0, 2, 3}[maxBytes%3] }

func ParseEvidenceFrameV1(raw []byte) (EvidenceFrameV1, error) {
	var out EvidenceFrameV1
	obj, err := exactObject(raw, maxEvidenceFrameBytes, "schema", "version", "run_id", "entry_digest", "permit_digest", "source_instance_id", "epoch", "sequence", "producer_role", "qualified_clock_ref", "observed_time", "previous_record_hash", "payload_type", "payload_length", "payload_sha256", "payload", "record_hash")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "EvidenceFrameV1"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 1); err != nil {
		return out, err
	}
	if out.RunID, err = asciiIDField(obj, "run_id"); err != nil {
		return out, err
	}
	if out.SourceInstanceID, err = asciiIDField(obj, "source_instance_id"); err != nil {
		return out, err
	}
	if out.EntryDigest, err = hexField(obj, "entry_digest", 64); err != nil {
		return out, err
	}
	if out.PermitDigest, err = hexField(obj, "permit_digest", 64); err != nil {
		return out, err
	}
	if out.Epoch, err = intField(obj, "epoch", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	if out.Sequence, err = intField(obj, "sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if err = literalString(obj, "producer_role", "es/outsideobserver"); err != nil {
		return out, err
	}
	if out.QualifiedClockRef, err = asciiIDField(obj, "qualified_clock_ref"); err != nil {
		return out, err
	}
	if out.ObservedTime, err = intField(obj, "observed_time", -maxSelectedInteger-1, maxSelectedInteger); err != nil {
		return out, err
	}
	if out.PreviousRecordHash, err = hexField(obj, "previous_record_hash", 64); err != nil {
		return out, err
	}
	if out.Sequence == 1 && out.PreviousRecordHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		return out, structuralError("initial previous_record_hash")
	}
	if out.PayloadType, err = enumField(obj, "payload_type", "SupervisorStartedV1", "SupervisorExitObservedV1", "SupervisorReapedV1", "NamespaceDrainedV1", "SourceCompleteV1"); err != nil {
		return out, err
	}
	if out.PayloadLength, err = intField(obj, "payload_length", 0, maxEvidencePayloadBytes); err != nil {
		return out, err
	}
	if out.PayloadSHA256, err = hexField(obj, "payload_sha256", 64); err != nil {
		return out, err
	}
	if out.RecordHash, err = hexField(obj, "record_hash", 64); err != nil {
		return out, err
	}
	if out.Payload, err = base64Field(obj, "payload", maxEvidencePayloadBytes, b64Chars(maxEvidencePayloadBytes)); err != nil {
		return out, err
	}
	if int64(len(out.Payload)) != out.PayloadLength {
		return out, structuralError("payload_length")
	}
	if out.PayloadValue, err = parseEvidencePayload(out.PayloadType, out.Payload); err != nil {
		return out, err
	}
	if completed, ok := out.PayloadValue.(SourceCompleteV1); ok && completed.LastNonfinalRecordHash != out.PreviousRecordHash {
		return out, structuralError("last_nonfinal_record_hash")
	}
	if out.PayloadSHA256 != hashDomain("R6J-OBS-PAYLOAD/v1", out.Payload) {
		return out, structuralError("payload_sha256")
	}
	core := make(map[string]any, len(obj)-1)
	for k, v := range obj {
		if k != "record_hash" {
			core[k] = v
		}
	}
	coreBytes, err := encodeCanonicalV2(core)
	if err != nil || out.RecordHash != hashDomain("R6J-OBS-RECORD/v1", coreBytes) {
		return out, structuralError("record_hash")
	}
	out.Schema = "EvidenceFrameV1"
	out.Version = 1
	out.ProducerRole = "es/outsideobserver"
	return out, nil
}

func ParseAckV1(raw []byte) (AckV1, error) {
	var out AckV1
	obj, err := exactObject(raw, maxAckBytes, "schema", "version", "run_id", "source_instance_id", "epoch", "sequence", "record_hash", "journal_segment_id", "durable_offset", "source_state", "commit_id")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "AckV1"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 1); err != nil {
		return out, err
	}
	if out.RunID, err = asciiIDField(obj, "run_id"); err != nil {
		return out, err
	}
	if out.SourceInstanceID, err = asciiIDField(obj, "source_instance_id"); err != nil {
		return out, err
	}
	if out.Epoch, err = intField(obj, "epoch", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	if out.Sequence, err = intField(obj, "sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if out.RecordHash, err = hexField(obj, "record_hash", 64); err != nil {
		return out, err
	}
	if out.JournalSegmentID, err = hexField(obj, "journal_segment_id", 64); err != nil {
		return out, err
	}
	if out.DurableOffset, err = intField(obj, "durable_offset", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	if out.SourceState, err = enumField(obj, "source_state", "OPEN", "COMPLETE", "ABORTED"); err != nil {
		return out, err
	}
	if out.CommitID, err = hexField(obj, "commit_id", 64); err != nil {
		return out, err
	}
	out.Schema = "AckV1"
	out.Version = 1
	return out, nil
}

func ParseJournalHeaderV2(raw []byte) (JournalHeaderV2, error) {
	var out JournalHeaderV2
	obj, err := exactObject(raw, maxCanonicalBytes, "endpoint_nonce", "entry_digest", "epoch", "journal_identity_sha256", "journal_nonce", "observer_session_nonce", "observer_spiffe_id", "permit_consumption_receipt_sha256", "permit_digest", "receiver_session_nonce", "receiver_spiffe_id", "run_id", "schema", "session_binding_sha256", "source_instance_id", "version")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "JournalHeaderV2"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 2); err != nil {
		return out, err
	}
	if out.RunID, err = asciiIDField(obj, "run_id"); err != nil {
		return out, err
	}
	if out.SourceInstanceID, err = asciiIDField(obj, "source_instance_id"); err != nil {
		return out, err
	}
	if out.EntryDigest, err = hexField(obj, "entry_digest", 64); err != nil {
		return out, err
	}
	if out.PermitDigest, err = hexField(obj, "permit_digest", 64); err != nil {
		return out, err
	}
	if out.PermitConsumptionReceiptSHA256, err = hexField(obj, "permit_consumption_receipt_sha256", 64); err != nil {
		return out, err
	}
	if out.Epoch, err = intField(obj, "epoch", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	for _, v := range []struct {
		key string
		dst *string
	}{{"endpoint_nonce", &out.EndpointNonce}, {"observer_session_nonce", &out.ObserverSessionNonce}, {"receiver_session_nonce", &out.ReceiverSessionNonce}, {"journal_nonce", &out.JournalNonce}} {
		if *v.dst, err = hexField(obj, v.key, 32); err != nil {
			return out, err
		}
	}
	if err = literalString(obj, "observer_spiffe_id", observerSPIFFEID); err != nil {
		return out, err
	}
	if err = literalString(obj, "receiver_spiffe_id", receiverSPIFFEID); err != nil {
		return out, err
	}
	if out.SessionBindingSHA256, err = hexField(obj, "session_binding_sha256", 64); err != nil {
		return out, err
	}
	if out.JournalIdentitySHA256, err = hexField(obj, "journal_identity_sha256", 64); err != nil {
		return out, err
	}
	core := map[string]any{}
	for _, key := range []string{"endpoint_nonce", "entry_digest", "epoch", "observer_session_nonce", "observer_spiffe_id", "permit_consumption_receipt_sha256", "permit_digest", "receiver_session_nonce", "receiver_spiffe_id", "run_id", "source_instance_id"} {
		core[key] = obj[key]
	}
	encoded, err := encodeCanonicalV2(core)
	if err != nil || out.SessionBindingSHA256 != hashDomain("R6J-SESSION-BINDING/v2", encoded) {
		return out, structuralError("session_binding_sha256")
	}
	wider, err := encodeCanonicalV2(map[string]any{"journal_nonce": out.JournalNonce, "session_binding_sha256": out.SessionBindingSHA256})
	if err != nil || out.JournalIdentitySHA256 != hashDomain("R6J-JOURNAL-IDENTITY/v2", wider) {
		return out, structuralError("journal_identity_sha256")
	}
	out.Schema = "JournalHeaderV2"
	out.Version = 2
	out.ObserverSPIFFEID = observerSPIFFEID
	out.ReceiverSPIFFEID = receiverSPIFFEID
	return out, nil
}

func ParseJournalFrameV2(raw []byte) (JournalFrameV2, error) {
	var out JournalFrameV2
	obj, err := exactObject(raw, maxJournalFrameBytes, "evidence_record_hash", "exact_frame_bytes_b64url", "frame_length", "frame_sha256", "journal_identity_sha256", "payload_type", "schema", "session_binding_sha256", "source_sequence", "transaction_kind", "transaction_sequence", "version")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "JournalFrameV2"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 2); err != nil {
		return out, err
	}
	if out.FrameLength, err = intField(obj, "frame_length", 1, maxEvidenceFrameBytes); err != nil {
		return out, err
	}
	if out.SourceSequence, err = intField(obj, "source_sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if out.TransactionSequence, err = intField(obj, "transaction_sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if out.SourceSequence != out.TransactionSequence {
		return out, structuralError("journal frame sequences")
	}
	for _, v := range []struct {
		key string
		dst *string
	}{{"evidence_record_hash", &out.EvidenceRecordHash}, {"frame_sha256", &out.FrameSHA256}, {"journal_identity_sha256", &out.JournalIdentitySHA256}, {"session_binding_sha256", &out.SessionBindingSHA256}} {
		if *v.dst, err = hexField(obj, v.key, 64); err != nil {
			return out, err
		}
	}
	if out.PayloadType, err = enumField(obj, "payload_type", "SupervisorStartedV1", "SupervisorExitObservedV1", "SupervisorReapedV1", "NamespaceDrainedV1", "SourceCompleteV1"); err != nil {
		return out, err
	}
	if out.TransactionKind, err = enumField(obj, "transaction_kind", "EVIDENCE", "COMPLETE", "ABORT"); err != nil {
		return out, err
	}
	if out.ExactFrameBytes, err = base64Field(obj, "exact_frame_bytes_b64url", maxEvidenceFrameBytes, maxJournalFrameBase64Chars); err != nil {
		return out, err
	}
	if int64(len(out.ExactFrameBytes)) != out.FrameLength {
		return out, structuralError("frame_length")
	}
	if out.FrameSHA256 != hashDomain("R6J-JOURNAL-FRAME/v2", out.ExactFrameBytes) {
		return out, structuralError("frame_sha256")
	}
	if out.EmbeddedFrame, err = ParseEvidenceFrameV1(out.ExactFrameBytes); err != nil {
		return out, err
	}
	if out.EvidenceRecordHash != out.EmbeddedFrame.RecordHash || out.PayloadType != out.EmbeddedFrame.PayloadType || out.SourceSequence != out.EmbeddedFrame.Sequence {
		return out, structuralError("embedded frame binding")
	}
	kind := "EVIDENCE"
	if completed, ok := out.EmbeddedFrame.PayloadValue.(SourceCompleteV1); ok {
		if completed.EvidenceFailure {
			kind = "ABORT"
		} else {
			kind = "COMPLETE"
		}
	}
	if out.TransactionKind != kind {
		return out, structuralError("transaction_kind")
	}
	out.Schema = "JournalFrameV2"
	out.Version = 2
	return out, nil
}

func ParseJournalCommitV2(raw []byte) (JournalCommitV2, error) {
	var out JournalCommitV2
	obj, err := exactObject(raw, maxCanonicalBytes, "commit_hash", "commit_id", "durable_offset_after_commit", "evidence_record_hash", "frame_record_sha256", "journal_identity_sha256", "next_source_state", "previous_commit_hash", "schema", "session_binding_sha256", "source_sequence", "transaction_kind", "transaction_payload_sha256", "transaction_sequence", "version")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "JournalCommitV2"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 2); err != nil {
		return out, err
	}
	for _, v := range []struct {
		key string
		dst *string
	}{{"commit_hash", &out.CommitHash}, {"commit_id", &out.CommitID}, {"evidence_record_hash", &out.EvidenceRecordHash}, {"frame_record_sha256", &out.FrameRecordSHA256}, {"journal_identity_sha256", &out.JournalIdentitySHA256}, {"previous_commit_hash", &out.PreviousCommitHash}, {"session_binding_sha256", &out.SessionBindingSHA256}, {"transaction_payload_sha256", &out.TransactionPayloadSHA256}} {
		if *v.dst, err = hexField(obj, v.key, 64); err != nil {
			return out, err
		}
	}
	if out.DurableOffsetAfterCommit, err = intField(obj, "durable_offset_after_commit", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	if out.SourceSequence, err = intField(obj, "source_sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if out.TransactionSequence, err = intField(obj, "transaction_sequence", 1, maxSequence); err != nil {
		return out, err
	}
	if out.SourceSequence != out.TransactionSequence {
		return out, structuralError("journal commit sequences")
	}
	if out.TransactionKind, err = enumField(obj, "transaction_kind", "EVIDENCE", "COMPLETE", "ABORT"); err != nil {
		return out, err
	}
	if out.NextSourceState, err = enumField(obj, "next_source_state", "OPEN", "COMPLETE", "ABORTED"); err != nil {
		return out, err
	}
	expectedState := map[string]string{"EVIDENCE": "OPEN", "COMPLETE": "COMPLETE", "ABORT": "ABORTED"}[out.TransactionKind]
	if out.NextSourceState != expectedState {
		return out, structuralError("next_source_state")
	}
	core := make(map[string]any, len(obj)-2)
	for k, v := range obj {
		if k != "commit_hash" && k != "commit_id" {
			core[k] = v
		}
	}
	encoded, err := encodeCanonicalV2(core)
	if err != nil || out.CommitHash != hashDomain("R6J-JOURNAL-COMMIT-HASH/v2", encoded) {
		return out, structuralError("commit_hash")
	}
	commitBytes, err := hex.DecodeString(out.CommitHash)
	if err != nil || out.CommitID != hashDomain("R6J-JOURNAL-COMMIT-ID/v2", commitBytes) {
		return out, structuralError("commit_id")
	}
	out.Schema = "JournalCommitV2"
	out.Version = 2
	return out, nil
}

func parseLimits(v any) (ProtocolLimits, error) {
	var out ProtocolLimits
	obj, err := exactNestedObject(v, "evidence_frame_max_bytes", "evidence_payload_max_bytes", "max_frames_per_session", "max_frames_per_source", "max_sources", "per_source_aggregate_max_bytes", "session_aggregate_max_bytes")
	if err != nil {
		return out, err
	}
	for _, item := range []struct {
		key   string
		value int64
		dst   *int64
	}{
		{"evidence_frame_max_bytes", 2162688, &out.EvidenceFrameMaxBytes},
		{"evidence_payload_max_bytes", 2097152, &out.EvidencePayloadMaxBytes},
		{"max_frames_per_session", 65536, &out.MaxFramesPerSession},
		{"max_frames_per_source", 16384, &out.MaxFramesPerSource},
		{"max_sources", 64, &out.MaxSources},
		{"per_source_aggregate_max_bytes", 16777216, &out.PerSourceAggregateMaxBytes},
		{"session_aggregate_max_bytes", 67108864, &out.SessionAggregateMaxBytes},
	} {
		if *item.dst, err = intField(obj, item.key, item.value, item.value); err != nil {
			return out, err
		}
	}
	return out, nil
}

func ParseObserverHelloV1(raw []byte) (ObserverHelloV1, error) {
	var out ObserverHelloV1
	obj, err := exactObject(raw, maxHelloBytes, "schema", "version", "run_id", "entry_digest", "permit_digest", "permit_nonce", "source_instance_id", "epoch", "observer_session_nonce", "endpoint_nonce", "observer_spiffe_id", "expected_receiver_spiffe_id", "requested_limits")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "ObserverHelloV1"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 1); err != nil {
		return out, err
	}
	if out.RunID, err = asciiIDField(obj, "run_id"); err != nil {
		return out, err
	}
	if out.SourceInstanceID, err = asciiIDField(obj, "source_instance_id"); err != nil {
		return out, err
	}
	if out.EntryDigest, err = hexField(obj, "entry_digest", 64); err != nil {
		return out, err
	}
	if out.PermitDigest, err = hexField(obj, "permit_digest", 64); err != nil {
		return out, err
	}
	for _, v := range []struct {
		key string
		dst *string
	}{{"permit_nonce", &out.PermitNonce}, {"observer_session_nonce", &out.ObserverSessionNonce}, {"endpoint_nonce", &out.EndpointNonce}} {
		if *v.dst, err = hexField(obj, v.key, 32); err != nil {
			return out, err
		}
	}
	if out.Epoch, err = intField(obj, "epoch", 1, maxSelectedInteger); err != nil {
		return out, err
	}
	if err = literalString(obj, "observer_spiffe_id", observerSPIFFEID); err != nil {
		return out, err
	}
	if err = literalString(obj, "expected_receiver_spiffe_id", receiverSPIFFEID); err != nil {
		return out, err
	}
	if out.RequestedLimits, err = parseLimits(obj["requested_limits"]); err != nil {
		return out, err
	}
	out.Schema = "ObserverHelloV1"
	out.Version = 1
	out.ObserverSPIFFEID = observerSPIFFEID
	out.ExpectedReceiverSPIFFEID = receiverSPIFFEID
	return out, nil
}

func ParseReceiverHelloV1(raw []byte) (ReceiverHelloV1, error) {
	var out ReceiverHelloV1
	obj, err := exactObject(raw, maxHelloBytes, "schema", "version", "run_id", "entry_digest", "receiver_session_nonce", "endpoint_nonce", "receiver_spiffe_id", "expected_observer_spiffe_id", "accepted_limits")
	if err != nil {
		return out, err
	}
	if err = literalString(obj, "schema", "ReceiverHelloV1"); err != nil {
		return out, err
	}
	if err = literalInt(obj, "version", 1); err != nil {
		return out, err
	}
	if out.RunID, err = asciiIDField(obj, "run_id"); err != nil {
		return out, err
	}
	if out.EntryDigest, err = hexField(obj, "entry_digest", 64); err != nil {
		return out, err
	}
	if out.ReceiverSessionNonce, err = hexField(obj, "receiver_session_nonce", 32); err != nil {
		return out, err
	}
	if out.EndpointNonce, err = hexField(obj, "endpoint_nonce", 32); err != nil {
		return out, err
	}
	if err = literalString(obj, "receiver_spiffe_id", receiverSPIFFEID); err != nil {
		return out, err
	}
	if err = literalString(obj, "expected_observer_spiffe_id", observerSPIFFEID); err != nil {
		return out, err
	}
	if out.AcceptedLimits, err = parseLimits(obj["accepted_limits"]); err != nil {
		return out, err
	}
	out.Schema = "ReceiverHelloV1"
	out.Version = 1
	out.ReceiverSPIFFEID = receiverSPIFFEID
	out.ExpectedObserverSPIFFEID = observerSPIFFEID
	return out, nil
}

func parseEvidencePayload(kind string, raw []byte) (any, error) {
	switch kind {
	case "SupervisorStartedV1":
		var out SupervisorStartedV1
		obj, err := exactObject(raw, maxEvidencePayloadBytes, "schema", "parent_pid", "pid", "process_group_id", "proc_start_token", "pid_namespace_device", "pid_namespace_inode", "mount_namespace_device", "mount_namespace_inode", "executable_sha256", "pidfd_bound", "execution_authority_digest")
		if err != nil {
			return nil, err
		}
		if err = literalString(obj, "schema", kind); err != nil {
			return nil, err
		}
		if err = literalInt(obj, "parent_pid", 1); err != nil {
			return nil, err
		}
		out.ParentPID = 1
		if out.PID, err = intField(obj, "pid", 2, maxPID); err != nil {
			return nil, err
		}
		if out.ProcessGroupID, err = intField(obj, "process_group_id", out.PID, out.PID); err != nil {
			return nil, err
		}
		if out.ProcStartToken, err = asciiTextField(obj, "proc_start_token", 256, false); err != nil {
			return nil, err
		}
		for _, v := range []struct {
			key string
			dst *int64
		}{{"pid_namespace_device", &out.PIDNamespaceDevice}, {"pid_namespace_inode", &out.PIDNamespaceInode}, {"mount_namespace_device", &out.MountNamespaceDevice}, {"mount_namespace_inode", &out.MountNamespaceInode}} {
			if *v.dst, err = intField(obj, v.key, 0, maxSelectedInteger); err != nil {
				return nil, err
			}
		}
		if out.ExecutableSHA256, err = hexField(obj, "executable_sha256", 64); err != nil {
			return nil, err
		}
		if err = literalBool(obj, "pidfd_bound", true); err != nil {
			return nil, err
		}
		out.PIDFDBound = true
		if out.ExecutionAuthorityDigest, err = hexField(obj, "execution_authority_digest", 64); err != nil {
			return nil, err
		}
		return out, nil
	case "SupervisorExitObservedV1":
		var out SupervisorExitObservedV1
		obj, err := exactObject(raw, maxEvidencePayloadBytes, "schema", "pid", "proc_start_token", "wait_code_kind", "exit_code", "signal", "core_dumped", "observed_by_pid", "identity_match")
		if err != nil {
			return nil, err
		}
		if err = literalString(obj, "schema", kind); err != nil {
			return nil, err
		}
		if out.PID, err = intField(obj, "pid", 2, maxPID); err != nil {
			return nil, err
		}
		if out.ProcStartToken, err = asciiTextField(obj, "proc_start_token", 256, true); err != nil {
			return nil, err
		}
		if out.WaitCodeKind, err = enumField(obj, "wait_code_kind", "exited", "signaled"); err != nil {
			return nil, err
		}
		if out.WaitCodeKind == "exited" {
			value, e := intField(obj, "exit_code", 0, 255)
			if e != nil {
				return nil, e
			}
			out.ExitCode = &value
			if obj["signal"] != nil {
				return nil, structuralError("signal")
			}
			if err = literalBool(obj, "core_dumped", false); err != nil {
				return nil, err
			}
		} else {
			if obj["exit_code"] != nil {
				return nil, structuralError("exit_code")
			}
			value, e := intField(obj, "signal", 1, 64)
			if e != nil {
				return nil, e
			}
			out.Signal = &value
			if out.CoreDumped, err = boolField(obj, "core_dumped"); err != nil {
				return nil, err
			}
		}
		if err = literalInt(obj, "observed_by_pid", 1); err != nil {
			return nil, err
		}
		out.ObservedByPID = 1
		if err = literalBool(obj, "identity_match", true); err != nil {
			return nil, err
		}
		out.IdentityMatch = true
		return out, nil
	case "SupervisorReapedV1":
		var out SupervisorReapedV1
		obj, err := exactObject(raw, maxEvidencePayloadBytes, "schema", "pid", "proc_start_token", "pidfd_bound", "reap_count", "wait_owner_pid", "terminal_status_sha256")
		if err != nil {
			return nil, err
		}
		if err = literalString(obj, "schema", kind); err != nil {
			return nil, err
		}
		if out.PID, err = intField(obj, "pid", 2, maxPID); err != nil {
			return nil, err
		}
		if out.ProcStartToken, err = asciiTextField(obj, "proc_start_token", 256, true); err != nil {
			return nil, err
		}
		if err = literalBool(obj, "pidfd_bound", true); err != nil {
			return nil, err
		}
		out.PIDFDBound = true
		if err = literalInt(obj, "reap_count", 1); err != nil {
			return nil, err
		}
		out.ReapCount = 1
		if err = literalInt(obj, "wait_owner_pid", 1); err != nil {
			return nil, err
		}
		out.WaitOwnerPID = 1
		if out.TerminalStatusSHA256, err = hexField(obj, "terminal_status_sha256", 64); err != nil {
			return nil, err
		}
		return out, nil
	case "NamespaceDrainedV1":
		var out NamespaceDrainedV1
		obj, err := exactObject(raw, maxEvidencePayloadBytes, "schema", "supervisor_pid", "term_signal_count", "kill_signal_count", "reaped_descendant_count", "remaining_pids", "waitid_all_result")
		if err != nil {
			return nil, err
		}
		if err = literalString(obj, "schema", kind); err != nil {
			return nil, err
		}
		if out.SupervisorPID, err = intField(obj, "supervisor_pid", 2, maxPID); err != nil {
			return nil, err
		}
		for _, v := range []struct {
			key string
			dst *int64
		}{{"term_signal_count", &out.TermSignalCount}, {"kill_signal_count", &out.KillSignalCount}, {"reaped_descendant_count", &out.ReapedDescendantCount}} {
			if *v.dst, err = intField(obj, v.key, 0, maxSelectedInteger); err != nil {
				return nil, err
			}
		}
		remaining, ok := obj["remaining_pids"].([]any)
		if !ok || len(remaining) != 0 {
			return nil, structuralError("remaining_pids")
		}
		out.RemainingPIDs = []int64{}
		if err = literalString(obj, "waitid_all_result", "ECHILD"); err != nil {
			return nil, err
		}
		out.WaitIDAllResult = "ECHILD"
		return out, nil
	case "SourceCompleteV1":
		var out SourceCompleteV1
		obj, err := exactObject(raw, maxEvidencePayloadBytes, "schema", "result_kind", "supervisor_terminal_status_sha256", "supervisor_reaped_once", "namespace_drained", "last_nonfinal_record_hash", "evidence_failure", "terminal_reason")
		if err != nil {
			return nil, err
		}
		if err = literalString(obj, "schema", kind); err != nil {
			return nil, err
		}
		if out.ResultKind, err = enumField(obj, "result_kind", "success", "supervisor_failure", "observer_failure"); err != nil {
			return nil, err
		}
		if out.SupervisorTerminalStatusSHA256, err = hexField(obj, "supervisor_terminal_status_sha256", 64); err != nil {
			return nil, err
		}
		if err = literalBool(obj, "supervisor_reaped_once", true); err != nil {
			return nil, err
		}
		out.SupervisorReapedOnce = true
		if err = literalBool(obj, "namespace_drained", true); err != nil {
			return nil, err
		}
		out.NamespaceDrained = true
		if out.LastNonfinalRecordHash, err = hexField(obj, "last_nonfinal_record_hash", 64); err != nil {
			return nil, err
		}
		if out.EvidenceFailure, err = boolField(obj, "evidence_failure"); err != nil {
			return nil, err
		}
		if out.ResultKind == "success" && out.EvidenceFailure {
			return nil, structuralError("evidence_failure")
		}
		if out.TerminalReason, err = asciiTextField(obj, "terminal_reason", 256, true); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, structuralError("payload_type")
	}
}
