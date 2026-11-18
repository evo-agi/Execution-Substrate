package reliablesubmit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	replayPayloadLimit = 1 << 20
	replaySealedLimit  = 2 << 20
	replayHeaderLimit  = 4 << 10
	replayNodeLimit    = 32768
	replayElementLimit = 8192
)

var errReplayFormat = errors.New("private replay custody: invalid format")

// privateReplayRedacted gives new private values one fixed formatting result.
// It is not an authorization to log or serialize the underlying value.
type privateReplayRedacted struct{}

func (privateReplayRedacted) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("<private replay value redacted>"))
}

type replayField struct {
	privateReplayRedacted
	id    uint16
	state byte
	value []byte
}

type replayDecodeBudget struct {
	privateReplayRedacted
	nodes       int
	elements    int
	leafBytes   int
	containers  int
	objectDepth int
}

func (b *replayDecodeBudget) addLeaf(length int) error {
	if length < 0 || length > replayPayloadLimit || b.leafBytes > replayPayloadLimit-length {
		return errReplayFormat
	}
	b.leafBytes += length
	return nil
}

func (b *replayDecodeBudget) addElements(count int) error {
	if count < 0 || count > replayElementLimit || b.elements > replayElementLimit-count {
		return errReplayFormat
	}
	b.elements += count
	return nil
}

func encodeReplayField(field replayField) ([]byte, error) {
	if field.id == 0 || field.state > 1 || len(field.value) > replayPayloadLimit ||
		(field.state == 0 && len(field.value) != 0) {
		return nil, errReplayFormat
	}
	encoded := make([]byte, 7+len(field.value))
	binary.BigEndian.PutUint16(encoded[:2], field.id)
	encoded[2] = field.state
	binary.BigEndian.PutUint32(encoded[3:7], uint32(len(field.value)))
	copy(encoded[7:], field.value)
	return encoded, nil
}

func encodeReplayObject(fields []replayField) ([]byte, error) {
	if len(fields) > 65535 {
		return nil, errReplayFormat
	}
	used := 2
	var previous uint16
	for _, field := range fields {
		if field.id == 0 || field.id <= previous || field.state > 1 ||
			(field.state == 0 && len(field.value) != 0) ||
			len(field.value) > replayPayloadLimit ||
			used > replayPayloadLimit-7-len(field.value) {
			return nil, errReplayFormat
		}
		used += 7 + len(field.value)
		previous = field.id
	}
	encoded := make([]byte, used)
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(fields)))
	offset := 2
	for _, field := range fields {
		binary.BigEndian.PutUint16(encoded[offset:offset+2], field.id)
		encoded[offset+2] = field.state
		binary.BigEndian.PutUint32(encoded[offset+3:offset+7], uint32(len(field.value)))
		copy(encoded[offset+7:], field.value)
		offset += 7 + len(field.value)
	}
	return encoded, nil
}

// parseReplayObject borrows its bounded input. Its caller must finish all
// semantic checks before releasing the authenticated plaintext buffer.
func parseReplayObject(raw []byte, expectedCount int, budget *replayDecodeBudget, objectDepth int, containerDepth int) ([]replayField, error) {
	if budget == nil || expectedCount < 0 || expectedCount > 65535 ||
		len(raw) < 2 || len(raw) > replayPayloadLimit ||
		objectDepth > 5 || containerDepth > 8 {
		return nil, errReplayFormat
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	if count != expectedCount || budget.nodes > replayNodeLimit-count {
		return nil, errReplayFormat
	}
	fields := make([]replayField, 0, count)
	offset := 2
	for i := 1; i <= count; i++ {
		if len(raw)-offset < 7 {
			return nil, errReplayFormat
		}
		id := binary.BigEndian.Uint16(raw[offset : offset+2])
		state := raw[offset+2]
		length := binary.BigEndian.Uint32(raw[offset+3 : offset+7])
		offset += 7
		if id != uint16(i) || state > 1 || length > uint32(len(raw)-offset) ||
			state == 0 && length != 0 {
			return nil, errReplayFormat
		}
		fields = append(fields, replayField{id: id, state: state, value: raw[offset : offset+int(length)]})
		offset += int(length)
	}
	if offset != len(raw) {
		return nil, errReplayFormat
	}
	budget.nodes += count
	return fields, nil
}

func replayRequirePresent(fields []replayField, id int, length int) ([]byte, error) {
	if id < 1 || id > len(fields) || fields[id-1].state != 1 {
		return nil, errReplayFormat
	}
	value := fields[id-1].value
	if length >= 0 && len(value) != length {
		return nil, errReplayFormat
	}
	return value, nil
}

func parseReplaySequence(raw []byte, maxCount int, budget *replayDecodeBudget, containerDepth int, visit func([]byte) error) error {
	if budget == nil || visit == nil || len(raw) < 2 || len(raw) > replayPayloadLimit ||
		containerDepth > 8 {
		return errReplayFormat
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	if count > maxCount || budget.addElements(count) != nil {
		return errReplayFormat
	}
	offset := 2
	for i := 0; i < count; i++ {
		if len(raw)-offset < 4 {
			return errReplayFormat
		}
		length := binary.BigEndian.Uint32(raw[offset : offset+4])
		offset += 4
		if length > uint32(len(raw)-offset) {
			return errReplayFormat
		}
		if err := visit(raw[offset : offset+int(length)]); err != nil {
			return err
		}
		offset += int(length)
	}
	if offset != len(raw) {
		return errReplayFormat
	}
	return nil
}

type PrivateReplayFrozen struct {
	privateReplayRedacted
	claim      ClaimID
	plan       BoundPlan
	keys       PrivateReplayKeys
	plaintext  []byte
	header     []byte
	aad        []byte
	objectID   [32]byte
	intentMAC  [32]byte
	contextMAC [32]byte
	digest     [32]byte
}

func NewPrivateReplayFrozen(claim ClaimID, plan BoundPlan, keys PrivateReplayKeys, plaintext []byte) (PrivateReplayFrozen, error) {
	if !claim.Valid() || !plan.Valid() || !keys.valid || len(plaintext) < 14 || len(plaintext) > replayPayloadLimit ||
		len(claim.caller.ref.value) != 32 || len(claim.submitKey.ref.value) != 32 ||
		len(plan.binding.ref.value) < 1 || len(plan.binding.ref.value) > 256 {
		return PrivateReplayFrozen{}, errReplayFormat
	}
	fields, err := parsePrivateReplayPayload(plaintext)
	if err != nil {
		return PrivateReplayFrozen{}, err
	}
	if err := checkReplayPayloadAssociations(fields, claim, plan, keys); err != nil {
		return PrivateReplayFrozen{}, err
	}
	intentWire, _ := encodeReplayField(fields[1])
	contextWire := make([]byte, 0)
	for _, field := range fields[5:8] {
		encoded, _ := encodeReplayField(field)
		contextWire = append(contextWire, encoded...)
	}
	intentMAC := replayHMAC(keys.binding, "ESRSINT1", intentWire)
	contextMAC := replayHMAC(keys.binding, "ESRSCTX1", contextWire)
	var objectID [32]byte
	if _, err := rand.Read(objectID[:]); err != nil {
		return PrivateReplayFrozen{}, errClaimStoreUnavailable
	}
	header, err := encodePrivateReplayHeader(claim, plan, keys, objectID, intentMAC, contextMAC, len(plaintext))
	if err != nil {
		return PrivateReplayFrozen{}, err
	}
	aad := append([]byte("ESRSAAD1"), header...)
	frozen := PrivateReplayFrozen{
		claim: claim.clone(), plan: plan.clone(), keys: keys,
		plaintext: append([]byte(nil), plaintext...), header: header, aad: aad,
		objectID: objectID, intentMAC: intentMAC, contextMAC: contextMAC,
	}
	frozen.digest = replayFrozenDigest(keys, frozen.header, frozen.plaintext)
	return frozen, nil
}

func replayFrozenDigest(keys PrivateReplayKeys, header, plaintext []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("ESRSFRZ1"))
	_, _ = h.Write(keys.bindingFP[:])
	_, _ = h.Write(keys.envelopeFP[:])
	_, _ = h.Write(header)
	_, _ = h.Write(plaintext)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func replayHMAC(key [32]byte, domain string, raw []byte) [32]byte {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(raw)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func parsePrivateReplayPayload(raw []byte) ([]replayField, error) {
	if len(raw) < 16 || len(raw) > replayPayloadLimit || string(raw[:8]) != "ESRSPAY1" ||
		binary.BigEndian.Uint16(raw[8:10]) != 1 ||
		binary.BigEndian.Uint32(raw[10:14]) != uint32(len(raw)-14) {
		return nil, errReplayFormat
	}
	budget := &replayDecodeBudget{}
	fields, err := parseReplayObject(raw[14:], 10, budget, 1, 1)
	if err != nil {
		return nil, err
	}
	for _, field := range fields {
		if field.state != 1 {
			return nil, errReplayFormat
		}
	}
	if err := validateReplayPayloadStructure(fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func checkReplayPayloadAssociations(fields []replayField, claim ClaimID, plan BoundPlan, keys PrivateReplayKeys) error {
	budget := &replayDecodeBudget{}
	identity, err := parseReplayObject(fields[0].value, 2, budget, 2, 2)
	if err != nil {
		return err
	}
	caller, err := replayRequirePresent(identity, 1, 32)
	if err != nil || subtle.ConstantTimeCompare(caller, claim.caller.ref.value) != 1 {
		return errReplayFormat
	}
	submit, err := replayRequirePresent(identity, 2, 32)
	if err != nil || subtle.ConstantTimeCompare(submit, claim.submitKey.ref.value) != 1 {
		return errReplayFormat
	}
	assessment, err := parseReplayObject(fields[4].value, 4, budget, 2, 2)
	if err != nil {
		return err
	}
	binding, err := replayRequirePresent(assessment, 1, -1)
	if err != nil || len(binding) < 3 || int(binary.BigEndian.Uint16(binding[:2])) != len(binding)-2 ||
		subtle.ConstantTimeCompare(binding[2:], plan.binding.ref.value) != 1 {
		return errReplayFormat
	}
	resolved, inapplicable, err := sqliteWitnessMasks(plan.Witness())
	if err != nil {
		return errReplayFormat
	}
	resolvedRaw, err := replayRequirePresent(assessment, 2, 2)
	if err != nil || int64(binary.BigEndian.Uint16(resolvedRaw)) != resolved {
		return errReplayFormat
	}
	inapplicableRaw, err := replayRequirePresent(assessment, 3, 2)
	if err != nil || int64(binary.BigEndian.Uint16(inapplicableRaw)) != inapplicable {
		return errReplayFormat
	}
	if _, err := replayRequirePresent(assessment, 4, -1); err != nil {
		return err
	}
	keyFormats, err := parseReplayObject(fields[8].value, 6, budget, 2, 2)
	if err != nil {
		return err
	}
	for _, field := range keyFormats {
		if field.state != 1 {
			return errReplayFormat
		}
	}
	for _, id := range []int{1, 4, 5, 6} {
		value, err := replayRequirePresent(keyFormats, id, 2)
		if err != nil || binary.BigEndian.Uint16(value) != 1 {
			return errReplayFormat
		}
	}
	bindingID, err := replayRequirePresent(keyFormats, 2, -1)
	if err != nil || string(bindingID) != keys.bindingID {
		return errReplayFormat
	}
	envelopeID, err := replayRequirePresent(keyFormats, 3, -1)
	if err != nil || string(envelopeID) != keys.envelopeID {
		return errReplayFormat
	}
	scope, err := replayRequirePresent(fields, 10, 1)
	if err != nil || scope[0] != 1 {
		return errReplayFormat
	}
	return nil
}

func replayU16(value uint16) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], value)
	return out[:]
}
func replayU32(value uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out[:]
}

func encodePrivateReplayHeader(claim ClaimID, plan BoundPlan, keys PrivateReplayKeys, objectID [32]byte, intentMAC [32]byte, contextMAC [32]byte, plaintextSize int) ([]byte, error) {
	if plaintextSize < 14 || plaintextSize > replayPayloadLimit {
		return nil, errReplayFormat
	}
	values := [][]byte{
		replayU16(1), replayU16(1), {1}, replayU16(1), []byte(keys.bindingID),
		[]byte(keys.envelopeID), objectID[:], claim.caller.ref.value,
		claim.submitKey.ref.value, plan.binding.ref.value, intentMAC[:], contextMAC[:],
		replayU32(uint32(plaintextSize)), replayU32(uint32(plaintextSize + 28)),
	}
	fields := make([]replayField, 14)
	for i, value := range values {
		fields[i] = replayField{id: uint16(i + 1), state: 1, value: value}
	}
	body, err := encodeReplayObject(fields)
	if err != nil || len(body)+14 > replayHeaderLimit {
		return nil, errReplayFormat
	}
	header := make([]byte, 14+len(body))
	copy(header, "ESRSENV1")
	binary.BigEndian.PutUint16(header[8:10], 1)
	binary.BigEndian.PutUint32(header[10:14], uint32(len(header)))
	copy(header[14:], body)
	return header, nil
}

func parsePrivateReplayHeader(file []byte) ([]replayField, []byte, error) {
	if len(file) < 16 || len(file) > replaySealedLimit || string(file[:8]) != "ESRSENV1" ||
		binary.BigEndian.Uint16(file[8:10]) != 1 {
		return nil, nil, errReplayFormat
	}
	length := binary.BigEndian.Uint32(file[10:14])
	if length < 16 || length > replayHeaderLimit || length > uint32(len(file)) {
		return nil, nil, errReplayFormat
	}
	header := file[:length]
	fields, err := parseReplayObject(header[14:], 14, &replayDecodeBudget{}, 1, 1)
	if err != nil {
		return nil, nil, err
	}
	for _, field := range fields {
		if field.state != 1 {
			return nil, nil, errReplayFormat
		}
	}
	return fields, header, nil
}

func replayObjectRef(id [32]byte) string { return "objects/v1/" + hex.EncodeToString(id[:]) }

// EncodePrivateReplayAssessment is the one bounded binary-custody exception
// for the opaque PB1 binding and witness. It does not expose a general raw
// PlanBinding getter or change PB1's canonical HMAC producer.
func EncodePrivateReplayAssessment(plan BoundPlan, materialIdentityObject []byte) ([]byte, error) {
	if !plan.Valid() || len(plan.binding.ref.value) < 1 || len(plan.binding.ref.value) > 256 ||
		len(materialIdentityObject) < 2 || len(materialIdentityObject) > replayPayloadLimit {
		return nil, errReplayFormat
	}
	if _, err := parseReplayObject(materialIdentityObject, 5, &replayDecodeBudget{}, 1, 1); err != nil {
		return nil, err
	}
	resolved, inapplicable, err := sqliteWitnessMasks(plan.Witness())
	if err != nil {
		return nil, errReplayFormat
	}
	binding := make([]byte, 2+len(plan.binding.ref.value))
	binary.BigEndian.PutUint16(binding[:2], uint16(len(plan.binding.ref.value)))
	copy(binding[2:], plan.binding.ref.value)
	return encodeReplayObject([]replayField{
		{id: 1, state: 1, value: binding},
		{id: 2, state: 1, value: replayU16(uint16(resolved))},
		{id: 3, state: 1, value: replayU16(uint16(inapplicable))},
		{id: 4, state: 1, value: materialIdentityObject},
	})
}

func EncodePrivateReplayIdentity(claim ClaimID) ([]byte, error) {
	if !claim.Valid() || len(claim.caller.ref.value) != 32 || len(claim.submitKey.ref.value) != 32 {
		return nil, errReplayFormat
	}
	return encodeReplayObject([]replayField{
		{id: 1, state: 1, value: claim.caller.ref.value},
		{id: 2, state: 1, value: claim.submitKey.ref.value},
	})
}
