package admission

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"execution-substrate/es/admission/internal/grantcaller"
)

var errPrivateReplayInvalidDelivery = errors.New("private replay: invalid synthetic delivery")

// syntheticCallerFact is the caller a private reliable submit delivery is
// bound to. canonicalURI keys the delivery's claim refs; grant is the
// caller its workload grants match on, built from the same URI when the
// fact is made (withDeliveryCaller).
type syntheticCallerFact struct {
	privateExecutionValue
	canonicalURI string
	grant        grantcaller.Caller
	valid        bool
}

func newSyntheticCallerFact(canonicalURI string) (syntheticCallerFact, error) {
	if !validReliableSubmitCallerURI(canonicalURI) {
		return syntheticCallerFact{}, errPrivateReplayInvalidDelivery
	}
	return syntheticCallerFact{canonicalURI: canonicalURI, grant: grantcaller.FromDelivery(canonicalURI), valid: true}, nil
}

type replayPresence[T any] struct {
	present bool
	value   T
}

type privateReplayOriginalMount struct {
	privateExecutionValue
	artifactDigest string
	targetPath     string
	readOnly       replayPresence[bool]
}

type privateReplayOriginalIntent struct {
	privateExecutionValue
	outerSchema       string
	contract          string
	invocationPresent bool
	invocationSchema  replayPresence[string]
	artifactDigest    string
	derivationDigest  string
	outputID          string
	mode              replayPresence[string]
	timeout           replayPresence[uint32]
	resources         replayPresence[ExecutionResources]
	argv              replayPresence[[]string]
	env               replayPresence[map[string]string]
	mounts            replayPresence[[]privateReplayOriginalMount]
	annotations       replayPresence[map[string]string]
	profile           replayPresence[string]
}

type privateReplayDelivery struct {
	privateExecutionValue
	request        PrepareRequest
	originalIntent privateReplayOriginalIntent
	family         reliableBindingFamily
	refs           reliableSubmitClaimRefs
}

type privateJSONNumber string
type privateJSONParser struct {
	raw      []byte
	offset   int
	nodes    int
	elements int
}

func parsePrivateReplayDelivery(raw []byte, caller syntheticCallerFact) (privateReplayDelivery, error) {
	if !caller.valid || len(raw) == 0 || len(raw) > 262144 || !utf8.Valid(raw) {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	p := privateJSONParser{raw: raw}
	value, err := p.value(1)
	if err != nil {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	p.space()
	if p.offset != len(raw) {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	outer, ok := value.(map[string]any)
	if !ok || !privateObjectFields(outer, "schema_version", "reliable_submit", "invocation", "mode", "timeout_seconds", "resources") {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	schema, ok := privateRequiredString(outer, "schema_version", 64)
	if !ok || schema != reliableSubmitRequestSchemaV1 {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	reliable, ok := privateRequiredObject(outer, "reliable_submit", "contract", "submit_key")
	if !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	contract, ok := privateRequiredString(reliable, "contract", 64)
	if !ok || contract != reliableSubmitContractV1 {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	encodedKey, ok := privateRequiredString(reliable, "submit_key", 43)
	if !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	rawKey, err := decodeCanonicalReliableSubmitKey(encodedKey)
	if err != nil {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	refs, err := deriveReliableSubmitClaimRefs(caller.canonicalURI, rawKey)
	if err != nil {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	invocation, ok := privateRequiredObject(outer, "invocation", "schema_version", "artifact_digest", "derivation_spec_digest", "output_id", "argv", "env", "mounts", "annotations")
	if !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	intent := privateReplayOriginalIntent{outerSchema: schema, contract: contract, invocationPresent: true}
	if intent.invocationSchema, ok = privateOptionalString(invocation, "schema_version", 64); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.invocationSchema.present && intent.invocationSchema.value != "" && intent.invocationSchema.value != "v1" {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.artifactDigest, ok = privateRequiredString(invocation, "artifact_digest", 256); !ok || intent.artifactDigest == "" {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.derivationDigest, ok = privateRequiredString(invocation, "derivation_spec_digest", 256); !ok || intent.derivationDigest == "" {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.outputID, ok = privateRequiredString(invocation, "output_id", 256); !ok || intent.outputID == "" {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.mode, ok = privateOptionalString(outer, "mode", 32); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.mode.present && intent.mode.value != "" && intent.mode.value != string(ExecutionModeAsync) {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.timeout, ok = privateOptionalUint(outer, "timeout_seconds", 0, 2147483647); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if resources, present := outer["resources"]; present {
		object, ok := resources.(map[string]any)
		if !ok || !privateObjectFields(object, "cpu", "memory_mb") || len(object) != 2 {
			return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
		}
		cpu, ok := privateRequiredUint(object, "cpu", 1, 2147483647)
		if !ok {
			return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
		}
		memory, ok := privateRequiredUint(object, "memory_mb", 1, 2147483647)
		if !ok {
			return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
		}
		intent.resources = replayPresence[ExecutionResources]{true, ExecutionResources{CPU: int(cpu), MemoryMB: int(memory)}}
	}
	if intent.argv, ok = privateOptionalStrings(invocation, "argv", 100, 65536); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.env, ok = privateOptionalStringMap(invocation, "env", 128); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if intent.annotations, ok = privateOptionalStringMap(invocation, "annotations", 128); !ok {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	if value, present := intent.annotations.value[runtimeProfileAnnotationKey]; present {
		intent.annotations.value[runtimeProfileAnnotationKey] = strings.TrimSpace(value)
		intent.profile = replayPresence[string]{true, strings.TrimSpace(value)}
	}
	if rawMounts, present := invocation["mounts"]; present {
		sequence, ok := rawMounts.([]any)
		if !ok || len(sequence) > 8 {
			return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
		}
		intent.mounts.present = true
		intent.mounts.value = make([]privateReplayOriginalMount, 0, len(sequence))
		for _, item := range sequence {
			mount, ok := item.(map[string]any)
			if !ok || !privateObjectFields(mount, "source", "target_path", "read_only") {
				return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
			}
			source, ok := privateRequiredObject(mount, "source", "artifact_digest")
			if !ok {
				return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
			}
			artifact, ok := privateRequiredString(source, "artifact_digest", 256)
			if !ok || artifact == "" {
				return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
			}
			target, ok := privateRequiredString(mount, "target_path", 4096)
			if !ok {
				return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
			}
			target, err = normalizeRuntimeMountTargetPath(target)
			if err != nil {
				return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
			}
			entry := privateReplayOriginalMount{artifactDigest: artifact, targetPath: target}
			if readOnly, present := mount["read_only"]; present {
				value, ok := readOnly.(bool)
				if !ok {
					return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
				}
				entry.readOnly = replayPresence[bool]{true, value}
			}
			intent.mounts.value = append(intent.mounts.value, entry)
		}
	}
	family, err := newReliableBindingFamily(schema, contract)
	if err != nil {
		return privateReplayDelivery{}, errPrivateReplayInvalidDelivery
	}
	request := PrepareRequest{SchemaVersion: "v1", Invocation: ArtifactInvocation{
		SchemaVersion: intent.invocationSchema.value, ArtifactDigest: intent.artifactDigest,
		DerivationSpecDigest: intent.derivationDigest, OutputID: intent.outputID,
		Argv: intent.argv.value, Env: intent.env.value, Annotations: intent.annotations.value,
	}, Mode: ExecutionMode(intent.mode.value), TimeoutSeconds: int(intent.timeout.value)}
	if intent.resources.present {
		resources := intent.resources.value
		request.Resources = &resources
	}
	if intent.mounts.present {
		request.Invocation.Mounts = make([]RuntimeMount, 0, len(intent.mounts.value))
		for _, mount := range intent.mounts.value {
			request.Invocation.Mounts = append(request.Invocation.Mounts, RuntimeMount{
				Source: MountSource{ArtifactDigest: mount.artifactDigest}, TargetPath: mount.targetPath, ReadOnly: mount.readOnly.value})
		}
	}
	return privateReplayDelivery{request: request, originalIntent: intent, family: family, refs: refs}, nil
}

func privateObjectFields(object map[string]any, allowed ...string) bool {
	for key := range object {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func privateRequiredObject(object map[string]any, key string, allowed ...string) (map[string]any, bool) {
	value, present := object[key]
	if !present {
		return nil, false
	}
	result, ok := value.(map[string]any)
	return result, ok && privateObjectFields(result, allowed...)
}

func privateRequiredString(object map[string]any, key string, max int) (string, bool) {
	value, present := object[key]
	if !present {
		return "", false
	}
	s, ok := value.(string)
	return s, ok && len(s) <= max
}

func privateOptionalString(object map[string]any, key string, max int) (replayPresence[string], bool) {
	value, present := object[key]
	if !present {
		return replayPresence[string]{}, true
	}
	s, ok := value.(string)
	if !ok || len(s) > max {
		return replayPresence[string]{}, false
	}
	return replayPresence[string]{true, s}, true
}

func privateRequiredUint(object map[string]any, key string, min, max uint32) (uint32, bool) {
	value, present := object[key]
	if !present {
		return 0, false
	}
	number, ok := value.(privateJSONNumber)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(string(number), 10, 32)
	return uint32(parsed), err == nil && uint32(parsed) >= min && uint32(parsed) <= max
}

func privateOptionalUint(object map[string]any, key string, min, max uint32) (replayPresence[uint32], bool) {
	if _, present := object[key]; !present {
		return replayPresence[uint32]{}, true
	}
	value, ok := privateRequiredUint(object, key, min, max)
	if !ok {
		return replayPresence[uint32]{}, false
	}
	return replayPresence[uint32]{true, value}, true
}

func privateOptionalStrings(object map[string]any, key string, maxCount, maxBytes int) (replayPresence[[]string], bool) {
	value, present := object[key]
	if !present {
		return replayPresence[[]string]{}, true
	}
	items, ok := value.([]any)
	if !ok || len(items) > maxCount {
		return replayPresence[[]string]{}, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok || len(s) > maxBytes {
			return replayPresence[[]string]{}, false
		}
		result = append(result, s)
	}
	return replayPresence[[]string]{true, result}, true
}

func privateOptionalStringMap(object map[string]any, key string, maxCount int) (replayPresence[map[string]string], bool) {
	value, present := object[key]
	if !present {
		return replayPresence[map[string]string]{}, true
	}
	items, ok := value.(map[string]any)
	if !ok || len(items) > maxCount {
		return replayPresence[map[string]string]{}, false
	}
	result := make(map[string]string, len(items))
	for k, item := range items {
		s, ok := item.(string)
		if !ok || len(k) > 1024 || len(s) > 65536 {
			return replayPresence[map[string]string]{}, false
		}
		result[k] = s
	}
	return replayPresence[map[string]string]{true, result}, true
}

func (p *privateJSONParser) space() {
	for p.offset < len(p.raw) {
		switch p.raw[p.offset] {
		case ' ', '\t', '\n', '\r':
			p.offset++
		default:
			return
		}
	}
}

func (p *privateJSONParser) value(depth int) (any, error) {
	if depth > 8 || p.nodes >= 32768 {
		return nil, errPrivateReplayInvalidDelivery
	}
	p.nodes++
	p.space()
	if p.offset >= len(p.raw) {
		return nil, errPrivateReplayInvalidDelivery
	}
	switch p.raw[p.offset] {
	case '{':
		return p.object(depth)
	case '[':
		return p.array(depth)
	case '"':
		return p.string()
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return p.number()
	}
	return nil, errPrivateReplayInvalidDelivery
}

func (p *privateJSONParser) literal(s string) bool {
	if len(p.raw)-p.offset < len(s) || string(p.raw[p.offset:p.offset+len(s)]) != s {
		return false
	}
	p.offset += len(s)
	return true
}

func (p *privateJSONParser) number() (privateJSONNumber, error) {
	start := p.offset
	if p.raw[p.offset] == '0' {
		p.offset++
	} else {
		for p.offset < len(p.raw) && p.raw[p.offset] >= '0' && p.raw[p.offset] <= '9' {
			p.offset++
		}
	}
	if p.offset < len(p.raw) {
		ch := p.raw[p.offset]
		if ch == '.' || ch == 'e' || ch == 'E' || ch == '-' || ch == '+' || ch >= '0' && ch <= '9' {
			return "", errPrivateReplayInvalidDelivery
		}
	}
	return privateJSONNumber(p.raw[start:p.offset]), nil
}

func (p *privateJSONParser) object(depth int) (map[string]any, error) {
	p.offset++
	p.space()
	result := make(map[string]any)
	if p.offset < len(p.raw) && p.raw[p.offset] == '}' {
		p.offset++
		return result, nil
	}
	for {
		p.space()
		if p.offset >= len(p.raw) || p.raw[p.offset] != '"' || len(result) >= 32768 {
			return nil, errPrivateReplayInvalidDelivery
		}
		key, err := p.string()
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errPrivateReplayInvalidDelivery
		}
		p.space()
		if p.offset >= len(p.raw) || p.raw[p.offset] != ':' {
			return nil, errPrivateReplayInvalidDelivery
		}
		p.offset++
		value, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		result[key] = value
		p.space()
		if p.offset >= len(p.raw) {
			return nil, errPrivateReplayInvalidDelivery
		}
		if p.raw[p.offset] == '}' {
			p.offset++
			return result, nil
		}
		if p.raw[p.offset] != ',' {
			return nil, errPrivateReplayInvalidDelivery
		}
		p.offset++
	}
}

func (p *privateJSONParser) array(depth int) ([]any, error) {
	p.offset++
	p.space()
	result := make([]any, 0)
	if p.offset < len(p.raw) && p.raw[p.offset] == ']' {
		p.offset++
		return result, nil
	}
	for {
		if p.elements >= 8192 {
			return nil, errPrivateReplayInvalidDelivery
		}
		p.elements++
		value, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
		p.space()
		if p.offset >= len(p.raw) {
			return nil, errPrivateReplayInvalidDelivery
		}
		if p.raw[p.offset] == ']' {
			p.offset++
			return result, nil
		}
		if p.raw[p.offset] != ',' {
			return nil, errPrivateReplayInvalidDelivery
		}
		p.offset++
	}
}

func (p *privateJSONParser) string() (string, error) {
	if p.offset >= len(p.raw) || p.raw[p.offset] != '"' {
		return "", errPrivateReplayInvalidDelivery
	}
	p.offset++
	out := make([]byte, 0, 64)
	for p.offset < len(p.raw) {
		ch := p.raw[p.offset]
		p.offset++
		if ch == '"' {
			return string(out), nil
		}
		if ch < 0x20 {
			return "", errPrivateReplayInvalidDelivery
		}
		if ch != '\\' {
			out = append(out, ch)
			continue
		}
		if p.offset >= len(p.raw) {
			return "", errPrivateReplayInvalidDelivery
		}
		escape := p.raw[p.offset]
		p.offset++
		switch escape {
		case '"', '\\', '/':
			out = append(out, escape)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			first, ok := p.hex4()
			if !ok {
				return "", errPrivateReplayInvalidDelivery
			}
			if first >= 0xD800 && first <= 0xDBFF {
				if p.offset+2 > len(p.raw) || p.raw[p.offset] != '\\' || p.raw[p.offset+1] != 'u' {
					return "", errPrivateReplayInvalidDelivery
				}
				p.offset += 2
				second, ok := p.hex4()
				if !ok || second < 0xDC00 || second > 0xDFFF {
					return "", errPrivateReplayInvalidDelivery
				}
				first = 0x10000 + (first-0xD800)*0x400 + (second - 0xDC00)
			} else if first >= 0xDC00 && first <= 0xDFFF {
				return "", errPrivateReplayInvalidDelivery
			}
			out = utf8.AppendRune(out, rune(first))
		default:
			return "", errPrivateReplayInvalidDelivery
		}
		if len(out) > 262144 {
			return "", errPrivateReplayInvalidDelivery
		}
	}
	return "", errPrivateReplayInvalidDelivery
}

func (p *privateJSONParser) hex4() (uint32, bool) {
	if len(p.raw)-p.offset < 4 {
		return 0, false
	}
	var value uint32
	for range 4 {
		ch := p.raw[p.offset]
		p.offset++
		value <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			value += uint32(ch - '0')
		case ch >= 'a' && ch <= 'f':
			value += uint32(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			value += uint32(ch-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
