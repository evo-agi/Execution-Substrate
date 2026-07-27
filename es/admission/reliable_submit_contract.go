package admission

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	reliableSubmitRequestSchemaV1 = "execution-substrate.reliable-submit-request/v1"
	reliableSubmitContractV1      = "execution-substrate.reliable-submit/v1"
	reliableSubmitDiscriminator   = "reliable_submit"
	reliableSubmitContractField   = "contract"
	reliableSubmitKeyField        = "submit_key"

	reliableSubmitKeyEncodedLength = 43
	reliableSubmitKeyRawLength     = 32
)

var (
	errReliableSubmitInvalidRequest = errors.New("reliable submit request: invalid request")
	errReliableSubmitInvalidKey     = errors.New("reliable submit request: invalid canonical submit key encoding")
)

type validatedReliableSubmitRequest struct {
	schemaVersion  string
	contract       string
	invocation     ArtifactInvocation
	effectiveMode  ExecutionMode
	timeoutSeconds int
	resources      ExecutionResources
	resourcesGiven bool
	claimRefs      reliableSubmitClaimRefs
}

func parseValidatedReliableSubmitRequest(payload []byte, canonicalSPIFFEURI string) (validatedReliableSubmitRequest, error) {
	type reliableSubmitWireMarker struct {
		Contract  string `json:"contract"`
		SubmitKey string `json:"submit_key"`
	}
	type reliableSubmitWireRequest struct {
		SchemaVersion  string                   `json:"schema_version"`
		ReliableSubmit reliableSubmitWireMarker `json:"reliable_submit"`
		Invocation     ArtifactInvocation       `json:"invocation"`
		Mode           ExecutionMode            `json:"mode,omitempty"`
		TimeoutSeconds int                      `json:"timeout_seconds,omitempty"`
		Resources      *ExecutionResources      `json:"resources,omitempty"`
	}

	var wire reliableSubmitWireRequest
	if err := decodeStrictReliableSubmitJSON(payload, &wire); err != nil {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}
	if wire.SchemaVersion != reliableSubmitRequestSchemaV1 {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}
	if wire.ReliableSubmit.Contract != reliableSubmitContractV1 {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}

	rawSubmitKey, err := decodeCanonicalReliableSubmitKey(wire.ReliableSubmit.SubmitKey)
	if err != nil {
		return validatedReliableSubmitRequest{}, err
	}
	refs, err := deriveReliableSubmitClaimRefs(canonicalSPIFFEURI, rawSubmitKey)
	if err != nil {
		return validatedReliableSubmitRequest{}, err
	}

	mode := wire.Mode
	if mode == "" {
		mode = ExecutionModeAsync
	}
	if mode != ExecutionModeAsync {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}
	if wire.TimeoutSeconds < 0 {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}
	if wire.Resources != nil && (wire.Resources.CPU <= 0 || wire.Resources.MemoryMB <= 0) {
		return validatedReliableSubmitRequest{}, errReliableSubmitInvalidRequest
	}

	validated := validatedReliableSubmitRequest{
		schemaVersion:  wire.SchemaVersion,
		contract:       wire.ReliableSubmit.Contract,
		invocation:     cloneReliableSubmitInvocation(wire.Invocation),
		effectiveMode:  mode,
		timeoutSeconds: wire.TimeoutSeconds,
		resourcesGiven: wire.Resources != nil,
		claimRefs:      refs,
	}
	if wire.Resources != nil {
		validated.resources = *wire.Resources
	}

	return validated, nil
}

func decodeStrictReliableSubmitJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	for _, ch := range payload[decoder.InputOffset():] {
		switch ch {
		case ' ', '\n', '\r', '\t':
		default:
			return errReliableSubmitInvalidRequest
		}
	}
	return nil
}

func cloneReliableSubmitInvocation(invocation ArtifactInvocation) ArtifactInvocation {
	cloned := invocation
	cloned.Argv = append([]string(nil), invocation.Argv...)
	cloned.Mounts = append([]RuntimeMount(nil), invocation.Mounts...)
	if invocation.Env != nil {
		cloned.Env = make(map[string]string, len(invocation.Env))
		for key, value := range invocation.Env {
			cloned.Env[key] = value
		}
	}
	if invocation.Annotations != nil {
		cloned.Annotations = make(map[string]string, len(invocation.Annotations))
		for key, value := range invocation.Annotations {
			cloned.Annotations[key] = value
		}
	}
	return cloned
}

func decodeCanonicalReliableSubmitKey(encoded string) ([reliableSubmitKeyRawLength]byte, error) {
	var key [reliableSubmitKeyRawLength]byte
	if len(encoded) != reliableSubmitKeyEncodedLength {
		return key, errReliableSubmitInvalidKey
	}
	for _, ch := range encoded {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_':
		default:
			return key, errReliableSubmitInvalidKey
		}
	}
	if strings.Contains(encoded, "=") {
		return key, errReliableSubmitInvalidKey
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return key, errReliableSubmitInvalidKey
	}
	if len(raw) != reliableSubmitKeyRawLength {
		return key, errReliableSubmitInvalidKey
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return key, errReliableSubmitInvalidKey
	}

	copy(key[:], raw)
	return key, nil
}
