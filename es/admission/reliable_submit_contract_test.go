package admission

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/internal/httpx"
)

const reliableSubmitTestCallerURI = "spiffe://execution.internal/control-plane/test"

func TestReliableSubmitRequestParserAcceptsExactPrivateContract(t *testing.T) {
	keyText := reliableSubmitTestKeyString(0x11)
	body := reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: keyText})

	validated, err := parseValidatedReliableSubmitRequest(body, reliableSubmitTestCallerURI)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: reliable request parsing failed")
	}
	if validated.schemaVersion != reliableSubmitRequestSchemaV1 {
		reliableSubmitPrivacyFail(t, "privacy validation: schema classification mismatch")
	}
	if validated.contract != reliableSubmitContractV1 {
		reliableSubmitPrivacyFail(t, "privacy validation: reliable contract classification mismatch")
	}
	if validated.effectiveMode != ExecutionModeAsync {
		reliableSubmitPrivacyFail(t, "privacy validation: mode classification mismatch")
	}
	if validated.resourcesGiven {
		reliableSubmitPrivacyFail(t, "privacy validation: resource presence classification mismatch")
	}
	if !validated.claimRefs.callerRef.Valid() || !validated.claimRefs.submitKeyRef.Valid() || !validated.claimRefs.claimID.Valid() {
		reliableSubmitPrivacyFail(t, "privacy validation: safe reference classification mismatch")
	}
}

func TestReliableSubmitRequestParserRejectsMalformedMixedRequests(t *testing.T) {
	validKey := reliableSubmitTestKeyString(0x22)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		body   func(t *testing.T) []byte
	}{
		{
			name: "legacy schema with reliable marker",
			mutate: func(payload map[string]any) {
				payload["schema_version"] = "v1"
			},
		},
		{
			name: "reliable schema without discriminator contract",
			mutate: func(payload map[string]any) {
				payload[reliableSubmitDiscriminator].(map[string]any)[reliableSubmitContractField] = ""
			},
		},
		{
			name: "wrong reliable contract",
			mutate: func(payload map[string]any) {
				payload[reliableSubmitDiscriminator].(map[string]any)[reliableSubmitContractField] = "governed-execution-producer/v1"
			},
		},
		{
			name: "sync mode",
			mutate: func(payload map[string]any) {
				payload["mode"] = ExecutionModeSync
			},
		},
		{
			name: "negative timeout",
			mutate: func(payload map[string]any) {
				payload["timeout_seconds"] = -1
			},
		},
		{
			name: "empty resources object",
			mutate: func(payload map[string]any) {
				payload["resources"] = map[string]any{}
			},
		},
		{
			name: "partial resources object",
			mutate: func(payload map[string]any) {
				payload["resources"] = map[string]any{"cpu": 10}
			},
		},
		{
			name: "unknown top-level field",
			mutate: func(payload map[string]any) {
				payload["unexpected"] = true
			},
		},
		{
			name: "unknown reliable marker field",
			mutate: func(payload map[string]any) {
				payload[reliableSubmitDiscriminator].(map[string]any)["unexpected"] = true
			},
		},
		{
			name: "trailing data",
			body: func(t *testing.T) []byte {
				t.Helper()
				return append(reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: validKey}), []byte(` {}`)...)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(nil)
			if tc.body != nil {
				body = tc.body(t)
			} else {
				payload := reliableSubmitTestPayload(validKey)
				tc.mutate(payload)
				body = reliableSubmitMarshalPayload(t, payload)
			}
			if _, err := parseValidatedReliableSubmitRequest(body, reliableSubmitTestCallerURI); !errors.Is(err, errReliableSubmitInvalidRequest) {
				reliableSubmitPrivacyFail(t, "privacy validation: invalid request classification mismatch")
			}
		})
	}
}

func TestReliableSubmitRequestParserAcceptsExplicitAsyncAndResources(t *testing.T) {
	_, err := parseValidatedReliableSubmitRequest(
		reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{
			submitKey: reliableSubmitTestKeyString(0x33),
			mode:      ExecutionModeAsync,
			resources: map[string]any{"cpu": 10, "memory_mb": 128},
		}),
		reliableSubmitTestCallerURI,
	)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: reliable request parsing failed")
	}
}

func TestReliableSubmitKeyValidationRequiresCanonicalBase64URL(t *testing.T) {
	valid := reliableSubmitTestKeyString(0x44)
	nonCanonicalTrailingBits := reliableSubmitTestKeyString(0x00)[:reliableSubmitKeyEncodedLength-1] + "B"
	if len(valid) != reliableSubmitKeyEncodedLength {
		reliableSubmitPrivacyFail(t, "privacy setup: key fixture length mismatch")
	}
	if _, err := parseValidatedReliableSubmitRequest(reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: valid}), reliableSubmitTestCallerURI); err != nil {
		reliableSubmitPrivacyFail(t, "privacy validation: canonical key unexpectedly rejected")
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "empty", key: ""},
		{name: "padded", key: base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, reliableSubmitKeyRawLength))},
		{name: "short", key: valid[:len(valid)-1]},
		{name: "long", key: valid + "A"},
		{name: "invalid alphabet", key: valid[:len(valid)-1] + "!"},
		{name: "whitespace", key: valid[:10] + "\n" + valid[11:]},
		{name: "standard base64 slash", key: strings.Repeat("/", reliableSubmitKeyEncodedLength)},
		{name: "noncanonical trailing bits", key: nonCanonicalTrailingBits},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseValidatedReliableSubmitRequest(
				reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: tc.key}),
				reliableSubmitTestCallerURI,
			)
			if !errors.Is(err, errReliableSubmitInvalidKey) {
				reliableSubmitPrivacyFail(t, "privacy validation: invalid key classification mismatch")
			}
			if err != nil && tc.key != "" && strings.Contains(err.Error(), tc.key) {
				reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
			}
		})
	}
}

func TestValidatedReliableSubmitRequestRetainsNoRawSubmitKeyMaterial(t *testing.T) {
	keyText := reliableSubmitTestKeyString(0xda)
	rawKey := mustDecodeReliableSubmitTestKey(t, keyText)
	body := reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{
		submitKey: keyText,
		argv:      []string{"run"},
		env:       map[string]string{"SAFE_KEY": "safe_value"},
	})

	validated, err := parseValidatedReliableSubmitRequest(body, reliableSubmitTestCallerURI)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: reliable request parsing failed")
	}
	assertValidatedReliableSubmitTypeOmitsRawMaterial(t, reflect.TypeOf(validated))
	assertReliableSubmitValueGraphOmitsString(t, "validatedReliableSubmitRequest", reflect.ValueOf(validated), keyText)
	wrapFormat := reliableSubmitMalformedWrapFormat()
	assertReliableSubmitProjectionOmitsSensitiveMaterial(t, "validatedReliableSubmitRequest", "malformed %w", fmt.Errorf(wrapFormat, validated).Error(), keyText, reliableSubmitTestCallerURI)

	originalRefs := validated.claimRefs
	originalArgv := append([]string(nil), validated.invocation.Argv...)
	for i := range body {
		body[i] = 'x'
	}
	callerURI := reliableSubmitTestCallerURI
	callerURI = "spiffe://execution.internal/control-plane/reassigned"
	rawKey[0] ^= 0xff
	if !validated.claimRefs.callerRef.Equal(originalRefs.callerRef) ||
		!validated.claimRefs.submitKeyRef.Equal(originalRefs.submitKeyRef) ||
		!validated.claimRefs.claimID.Equal(originalRefs.claimID) {
		reliableSubmitPrivacyFail(t, "privacy aliasing: reference invariant failed")
	}
	if !reflect.DeepEqual(validated.invocation.Argv, originalArgv) || callerURI == reliableSubmitTestCallerURI {
		reliableSubmitPrivacyFail(t, "privacy aliasing: request fact invariant failed")
	}
}

func TestReliableSubmitMalformedPercentWCannotRevealRawMaterial(t *testing.T) {
	keyText := reliableSubmitTestKeyString(0xfb)
	validated, err := parseValidatedReliableSubmitRequest(
		reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: keyText}),
		reliableSubmitTestCallerURI,
	)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: reliable request parsing failed")
	}

	for _, projection := range []struct {
		label string
		text  string
	}{
		{label: "validated value", text: fmt.Errorf(reliableSubmitMalformedWrapFormat(), validated).Error()},
		{label: "validated pointer", text: fmt.Errorf(reliableSubmitMalformedWrapFormat(), &validated).Error()},
		{label: "validated zero value", text: fmt.Errorf(reliableSubmitMalformedWrapFormat(), validatedReliableSubmitRequest{}).Error()},
	} {
		t.Run(projection.label, func(t *testing.T) {
			assertReliableSubmitProjectionOmitsSensitiveMaterial(t, projection.label, "malformed %w", projection.text, keyText, reliableSubmitTestCallerURI)
		})
	}
}

func TestReliableSubmitTypesDoNotImplementProjectionOrErrorInterfaces(t *testing.T) {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	for _, tc := range []struct {
		name  string
		value any
	}{
		{name: "validatedReliableSubmitRequest", value: validatedReliableSubmitRequest{}},
		{name: "reliableSubmitClaimRefs", value: reliableSubmitClaimRefs{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typ := reflect.TypeOf(tc.value)
			for _, iface := range []struct {
				name string
				typ  reflect.Type
			}{
				{name: "fmt.Stringer", typ: reflect.TypeOf((*fmt.Stringer)(nil)).Elem()},
				{name: "fmt.GoStringer", typ: reflect.TypeOf((*fmt.GoStringer)(nil)).Elem()},
				{name: "fmt.Formatter", typ: reflect.TypeOf((*fmt.Formatter)(nil)).Elem()},
				{name: "json.Marshaler", typ: reflect.TypeOf((*json.Marshaler)(nil)).Elem()},
				{name: "encoding.TextMarshaler", typ: reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()},
				{name: "error", typ: errorType},
			} {
				if typ.Implements(iface.typ) || reflect.PointerTo(typ).Implements(iface.typ) {
					reliableSubmitPrivacyFail(t, "privacy reflection: projection interface mismatch")
				}
			}
		})
	}

	var validatedNil *validatedReliableSubmitRequest
	for _, iface := range []struct {
		name string
		ok   bool
	}{
		{name: "fmt.Stringer", ok: implementsStringer(validatedNil)},
		{name: "fmt.GoStringer", ok: implementsGoStringer(validatedNil)},
		{name: "fmt.Formatter", ok: implementsFormatter(validatedNil)},
		{name: "json.Marshaler", ok: implementsJSONMarshaler(validatedNil)},
		{name: "encoding.TextMarshaler", ok: implementsTextMarshaler(validatedNil)},
		{name: "error", ok: implementsError(validatedNil)},
	} {
		if iface.ok {
			reliableSubmitPrivacyFail(t, "privacy reflection: typed nil interface mismatch")
		}
	}
}

func TestPrepareRequestShapeRemainsLegacyAndUnkeyed(t *testing.T) {
	typ := reflect.TypeOf(PrepareRequest{})
	for _, forbidden := range []string{"ReliableSubmit", "SubmitKey", "IdempotencyKey"} {
		if _, ok := typ.FieldByName(forbidden); ok {
			reliableSubmitPrivacyFail(t, "privacy runtime boundary: request shape mismatch")
		}
	}
	if _, ok := typ.FieldByName("SchemaVersion"); !ok {
		reliableSubmitPrivacyFail(t, "privacy runtime boundary: request shape mismatch")
	}
}

func TestCurrentStrictPrepareRequestDecoderRejectsReliableSubmitDiscriminator(t *testing.T) {
	body := `{
		"schema_version":"execution-substrate.reliable-submit-request/v1",
		"reliable_submit":{"contract":"execution-substrate.reliable-submit/v1","submit_key":"` + reliableSubmitTestKeyString(0x88) + `"},
		"invocation":{
			"schema_version":"v1",
			"artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"output_id":"result"
		},
		"mode":"async"
	}`
	var request PrepareRequest
	if err := httpx.DecodeStrictJSON(strings.NewReader(body), &request); err == nil {
		reliableSubmitPrivacyFail(t, "privacy runtime boundary: strict decoder unexpectedly accepted request")
	} else if !strings.Contains(err.Error(), "reliable_submit") {
		reliableSubmitPrivacyFail(t, "privacy runtime boundary: strict decoder classification mismatch")
	}
}

func TestReliableSubmitProductionErrorsRemainBounded(t *testing.T) {
	keyText := reliableSubmitTestKeyString(0x8a)
	rawKey := mustDecodeReliableSubmitTestKey(t, keyText)
	rawHex := hex.EncodeToString(rawKey)
	rawDecimal := fmt.Sprint(rawKey)
	callerURI := "spiffe://execution.internal/caller/bounded"

	invalidRequestBody := reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: keyText})
	if _, err := parseValidatedReliableSubmitRequest(append(invalidRequestBody, []byte(` {}`)...), callerURI); !errors.Is(err, errReliableSubmitInvalidRequest) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: production error classification mismatch")
	} else if reliableSubmitDiagnosticContainsProtectedMaterial(err.Error(), keyText, rawHex, rawDecimal, callerURI) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
	}

	invalidKey := keyText[:len(keyText)-1] + "!"
	if _, err := parseValidatedReliableSubmitRequest(reliableSubmitTestRequestBody(t, reliableSubmitTestPayloadOptions{submitKey: invalidKey}), callerURI); !errors.Is(err, errReliableSubmitInvalidKey) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: production error classification mismatch")
	} else if reliableSubmitDiagnosticContainsProtectedMaterial(err.Error(), invalidKey, callerURI) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
	}

	decoded, err := decodeCanonicalReliableSubmitKey(keyText)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}
	badCaller := callerURI + "\x00bad"
	if _, err := deriveReliableSubmitClaimRefs(badCaller, decoded); !errors.Is(err, errReliableSubmitInvalidCaller) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: production error classification mismatch")
	} else if reliableSubmitDiagnosticContainsProtectedMaterial(err.Error(), keyText, rawHex, rawDecimal, badCaller) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
	}
}

func TestReliableSubmitPrivacyDiagnosticsUseStaticClassifications(t *testing.T) {
	for _, rel := range []string{
		"reliable_submit_contract_test.go",
		"reliable_submit_identity_test.go",
	} {
		file := mustParseReliableSubmitPrivacyTestSource(t, rel)
		assertReliableSubmitPrivacyDiagnosticSourceIsBounded(t, rel, file)
	}
}

func reliableSubmitTestKeyString(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, reliableSubmitKeyRawLength))
}

func reliableSubmitMalformedWrapFormat() string {
	return "wrapped reliable projection: " + "%w"
}

type reliableSubmitPrivacyDiagnostic string

func reliableSubmitPrivacyFail(t *testing.T, classification reliableSubmitPrivacyDiagnostic) {
	t.Helper()
	t.Fatal(string(classification))
}

type reliableSubmitTestPayloadOptions struct {
	submitKey string
	mode      ExecutionMode
	resources map[string]any
	argv      []string
	env       map[string]string
}

func reliableSubmitTestRequestBody(t *testing.T, opts reliableSubmitTestPayloadOptions) []byte {
	t.Helper()
	payload := reliableSubmitTestPayload(opts.submitKey)
	if opts.mode != "" {
		payload["mode"] = opts.mode
	}
	if opts.resources != nil {
		payload["resources"] = opts.resources
	}
	invocation := payload["invocation"].(map[string]any)
	if opts.argv != nil {
		invocation["argv"] = opts.argv
	}
	if opts.env != nil {
		invocation["env"] = opts.env
	}
	return reliableSubmitMarshalPayload(t, payload)
}

func reliableSubmitTestPayload(submitKey string) map[string]any {
	return map[string]any{
		"schema_version": reliableSubmitRequestSchemaV1,
		reliableSubmitDiscriminator: map[string]any{
			reliableSubmitContractField: reliableSubmitContractV1,
			reliableSubmitKeyField:      submitKey,
		},
		"invocation": map[string]any{
			"schema_version":         "v1",
			"artifact_digest":        "sha256:artifact",
			"derivation_spec_digest": "sha256:derivation",
			"output_id":              "output",
		},
	}
}

func reliableSubmitMarshalPayload(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: reliable request marshal failed")
	}
	return body
}

func assertValidatedReliableSubmitTypeOmitsRawMaterial(t *testing.T, typ reflect.Type) {
	t.Helper()
	if _, ok := typ.FieldByName("request"); ok {
		reliableSubmitPrivacyFail(t, "privacy reflection: raw request object retained")
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		normalized := strings.ToLower(field.Name)
		if field.Type.Kind() == reflect.String && strings.Contains(normalized, "key") {
			reliableSubmitPrivacyFail(t, "privacy reflection: raw submit-key string retained")
		}
		if field.Type.Kind() == reflect.Array && field.Type.Len() == reliableSubmitKeyRawLength && field.Type.Elem().Kind() == reflect.Uint8 {
			reliableSubmitPrivacyFail(t, "privacy reflection: raw key byte array retained")
		}
		if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
			reliableSubmitPrivacyFail(t, "privacy reflection: raw key byte slice retained")
		}
		if field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Func {
			reliableSubmitPrivacyFail(t, "privacy reflection: closure-capable field retained")
		}
		if strings.Contains(normalized, "wire") || strings.Contains(normalized, "marker") {
			reliableSubmitPrivacyFail(t, "privacy reflection: wire request field retained")
		}
	}
}

func assertReliableSubmitValueGraphOmitsString(t *testing.T, label string, value reflect.Value, raw string) {
	t.Helper()
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return
		}
		assertReliableSubmitValueGraphOmitsString(t, label, value.Elem(), raw)
	case reflect.Struct:
		if value.Type().PkgPath() == "execution-substrate/es/admission/internal/reliablesubmit" {
			return
		}
		for i := 0; i < value.NumField(); i++ {
			assertReliableSubmitValueGraphOmitsString(t, label, value.Field(i), raw)
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			assertReliableSubmitValueGraphOmitsString(t, label, key, raw)
			assertReliableSubmitValueGraphOmitsString(t, label, value.MapIndex(key), raw)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			assertReliableSubmitValueGraphOmitsString(t, label, value.Index(i), raw)
		}
	case reflect.String:
		if strings.Contains(value.String(), raw) {
			reliableSubmitPrivacyFail(t, "privacy reflection: protected string retained")
		}
	}
}

func assertReliableSubmitProjectionOmitsSensitiveMaterial(t *testing.T, label string, mechanism string, projection string, rawKey string, callerURI string) {
	t.Helper()
	raw := mustDecodeReliableSubmitTestKey(t, rawKey)
	rawHex := hex.EncodeToString(raw)
	rawHexUpper := strings.ToUpper(rawHex)
	rawDecimal := fmt.Sprint(raw)
	for _, forbidden := range []string{rawKey, rawHex, rawHexUpper, rawDecimal, callerURI} {
		if forbidden != "" && strings.Contains(projection, forbidden) {
			reliableSubmitPrivacyFail(t, "privacy projection: protected material leaked")
		}
	}
}

func mustDecodeReliableSubmitTestKey(t *testing.T, rawKey string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(rawKey)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}
	return decoded
}

func reliableSubmitDiagnosticContainsProtectedMaterial(diagnostic string, protected ...string) bool {
	for _, value := range protected {
		if value != "" && strings.Contains(diagnostic, value) {
			return true
		}
	}
	return false
}

func mustParseReliableSubmitPrivacyTestSource(t *testing.T, rel string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), rel, nil, parser.ParseComments)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: source parse failed")
	}
	return file
}

func assertReliableSubmitPrivacyDiagnosticSourceIsBounded(t *testing.T, rel string, file *ast.File) {
	t.Helper()
	var helperFound bool
	var helperSignatureChecked bool
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "reliableSubmitPrivacyFail" {
				helperFound = true
				helperSignatureChecked = reliableSubmitPrivacyHelperSignatureIsBounded(typed)
				if reliableSubmitPrivacyHelperUsesFormatting(typed) {
					reliableSubmitPrivacyFail(t, "privacy diagnostics: helper source contract mismatch")
				}
			}
		case *ast.CallExpr:
			selector, ok := typed.Fun.(*ast.SelectorExpr)
			if ok && reliableSubmitSelectorReceiverName(selector) == "t" {
				switch selector.Sel.Name {
				case "Fatalf":
					reliableSubmitPrivacyFail(t, "privacy diagnostics: formatted fatal source contract mismatch")
				case "Errorf", "Error":
					reliableSubmitPrivacyFail(t, "privacy diagnostics: formatted error source contract mismatch")
				}
			}
			if reliableSubmitCallName(typed) == "reliableSubmitPrivacyFail" {
				assertReliableSubmitPrivacyFailureCallIsStatic(t, typed)
			}
		}
		return true
	})
	if rel == "reliable_submit_contract_test.go" && (!helperFound || !helperSignatureChecked) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: helper source contract mismatch")
	}
}

func reliableSubmitPrivacyHelperSignatureIsBounded(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 2 {
		return false
	}
	second := fn.Type.Params.List[1]
	return exprSourceName(second.Type) == "reliableSubmitPrivacyDiagnostic"
}

func reliableSubmitPrivacyHelperUsesFormatting(fn *ast.FuncDecl) bool {
	var usesFormatting bool
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && exprSourceName(selector.X) == "fmt" {
			usesFormatting = true
			return false
		}
		return true
	})
	return usesFormatting
}

func assertReliableSubmitPrivacyFailureCallIsStatic(t *testing.T, call *ast.CallExpr) {
	t.Helper()
	if len(call.Args) != 2 {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: helper source contract mismatch")
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: helper source contract mismatch")
	}
	text, err := strconv.Unquote(lit.Value)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: helper source contract mismatch")
	}
	for _, sentinel := range []string{
		reliableSubmitTestKeyString(0xa5),
		hex.EncodeToString(bytes.Repeat([]byte{0xa5}, reliableSubmitKeyRawLength)),
		fmt.Sprint(bytes.Repeat([]byte{0xa5}, reliableSubmitKeyRawLength)),
		"spiffe://execution.internal/caller/private",
	} {
		if strings.Contains(text, sentinel) {
			reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
		}
	}
}

func reliableSubmitCallName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	default:
		return ""
	}
}

func reliableSubmitSelectorReceiverName(selector *ast.SelectorExpr) string {
	if ident, ok := selector.X.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func implementsStringer(value any) bool {
	_, ok := value.(fmt.Stringer)
	return ok
}

func implementsGoStringer(value any) bool {
	_, ok := value.(fmt.GoStringer)
	return ok
}

func implementsFormatter(value any) bool {
	_, ok := value.(fmt.Formatter)
	return ok
}

func implementsJSONMarshaler(value any) bool {
	_, ok := value.(json.Marshaler)
	return ok
}

func implementsTextMarshaler(value any) bool {
	_, ok := value.(encoding.TextMarshaler)
	return ok
}

func implementsError(value any) bool {
	_, ok := value.(error)
	return ok
}
