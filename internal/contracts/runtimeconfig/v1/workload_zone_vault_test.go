package runtimeconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWorkloadZoneVaultConfigRefValidate(t *testing.T) {
	ref := WorkloadZoneVaultConfigRef{Digest: " sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "}
	if err := ref.Validate(); err != nil {
		t.Fatalf("expected ref to validate, got %v", err)
	}
	if normalized := ref.Normalized(); normalized.Digest != "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected normalized digest %q", normalized.Digest)
	}
}

func TestWorkloadZoneVaultConfigRefValidateRejectsInvalidDigest(t *testing.T) {
	err := WorkloadZoneVaultConfigRef{Digest: "sha256:not-a-real-digest"}.Validate()
	if err == nil || !strings.Contains(err.Error(), "labeled SHA-256 digest") {
		t.Fatalf("expected labeled digest error, got %v", err)
	}
}

func TestWorkloadZoneVaultConfigBlobJSONRoundTrip(t *testing.T) {
	caBundle := testCertificatePEM(t)
	raw := []byte(`{
  "vault_config": {
    "address": "https://vault.internal:8200",
    "auth_mount": "jwt",
    "auth_role": "service_execution",
    "jwt_audience": "vault",
    "ca_bundle_pem": ` + strconvQuoteForJSON(caBundle) + `
  }
}`)

	var blob WorkloadZoneVaultConfigBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	if err := blob.Validate(); err != nil {
		t.Fatalf("expected blob to validate, got %v", err)
	}

	if blob.VaultConfig.AuthRole != "service_execution" {
		t.Fatalf("unexpected auth role %q", blob.VaultConfig.AuthRole)
	}
	if !strings.Contains(blob.VaultConfig.CABundlePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected CA bundle PEM to round trip, got %q", blob.VaultConfig.CABundlePEM)
	}
}

func TestWorkloadZoneVaultConfigBlobRejectsMissingRole(t *testing.T) {
	blob := WorkloadZoneVaultConfigBlob{
		VaultConfig: WorkloadZoneVaultConfig{
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			JWTAudience: "vault",
		},
	}

	err := blob.Validate()
	if err == nil || !strings.Contains(err.Error(), "auth role") {
		t.Fatalf("expected auth role validation error, got %v", err)
	}
}

func TestWorkloadZoneVaultConfigBlobRejectsInvalidCABundle(t *testing.T) {
	blob := WorkloadZoneVaultConfigBlob{
		VaultConfig: WorkloadZoneVaultConfig{
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
			CABundlePEM: "not pem",
		},
	}

	err := blob.Validate()
	if err == nil || !strings.Contains(err.Error(), "ca_bundle_pem") {
		t.Fatalf("expected ca_bundle_pem validation error, got %v", err)
	}
}

func TestWorkloadZoneVaultConfigBlobCarriesOnlyNonSecretVaultMetadata(t *testing.T) {
	var vaultConfig []runtimeConfigJSONNode
	blob := []runtimeConfigJSONNode{{path: "vault_config", kind: "object"}}
	for _, key := range workloadZoneVaultConfigKeys {
		vaultConfig = append(vaultConfig, runtimeConfigJSONNode{path: key, kind: "string"})
		blob = append(blob, runtimeConfigJSONNode{path: "vault_config." + key, kind: "string"})
	}
	checkWorkloadZoneVaultConfigJSON(t, WorkloadZoneVaultConfigRef{}, []runtimeConfigJSONNode{{path: "digest", kind: "string"}})
	checkWorkloadZoneVaultConfigJSON(t, WorkloadZoneVaultConfigBlob{}, blob)
	checkWorkloadZoneVaultConfigJSON(t, WorkloadZoneVaultConfig{}, vaultConfig)
}

// workloadZoneVaultConfigKeys are the non-secret Vault metadata keys of the
// workload-zone Vault config, in the order the guard reports them.
var workloadZoneVaultConfigKeys = []string{
	"address",
	"auth_mount",
	"auth_role",
	"jwt_audience",
	"ca_bundle_pem",
}

// workloadZoneVaultForbiddenKeys are token, secret, lease and raw SPIRE keys
// that no object of the config may decode.
var workloadZoneVaultForbiddenKeys = []string{
	"vault_token",
	"client_token",
	"root_token",
	"unseal_key",
	"jwt_svid",
	"x509_svid",
	"private_key",
	"api_key",
	"proof_secret",
	"secret_payload",
	"lease_id",
	"lease_duration",
	"raw_spire_socket",
}

// checkWorkloadZoneVaultConfigJSON fails t unless value's type has exactly the
// JSON form want: every field of the type, at any depth, is an exported,
// tagged string or struct field that encoding/json writes and reads; no type
// in it chooses its own encoding; no object in it decodes a forbidden key; and
// json.Marshal writes exactly want's key paths, each holding want's kind of
// JSON value. It reports every finding; only a value that json.Marshal cannot
// write as an object stops it.
func checkWorkloadZoneVaultConfigJSON(t testing.TB, value any, want []runtimeConfigJSONNode) {
	t.Helper()
	objects := []string{""}
	wanted := map[string]string{}
	for _, node := range want {
		wanted[node.path] = node.kind
		if node.kind == "object" {
			objects = append(objects, node.path)
		}
	}
	for _, field := range runtimeConfigFieldsNotPlainJSON(t, value) {
		t.Errorf("workload-zone Vault config field %s must be an exported, tagged string or struct field, not %s", field.where, field.why)
	}
	for _, method := range runtimeConfigCodecMethods(t, value) {
		t.Errorf("workload-zone Vault config type %s must not choose its own encoding with %s", method.typ, method.method)
	}
	for _, decoded := range runtimeConfigJSONKeysDecoded(t, value, objects, workloadZoneVaultForbiddenKeys...) {
		t.Errorf("workload-zone Vault config %T must not decode token, secret, lease, or raw SPIRE key %q", value, decoded)
	}
	written := map[string]string{}
	for _, node := range runtimeConfigJSONWritten(t, value) {
		written[node.path] = node.kind
		if kind, ok := wanted[node.path]; !ok {
			t.Errorf("workload-zone Vault config %T must write only its non-secret Vault metadata keys, not %q", value, node.path)
		} else if node.kind != kind {
			t.Errorf("workload-zone Vault config %T key %q must hold a JSON %s, not %s", value, node.path, kind, node.kind)
		}
	}
	for _, node := range want {
		if _, ok := written[node.path]; !ok {
			t.Errorf("expected non-secret workload-zone Vault metadata key %q in %T", node.path, value)
		}
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test vault ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test CA certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func strconvQuoteForJSON(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// runtimeConfigJSONNode is a key path in a JSON document and the kind of JSON
// value at it: "object", "array", "string", "number", "bool" or "null". A key
// path joins keys with ".", marks the elements of an array with "[]" and names
// the entry of a map "*".
type runtimeConfigJSONNode struct {
	path string
	kind string
}

// runtimeConfigJSONWritten answers one question: which key paths does
// encoding/json write for a filled value of value's type, and what kind of
// JSON value is at each? So encoding/json itself decides names, tags, case,
// omitempty, name clashes and embedding. The filler sets every string it can
// reach to a non-empty value, allocates pointers, gives slices one element and
// maps one entry under the empty key, and sets numbers and booleans; it leaves
// interfaces, functions and channels empty, so a key whose value is one of
// those may not be written. runtimeConfigFieldsNotPlainJSON refuses those.
// The value is written by value and through a pointer; the two must match. A
// written key that holds ".", "[", "]" or "*" is reported, since no key path
// could name it. It returns the nodes depth first, in key order at each
// object.
func runtimeConfigJSONWritten(t testing.TB, value any) []runtimeConfigJSONNode {
	t.Helper()
	root := runtimeConfigStructType(t, value)
	filled := reflect.New(root)
	fillRuntimeConfigValue(filled.Elem(), map[reflect.Type]bool{})
	byPointer, err := json.Marshal(filled.Interface())
	if err != nil {
		t.Fatalf("json.Marshal of a filled %s: %v", root, err)
	}
	byValue, err := json.Marshal(filled.Elem().Interface())
	if err != nil {
		t.Fatalf("json.Marshal of a filled %s: %v", root, err)
	}
	if !bytes.Equal(byPointer, byValue) {
		t.Fatalf("json.Marshal writes %s as %s through a pointer but as %s by value", root, byPointer, byValue)
	}
	decoder := json.NewDecoder(bytes.NewReader(byPointer))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode the JSON written for %s: %v", root, err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		t.Fatalf("json.Marshal writes %s as %s, not an object", root, byPointer)
	}
	var nodes []runtimeConfigJSONNode
	var walk func(prefix string, object map[string]any)
	visit := func(path string, value any) {
		switch value := value.(type) {
		case map[string]any:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "object"})
			walk(path, value)
		case []any:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "array"})
			for _, element := range value {
				if inner, ok := element.(map[string]any); ok {
					walk(path+"[]", inner)
				}
			}
		case string:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "string"})
		case json.Number:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "number"})
		case bool:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "bool"})
		default:
			nodes = append(nodes, runtimeConfigJSONNode{path: path, kind: "null"})
		}
	}
	walk = func(prefix string, object map[string]any) {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			name := key
			if key == "" {
				name = "*"
			} else if strings.ContainsAny(key, ".[]*") {
				t.Errorf("json.Marshal writes %s with key %q, which no key path can name", root, key)
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			visit(path, object[key])
		}
	}
	walk("", object)
	return nodes
}

// fillRuntimeConfigValue sets every string, number and boolean it can reach in
// value, allocates pointers, gives slices one element and maps one entry under
// the empty key. A pointer to a type already being filled further up is left
// nil, so a recursive type ends.
func fillRuntimeConfigValue(value reflect.Value, filling map[reflect.Type]bool) {
	switch value.Kind() {
	case reflect.String:
		value.SetString("x")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		value.SetUint(1)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(1)
	case reflect.Pointer:
		if filling[value.Type().Elem()] {
			return
		}
		value.Set(reflect.New(value.Type().Elem()))
		fillRuntimeConfigValue(value.Elem(), filling)
	case reflect.Slice:
		value.Set(reflect.MakeSlice(value.Type(), 1, 1))
		fillRuntimeConfigValue(value.Index(0), filling)
	case reflect.Array:
		for i := range value.Len() {
			fillRuntimeConfigValue(value.Index(i), filling)
		}
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return
		}
		entry := reflect.New(value.Type().Elem()).Elem()
		fillRuntimeConfigValue(entry, filling)
		value.Set(reflect.MakeMap(value.Type()))
		value.SetMapIndex(reflect.New(value.Type().Key()).Elem(), entry)
	case reflect.Struct:
		filling[value.Type()] = true
		for i := range value.NumField() {
			if value.Field(i).CanSet() {
				fillRuntimeConfigValue(value.Field(i), filling)
			}
		}
		delete(filling, value.Type())
	}
}

// runtimeConfigField is a field of a type, where it is, and what is wrong
// with it.
type runtimeConfigField struct {
	where string
	why   string
}

// runtimeConfigFieldsNotPlainJSON answers one question: which fields of
// value's type, at any depth, are not an exported, tagged field of kind string
// or struct that encoding/json writes and reads? Every field of every struct
// reached counts, exported or not. A field is reported when it is unexported,
// embedded, untagged, tagged "-", tagged with an option other than omitempty,
// or of any kind but string or struct; a struct field is read in turn. Names
// are not judged here; runtimeConfigJSONWritten shows them as written. It
// returns the fields in the order reached.
func runtimeConfigFieldsNotPlainJSON(t testing.TB, value any) []runtimeConfigField {
	t.Helper()
	root := runtimeConfigStructType(t, value)
	var fields []runtimeConfigField
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, place string)
	walk = func(typ reflect.Type, place string) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			field := typ.Field(i)
			where := place + "." + field.Name
			tag := field.Tag.Get("json")
			name, options, _ := strings.Cut(tag, ",")
			switch {
			case field.Anonymous:
				fields = append(fields, runtimeConfigField{where: where, why: "an embedded field"})
			case !field.IsExported():
				fields = append(fields, runtimeConfigField{where: where, why: "an unexported field"})
			case tag == "-":
				fields = append(fields, runtimeConfigField{where: where, why: "a field encoding/json skips"})
			case name == "":
				fields = append(fields, runtimeConfigField{where: where, why: "an untagged field"})
			case options != "" && options != "omitempty":
				fields = append(fields, runtimeConfigField{where: where, why: "a field with tag options " + strconv.Quote(options)})
			}
			switch field.Type.Kind() {
			case reflect.String:
			case reflect.Struct:
				walk(field.Type, where)
			default:
				fields = append(fields, runtimeConfigField{where: where, why: "a field of type " + field.Type.String()})
			}
		}
	}
	walk(root, root.String())
	return fields
}

// runtimeConfigCodecMethod is a type that chooses its own encoding, and the
// method it does it with.
type runtimeConfigCodecMethod struct {
	typ    string
	method string
}

// runtimeConfigCodecMethods answers one question: which types in value's type,
// at any depth, choose their own JSON or text encoding? A struct or field type
// counts when it or a pointer to it implements json.Marshaler,
// json.Unmarshaler, encoding.TextMarshaler or encoding.TextUnmarshaler. Such
// a method decides what is written and read, so runtimeConfigJSONWritten
// would no longer show it. It returns them in the order reached.
func runtimeConfigCodecMethods(t testing.TB, value any) []runtimeConfigCodecMethod {
	t.Helper()
	root := runtimeConfigStructType(t, value)
	interfaces := []struct {
		method string
		typ    reflect.Type
	}{
		{"MarshalJSON", reflect.TypeFor[json.Marshaler]()},
		{"UnmarshalJSON", reflect.TypeFor[json.Unmarshaler]()},
		{"MarshalText", reflect.TypeFor[encoding.TextMarshaler]()},
		{"UnmarshalText", reflect.TypeFor[encoding.TextUnmarshaler]()},
	}
	var methods []runtimeConfigCodecMethod
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type)
	walk = func(typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		for _, codec := range interfaces {
			if reflect.PointerTo(typ).Implements(codec.typ) {
				methods = append(methods, runtimeConfigCodecMethod{typ: typ.String(), method: codec.method})
			}
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
			walk(typ.Elem())
		case reflect.Map:
			walk(typ.Key())
			walk(typ.Elem())
		case reflect.Struct:
			for i := range typ.NumField() {
				walk(typ.Field(i).Type)
			}
		}
	}
	walk(root)
	return methods
}

// runtimeConfigJSONKeysDecoded answers one question: which of keys does a
// strict decoder, as ES uses for this config (DisallowUnknownFields), take at
// each of objects? An object is a key path to a JSON object in value's form;
// "" is the top level. For each object and key, it decodes a document that
// holds only that key, with a string value, at that object, into a new value
// of value's type. The key is taken when decoding succeeds or fails on the
// value's type; it is refused only when the decoder reports it as unknown. So
// encoding/json itself decides case folding, tags and promoted fields. It
// returns each taken key's path, in the order of objects, then keys.
func runtimeConfigJSONKeysDecoded(t testing.TB, value any, objects []string, keys ...string) []string {
	t.Helper()
	root := runtimeConfigStructType(t, value)
	var decoded []string
	for _, object := range objects {
		for _, key := range keys {
			var document any = map[string]any{key: "x"}
			path := key
			if object != "" {
				path = object + "." + key
				parts := strings.Split(object, ".")
				for i := len(parts) - 1; i >= 0; i-- {
					document = map[string]any{parts[i]: document}
				}
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode a probe document: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(reflect.New(root).Interface())
			var typeErr *json.UnmarshalTypeError
			switch {
			case err == nil, errors.As(err, &typeErr):
				decoded = append(decoded, path)
			case strings.HasPrefix(err.Error(), "json: unknown field "):
			default:
				t.Fatalf("decode %s into %s: %v", raw, root, err)
			}
		}
	}
	return decoded
}

func runtimeConfigStructType(t testing.TB, value any) reflect.Type {
	t.Helper()
	typ := reflect.TypeOf(value)
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		t.Fatalf("expected a struct, got %v", typ)
	}
	return typ
}
