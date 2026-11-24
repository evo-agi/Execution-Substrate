package runtimeconfig

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

type zzRuntimeConfigEmbedded struct {
	A string `json:"a"`
}

// Two embedded structs with the same untagged field name: encoding/json
// writes neither.
type zzRuntimeConfigClashOne struct{ A string }

type zzRuntimeConfigClashTwo struct{ A string }

type zzRuntimeConfigNode struct {
	A    string               `json:"a"`
	Next *zzRuntimeConfigNode `json:"next"`
}

// zzRuntimeConfigPointerJSON writes itself only through a pointer.
type zzRuntimeConfigPointerJSON struct {
	A string `json:"a"`
}

func (*zzRuntimeConfigPointerJSON) MarshalJSON() ([]byte, error) { return []byte(`{"b":"x"}`), nil }

// zzRuntimeConfigStringJSON writes itself as a string.
type zzRuntimeConfigStringJSON struct {
	A string `json:"a"`
}

func (zzRuntimeConfigStringJSON) MarshalJSON() ([]byte, error) { return []byte(`"x"`), nil }

// The written key paths come from encoding/json itself.
func TestRuntimeConfigJSONWrittenFollowsEncodingJSON(t *testing.T) {
	type node = runtimeConfigJSONNode
	for _, test := range []struct {
		name  string
		value any
		want  []node
	}{
		{"a tagged string", struct {
			A string `json:"a"`
		}{}, []node{{"a", "string"}}},
		{"a pointer to the struct", &struct {
			A string `json:"a"`
		}{}, []node{{"a", "string"}}},
		{"an untagged field, under its Go name", struct{ VaultToken string }{}, []node{{"VaultToken", "string"}}},
		{"a tag in another case", struct {
			T string `json:"VAULT_TOKEN"`
		}{}, []node{{"VAULT_TOKEN", "string"}}},
		{"an omitempty string, filled", struct {
			A string `json:"a,omitempty"`
		}{}, []node{{"a", "string"}}},
		{"a skipped field", struct {
			A string `json:"-"`
		}{}, nil},
		{"an unexported field", struct{ a string }{}, nil},
		{"a nested struct", struct {
			V struct {
				A string `json:"a"`
			} `json:"v"`
		}{}, []node{{"v", "object"}, {"v.a", "string"}}},
		{"a field promoted from an embedded struct", struct{ zzRuntimeConfigEmbedded }{}, []node{{"a", "string"}}},
		{"two promoted fields that clash, dropped by encoding/json", struct {
			zzRuntimeConfigClashOne
			zzRuntimeConfigClashTwo
		}{}, nil},
		{"a map value", struct {
			M map[string]struct {
				A string `json:"a"`
			} `json:"m"`
		}{}, []node{{"m", "object"}, {"m.*", "object"}, {"m.*.a", "string"}}},
		{"a slice of structs", struct {
			S []struct {
				A string `json:"a"`
			} `json:"s"`
		}{}, []node{{"s", "array"}, {"s[].a", "string"}}},
		{"a pointer field", struct {
			P *struct {
				A string `json:"a"`
			} `json:"p"`
		}{}, []node{{"p", "object"}, {"p.a", "string"}}},
		{"a number and a boolean", struct {
			N int  `json:"n"`
			B bool `json:"b"`
		}{}, []node{{"b", "bool"}, {"n", "number"}}},
		{"an interface", struct {
			X any `json:"x"`
		}{}, []node{{"x", "null"}}},
		{"an omitempty interface, not written", struct {
			X any `json:"x,omitempty"`
		}{}, nil},
		{"a recursive type, filled one level", zzRuntimeConfigNode{}, []node{{"a", "string"}, {"next", "null"}}},
		{"the same type twice, filled both times", struct {
			P *zzRuntimeConfigEmbedded `json:"p"`
			Q *zzRuntimeConfigEmbedded `json:"q"`
		}{}, []node{{"p", "object"}, {"p.a", "string"}, {"q", "object"}, {"q.a", "string"}}},
		{"keys depth first, in key order", struct {
			Z string `json:"z"`
			V struct {
				B string `json:"b"`
				A string `json:"a"`
			} `json:"v"`
		}{}, []node{{"v", "object"}, {"v.a", "string"}, {"v.b", "string"}, {"z", "string"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeConfigJSONWritten(t, test.value); !slices.Equal(got, test.want) {
				t.Fatalf("runtimeConfigJSONWritten(%T) = %+v, want %+v", test.value, got, test.want)
			}
		})
	}

	t.Run("a key no key path can name", func(t *testing.T) {
		got := zzRuntimeConfigGuardReports(t, func(tb testing.TB) {
			runtimeConfigJSONWritten(tb, struct {
				A string `json:"v.a"`
			}{})
		})
		want := []string{`json.Marshal writes struct { A string "json:\"v.a\"" } with key "v.a", which no key path can name`}
		if got.fatal != "" || !slices.Equal(got.errors, want) {
			t.Fatalf("runtimeConfigJSONWritten reported %q and stopped with %q, want %q", got.errors, got.fatal, want)
		}
	})

	for _, test := range []struct {
		name  string
		value any
		want  string
	}{
		{"written differently through a pointer", zzRuntimeConfigPointerJSON{}, `json.Marshal writes runtimeconfig.zzRuntimeConfigPointerJSON as {"b":"x"} through a pointer but as {"a":"x"} by value`},
		{"written as something other than an object", zzRuntimeConfigStringJSON{}, `json.Marshal writes runtimeconfig.zzRuntimeConfigStringJSON as "x", not an object`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := zzRuntimeConfigGuardReports(t, func(tb testing.TB) { runtimeConfigJSONWritten(tb, test.value) }); got.fatal != test.want {
				t.Fatalf("runtimeConfigJSONWritten(%T) stopped with %q, want %q", test.value, got.fatal, test.want)
			}
		})
	}
}

type zzRuntimeConfigNested struct {
	Inner struct {
		Data []byte `json:"data"`
	} `json:"inner"`
}

// Every field of the type counts, at any depth, exported or not.
func TestRuntimeConfigFieldsNotPlainJSONReadsEveryField(t *testing.T) {
	type field = runtimeConfigField
	for _, test := range []struct {
		name  string
		value any
		want  []field
	}{
		{"a tagged string", struct {
			A string `json:"a"`
		}{}, nil},
		{"a tagged string with omitempty", struct {
			A string `json:"a,omitempty"`
		}{}, nil},
		{"a tagged nested struct", struct {
			V struct {
				A string `json:"a"`
			} `json:"v"`
		}{}, nil},
		{"a field of a named string type", struct {
			A zzRuntimeConfigText `json:"a"`
		}{}, nil},
		{"an unexported field", struct{ a string }{}, []field{{"struct { a string }.a", "an unexported field"}}},
		{"an embedded field", struct{ zzRuntimeConfigEmbedded }{}, []field{{"struct { runtimeconfig.zzRuntimeConfigEmbedded }.zzRuntimeConfigEmbedded", "an embedded field"}}},
		{"a skipped field", struct {
			A string `json:"-"`
		}{}, []field{{"struct { A string \"json:\\\"-\\\"\" }.A", "a field encoding/json skips"}}},
		{"an untagged field", struct{ A string }{}, []field{{"struct { A string }.A", "an untagged field"}}},
		{"a tag option other than omitempty", struct {
			A string `json:"a,string"`
		}{}, []field{{"struct { A string \"json:\\\"a,string\\\"\" }.A", "a field with tag options \"string\""}}},
		{"a byte slice", struct {
			A []byte `json:"a"`
		}{}, []field{{"struct { A []uint8 \"json:\\\"a\\\"\" }.A", "a field of type []uint8"}}},
		{"an interface", struct {
			A any `json:"a"`
		}{}, []field{{"struct { A interface {} \"json:\\\"a\\\"\" }.A", "a field of type interface {}"}}},
		{"a map", struct {
			A map[string]string `json:"a"`
		}{}, []field{{"struct { A map[string]string \"json:\\\"a\\\"\" }.A", "a field of type map[string]string"}}},
		{"a pointer to a struct", struct {
			A *zzRuntimeConfigEmbedded `json:"a"`
		}{}, []field{{"struct { A *runtimeconfig.zzRuntimeConfigEmbedded \"json:\\\"a\\\"\" }.A", "a field of type *runtimeconfig.zzRuntimeConfigEmbedded"}}},
		{"a number", struct {
			A int `json:"a"`
		}{}, []field{{"struct { A int \"json:\\\"a\\\"\" }.A", "a field of type int"}}},
		{"a function", struct {
			A func() string `json:"a"`
		}{}, []field{{"struct { A func() string \"json:\\\"a\\\"\" }.A", "a field of type func() string"}}},
		{"a field at depth", zzRuntimeConfigNested{}, []field{{"runtimeconfig.zzRuntimeConfigNested.Inner.Data", "a field of type []uint8"}}},
		{"in the order reached, with every reason", struct {
			b []byte
			A string
		}{}, []field{
			{"struct { b []uint8; A string }.b", "an unexported field"},
			{"struct { b []uint8; A string }.b", "a field of type []uint8"},
			{"struct { b []uint8; A string }.A", "an untagged field"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeConfigFieldsNotPlainJSON(t, test.value); !slices.Equal(got, test.want) {
				t.Fatalf("runtimeConfigFieldsNotPlainJSON(%T) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

// Every kind from reflect.Bool to reflect.UnsafePointer, so that a check
// written as a list of refused kinds cannot pass: only string and struct are
// accepted. The unsafe.Pointer type is taken from the result of
// reflect.Value.UnsafePointer, so the test needs no unsafe import.
func TestRuntimeConfigFieldsNotPlainJSONTriesEveryKind(t *testing.T) {
	samples := map[reflect.Kind]reflect.Type{}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[bool](), reflect.TypeFor[int](), reflect.TypeFor[int8](), reflect.TypeFor[int16](),
		reflect.TypeFor[int32](), reflect.TypeFor[int64](), reflect.TypeFor[uint](), reflect.TypeFor[uint8](),
		reflect.TypeFor[uint16](), reflect.TypeFor[uint32](), reflect.TypeFor[uint64](), reflect.TypeFor[uintptr](),
		reflect.TypeFor[float32](), reflect.TypeFor[float64](), reflect.TypeFor[complex64](), reflect.TypeFor[complex128](),
		reflect.TypeFor[[1]string](), reflect.TypeFor[chan string](), reflect.TypeFor[func() string](), reflect.TypeFor[any](),
		reflect.TypeFor[map[string]string](), reflect.TypeFor[*string](), reflect.TypeFor[[]string](), reflect.TypeFor[string](),
		reflect.TypeFor[struct{}](), reflect.TypeOf(reflect.Value.UnsafePointer).Out(0),
	} {
		samples[typ.Kind()] = typ
	}
	for kind := reflect.Bool; kind <= reflect.UnsafePointer; kind++ {
		typ, ok := samples[kind]
		if !ok {
			t.Fatalf("no sample type of kind %s", kind)
		}
		root := reflect.StructOf([]reflect.StructField{{Name: "A", Type: typ, Tag: `json:"a"`}})
		got := runtimeConfigFieldsNotPlainJSON(t, reflect.New(root).Elem().Interface())
		var want []runtimeConfigField
		if kind != reflect.String && kind != reflect.Struct {
			want = []runtimeConfigField{{where: root.String() + ".A", why: "a field of type " + typ.String()}}
		}
		if !slices.Equal(got, want) {
			t.Errorf("kind %s: runtimeConfigFieldsNotPlainJSON = %q, want %q", kind, got, want)
		}
	}
}

type zzRuntimeConfigText string

type zzRuntimeConfigTextMarshaler string

func (zzRuntimeConfigTextMarshaler) MarshalText() ([]byte, error) { return []byte("x"), nil }

// zzRuntimeConfigKeyText is used only as a map key.
type zzRuntimeConfigKeyText string

func (zzRuntimeConfigKeyText) MarshalText() ([]byte, error) { return []byte("x"), nil }

type zzRuntimeConfigTextUnmarshaler struct {
	A string `json:"a"`
}

func (*zzRuntimeConfigTextUnmarshaler) UnmarshalText([]byte) error { return nil }

type zzRuntimeConfigJSONUnmarshaler struct {
	A string `json:"a"`
}

func (*zzRuntimeConfigJSONUnmarshaler) UnmarshalJSON([]byte) error { return nil }

// A type that chooses its own encoding is found wherever it sits.
func TestRuntimeConfigCodecMethodsFindEveryEncoder(t *testing.T) {
	type method = runtimeConfigCodecMethod
	for _, test := range []struct {
		name  string
		value any
		want  []method
	}{
		{"none", struct {
			A zzRuntimeConfigText `json:"a"`
		}{}, nil},
		{"MarshalJSON on the type, by value", zzRuntimeConfigStringJSON{}, []method{{"runtimeconfig.zzRuntimeConfigStringJSON", "MarshalJSON"}}},
		{"MarshalJSON on the type, through a pointer", &zzRuntimeConfigPointerJSON{}, []method{{"runtimeconfig.zzRuntimeConfigPointerJSON", "MarshalJSON"}}},
		{"UnmarshalJSON on the type", zzRuntimeConfigJSONUnmarshaler{}, []method{{"runtimeconfig.zzRuntimeConfigJSONUnmarshaler", "UnmarshalJSON"}}},
		{"MarshalText on a field type", struct {
			A zzRuntimeConfigTextMarshaler `json:"a"`
		}{}, []method{{"runtimeconfig.zzRuntimeConfigTextMarshaler", "MarshalText"}}},
		{"UnmarshalText on a nested struct", struct {
			V zzRuntimeConfigTextUnmarshaler `json:"v"`
		}{}, []method{{"runtimeconfig.zzRuntimeConfigTextUnmarshaler", "UnmarshalText"}}},
		{"behind a pointer, slice, array, map key and value, and channel", struct {
			P *zzRuntimeConfigJSONUnmarshaler           `json:"p"`
			S []zzRuntimeConfigTextMarshaler            `json:"s"`
			A [1]zzRuntimeConfigStringJSON              `json:"a"`
			K map[zzRuntimeConfigKeyText]string         `json:"k"`
			M map[string]zzRuntimeConfigTextUnmarshaler `json:"m"`
			C chan zzRuntimeConfigPointerJSON           `json:"-"`
		}{}, []method{
			{"runtimeconfig.zzRuntimeConfigJSONUnmarshaler", "UnmarshalJSON"},
			{"runtimeconfig.zzRuntimeConfigTextMarshaler", "MarshalText"},
			{"runtimeconfig.zzRuntimeConfigStringJSON", "MarshalJSON"},
			{"runtimeconfig.zzRuntimeConfigKeyText", "MarshalText"},
			{"runtimeconfig.zzRuntimeConfigTextUnmarshaler", "UnmarshalText"},
			{"runtimeconfig.zzRuntimeConfigPointerJSON", "MarshalJSON"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeConfigCodecMethods(t, test.value); !slices.Equal(got, test.want) {
				t.Fatalf("runtimeConfigCodecMethods(%T) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

type zzRuntimeConfigLease struct {
	LeaseID string `json:"lease_id"`
}

// Whether a key is taken is decided by a strict encoding/json decoder.
func TestRuntimeConfigJSONKeysDecodedUsesTheDecoder(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   any
		objects []string
		want    []string
	}{
		{"an exact tag", struct {
			T string `json:"vault_token"`
		}{}, []string{""}, []string{"vault_token"}},
		{"a tag in another case", struct {
			T string `json:"VAULT_TOKEN"`
		}{}, []string{""}, []string{"vault_token"}},
		{"an untagged field, whose Go name has no underscore", struct{ VaultToken string }{}, []string{""}, nil},
		{"a field of another type, which the decoder still matches", struct {
			T struct{} `json:"vault_token"`
		}{}, []string{""}, []string{"vault_token"}},
		{"a field promoted from an embedded struct", struct{ zzRuntimeConfigLease }{}, []string{""}, []string{"lease_id"}},
		{"a nested object", struct {
			V struct {
				T string `json:"vault_token"`
			} `json:"v"`
		}{}, []string{"", "v"}, []string{"v.vault_token"}},
		{"an object at depth two", struct {
			V struct {
				W struct {
					T string `json:"vault_token"`
				} `json:"w"`
			} `json:"v"`
		}{}, []string{"v.w"}, []string{"v.w.vault_token"}},
		{"not at an object that is not asked", struct {
			V struct {
				T string `json:"vault_token"`
			} `json:"v"`
		}{}, []string{""}, nil},
		{"not inside a map, which is no object of the form", struct {
			M map[string]string `json:"m"`
		}{}, []string{""}, nil},
		{"objects, then keys, in the order asked", struct {
			L string `json:"lease_id"`
			V struct {
				T string `json:"vault_token"`
				L string `json:"lease_id"`
			} `json:"v"`
		}{}, []string{"v", ""}, []string{"v.vault_token", "v.lease_id", "lease_id"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeConfigJSONKeysDecoded(t, test.value, test.objects, "vault_token", "lease_id"); !slices.Equal(got, test.want) {
				t.Fatalf("runtimeConfigJSONKeysDecoded(%T, %q) = %q, want %q", test.value, test.objects, got, test.want)
			}
		})
	}
}

func TestRuntimeConfigGuardHelpersRefuseNonStructs(t *testing.T) {
	for _, test := range []struct {
		value any
		want  string
	}{
		{nil, "expected a struct, got <nil>"},
		{"text", "expected a struct, got string"},
		{new(map[string]string), "expected a struct, got map[string]string"},
	} {
		for name, check := range map[string]func(testing.TB){
			"runtimeConfigJSONWritten":        func(tb testing.TB) { runtimeConfigJSONWritten(tb, test.value) },
			"runtimeConfigFieldsNotPlainJSON": func(tb testing.TB) { runtimeConfigFieldsNotPlainJSON(tb, test.value) },
			"runtimeConfigCodecMethods":       func(tb testing.TB) { runtimeConfigCodecMethods(tb, test.value) },
			"runtimeConfigJSONKeysDecoded":    func(tb testing.TB) { runtimeConfigJSONKeysDecoded(tb, test.value, []string{""}, "vault_token") },
		} {
			if got := zzRuntimeConfigGuardReports(t, check); got.fatal != test.want {
				t.Fatalf("%s(%T) stopped with %q, want %q", name, test.value, got.fatal, test.want)
			}
		}
	}
}

// zzRuntimeConfigGuardRecorder stands in for the testing.T of a guard check,
// so that a test can see what the check reports.
type zzRuntimeConfigGuardRecorder struct {
	testing.TB
	errors []string
	fatal  string
}

func (recorder *zzRuntimeConfigGuardRecorder) Helper() {}

func (recorder *zzRuntimeConfigGuardRecorder) Errorf(format string, args ...any) {
	recorder.errors = append(recorder.errors, fmt.Sprintf(format, args...))
}

func (recorder *zzRuntimeConfigGuardRecorder) Fatalf(format string, args ...any) {
	recorder.fatal = fmt.Sprintf(format, args...)
	panic(recorder)
}

// zzRuntimeConfigGuardReports runs check with a recorder and returns what
// check reported. A Fatalf ends check, as it would end a test.
func zzRuntimeConfigGuardReports(t *testing.T, check func(testing.TB)) *zzRuntimeConfigGuardRecorder {
	recorder := &zzRuntimeConfigGuardRecorder{TB: t}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != any(recorder) {
				panic(recovered)
			}
		}()
		check(recorder)
	}()
	return recorder
}

// Planted copies of WorkloadZoneVaultConfig and WorkloadZoneVaultConfigBlob.
// The first six are the probes of audit 02 on PR #33 (O33-2), which the old
// guard accepted except the first.

type zzVaultConfigWithTokenTag struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	Token       string `json:"vault_token"`
}

type zzVaultConfigWithUntaggedToken struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	VaultToken  string
}

type zzVaultConfigWithUpperTokenTag struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	Token       string `json:"VAULT_TOKEN"`
}

type zzVaultConfigWithTokenInMap struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	Extra       map[string]struct {
		Token string `json:"vault_token"`
	} `json:"extra"`
}

type zzVaultConfigWithAddressAtDepth struct {
	Address     string `json:"addr"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	Meta        struct {
		A string `json:"address"`
	} `json:"meta"`
}

type zzVaultConfigWithAnyField struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	Extra       any    `json:"extra"`
}

type zzVaultConfigWithSkippedCABundle struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"-"`
}

type zzVaultConfigWithEmbeddedLease struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	zzRuntimeConfigLease
}

type zzVaultConfigWithUnexportedToken struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
	token       string
}

type zzVaultConfigWithBytesCABundle struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM []byte `json:"ca_bundle_pem,omitempty"`
}

type zzVaultConfigWithTextRole struct {
	Address     string                       `json:"address"`
	AuthMount   string                       `json:"auth_mount"`
	AuthRole    zzRuntimeConfigTextMarshaler `json:"auth_role"`
	JWTAudience string                       `json:"jwt_audience"`
	CABundlePEM string                       `json:"ca_bundle_pem,omitempty"`
}

type zzVaultConfigWithoutAddress struct {
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
}

type zzVaultConfigWithNumberMount struct {
	Address     string `json:"address"`
	AuthMount   int    `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
}

type zzBlobWithTokenInConfig struct {
	VaultConfig zzVaultConfigWithTokenTag `json:"vault_config"`
}

// zzBlobWithDottedKey writes a top-level key that reads as the nested key path
// vault_config.address.
type zzBlobWithDottedKey struct {
	VaultConfig zzVaultConfigWithoutAddress `json:"vault_config"`
	Address     string                      `json:"vault_config.address"`
}

func TestWorkloadZoneVaultConfigGuardRefusesPlantedFields(t *testing.T) {
	var vaultConfig []runtimeConfigJSONNode
	blob := []runtimeConfigJSONNode{{path: "vault_config", kind: "object"}}
	for _, key := range workloadZoneVaultConfigKeys {
		vaultConfig = append(vaultConfig, runtimeConfigJSONNode{path: key, kind: "string"})
		blob = append(blob, runtimeConfigJSONNode{path: "vault_config." + key, kind: "string"})
	}
	for _, test := range []struct {
		name   string
		value  any
		want   []runtimeConfigJSONNode
		report []string
	}{
		{"the real config", WorkloadZoneVaultConfig{}, vaultConfig, nil},
		{"the real blob", WorkloadZoneVaultConfigBlob{}, blob, nil},
		{"the real ref", WorkloadZoneVaultConfigRef{}, []runtimeConfigJSONNode{{path: "digest", kind: "string"}}, nil},
		{"an exact vault_token tag", zzVaultConfigWithTokenTag{}, vaultConfig, []string{
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithTokenTag must not decode token, secret, lease, or raw SPIRE key "vault_token"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithTokenTag must write only its non-secret Vault metadata keys, not "vault_token"`,
		}},
		{"an untagged VaultToken", zzVaultConfigWithUntaggedToken{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithUntaggedToken.VaultToken must be an exported, tagged string or struct field, not an untagged field`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithUntaggedToken must write only its non-secret Vault metadata keys, not "VaultToken"`,
		}},
		{"a VAULT_TOKEN tag", zzVaultConfigWithUpperTokenTag{}, vaultConfig, []string{
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithUpperTokenTag must not decode token, secret, lease, or raw SPIRE key "vault_token"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithUpperTokenTag must write only its non-secret Vault metadata keys, not "VAULT_TOKEN"`,
		}},
		{"a vault_token in a map value", zzVaultConfigWithTokenInMap{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithTokenInMap.Extra must be an exported, tagged string or struct field, not a field of type map[string]struct { Token string "json:\"vault_token\"" }`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithTokenInMap must write only its non-secret Vault metadata keys, not "extra"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithTokenInMap must write only its non-secret Vault metadata keys, not "extra.*"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithTokenInMap must write only its non-secret Vault metadata keys, not "extra.*.vault_token"`,
		}},
		{"the address only at depth", zzVaultConfigWithAddressAtDepth{}, vaultConfig, []string{
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithAddressAtDepth must write only its non-secret Vault metadata keys, not "addr"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithAddressAtDepth must write only its non-secret Vault metadata keys, not "meta"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithAddressAtDepth must write only its non-secret Vault metadata keys, not "meta.address"`,
			`expected non-secret workload-zone Vault metadata key "address" in runtimeconfig.zzVaultConfigWithAddressAtDepth`,
		}},
		{"an any field", zzVaultConfigWithAnyField{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithAnyField.Extra must be an exported, tagged string or struct field, not a field of type interface {}`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithAnyField must write only its non-secret Vault metadata keys, not "extra"`,
		}},
		{"a required key skipped", zzVaultConfigWithSkippedCABundle{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithSkippedCABundle.CABundlePEM must be an exported, tagged string or struct field, not a field encoding/json skips`,
			`expected non-secret workload-zone Vault metadata key "ca_bundle_pem" in runtimeconfig.zzVaultConfigWithSkippedCABundle`,
		}},
		{"a lease in an embedded struct", zzVaultConfigWithEmbeddedLease{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithEmbeddedLease.zzRuntimeConfigLease must be an exported, tagged string or struct field, not an embedded field`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithEmbeddedLease must not decode token, secret, lease, or raw SPIRE key "lease_id"`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithEmbeddedLease must write only its non-secret Vault metadata keys, not "lease_id"`,
		}},
		{"an unexported token", zzVaultConfigWithUnexportedToken{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithUnexportedToken.token must be an exported, tagged string or struct field, not an unexported field`,
		}},
		{"a byte slice under a required key", zzVaultConfigWithBytesCABundle{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithBytesCABundle.CABundlePEM must be an exported, tagged string or struct field, not a field of type []uint8`,
		}},
		{"a field type with its own text encoding", zzVaultConfigWithTextRole{}, vaultConfig, []string{
			`workload-zone Vault config type runtimeconfig.zzRuntimeConfigTextMarshaler must not choose its own encoding with MarshalText`,
		}},
		{"a number under a required key", zzVaultConfigWithNumberMount{}, vaultConfig, []string{
			`workload-zone Vault config field runtimeconfig.zzVaultConfigWithNumberMount.AuthMount must be an exported, tagged string or struct field, not a field of type int`,
			`workload-zone Vault config runtimeconfig.zzVaultConfigWithNumberMount key "auth_mount" must hold a JSON string, not number`,
		}},
		{"a token in the nested config of a blob", zzBlobWithTokenInConfig{}, blob, []string{
			`workload-zone Vault config runtimeconfig.zzBlobWithTokenInConfig must not decode token, secret, lease, or raw SPIRE key "vault_config.vault_token"`,
			`workload-zone Vault config runtimeconfig.zzBlobWithTokenInConfig must write only its non-secret Vault metadata keys, not "vault_config.vault_token"`,
		}},
		{"a top-level key that reads as a nested path", zzBlobWithDottedKey{}, blob, []string{
			`json.Marshal writes runtimeconfig.zzBlobWithDottedKey with key "vault_config.address", which no key path can name`,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := zzRuntimeConfigGuardReports(t, func(tb testing.TB) { checkWorkloadZoneVaultConfigJSON(tb, test.value, test.want) })
			if got.fatal != "" {
				t.Fatalf("checkWorkloadZoneVaultConfigJSON(%T) stopped with %q", test.value, got.fatal)
			}
			if !slices.Equal(got.errors, test.report) {
				t.Fatalf("checkWorkloadZoneVaultConfigJSON(%T) reported\n%q\nwant\n%q", test.value, got.errors, test.report)
			}
		})
	}
}
