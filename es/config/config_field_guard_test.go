package config

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

type zzConfigNested struct{ VaultToken string }

type zzconfigHidden struct{ VaultToken string }

// vault_token is a type whose name folds to VaultToken.
type vault_token string

type zzConfigNode struct {
	Next *zzConfigNode
	Leaf string
}

type zzConfigNodeWithToken struct {
	Next       *zzConfigNodeWithToken
	VaultToken string
}

type zzConfigPlanNested struct {
	Mode   string
	Auth   zzConfigNested
	Backup *zzConfigNested
}

// The forbidden-field question reads every place a value of the type can hold
// data, not only its own exported fields.
func TestConfigFieldsCarriedReadsTheWholeType(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   any
		carried bool
	}{
		{"a top-level field", struct{ VaultToken string }{}, true},
		{"a pointer to the struct", &struct{ VaultToken string }{}, true},
		{"an unexported field", struct{ vaultToken string }{}, true},
		{"a field of a nested struct", struct{ Auth struct{ VaultToken string } }{}, true},
		{"a field promoted from an embedded struct", struct{ zzConfigNested }{}, true},
		{"a field promoted from an embedded pointer", struct{ *zzConfigNested }{}, true},
		{"a field of an embedded unexported struct", struct{ zzconfigHidden }{}, true},
		{"through a pointer", struct{ Auth *zzConfigNested }{}, true},
		{"through a slice", struct{ Auth []zzConfigNested }{}, true},
		{"through an array", struct{ Auth [1]zzConfigNested }{}, true},
		{"in a map value", struct{ Auth map[string]zzConfigNested }{}, true},
		{"in a map key", struct{ Auth map[zzConfigNested]string }{}, true},
		{"through a channel", struct{ Auth chan zzConfigNested }{}, true},
		{"a field of a type named for it", struct{ Auth vault_token }{}, true},
		{"in another case", struct{ VAULTTOKEN string }{}, true},
		{"with an underscore", struct{ Vault_Token string }{}, true},
		{"with the Kelvin sign for k", struct{ VaultToKen string }{}, true},
		{"in a recursive type", struct{ Head zzConfigNodeWithToken }{}, true},
		{"not in a recursive type without it", struct{ Head zzConfigNode }{}, false},
		{"not as part of a longer name", struct{ VaultTokenizer, MyVaultToken string }{}, false},
		{"not in an unrelated struct", struct {
			Address string
			Labels  map[string]string
		}{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			carried := configFieldsCarried(t, test.value, "VaultToken")
			if got := len(carried) == 1; got != test.carried {
				t.Fatalf("configFieldsCarried(%T, VaultToken) = %v, want carried=%v", test.value, carried, test.carried)
			}
		})
	}

	t.Run("with the long s for s", func(t *testing.T) {
		if carried := configFieldsCarried(t, struct{ Proofſecret string }{}, "ProofSecret"); len(carried) != 1 {
			t.Fatalf("configFieldsCarried = %v, want ProofSecret carried", carried)
		}
	})

	t.Run("names come back in the order asked, with the first place each is carried", func(t *testing.T) {
		got := configFieldsCarried(t, zzConfigPlanNested{}, "LeaseID", "VaultToken", "zzConfigNested", "Mode")
		want := []configCarriedField{
			{name: "VaultToken", where: "config.zzConfigPlanNested.Auth.VaultToken"},
			{name: "zzConfigNested", where: "config.zzConfigPlanNested.Auth of type config.zzConfigNested"},
			{name: "Mode", where: "config.zzConfigPlanNested.Mode"},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("configFieldsCarried = %+v, want %+v", got, want)
		}
	})
}

type ZzVaultAddress struct{ Host string }

type zzConfigPromoted struct{ ZzVaultAddress string }

// The required-field question counts only a field of the type's own, under
// its exact name.
func TestConfigOwnFieldsMissingCountsOnlyOwnExportedFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   any
		missing bool
	}{
		{"an own exported field", struct{ ZzVaultAddress string }{}, false},
		{"a pointer to the struct", &struct{ ZzVaultAddress string }{}, false},
		{"an unexported field", struct{ zzVaultAddress string }{}, true},
		{"in another case", struct{ ZZVAULTADDRESS string }{}, true},
		{"only in a nested struct", struct {
			Vault struct{ ZzVaultAddress string }
		}{}, true},
		{"only promoted from an embedded struct", struct{ zzConfigPromoted }{}, true},
		{"an embedded field of a type with that name", struct{ ZzVaultAddress }{}, true},
		{"an embedded pointer to a type with that name", struct{ *ZzVaultAddress }{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			missing := configOwnFieldsMissing(t, test.value, "ZzVaultAddress")
			if got := len(missing) == 1; got != test.missing {
				t.Fatalf("configOwnFieldsMissing(%T, ZzVaultAddress) = %v, want missing=%v", test.value, missing, test.missing)
			}
		})
	}

	t.Run("names come back in the order asked", func(t *testing.T) {
		got := configOwnFieldsMissing(t, struct{ Mode, Address string }{}, "AuthRole", "Mode", "AuthMount", "Address")
		if want := []string{"AuthRole", "AuthMount"}; !slices.Equal(got, want) {
			t.Fatalf("configOwnFieldsMissing = %v, want %v", got, want)
		}
	})
}

// The extra-field question counts every field the type declares beyond the
// names, whatever its kind, and nothing at depth.
func TestConfigOwnFieldsBeyondCountsEveryOwnField(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  []string
	}{
		{"only the named fields", struct{ ZzVaultAddress, Mode string }{}, nil},
		{"a pointer to the struct", &struct{ ZzVaultAddress string }{}, nil},
		{"an exported field beyond", struct{ ZzVaultAddress, Token string }{}, []string{"Token"}},
		{"an unexported field", struct {
			ZzVaultAddress string
			token          string
		}{}, []string{"token"}},
		{"a blank field", struct {
			ZzVaultAddress string
			_              [0]func()
		}{}, []string{"_"}},
		{"an interface field", struct {
			ZzVaultAddress string
			Extra          any
		}{}, []string{"Extra"}},
		{"a function field", struct {
			ZzVaultAddress string
			Login          func() string
		}{}, []string{"Login"}},
		{"a named field in another case", struct{ ZZVAULTADDRESS string }{}, []string{"ZZVAULTADDRESS"}},
		{"an embedded field of a type with an allowed name", struct{ ZzVaultAddress }{}, []string{"ZzVaultAddress"}},
		{"an embedded pointer to a type with an allowed name", struct{ *ZzVaultAddress }{}, []string{"ZzVaultAddress"}},
		{"a nested struct, by its own name only", struct {
			ZzVaultAddress string
			Vault          struct{ Token string }
		}{}, []string{"Vault"}},
		{"in the order declared", struct {
			Token          string
			ZzVaultAddress string
			Lease          string
		}{}, []string{"Token", "Lease"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := configOwnFieldsBeyond(t, test.value, "ZzVaultAddress", "Mode"); !slices.Equal(got, test.want) {
				t.Fatalf("configOwnFieldsBeyond(%T, ZzVaultAddress, Mode) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

type zzConfigPromotedBytes struct{ ZzVaultAddress []byte }

// The string question counts only a field of the type's own, under its exact
// name, and asks only whether its type is of kind string.
func TestConfigOwnFieldsNotStringsCountsOnlyOwnFieldsOfOtherKinds(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  []configOwnFieldType
	}{
		{"a string field", struct{ ZzVaultAddress string }{}, nil},
		{"a field of a named string type", struct{ ZzVaultAddress WorkloadVaultAuthMode }{}, nil},
		{"a pointer to the struct", &struct{ ZzVaultAddress string }{}, nil},
		{"a pointer to a string", struct{ ZzVaultAddress *string }{}, []configOwnFieldType{{name: "ZzVaultAddress", typ: "*string"}}},
		{"a byte slice", struct{ ZzVaultAddress []byte }{}, []configOwnFieldType{{name: "ZzVaultAddress", typ: "[]uint8"}}},
		{"an interface", struct{ ZzVaultAddress any }{}, []configOwnFieldType{{name: "ZzVaultAddress", typ: "interface {}"}}},
		{"a function", struct{ ZzVaultAddress func() string }{}, []configOwnFieldType{{name: "ZzVaultAddress", typ: "func() string"}}},
		{"a struct", struct {
			ZzVaultAddress struct{ Name, SecretID string }
		}{}, []configOwnFieldType{{name: "ZzVaultAddress", typ: "struct { Name string; SecretID string }"}}},
		{"a field in another case", struct{ zzVaultAddress []byte }{}, nil},
		{"a name the type lacks", struct{ Mode string }{}, nil},
		{"an embedded field of a type with that name", struct{ ZzVaultAddress }{}, nil},
		{"a field promoted from an embedded struct", struct{ zzConfigPromotedBytes }{}, nil},
		{"a field only in a nested struct", struct {
			Vault struct{ ZzVaultAddress []byte }
		}{}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := configOwnFieldsNotStrings(t, test.value, "ZzVaultAddress"); !slices.Equal(got, test.want) {
				t.Fatalf("configOwnFieldsNotStrings(%T, ZzVaultAddress) = %+v, want %+v", test.value, got, test.want)
			}
		})
	}

	t.Run("a field of the type's own other than a string, asked by its exact name", func(t *testing.T) {
		got := configOwnFieldsNotStrings(t, struct{ zzVaultAddress []byte }{}, "zzVaultAddress")
		if want := []configOwnFieldType{{name: "zzVaultAddress", typ: "[]uint8"}}; !slices.Equal(got, want) {
			t.Fatalf("configOwnFieldsNotStrings = %+v, want %+v", got, want)
		}
	})

	t.Run("fields come back in the order asked", func(t *testing.T) {
		got := configOwnFieldsNotStrings(t, struct {
			Mode    []byte
			Address string
			Role    any
		}{}, "Role", "Address", "Mode")
		want := []configOwnFieldType{{name: "Role", typ: "interface {}"}, {name: "Mode", typ: "[]uint8"}}
		if !slices.Equal(got, want) {
			t.Fatalf("configOwnFieldsNotStrings = %+v, want %+v", got, want)
		}
	})

	// Every kind from reflect.Bool to reflect.UnsafePointer, so that a check
	// written as a list of refused kinds cannot pass. The unsafe.Pointer type
	// is taken from the result of reflect.Value.UnsafePointer, so the test
	// needs no unsafe import.
	t.Run("a field of every kind but string is refused", func(t *testing.T) {
		samples := map[reflect.Kind]reflect.Type{}
		for _, typ := range []reflect.Type{
			reflect.TypeFor[bool](), reflect.TypeFor[int](), reflect.TypeFor[int8](), reflect.TypeFor[int16](),
			reflect.TypeFor[int32](), reflect.TypeFor[int64](), reflect.TypeFor[uint](), reflect.TypeFor[uint8](),
			reflect.TypeFor[uint16](), reflect.TypeFor[uint32](), reflect.TypeFor[uint64](), reflect.TypeFor[uintptr](),
			reflect.TypeFor[float32](), reflect.TypeFor[float64](), reflect.TypeFor[complex64](), reflect.TypeFor[complex128](),
			reflect.TypeFor[[1]string](), reflect.TypeFor[chan string](), reflect.TypeFor[func() string](), reflect.TypeFor[any](),
			reflect.TypeFor[map[string]string](), reflect.TypeFor[*string](), reflect.TypeFor[[]string](), reflect.TypeFor[string](),
			reflect.TypeFor[struct{ Name string }](), reflect.TypeOf(reflect.Value.UnsafePointer).Out(0),
		} {
			samples[typ.Kind()] = typ
		}
		for kind := reflect.Bool; kind <= reflect.UnsafePointer; kind++ {
			typ, ok := samples[kind]
			if !ok {
				t.Fatalf("no sample type of kind %s", kind)
			}
			value := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "ZzVaultAddress", Type: typ}})).Elem().Interface()
			got := configOwnFieldsNotStrings(t, value, "ZzVaultAddress")
			var want []configOwnFieldType
			if kind != reflect.String {
				want = []configOwnFieldType{{name: "ZzVaultAddress", typ: typ.String()}}
			}
			if !slices.Equal(got, want) {
				t.Errorf("kind %s: configOwnFieldsNotStrings = %+v, want %+v", kind, got, want)
			}
		}
	})
}

func TestConfigFieldGuardHelpersRefuseNonStructs(t *testing.T) {
	for _, test := range []struct {
		value any
		want  string
	}{
		{nil, "expected a struct, got <nil>"},
		{"text", "expected a struct, got string"},
		{new(map[string]string), "expected a struct, got map[string]string"},
	} {
		carried := zzConfigGuardReports(t, func(tb testing.TB) { configFieldsCarried(tb, test.value, "VaultToken") })
		missing := zzConfigGuardReports(t, func(tb testing.TB) { configOwnFieldsMissing(tb, test.value, "Mode") })
		beyond := zzConfigGuardReports(t, func(tb testing.TB) { configOwnFieldsBeyond(tb, test.value, "Mode") })
		notStrings := zzConfigGuardReports(t, func(tb testing.TB) { configOwnFieldsNotStrings(tb, test.value, "Mode") })
		if carried.fatal != test.want || missing.fatal != test.want || beyond.fatal != test.want || notStrings.fatal != test.want {
			t.Fatalf("for %T: configFieldsCarried stopped with %q, configOwnFieldsMissing with %q, configOwnFieldsBeyond with %q and configOwnFieldsNotStrings with %q, want %q", test.value, carried.fatal, missing.fatal, beyond.fatal, notStrings.fatal, test.want)
		}
	}
}

// zzConfigGuardRecorder stands in for the testing.T of a guard check, so that
// a test can see what the check reports.
type zzConfigGuardRecorder struct {
	testing.TB
	errors []string
	fatal  string
}

func (recorder *zzConfigGuardRecorder) Helper() {}

func (recorder *zzConfigGuardRecorder) Errorf(format string, args ...any) {
	recorder.errors = append(recorder.errors, fmt.Sprintf(format, args...))
}

func (recorder *zzConfigGuardRecorder) Fatalf(format string, args ...any) {
	recorder.fatal = fmt.Sprintf(format, args...)
	panic(recorder)
}

// zzConfigGuardReports runs check with a recorder and returns what check
// reported. A Fatalf ends check, as it would end a test.
func zzConfigGuardReports(t *testing.T, check func(testing.TB)) *zzConfigGuardRecorder {
	recorder := &zzConfigGuardRecorder{TB: t}
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

// Planted copies of ResolvedWorkloadVaultAuthPlan. Each of the first seven
// declares a field beyond the plan's metadata fields. The first three carry a
// secret where the old guard, which read only the plan's own exported field
// names, did not look; the next two lose a metadata field of the plan's own;
// the next two carry what no forbidden name can match. The last two declare
// only the metadata fields: in one, a field holds a struct, not a string; in
// the other, no field holds a string.

type zzPlanWithNestedToken struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
	Session     struct{ ClientToken string }
}

type zzVaultLease struct {
	LeaseID       string
	LeaseDuration int64
}

type zzPlanWithEmbeddedLease struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
	zzVaultLease
}

type zzPlanWithUnexportedKey struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
	privateKey  []byte
}

type zzVaultEndpoint struct{ Address string }

type zzPlanWithPromotedAddress struct {
	Mode WorkloadVaultAuthMode
	zzVaultEndpoint
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
}

type zzPlanWithNestedAudience struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWT         struct{ JWTAudience string }
	CABundlePEM string
}

type zzPlanWithAnyField struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
	Extra       any
}

type zzPlanWithTokenFile struct {
	Mode           WorkloadVaultAuthMode
	Address        string
	AuthMount      string
	AuthRole       string
	JWTAudience    string
	CABundlePEM    string
	VaultTokenFile string
}

type zzPlanWithRoleSecret struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    struct{ Name, SecretID string }
	JWTAudience string
	CABundlePEM string
}

type zzPlanWithNoStrings struct {
	Mode        *WorkloadVaultAuthMode
	Address     []byte
	AuthMount   any
	AuthRole    struct{ Name, SecretID string }
	JWTAudience func() string
	CABundlePEM [1]string
}

func TestWorkloadVaultAuthPlanGuardRefusesPlantedFields(t *testing.T) {
	for _, test := range []struct {
		name string
		plan any
		want []string
	}{
		{"the real plan", ResolvedWorkloadVaultAuthPlan{}, nil},
		{"a token in a nested struct", zzPlanWithNestedToken{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "ClientToken" (carried as config.zzPlanWithNestedToken.Session.ClientToken)`,
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "Session"`,
		}},
		{"a lease in an embedded struct", zzPlanWithEmbeddedLease{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "LeaseID" (carried as config.zzPlanWithEmbeddedLease.zzVaultLease.LeaseID)`,
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "LeaseDuration" (carried as config.zzPlanWithEmbeddedLease.zzVaultLease.LeaseDuration)`,
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "zzVaultLease"`,
		}},
		{"a private key in an unexported field", zzPlanWithUnexportedKey{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "PrivateKey" (carried as config.zzPlanWithUnexportedKey.privateKey)`,
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "privateKey"`,
		}},
		{"the address only promoted from an embedded struct", zzPlanWithPromotedAddress{}, []string{
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "zzVaultEndpoint"`,
			`expected non-secret workload Vault metadata field "Address"`,
		}},
		{"the audience only in a nested struct", zzPlanWithNestedAudience{}, []string{
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "JWT"`,
			`expected non-secret workload Vault metadata field "JWTAudience"`,
		}},
		{"an interface field", zzPlanWithAnyField{}, []string{
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "Extra"`,
		}},
		{"a longer name that holds a forbidden one", zzPlanWithTokenFile{}, []string{
			`resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field "VaultTokenFile"`,
		}},
		{"a secret inside a metadata field", zzPlanWithRoleSecret{}, []string{
			`resolved workload Vault auth plan field "AuthRole" must hold a string, not struct { Name string; SecretID string }`,
		}},
		{"no metadata field holding a string", zzPlanWithNoStrings{}, []string{
			`resolved workload Vault auth plan field "Mode" must hold a string, not *config.WorkloadVaultAuthMode`,
			`resolved workload Vault auth plan field "Address" must hold a string, not []uint8`,
			`resolved workload Vault auth plan field "AuthMount" must hold a string, not interface {}`,
			`resolved workload Vault auth plan field "AuthRole" must hold a string, not struct { Name string; SecretID string }`,
			`resolved workload Vault auth plan field "JWTAudience" must hold a string, not func() string`,
			`resolved workload Vault auth plan field "CABundlePEM" must hold a string, not [1]string`,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := zzConfigGuardReports(t, func(tb testing.TB) { checkWorkloadVaultAuthPlanFields(tb, test.plan) })
			if got.fatal != "" {
				t.Fatalf("checkWorkloadVaultAuthPlanFields(%T) stopped with %q", test.plan, got.fatal)
			}
			if !slices.Equal(got.errors, test.want) {
				t.Fatalf("checkWorkloadVaultAuthPlanFields(%T) reported\n%q\nwant\n%q", test.plan, got.errors, test.want)
			}
		})
	}
}
