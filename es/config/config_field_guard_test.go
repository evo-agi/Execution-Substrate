package config

import (
	"fmt"
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
		if carried.fatal != test.want || missing.fatal != test.want {
			t.Fatalf("for %T: configFieldsCarried stopped with %q and configOwnFieldsMissing with %q, want %q", test.value, carried.fatal, missing.fatal, test.want)
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

// Planted copies of ResolvedWorkloadVaultAuthPlan. The first three carry a
// secret where the old guard, which read only the plan's own exported field
// names, did not look; the others lose a metadata field of the plan's own.

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

func TestWorkloadVaultAuthPlanGuardRefusesPlantedFields(t *testing.T) {
	for _, test := range []struct {
		name string
		plan any
		want []string
	}{
		{"the real plan", ResolvedWorkloadVaultAuthPlan{}, nil},
		{"a token in a nested struct", zzPlanWithNestedToken{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "ClientToken" (carried as config.zzPlanWithNestedToken.Session.ClientToken)`,
		}},
		{"a lease in an embedded struct", zzPlanWithEmbeddedLease{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "LeaseID" (carried as config.zzPlanWithEmbeddedLease.zzVaultLease.LeaseID)`,
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "LeaseDuration" (carried as config.zzPlanWithEmbeddedLease.zzVaultLease.LeaseDuration)`,
		}},
		{"a private key in an unexported field", zzPlanWithUnexportedKey{}, []string{
			`resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field "PrivateKey" (carried as config.zzPlanWithUnexportedKey.privateKey)`,
		}},
		{"the address only promoted from an embedded struct", zzPlanWithPromotedAddress{}, []string{
			`expected non-secret workload Vault metadata field "Address"`,
		}},
		{"the audience only in a nested struct", zzPlanWithNestedAudience{}, []string{
			`expected non-secret workload Vault metadata field "JWTAudience"`,
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
