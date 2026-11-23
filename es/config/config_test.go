package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestExecutionConfigValidateAllowsDefaultRuntimeIdentityTmpfsSize(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		RetainedResultAuth:         RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/tmp/es-auth/key"},
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
	}

	if err := cfg.Validate("execution"); err != nil {
		t.Fatalf("expected config to validate with default tmpfs size, got %v", err)
	}
	if got := cfg.EffectiveRuntimeIdentityTmpfsSize(); got != defaultRuntimeIdentityTmpfsSizeBytes {
		t.Fatalf("expected default tmpfs size %d, got %d", defaultRuntimeIdentityTmpfsSizeBytes, got)
	}
}

func TestExecutionConfigValidateRejectsTmpfsSizeAboveMax(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RuntimeIdentityTmpfsSize:   maxRuntimeIdentityTmpfsSizeBytes + 1,
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for tmpfs size above max")
	}
	if !strings.Contains(err.Error(), "runtime_identity_tmpfs_size") {
		t.Fatalf("expected runtime_identity_tmpfs_size validation error, got %v", err)
	}
}

func TestExecutionConfigEffectiveRuntimeIdentityTmpfsSizeUsesExplicitValue(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RuntimeIdentityTmpfsSize:   2 << 20,
	}

	if got := cfg.EffectiveRuntimeIdentityTmpfsSize(); got != 2<<20 {
		t.Fatalf("expected explicit tmpfs size to be preserved, got %d", got)
	}
}

func TestExecutionConfigValidateAllowsEnabledControlPlaneNormalShellProfile(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RuntimeProfiles: RuntimeProfilesConfig{
			ControlPlaneNormalShell: ControlPlaneNormalShellProfileConfig{
				Enabled:                    true,
				Image:                      "execution-substrate/control-plane-normal-shell:supported-local",
				CodexCLIPath:               "/usr/local/bin/codex",
				CredentialVaultSecretPath:  "proof-secrets/data/codex-runtime-profile",
				CredentialVaultSecretField: "api_key",
			},
		},
		RetainedResultAuth: RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/tmp/es-auth/key"},
	}

	if err := cfg.Validate("execution"); err != nil {
		t.Fatalf("expected enabled control-plane normal-shell profile to validate, got %v", err)
	}
}

func TestRetainedResultAuthConfigRequiresCanonicalExplicitInputs(t *testing.T) {
	valid := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RetainedResultAuth:         RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/tmp/es-auth/key"},
	}
	if err := valid.Validate("execution"); err != nil {
		t.Fatalf("valid explicit result auth config: %v", err)
	}
	tests := []struct {
		name string
		edit func(*ExecutionConfig)
	}{
		{"missing store", func(c *ExecutionConfig) { c.RetainedResultAuth.StoreID = "" }},
		{"invalid store", func(c *ExecutionConfig) { c.RetainedResultAuth.StoreID = "Upper" }},
		{"oversized key ID", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyID = strings.Repeat("a", 33) }},
		{"missing key path", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyFile = "" }},
		{"relative key path", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyFile = "key" }},
		{"unclean key path", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyFile = "/tmp/es-auth/../key" }},
		{"key in results", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyFile = "/tmp/es-results/key" }},
		{"key in staging", func(c *ExecutionConfig) { c.RetainedResultAuth.KeyFile = "/tmp/es-stage/key" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.edit(&cfg)
			if err := cfg.Validate("execution"); err == nil || !strings.Contains(err.Error(), "retained_result_auth") {
				t.Fatalf("unsafe result auth config accepted or misclassified: %v", err)
			}
		})
	}
}

func TestRetainedResultAuditF1SubmitExamplesPassFullConfigValidation(t *testing.T) {
	for _, name := range []string{
		"es.json",
		"es.configured_literal_policy_demo.json",
		"es.operator_and_control_plane.json",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", ".examples", "config", name))
			if err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("decode example: %v", err)
			}
			if cfg.Nomad.BaseURL == "" || cfg.Execution.StagingRootDir == "" || cfg.Execution.RetainedResultAuth.KeyFile == "" {
				t.Fatal("Submit-enabled example lacks required configuration")
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("full example configuration rejected: %v", err)
			}
		})
	}
}

func TestRetainedResultAuditF3RootParentIsOutsideSupportedPlacement(t *testing.T) {
	cfg := RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/tmp/external-auth/key"}
	if err := cfg.Validate("execution.retained_result_auth", "/tmp/stage", "/tmp/results"); err != nil {
		t.Fatalf("nested external key rejected: %v", err)
	}
	for _, path := range []string{"/key", "/"} {
		cfg.KeyFile = path
		err := cfg.Validate("execution.retained_result_auth", "/tmp/stage", "/tmp/results")
		if err == nil || !strings.Contains(err.Error(), "execution.retained_result_auth.key_file") ||
			!strings.Contains(err.Error(), "non-root parent") || strings.Contains(err.Error(), path) {
			t.Fatalf("root-parent key did not fail with bounded field reason: %v", err)
		}
	}
}

func TestRetainedResultReviewKeyExclusionUsesEffectivePaddedRoots(t *testing.T) {
	valid := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage ",
		ResultsRootDir:             " /tmp/es-results ",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RetainedResultAuth:         RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/tmp/es-auth /key"},
	}
	if err := valid.Validate("execution"); err != nil {
		t.Fatalf("distinct canonical key parent was rejected: %v", err)
	}
	for _, keyPath := range []string{"/tmp/es-stage/auth/key", "/tmp/es-results/auth/key"} {
		cfg := valid
		cfg.RetainedResultAuth.KeyFile = keyPath
		if err := cfg.Validate("execution"); err == nil || !strings.Contains(err.Error(), "retained_result_auth.key_file") {
			t.Fatalf("key inside normalized execution root was accepted: %v", err)
		}
	}
}

func TestExecutionConfigValidateRejectsIncompleteControlPlaneNormalShellProfile(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RuntimeProfiles: RuntimeProfilesConfig{
			ControlPlaneNormalShell: ControlPlaneNormalShellProfileConfig{
				Enabled: true,
			},
		},
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for incomplete control-plane normal-shell profile")
	}
	if !strings.Contains(err.Error(), "control_plane_normal_shell.image") {
		t.Fatalf("expected profile image validation error, got %v", err)
	}

	cfg.RuntimeProfiles.ControlPlaneNormalShell.Image = "execution-substrate/control-plane-normal-shell:supported-local"
	cfg.RuntimeProfiles.ControlPlaneNormalShell.CodexCLIPath = "codex"
	err = cfg.Validate("execution")
	if err == nil || !strings.Contains(err.Error(), "codex_cli_path") {
		t.Fatalf("expected codex_cli_path validation error, got %v", err)
	}
}

func TestExecutionConfigValidateRejectsMissingRuntimeSupportBinary(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-results",
		BaseImage:                  "alpine:3.20",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for missing runtime support binary")
	}
	if !strings.Contains(err.Error(), "runtime_support_binary") {
		t.Fatalf("expected runtime_support_binary validation error, got %v", err)
	}
}

func TestExecutionConfigValidateRejectsMissingSPIRESocketPath(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:       "/tmp/es-stage",
		ResultsRootDir:       "/tmp/es-results",
		BaseImage:            "alpine:3.20",
		RuntimeSupportBinary: "/usr/local/bin/es-runtime-support",
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for missing spire workload api socket path")
	}
	if !strings.Contains(err.Error(), "spire_workload_api_socket_path") {
		t.Fatalf("expected spire_workload_api_socket_path validation error, got %v", err)
	}
}

func TestExecutionConfigValidateRejectsMissingResultsRootDir(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for missing results root dir")
	}
	if !strings.Contains(err.Error(), "results_root_dir") {
		t.Fatalf("expected results_root_dir validation error, got %v", err)
	}
}

func TestExecutionConfigValidateRejectsResultsRootDirEqualToStagingRootDir(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-stage",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for results root matching staging root")
	}
	if !strings.Contains(err.Error(), "results_root_dir") {
		t.Fatalf("expected results_root_dir validation error, got %v", err)
	}
}

func TestExecutionConfigValidateRejectsResultsRootDirUnderStagingRootDir(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
		ResultsRootDir:             "/tmp/es-stage/results",
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
	}

	err := cfg.Validate("execution")
	if err == nil {
		t.Fatalf("expected validation error for results root under staging root")
	}
	if !strings.Contains(err.Error(), "results_root_dir") {
		t.Fatalf("expected results_root_dir validation error, got %v", err)
	}
}

func TestRuntimeConfigValidateRejectsMissingWorkloadZoneVaultConfigRef(t *testing.T) {
	cfg := RuntimeConfigConfig{}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected missing workload-zone vault config ref to fail validation")
	}
	if !strings.Contains(err.Error(), "runtime_config.workload_zone_vault_config_ref") {
		t.Fatalf("expected runtime_config.workload_zone_vault_config_ref validation error, got %v", err)
	}
}

func TestRuntimeConfigValidateAcceptsValidWorkloadZoneVaultConfigRef(t *testing.T) {
	cfg := RuntimeConfigConfig{
		WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
			Digest: " sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected workload-zone vault config ref to validate, got %v", err)
	}
}

func TestWorkloadVaultAuthResolveUsesVaultRuntimeFields(t *testing.T) {
	cfg := WorkloadVaultAuthConfig{
		DefaultMode: WorkloadVaultAuthModeVaultIdentityJWT,
	}

	plan, err := cfg.Resolve(runtimeconfigv1.WorkloadZoneVaultConfig{
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "service_execution",
		JWTAudience: "vault",
	})
	if err != nil {
		t.Fatalf("expected workload vault auth plan to resolve, got %v", err)
	}

	if plan.Mode != WorkloadVaultAuthModeVaultIdentityJWT {
		t.Fatalf("expected default auth mode to be preserved, got %q", plan.Mode)
	}
	if plan.Address != "https://vault.internal:8200" || plan.AuthMount != "jwt" || plan.AuthRole != "service_execution" || plan.JWTAudience != "vault" {
		t.Fatalf("unexpected resolved plan: %+v", plan)
	}
}

func TestWorkloadVaultAuthPlanCarriesOnlyNonSecretVaultMetadata(t *testing.T) {
	checkWorkloadVaultAuthPlanFields(t, ResolvedWorkloadVaultAuthPlan{})
}

// checkWorkloadVaultAuthPlanFields fails t when a value of plan's type can carry
// a token, secret, lease or raw SPIRE field anywhere in it, or when plan's own
// type declares anything but exactly the non-secret Vault metadata fields, each
// holding a string.
func checkWorkloadVaultAuthPlanFields(t testing.TB, plan any) {
	t.Helper()
	metadata := []string{
		"Mode",
		"Address",
		"AuthMount",
		"AuthRole",
		"JWTAudience",
		"CABundlePEM",
	}
	for _, carried := range configFieldsCarried(t, plan,
		"VaultToken",
		"ClientToken",
		"RootToken",
		"UnsealKey",
		"JWTSVID",
		"X509SVID",
		"PrivateKey",
		"APIKey",
		"ProofSecret",
		"SecretPayload",
		"LeaseID",
		"LeaseDuration",
		"RawSPIRESocket",
	) {
		t.Errorf("resolved workload Vault auth plan must not carry token, secret, lease, or raw SPIRE field %q (carried as %s)", carried.name, carried.where)
	}
	for _, beyond := range configOwnFieldsBeyond(t, plan, metadata...) {
		t.Errorf("resolved workload Vault auth plan must declare only its non-secret Vault metadata fields, not field %q", beyond)
	}
	for _, missing := range configOwnFieldsMissing(t, plan, metadata...) {
		t.Errorf("expected non-secret workload Vault metadata field %q", missing)
	}
	for _, field := range configOwnFieldsNotStrings(t, plan, metadata...) {
		t.Errorf("resolved workload Vault auth plan field %q must hold a string, not %s", field.name, field.typ)
	}
}

func TestWorkloadVaultAuthResolveRejectsMissingVaultRole(t *testing.T) {
	cfg := WorkloadVaultAuthConfig{
		DefaultMode: WorkloadVaultAuthModeVaultIdentityJWT,
	}

	_, err := cfg.Resolve(runtimeconfigv1.WorkloadZoneVaultConfig{
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		JWTAudience: "vault",
	})
	if err == nil {
		t.Fatalf("expected workload vault auth plan resolution to fail without auth role")
	}
	if !strings.Contains(err.Error(), "auth role") {
		t.Fatalf("expected missing auth role error, got %v", err)
	}
}

func TestConfigValidateAllowsPrepareOnlyConfiguration(t *testing.T) {
	cfg := validTestConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected prepare-only config to validate, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateAcceptsHarmlessStaticScriptLiteralMarker(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()

	if err := cfg.Validate("admission_policy.configured_static_script_literal_deny"); err != nil {
		t.Fatalf("expected configured static-script literal deny policy to validate, got %v", err)
	}
}

func TestConfiguredLiteralPolicyDemoExampleActivatesAdmissionPolicy(t *testing.T) {
	examplePath := filepath.Join("..", "..", ".examples", "config", "es.configured_literal_policy_demo.json")
	raw, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read configured literal policy demo example: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode configured literal policy demo example: %v", err)
	}
	if cfg.AdmissionPolicy == nil || cfg.AdmissionPolicy.ConfiguredStaticScriptLiteralDeny == nil {
		t.Fatalf("configured literal policy demo example must activate configured_static_script_literal_deny")
	}

	policy := cfg.AdmissionPolicy.ConfiguredStaticScriptLiteralDeny
	if policy.Mode != ConfiguredStaticScriptLiteralDenyModeEnforce {
		t.Fatalf("configured literal policy demo example must use enforce mode")
	}
	if len(policy.Entries) != 1 {
		t.Fatalf("configured literal policy demo example must carry exactly one placeholder entry")
	}
	entry := policy.Entries[0]
	if entry.InputClass != ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText {
		t.Fatalf("configured literal policy demo example must use static_script_payload_text")
	}
	if strings.TrimSpace(entry.ID) == "" || strings.TrimSpace(entry.Literal) == "" {
		t.Fatalf("configured literal policy demo example must use a safe ID and placeholder literal")
	}
	if err := cfg.AdmissionPolicy.Validate(); err != nil {
		t.Fatalf("configured literal policy demo admission policy must validate: %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsInvalidEntryID(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries[0].ID = "not safe"

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected invalid configured literal deny entry ID to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].id") {
		t.Fatalf("expected entry ID validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsDuplicateEntryIDs(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries = append(cfg.Entries, ConfiguredStaticScriptLiteralDenyEntryConfig{
		ID:         cfg.Entries[0].ID,
		InputClass: ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
		Literal:    "ES_DEMO_LITERAL_MARKER_DUPLICATE",
	})

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected duplicate configured literal deny entry ID to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[1].id") || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("expected duplicate entry ID validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsOversizedLiteralWithoutEchoingValue(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	unsafeLiteral := "ES_PRIVATE_MARKER_" + strings.Repeat("X", MaxConfiguredStaticScriptLiteralDenyLiteralBytes+1)
	cfg.Entries[0].Literal = unsafeLiteral

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected oversized configured literal to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
	if strings.Contains(err.Error(), unsafeLiteral) {
		t.Fatalf("configured literal validation error must not echo the literal value")
	}
}

func TestAdmissionPolicyConfigValidateRejectsEmptyLiteral(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries[0].Literal = ""

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected empty configured literal to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsWhitespaceOnlyLiteral(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	unsafeLiteral := "   "
	cfg.Entries[0].Literal = unsafeLiteral

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected whitespace-only configured literal to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
	assertConfigValidationErrorOmitsLiteral(t, err, unsafeLiteral)
}

func TestAdmissionPolicyConfigValidateRejectsTooManyEntries(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	for len(cfg.Entries) <= MaxConfiguredStaticScriptLiteralDenyEntries {
		cfg.Entries = append(cfg.Entries, ConfiguredStaticScriptLiteralDenyEntryConfig{
			ID:         "marker-extra",
			InputClass: ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
			Literal:    "ES_DEMO_LITERAL_MARKER_EXTRA",
		})
	}

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected too many configured literal deny entries to fail validation")
	}
	if !strings.Contains(err.Error(), "entries") {
		t.Fatalf("expected entries validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsEnforceWithoutEntries(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries = nil

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected enforce mode without configured literal entries to fail validation")
	}
	if !strings.Contains(err.Error(), "entries") {
		t.Fatalf("expected entries validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsInvalidMode(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Mode = ConfiguredStaticScriptLiteralDenyPolicyMode("audit")

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected invalid configured literal deny mode to fail validation")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Fatalf("expected mode validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateAllowsDisabledWithoutEntries(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Mode = ConfiguredStaticScriptLiteralDenyModeDisabled
	cfg.Entries = nil

	if err := cfg.Validate("admission_policy.configured_static_script_literal_deny"); err != nil {
		t.Fatalf("expected disabled configured literal deny policy without entries to validate, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateAllowsDisabledWithValidEntries(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Mode = ConfiguredStaticScriptLiteralDenyModeDisabled

	if err := cfg.Validate("admission_policy.configured_static_script_literal_deny"); err != nil {
		t.Fatalf("expected disabled configured literal deny policy with valid entries to validate, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsDisabledWithInvalidEntries(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Mode = ConfiguredStaticScriptLiteralDenyModeDisabled
	cfg.Entries[0].Literal = ""

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected disabled configured literal deny policy with invalid entries to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsUnsupportedInputClass(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries[0].InputClass = ConfiguredStaticScriptLiteralDenyInputClass("workspace_archive")

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected unsupported configured literal deny input class to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].input_class") {
		t.Fatalf("expected input class validation error, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateTreatsRegexLikeLiteralAsLiteralConfig(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	cfg.Entries[0].Literal = "^ES_DEMO_LITERAL_MARKER.*$"

	if err := cfg.Validate("admission_policy.configured_static_script_literal_deny"); err != nil {
		t.Fatalf("expected regex-looking configured literal to validate as literal text, got %v", err)
	}
}

func TestAdmissionPolicyConfigValidateRejectsControlCharactersWithoutEchoingValue(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	unsafeLiteral := "ES_PRIVATE_MARKER_WITH_CONTROL\n"
	cfg.Entries[0].Literal = unsafeLiteral

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected configured literal with control character to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
	if strings.Contains(err.Error(), unsafeLiteral) {
		t.Fatalf("configured literal validation error must not echo the literal value")
	}
}

func TestAdmissionPolicyConfigValidateRejectsUnicodeControlAndNonPrintableLiteralsWithoutEchoingValue(t *testing.T) {
	tests := []struct {
		name          string
		unsafeLiteral string
	}{
		{name: "non_ascii_control", unsafeLiteral: "ES_PRIVATE_MARKER_\u0085"},
		{name: "format_invisible", unsafeLiteral: "ES_PRIVATE_MARKER_\u200b"},
		{name: "unassigned_non_printable", unsafeLiteral: "ES_PRIVATE_MARKER_\u0378"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
			cfg.Entries[0].Literal = tt.unsafeLiteral

			err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
			if err == nil {
				t.Fatalf("expected configured literal with non-printable Unicode to fail validation")
			}
			if !strings.Contains(err.Error(), "entries[0].literal") {
				t.Fatalf("expected literal validation error, got %v", err)
			}
			assertConfigValidationErrorOmitsLiteral(t, err, tt.unsafeLiteral)
		})
	}
}

func TestAdmissionPolicyConfigValidateRejectsInvalidUTF8Literal(t *testing.T) {
	cfg := validConfiguredStaticScriptLiteralDenyPolicyConfig()
	unsafeLiteral := string([]byte{0xff})
	cfg.Entries[0].Literal = unsafeLiteral

	err := cfg.Validate("admission_policy.configured_static_script_literal_deny")
	if err == nil {
		t.Fatalf("expected configured literal with invalid UTF-8 to fail validation")
	}
	if !strings.Contains(err.Error(), "entries[0].literal") {
		t.Fatalf("expected literal validation error, got %v", err)
	}
	assertConfigValidationErrorOmitsLiteral(t, err, unsafeLiteral)
}

func assertConfigValidationErrorOmitsLiteral(t *testing.T, err error, unsafeLiteral string) {
	t.Helper()
	if unsafeLiteral != "" && strings.Contains(err.Error(), unsafeLiteral) {
		t.Fatalf("configured literal validation error must not echo the literal value")
	}
}

func TestConfigValidateAllowsNarrowSPIFFEPathPrefixes(t *testing.T) {
	cfg := validTestConfig()
	cfg.Authorization.AllowedSPIFFEPathPrefixes = []string{
		"service/control-plane",
		"service/control-plane/provider",
		"operator/local",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected narrow SPIFFE path prefixes to validate, got %v", err)
	}
}

func TestConfigValidateRejectsBroadOrMalformedSPIFFEPathPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "empty", prefix: ""},
		{name: "whitespace", prefix: " "},
		{name: "root", prefix: "/"},
		{name: "dot", prefix: "."},
		{name: "dotdot", prefix: ".."},
		{name: "single segment service", prefix: "service"},
		{name: "single segment operator", prefix: "operator"},
		{name: "leading slash", prefix: "/service/control-plane"},
		{name: "trailing slash", prefix: "service/control-plane/"},
		{name: "empty middle segment", prefix: "service//control-plane"},
		{name: "dot segment", prefix: "service/./control-plane"},
		{name: "dotdot segment", prefix: "service/../control-plane"},
		{name: "full spiffe uri", prefix: "spiffe://execution.internal/service/control-plane"},
		// Since the shared rule in internal/callerallowlist (PR 27 red-team R6):
		// prefixes no canonical caller path can match.
		{name: "leading whitespace", prefix: " service/control-plane"},
		{name: "space inside a segment", prefix: "service/control plane"},
		{name: "query", prefix: "service/control-plane?x"},
		{name: "percent encoding", prefix: "service/control%2Dplane"},
		{name: "non-ASCII letter", prefix: "service/contröl-plane"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Authorization.AllowedSPIFFEPathPrefixes = []string{tt.prefix}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected SPIFFE prefix %q to fail validation", tt.prefix)
			}
			if !strings.Contains(err.Error(), "authorization.allowed_spiffe_path_prefixes") {
				t.Fatalf("expected authorization prefix validation error, got %v", err)
			}
		})
	}
}

func TestConfigValidateRequiresExecutionWhenSubmitConfigured(t *testing.T) {
	cfg := validTestConfig()
	cfg.Nomad = NomadConfig{
		BaseURL:        "http://127.0.0.1:4646",
		Datacenter:     "dc1",
		TimeoutSeconds: 5,
	}
	cfg.Execution = ExecutionConfig{
		StagingRootDir: "/tmp/es-stage",
		ResultsRootDir: "/tmp/es-results",
		BaseImage:      "alpine:3.20",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected submit-configured validation failure")
	}
	if !strings.Contains(err.Error(), "execution.runtime_support_binary") {
		t.Fatalf("expected execution validation error, got %v", err)
	}
}

func TestLoadRejectsTrailingDataAfterFirstDocument(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "es.json")
	if err := os.WriteFile(configPath, []byte(validTestConfigJSON()+"\n{}"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("expected trailing JSON data to be rejected")
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected trailing data error, got %v", err)
	}
}

func TestWorkloadVaultAuthValidateRejectsUnsupportedMode(t *testing.T) {
	err := WorkloadVaultAuthConfig{DefaultMode: WorkloadVaultAuthMode("other")}.Validate()
	if err == nil {
		t.Fatalf("expected unsupported workload vault auth mode to fail validation")
	}
	if !strings.Contains(err.Error(), "workload_vault_auth.default_mode") {
		t.Fatalf("expected workload vault auth mode validation error, got %v", err)
	}
}

// configCarriedField is a forbidden name that a value of a type may carry, and
// the first place where configFieldsCarried found it.
type configCarriedField struct {
	name  string
	where string
}

// configFieldsCarried answers one question: may a value of value's type carry
// one of names anywhere in it? It returns each such name with the first place
// it is carried, in the order of names.
//
// It reads the whole type, and records too much on purpose:
//   - every field at any depth, exported or not, embedded or not, so a field
//     promoted from an embedded struct counts under its own name;
//   - through pointers, slices, arrays, maps (key and value) and channels;
//   - the name of each named type on the way, so a field of a type named
//     PrivateKey counts, and so does an embedded field;
//   - names compared with case folded and underscores dropped, so
//     vault_token and VAULTTOKEN count as VaultToken.
//
// It cannot see inside an interface or a function. Use configOwnFieldsMissing,
// never this, to ask whether a field is there.
func configFieldsCarried(t testing.TB, value any, names ...string) []configCarriedField {
	t.Helper()
	root := configStructType(t, value)
	where := map[string]string{}
	record := func(name, place string) {
		key := foldConfigFieldName(name)
		if _, ok := where[key]; !ok {
			where[key] = place
		}
	}
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, place string)
	walk = func(typ reflect.Type, place string) {
		if typ.Name() != "" {
			record(typ.Name(), place+" of type "+typ.String())
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
			walk(typ.Elem(), place+"[elem]")
		case reflect.Map:
			walk(typ.Key(), place+"[key]")
			walk(typ.Elem(), place+"[value]")
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldPlace := place + "." + field.Name
				record(field.Name, fieldPlace)
				walk(field.Type, fieldPlace)
			}
		}
	}
	walk(root, root.String())

	var carried []configCarriedField
	for _, name := range names {
		if place, ok := where[foldConfigFieldName(name)]; ok {
			carried = append(carried, configCarriedField{name: name, where: place})
		}
	}
	return carried
}

// configOwnFieldsMissing answers one question: which of names is not a field
// of value's own struct type? A field counts only when the type itself
// declares it, not embedded, under exactly that name. A field promoted from an
// embedded struct, one at depth, one in another case, or an embedded field of
// a type with that name does not count.
func configOwnFieldsMissing(t testing.TB, value any, names ...string) []string {
	t.Helper()
	root := configStructType(t, value)
	own := map[string]bool{}
	for i := 0; i < root.NumField(); i++ {
		field := root.Field(i)
		if !field.Anonymous {
			own[field.Name] = true
		}
	}
	var missing []string
	for _, name := range names {
		if !own[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// configOwnFieldsBeyond answers one question: which fields does value's own
// struct type declare beyond names? Every field the type declares counts,
// exported or not, blank or not, of any type, in the order declared. An
// embedded field is always beyond names, even when its type has one of those
// names, because configOwnFieldsMissing does not count it as that field. A
// field at depth is not the type's own; configFieldsCarried reads those.
func configOwnFieldsBeyond(t testing.TB, value any, names ...string) []string {
	t.Helper()
	root := configStructType(t, value)
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	var beyond []string
	for i := range root.NumField() {
		field := root.Field(i)
		if field.Anonymous || !allowed[field.Name] {
			beyond = append(beyond, field.Name)
		}
	}
	return beyond
}

// configOwnFieldType is a field of a struct type's own and the type it holds.
type configOwnFieldType struct {
	name string
	typ  string
}

// configOwnFieldsNotStrings answers one question: which of names is a field of
// value's own struct type that does not hold a string? A field counts as in
// configOwnFieldsMissing: the type itself declares it, not embedded, under
// exactly that name. A name the type lacks is not reported here, because
// configOwnFieldsMissing reports it. A field holds a string when its type is
// of kind string, so a named string type such as WorkloadVaultAuthMode does,
// and a pointer, slice, interface, function or struct does not. It returns
// each such field with its type, in the order of names.
func configOwnFieldsNotStrings(t testing.TB, value any, names ...string) []configOwnFieldType {
	t.Helper()
	root := configStructType(t, value)
	own := map[string]reflect.Type{}
	for i := range root.NumField() {
		if field := root.Field(i); !field.Anonymous {
			own[field.Name] = field.Type
		}
	}
	var notStrings []configOwnFieldType
	for _, name := range names {
		if typ, ok := own[name]; ok && typ.Kind() != reflect.String {
			notStrings = append(notStrings, configOwnFieldType{name: name, typ: typ.String()})
		}
	}
	return notStrings
}

func configStructType(t testing.TB, value any) reflect.Type {
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

// foldConfigFieldName drops underscores and maps each letter to the smallest
// letter of its case-folding orbit, so two names fold alike exactly when
// strings.EqualFold holds for them without their underscores.
func foldConfigFieldName(name string) string {
	var folded strings.Builder
	for _, r := range name {
		if r == '_' {
			continue
		}
		smallest := r
		for other := unicode.SimpleFold(r); other != r; other = unicode.SimpleFold(other) {
			smallest = min(smallest, other)
		}
		folded.WriteRune(smallest)
	}
	return folded.String()
}

func validTestConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   8443,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: TLSConfig{
			CertFile:     "/tmp/es.crt",
			KeyFile:      "/tmp/es.key",
			ClientCAFile: "/tmp/ca.crt",
		},
		Security: SecurityConfig{
			BootstrapIssuerCommonName: "Execution Bootstrap",
		},
		Authorization: AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"operator/local"},
		},
		Dependencies: DependenciesConfig{
			ArtifactRegistry: validTestDependencyConfig(),
			ExecutionGovernance: DependencyConfig{
				BaseURL:        "https://egs.internal:8443",
				ServerName:     "egs.internal",
				ClientCertFile: "/tmp/es-client.crt",
				ClientKeyFile:  "/tmp/es-client.key",
				RootCAFile:     "/tmp/ca.crt",
				TimeoutSeconds: 5,
			},
		},
		RuntimeConfig: RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		},
		Verification: VerificationConfig{
			TrustModel:              validTestSignerVerifierConfig(),
			Provenance:              validTestSignerVerifierConfig(),
			DerivationAttestation:   validTestSignerVerifierConfig(),
			WorkloadIdentityBinding: validTestSignerVerifierConfig(),
		},
		WorkloadVaultAuth: WorkloadVaultAuthConfig{
			DefaultMode: WorkloadVaultAuthModeVaultIdentityJWT,
		},
	}
}

func validTestConfigJSON() string {
	return `{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8443,
    "read_timeout_seconds": 5,
    "write_timeout_seconds": 5,
    "shutdown_timeout_seconds": 5
  },
  "tls": {
    "cert_file": "/tmp/es.crt",
    "key_file": "/tmp/es.key",
    "client_ca_file": "/tmp/ca.crt"
  },
  "security": {
    "bootstrap_issuer_common_name": "Execution Bootstrap"
  },
  "authorization": {
    "allowed_spiffe_path_prefixes": ["operator/local"]
  },
  "dependencies": {
    "artifact_registry": {
      "base_url": "https://ars.internal:8443",
      "server_name": "ars.internal",
      "client_cert_file": "/tmp/es-client.crt",
      "client_key_file": "/tmp/es-client.key",
      "root_ca_file": "/tmp/ca.crt",
      "timeout_seconds": 5
    },
    "execution_governance": {
      "base_url": "https://egs.internal:8443",
      "server_name": "egs.internal",
      "client_cert_file": "/tmp/es-client.crt",
      "client_key_file": "/tmp/es-client.key",
      "root_ca_file": "/tmp/ca.crt",
      "timeout_seconds": 5
    }
  },
  "runtime_config": {
    "workload_zone_vault_config_ref": {
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  },
  "verification": {
    "trust_model": {
      "algorithm": "ed25519",
      "key_id": "test-key",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "provenance": {
      "algorithm": "ed25519",
      "key_id": "test-key",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "derivation_attestation": {
      "algorithm": "ed25519",
      "key_id": "test-key",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "workload_identity_binding": {
      "algorithm": "ed25519",
      "key_id": "test-key",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  },
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt"
  }
}`
}

func validTestDependencyConfig() DependencyConfig {
	return DependencyConfig{
		BaseURL:        "https://ars.internal:8443",
		ServerName:     "ars.internal",
		ClientCertFile: "/tmp/es-client.crt",
		ClientKeyFile:  "/tmp/es-client.key",
		RootCAFile:     "/tmp/ca.crt",
		TimeoutSeconds: 5,
	}
}

func validTestSignerVerifierConfig() SignerVerifierConfig {
	return SignerVerifierConfig{
		Algorithm:    "ed25519",
		KeyID:        "test-key",
		PublicKeyHex: strings.Repeat("00", 32),
	}
}

func validConfiguredStaticScriptLiteralDenyPolicyConfig() ConfiguredStaticScriptLiteralDenyPolicyConfig {
	return ConfiguredStaticScriptLiteralDenyPolicyConfig{
		Mode: ConfiguredStaticScriptLiteralDenyModeEnforce,
		Entries: []ConfiguredStaticScriptLiteralDenyEntryConfig{
			{
				ID:         "demo-marker",
				InputClass: ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
				Literal:    "ES_DEMO_LITERAL_MARKER",
			},
		},
	}
}
