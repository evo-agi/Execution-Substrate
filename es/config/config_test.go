package config

import (
	"strings"
	"testing"

	runtimeconfigv1 "execution-substrate/contracts/runtimeconfig/v1"
)

func TestExecutionConfigValidateAllowsDefaultRuntimeIdentityTmpfsSize(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
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
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		RuntimeIdentityTmpfsSize:   2 << 20,
	}

	if got := cfg.EffectiveRuntimeIdentityTmpfsSize(); got != 2<<20 {
		t.Fatalf("expected explicit tmpfs size to be preserved, got %d", got)
	}
}

func TestExecutionConfigValidateRejectsMissingRuntimeSupportBinary(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir:             "/tmp/es-stage",
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
