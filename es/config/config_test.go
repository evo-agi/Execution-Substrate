package config

import (
	"strings"
	"testing"
)

func TestExecutionConfigValidateAllowsDefaultRuntimeIdentityTmpfsSize(t *testing.T) {
	cfg := ExecutionConfig{
		StagingRootDir: "/tmp/es-stage",
		BaseImage:      "alpine:3.20",
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
		StagingRootDir:           "/tmp/es-stage",
		BaseImage:                "alpine:3.20",
		RuntimeIdentityTmpfsSize: maxRuntimeIdentityTmpfsSizeBytes + 1,
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
		StagingRootDir:           "/tmp/es-stage",
		BaseImage:                "alpine:3.20",
		RuntimeIdentityTmpfsSize: 2 << 20,
	}

	if got := cfg.EffectiveRuntimeIdentityTmpfsSize(); got != 2<<20 {
		t.Fatalf("expected explicit tmpfs size to be preserved, got %d", got)
	}
}
