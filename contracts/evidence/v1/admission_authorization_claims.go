package evidencev1

import (
	"fmt"
	"strings"
)

type AuthorizationClaims struct {
	Derivation      DerivationAuthorization `json:"derivation"`
	WorkloadBinding WorkloadBinding         `json:"workload_binding"`
}

type DerivationAuthorization struct {
	DerivationSpecDigest string                `json:"derivation_spec_digest"`
	OutputID             string                `json:"output_id"`
	ProducerRunID        string                `json:"producer_run_id"`
	PolicyVersion        string                `json:"policy_version"`
	ExpectedArtifactType string                `json:"expected_artifact_type,omitempty"`
	Constraints          DerivationConstraints `json:"constraints"`
}

type DerivationConstraints struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type WorkloadBinding struct {
	ModulePath    string `json:"module_path"`
	PolicyVersion string `json:"policy_version"`
}

type canonicalAuthorizationClaims struct {
	Derivation      canonicalDerivationAuthorization `json:"derivation"`
	WorkloadBinding canonicalWorkloadBinding         `json:"workload_binding"`
}

type canonicalDerivationConstraints struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type canonicalDerivationAuthorization struct {
	DerivationSpecDigest string                         `json:"derivation_spec_digest"`
	OutputID             string                         `json:"output_id"`
	ProducerRunID        string                         `json:"producer_run_id"`
	PolicyVersion        string                         `json:"policy_version"`
	ExpectedArtifactType string                         `json:"expected_artifact_type,omitempty"`
	Constraints          canonicalDerivationConstraints `json:"constraints"`
}

type canonicalWorkloadBinding struct {
	ModulePath    string `json:"module_path"`
	PolicyVersion string `json:"policy_version"`
}

func (a AuthorizationClaims) validate(artifactType string) error {
	requiredDigests := map[string]string{
		"claims.admission.authorization.derivation.derivation_spec_digest": a.Derivation.DerivationSpecDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	requiredStrings := map[string]string{
		"claims.admission.authorization.derivation.output_id":            a.Derivation.OutputID,
		"claims.admission.authorization.derivation.producer_run_id":      a.Derivation.ProducerRunID,
		"claims.admission.authorization.derivation.policy_version":       a.Derivation.PolicyVersion,
		"claims.admission.authorization.workload_binding.module_path":    a.WorkloadBinding.ModulePath,
		"claims.admission.authorization.workload_binding.policy_version": a.WorkloadBinding.PolicyVersion,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if expected := strings.TrimSpace(a.Derivation.ExpectedArtifactType); expected != "" && expected != strings.TrimSpace(artifactType) {
		return fmt.Errorf("claims.admission.authorization.derivation.expected_artifact_type must match claims.package.identity.artifact_type")
	}
	if strings.TrimSpace(a.Derivation.PolicyVersion) != strings.TrimSpace(a.WorkloadBinding.PolicyVersion) {
		return fmt.Errorf("claims.admission.authorization.derivation.policy_version must match claims.admission.authorization.workload_binding.policy_version")
	}

	return nil
}

func (a AuthorizationClaims) canonicalize() canonicalAuthorizationClaims {
	return canonicalAuthorizationClaims{
		Derivation: canonicalDerivationAuthorization{
			DerivationSpecDigest: strings.TrimSpace(a.Derivation.DerivationSpecDigest),
			OutputID:             strings.TrimSpace(a.Derivation.OutputID),
			ProducerRunID:        strings.TrimSpace(a.Derivation.ProducerRunID),
			PolicyVersion:        strings.TrimSpace(a.Derivation.PolicyVersion),
			ExpectedArtifactType: strings.TrimSpace(a.Derivation.ExpectedArtifactType),
			Constraints: canonicalDerivationConstraints{
				AllowedToolchains:      normalizeStringSet(a.Derivation.Constraints.AllowedToolchains),
				ForbiddenToolchains:    normalizeStringSet(a.Derivation.Constraints.ForbiddenToolchains),
				OS:                     strings.TrimSpace(a.Derivation.Constraints.OS),
				Arch:                   strings.TrimSpace(a.Derivation.Constraints.Arch),
				WritablePaths:          normalizeStringSet(a.Derivation.Constraints.WritablePaths),
				ForbiddenPaths:         normalizeStringSet(a.Derivation.Constraints.ForbiddenPaths),
				DeterminismExpectation: strings.TrimSpace(a.Derivation.Constraints.DeterminismExpectation),
			},
		},
		WorkloadBinding: canonicalWorkloadBinding{
			ModulePath:    strings.TrimSpace(a.WorkloadBinding.ModulePath),
			PolicyVersion: strings.TrimSpace(a.WorkloadBinding.PolicyVersion),
		},
	}
}
