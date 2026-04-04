package evidencev1

import (
	"fmt"
	"strings"
)

type AdmissionClaims struct {
	Runtime    Runtime    `json:"runtime"`
	Derivation Derivation `json:"derivation"`
	Workload   Workload   `json:"workload"`
}

type Runtime struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type Derivation struct {
	DerivationSpecDigest string      `json:"derivation_spec_digest"`
	OutputID             string      `json:"output_id"`
	ProducerRunID        string      `json:"producer_run_id"`
	PolicyVersion        string      `json:"policy_version"`
	ExpectedArtifactType string      `json:"expected_artifact_type,omitempty"`
	Constraints          Constraints `json:"constraints"`
}

type Constraints struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type Workload struct {
	ArtifactClass      string `json:"artifact_class"`
	WorkloadType       string `json:"workload_type"`
	ModulePath         string `json:"module_path"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id"`
	PolicyVersion      string `json:"policy_version"`
}

type canonicalAdmissionClaims struct {
	Runtime    canonicalRuntime    `json:"runtime"`
	Derivation canonicalDerivation `json:"derivation"`
	Workload   canonicalWorkload   `json:"workload"`
}

type canonicalRuntime struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type canonicalConstraints struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type canonicalDerivation struct {
	DerivationSpecDigest string               `json:"derivation_spec_digest"`
	OutputID             string               `json:"output_id"`
	ProducerRunID        string               `json:"producer_run_id"`
	PolicyVersion        string               `json:"policy_version"`
	ExpectedArtifactType string               `json:"expected_artifact_type,omitempty"`
	Constraints          canonicalConstraints `json:"constraints"`
}

type canonicalWorkload struct {
	ArtifactClass      string `json:"artifact_class"`
	WorkloadType       string `json:"workload_type"`
	ModulePath         string `json:"module_path"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id"`
	PolicyVersion      string `json:"policy_version"`
}

func (a AdmissionClaims) validate(artifactType string) error {
	requiredDigests := map[string]string{
		"claims.admission.derivation.derivation_spec_digest": a.Derivation.DerivationSpecDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	requiredStrings := map[string]string{
		"claims.admission.derivation.output_id":          a.Derivation.OutputID,
		"claims.admission.derivation.producer_run_id":    a.Derivation.ProducerRunID,
		"claims.admission.derivation.policy_version":     a.Derivation.PolicyVersion,
		"claims.admission.workload.artifact_class":       a.Workload.ArtifactClass,
		"claims.admission.workload.workload_type":        a.Workload.WorkloadType,
		"claims.admission.workload.module_path":          a.Workload.ModulePath,
		"claims.admission.workload.workload_identity_id": a.Workload.WorkloadIdentityID,
		"claims.admission.workload.policy_version":       a.Workload.PolicyVersion,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if strings.TrimSpace(a.Workload.WorkloadType) == "service" && strings.TrimSpace(a.Workload.ServiceName) == "" {
		return fmt.Errorf("claims.admission.workload.service_name is required for service workloads")
	}
	if expected := strings.TrimSpace(a.Derivation.ExpectedArtifactType); expected != "" && expected != strings.TrimSpace(artifactType) {
		return fmt.Errorf("claims.admission.derivation.expected_artifact_type must match claims.package.identity.artifact_type")
	}
	if strings.TrimSpace(a.Derivation.PolicyVersion) != strings.TrimSpace(a.Workload.PolicyVersion) {
		return fmt.Errorf("claims.admission.derivation.policy_version must match claims.admission.workload.policy_version")
	}

	return nil
}

func (a AdmissionClaims) canonicalize() canonicalAdmissionClaims {
	return canonicalAdmissionClaims{
		Runtime: canonicalRuntime{
			Parameters:           normalizeStringSet(a.Runtime.Parameters),
			EnvironmentVariables: normalizeStringSet(a.Runtime.EnvironmentVariables),
			RequiredCapabilities: normalizeStringSet(a.Runtime.RequiredCapabilities),
		},
		Derivation: canonicalDerivation{
			DerivationSpecDigest: strings.TrimSpace(a.Derivation.DerivationSpecDigest),
			OutputID:             strings.TrimSpace(a.Derivation.OutputID),
			ProducerRunID:        strings.TrimSpace(a.Derivation.ProducerRunID),
			PolicyVersion:        strings.TrimSpace(a.Derivation.PolicyVersion),
			ExpectedArtifactType: strings.TrimSpace(a.Derivation.ExpectedArtifactType),
			Constraints: canonicalConstraints{
				AllowedToolchains:      normalizeStringSet(a.Derivation.Constraints.AllowedToolchains),
				ForbiddenToolchains:    normalizeStringSet(a.Derivation.Constraints.ForbiddenToolchains),
				OS:                     strings.TrimSpace(a.Derivation.Constraints.OS),
				Arch:                   strings.TrimSpace(a.Derivation.Constraints.Arch),
				NetworkAccess:          a.Derivation.Constraints.NetworkAccess,
				WritablePaths:          normalizeStringSet(a.Derivation.Constraints.WritablePaths),
				ForbiddenPaths:         normalizeStringSet(a.Derivation.Constraints.ForbiddenPaths),
				DeterminismExpectation: strings.TrimSpace(a.Derivation.Constraints.DeterminismExpectation),
			},
		},
		Workload: canonicalWorkload{
			ArtifactClass:      strings.TrimSpace(a.Workload.ArtifactClass),
			WorkloadType:       strings.TrimSpace(a.Workload.WorkloadType),
			ModulePath:         strings.TrimSpace(a.Workload.ModulePath),
			ServiceName:        strings.TrimSpace(a.Workload.ServiceName),
			TargetPlatform:     strings.TrimSpace(a.Workload.TargetPlatform),
			Description:        strings.TrimSpace(a.Workload.Description),
			WorkloadIdentityID: strings.TrimSpace(a.Workload.WorkloadIdentityID),
			PolicyVersion:      strings.TrimSpace(a.Workload.PolicyVersion),
		},
	}
}
