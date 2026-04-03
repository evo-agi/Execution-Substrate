package evidencev1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const Version = "v1"

type Claims struct {
	SchemaVersion string      `json:"schema_version"`
	Artifact      Artifact    `json:"artifact"`
	Publication   Publication `json:"publication"`
	Admission     Admission   `json:"admission"`
}

type Artifact struct {
	ArtifactDigest string `json:"artifact_digest"`
	PayloadDigest  string `json:"payload_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type Publication struct {
	BuilderService  string           `json:"builder_service"`
	Invoker         Invoker          `json:"invoker"`
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`
	BuildLogDigest  string           `json:"build_log_digest"`
}

type Invoker struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type Admission struct {
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

func (c Claims) CanonicalBytes() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	type canonicalArtifact struct {
		ArtifactDigest string `json:"artifact_digest"`
		PayloadDigest  string `json:"payload_digest"`
		ArtifactType   string `json:"artifact_type"`
		IntentDigest   string `json:"intent_digest"`
	}
	type canonicalInvoker struct {
		Service   string `json:"service"`
		Principal string `json:"principal"`
	}
	type canonicalDecision struct {
		Rule   string `json:"rule"`
		Result string `json:"result"`
	}
	type canonicalPublication struct {
		BuilderService  string              `json:"builder_service"`
		Invoker         canonicalInvoker    `json:"invoker"`
		PolicyDecisions []canonicalDecision `json:"policy_decisions"`
		BuildLogDigest  string              `json:"build_log_digest"`
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
	type canonicalAdmission struct {
		Runtime    canonicalRuntime    `json:"runtime"`
		Derivation canonicalDerivation `json:"derivation"`
		Workload   canonicalWorkload   `json:"workload"`
	}
	type canonicalClaims struct {
		SchemaVersion string               `json:"schema_version"`
		Artifact      canonicalArtifact    `json:"artifact"`
		Publication   canonicalPublication `json:"publication"`
		Admission     canonicalAdmission   `json:"admission"`
	}

	decisions := normalizePolicyDecisions(c.Publication.PolicyDecisions)
	canonicalDecisions := make([]canonicalDecision, 0, len(decisions))
	for _, decision := range decisions {
		canonicalDecisions = append(canonicalDecisions, canonicalDecision{
			Rule:   strings.TrimSpace(decision.Rule),
			Result: strings.TrimSpace(decision.Result),
		})
	}

	payload := canonicalClaims{
		SchemaVersion: Version,
		Artifact: canonicalArtifact{
			ArtifactDigest: strings.TrimSpace(c.Artifact.ArtifactDigest),
			PayloadDigest:  strings.TrimSpace(c.Artifact.PayloadDigest),
			ArtifactType:   strings.TrimSpace(c.Artifact.ArtifactType),
			IntentDigest:   strings.TrimSpace(c.Artifact.IntentDigest),
		},
		Publication: canonicalPublication{
			BuilderService: strings.TrimSpace(c.Publication.BuilderService),
			Invoker: canonicalInvoker{
				Service:   strings.TrimSpace(c.Publication.Invoker.Service),
				Principal: strings.TrimSpace(c.Publication.Invoker.Principal),
			},
			PolicyDecisions: canonicalDecisions,
			BuildLogDigest:  strings.TrimSpace(c.Publication.BuildLogDigest),
		},
		Admission: canonicalAdmission{
			Runtime: canonicalRuntime{
				Parameters:           normalizeStringSet(c.Admission.Runtime.Parameters),
				EnvironmentVariables: normalizeStringSet(c.Admission.Runtime.EnvironmentVariables),
				RequiredCapabilities: normalizeStringSet(c.Admission.Runtime.RequiredCapabilities),
			},
			Derivation: canonicalDerivation{
				DerivationSpecDigest: strings.TrimSpace(c.Admission.Derivation.DerivationSpecDigest),
				OutputID:             strings.TrimSpace(c.Admission.Derivation.OutputID),
				ProducerRunID:        strings.TrimSpace(c.Admission.Derivation.ProducerRunID),
				PolicyVersion:        strings.TrimSpace(c.Admission.Derivation.PolicyVersion),
				ExpectedArtifactType: strings.TrimSpace(c.Admission.Derivation.ExpectedArtifactType),
				Constraints: canonicalConstraints{
					AllowedToolchains:      normalizeStringSet(c.Admission.Derivation.Constraints.AllowedToolchains),
					ForbiddenToolchains:    normalizeStringSet(c.Admission.Derivation.Constraints.ForbiddenToolchains),
					OS:                     strings.TrimSpace(c.Admission.Derivation.Constraints.OS),
					Arch:                   strings.TrimSpace(c.Admission.Derivation.Constraints.Arch),
					NetworkAccess:          c.Admission.Derivation.Constraints.NetworkAccess,
					WritablePaths:          normalizeStringSet(c.Admission.Derivation.Constraints.WritablePaths),
					ForbiddenPaths:         normalizeStringSet(c.Admission.Derivation.Constraints.ForbiddenPaths),
					DeterminismExpectation: strings.TrimSpace(c.Admission.Derivation.Constraints.DeterminismExpectation),
				},
			},
			Workload: canonicalWorkload{
				ArtifactClass:      strings.TrimSpace(c.Admission.Workload.ArtifactClass),
				WorkloadType:       strings.TrimSpace(c.Admission.Workload.WorkloadType),
				ModulePath:         strings.TrimSpace(c.Admission.Workload.ModulePath),
				ServiceName:        strings.TrimSpace(c.Admission.Workload.ServiceName),
				TargetPlatform:     strings.TrimSpace(c.Admission.Workload.TargetPlatform),
				Description:        strings.TrimSpace(c.Admission.Workload.Description),
				WorkloadIdentityID: strings.TrimSpace(c.Admission.Workload.WorkloadIdentityID),
				PolicyVersion:      strings.TrimSpace(c.Admission.Workload.PolicyVersion),
			},
		},
	}

	return json.Marshal(payload)
}

func (c Claims) Validate() error {
	if strings.TrimSpace(c.SchemaVersion) != Version {
		return fmt.Errorf("artifact evidence claims schema_version must be %s", Version)
	}

	requiredDigests := map[string]string{
		"claims.artifact.artifact_digest":                    c.Artifact.ArtifactDigest,
		"claims.artifact.payload_digest":                     c.Artifact.PayloadDigest,
		"claims.artifact.intent_digest":                      c.Artifact.IntentDigest,
		"claims.publication.build_log_digest":                c.Publication.BuildLogDigest,
		"claims.admission.derivation.derivation_spec_digest": c.Admission.Derivation.DerivationSpecDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	requiredStrings := map[string]string{
		"claims.artifact.artifact_type":                  c.Artifact.ArtifactType,
		"claims.publication.builder_service":             c.Publication.BuilderService,
		"claims.publication.invoker.service":             c.Publication.Invoker.Service,
		"claims.publication.invoker.principal":           c.Publication.Invoker.Principal,
		"claims.admission.derivation.output_id":          c.Admission.Derivation.OutputID,
		"claims.admission.derivation.producer_run_id":    c.Admission.Derivation.ProducerRunID,
		"claims.admission.derivation.policy_version":     c.Admission.Derivation.PolicyVersion,
		"claims.admission.workload.artifact_class":       c.Admission.Workload.ArtifactClass,
		"claims.admission.workload.workload_type":        c.Admission.Workload.WorkloadType,
		"claims.admission.workload.module_path":          c.Admission.Workload.ModulePath,
		"claims.admission.workload.workload_identity_id": c.Admission.Workload.WorkloadIdentityID,
		"claims.admission.workload.policy_version":       c.Admission.Workload.PolicyVersion,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if strings.TrimSpace(c.Admission.Workload.WorkloadType) == "service" && strings.TrimSpace(c.Admission.Workload.ServiceName) == "" {
		return fmt.Errorf("claims.admission.workload.service_name is required for service workloads")
	}
	if expected := strings.TrimSpace(c.Admission.Derivation.ExpectedArtifactType); expected != "" && expected != strings.TrimSpace(c.Artifact.ArtifactType) {
		return fmt.Errorf("claims.admission.derivation.expected_artifact_type must match claims.artifact.artifact_type")
	}
	if strings.TrimSpace(c.Admission.Derivation.PolicyVersion) != strings.TrimSpace(c.Admission.Workload.PolicyVersion) {
		return fmt.Errorf("claims.admission.derivation.policy_version must match claims.admission.workload.policy_version")
	}

	return nil
}

func normalizePolicyDecisions(values []PolicyDecision) []PolicyDecision {
	if len(values) == 0 {
		return []PolicyDecision{}
	}
	normalized := append([]PolicyDecision(nil), values...)
	sort.Slice(normalized, func(i, j int) bool {
		leftRule := strings.TrimSpace(normalized[i].Rule)
		rightRule := strings.TrimSpace(normalized[j].Rule)
		if leftRule == rightRule {
			return strings.TrimSpace(normalized[i].Result) < strings.TrimSpace(normalized[j].Result)
		}
		return leftRule < rightRule
	})
	return normalized
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	normalized := append([]string(nil), values...)
	for i := range normalized {
		normalized[i] = strings.TrimSpace(normalized[i])
	}
	sort.Strings(normalized)
	return normalized
}

func validateDigest(value string) error {
	if !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	sum := strings.TrimPrefix(value, "sha256:")
	if len(sum) != 64 {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	return nil
}
