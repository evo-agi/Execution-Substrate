package evidencev1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const Version = "v1"

type ArtifactEvidence struct {
	SchemaVersion string      `json:"schema_version"`
	Artifact      Artifact    `json:"artifact"`
	Publication   Publication `json:"publication"`
	Admission     Admission   `json:"admission"`
	Seal          Seal        `json:"seal"`
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

type Seal struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	ContentDigest string `json:"content_digest"`
	Signature     string `json:"signature"`
}

func (e ArtifactEvidence) CanonicalBytes() ([]byte, error) {
	if err := e.validateCore(); err != nil {
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
	type canonicalEvidence struct {
		SchemaVersion string               `json:"schema_version"`
		Artifact      canonicalArtifact    `json:"artifact"`
		Publication   canonicalPublication `json:"publication"`
		Admission     canonicalAdmission   `json:"admission"`
	}

	decisions := normalizePolicyDecisions(e.Publication.PolicyDecisions)
	canonicalDecisions := make([]canonicalDecision, 0, len(decisions))
	for _, decision := range decisions {
		canonicalDecisions = append(canonicalDecisions, canonicalDecision{
			Rule:   strings.TrimSpace(decision.Rule),
			Result: strings.TrimSpace(decision.Result),
		})
	}

	payload := canonicalEvidence{
		SchemaVersion: Version,
		Artifact: canonicalArtifact{
			ArtifactDigest: strings.TrimSpace(e.Artifact.ArtifactDigest),
			PayloadDigest:  strings.TrimSpace(e.Artifact.PayloadDigest),
			ArtifactType:   strings.TrimSpace(e.Artifact.ArtifactType),
			IntentDigest:   strings.TrimSpace(e.Artifact.IntentDigest),
		},
		Publication: canonicalPublication{
			BuilderService: strings.TrimSpace(e.Publication.BuilderService),
			Invoker: canonicalInvoker{
				Service:   strings.TrimSpace(e.Publication.Invoker.Service),
				Principal: strings.TrimSpace(e.Publication.Invoker.Principal),
			},
			PolicyDecisions: canonicalDecisions,
			BuildLogDigest:  strings.TrimSpace(e.Publication.BuildLogDigest),
		},
		Admission: canonicalAdmission{
			Runtime: canonicalRuntime{
				Parameters:           normalizeStringSet(e.Admission.Runtime.Parameters),
				EnvironmentVariables: normalizeStringSet(e.Admission.Runtime.EnvironmentVariables),
				RequiredCapabilities: normalizeStringSet(e.Admission.Runtime.RequiredCapabilities),
			},
			Derivation: canonicalDerivation{
				DerivationSpecDigest: strings.TrimSpace(e.Admission.Derivation.DerivationSpecDigest),
				OutputID:             strings.TrimSpace(e.Admission.Derivation.OutputID),
				ProducerRunID:        strings.TrimSpace(e.Admission.Derivation.ProducerRunID),
				PolicyVersion:        strings.TrimSpace(e.Admission.Derivation.PolicyVersion),
				ExpectedArtifactType: strings.TrimSpace(e.Admission.Derivation.ExpectedArtifactType),
				Constraints: canonicalConstraints{
					AllowedToolchains:      normalizeStringSet(e.Admission.Derivation.Constraints.AllowedToolchains),
					ForbiddenToolchains:    normalizeStringSet(e.Admission.Derivation.Constraints.ForbiddenToolchains),
					OS:                     strings.TrimSpace(e.Admission.Derivation.Constraints.OS),
					Arch:                   strings.TrimSpace(e.Admission.Derivation.Constraints.Arch),
					NetworkAccess:          e.Admission.Derivation.Constraints.NetworkAccess,
					WritablePaths:          normalizeStringSet(e.Admission.Derivation.Constraints.WritablePaths),
					ForbiddenPaths:         normalizeStringSet(e.Admission.Derivation.Constraints.ForbiddenPaths),
					DeterminismExpectation: strings.TrimSpace(e.Admission.Derivation.Constraints.DeterminismExpectation),
				},
			},
			Workload: canonicalWorkload{
				ArtifactClass:      strings.TrimSpace(e.Admission.Workload.ArtifactClass),
				WorkloadType:       strings.TrimSpace(e.Admission.Workload.WorkloadType),
				ModulePath:         strings.TrimSpace(e.Admission.Workload.ModulePath),
				ServiceName:        strings.TrimSpace(e.Admission.Workload.ServiceName),
				TargetPlatform:     strings.TrimSpace(e.Admission.Workload.TargetPlatform),
				Description:        strings.TrimSpace(e.Admission.Workload.Description),
				WorkloadIdentityID: strings.TrimSpace(e.Admission.Workload.WorkloadIdentityID),
				PolicyVersion:      strings.TrimSpace(e.Admission.Workload.PolicyVersion),
			},
		},
	}

	return json.Marshal(payload)
}

func (e ArtifactEvidence) Validate() error {
	if err := e.validateCore(); err != nil {
		return err
	}
	if err := e.validateSeal(); err != nil {
		return err
	}
	return nil
}

func (e ArtifactEvidence) validateCore() error {
	if strings.TrimSpace(e.SchemaVersion) != Version {
		return fmt.Errorf("artifact evidence schema_version must be %s", Version)
	}

	requiredDigests := map[string]string{
		"artifact.artifact_digest":                    e.Artifact.ArtifactDigest,
		"artifact.payload_digest":                     e.Artifact.PayloadDigest,
		"artifact.intent_digest":                      e.Artifact.IntentDigest,
		"publication.build_log_digest":                e.Publication.BuildLogDigest,
		"admission.derivation.derivation_spec_digest": e.Admission.Derivation.DerivationSpecDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	requiredStrings := map[string]string{
		"artifact.artifact_type":                  e.Artifact.ArtifactType,
		"publication.builder_service":             e.Publication.BuilderService,
		"publication.invoker.service":             e.Publication.Invoker.Service,
		"publication.invoker.principal":           e.Publication.Invoker.Principal,
		"admission.derivation.output_id":          e.Admission.Derivation.OutputID,
		"admission.derivation.producer_run_id":    e.Admission.Derivation.ProducerRunID,
		"admission.derivation.policy_version":     e.Admission.Derivation.PolicyVersion,
		"admission.workload.artifact_class":       e.Admission.Workload.ArtifactClass,
		"admission.workload.workload_type":        e.Admission.Workload.WorkloadType,
		"admission.workload.module_path":          e.Admission.Workload.ModulePath,
		"admission.workload.workload_identity_id": e.Admission.Workload.WorkloadIdentityID,
		"admission.workload.policy_version":       e.Admission.Workload.PolicyVersion,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if strings.TrimSpace(e.Admission.Workload.WorkloadType) == "service" && strings.TrimSpace(e.Admission.Workload.ServiceName) == "" {
		return fmt.Errorf("admission.workload.service_name is required for service workloads")
	}
	if expected := strings.TrimSpace(e.Admission.Derivation.ExpectedArtifactType); expected != "" && expected != strings.TrimSpace(e.Artifact.ArtifactType) {
		return fmt.Errorf("admission.derivation.expected_artifact_type must match artifact.artifact_type")
	}
	if strings.TrimSpace(e.Admission.Derivation.PolicyVersion) != strings.TrimSpace(e.Admission.Workload.PolicyVersion) {
		return fmt.Errorf("admission.derivation.policy_version must match admission.workload.policy_version")
	}

	return nil
}

func (e ArtifactEvidence) validateSeal() error {
	requiredStrings := map[string]string{
		"seal.algorithm":      e.Seal.Algorithm,
		"seal.key_id":         e.Seal.KeyID,
		"seal.content_digest": e.Seal.ContentDigest,
		"seal.signature":      e.Seal.Signature,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if err := validateDigest(strings.TrimSpace(e.Seal.ContentDigest)); err != nil {
		return fmt.Errorf("seal.content_digest: %w", err)
	}
	return nil
}

func NewSeal(canonical []byte, keyID string, algorithm string, signature string) Seal {
	return Seal{
		Algorithm:     strings.TrimSpace(algorithm),
		KeyID:         strings.TrimSpace(keyID),
		ContentDigest: ContentDigest(canonical),
		Signature:     strings.TrimSpace(signature),
	}
}

func Verify(e ArtifactEvidence, expectedKeyID string, expectedAlgorithm string, publicKey ed25519.PublicKey) error {
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return err
	}
	if strings.TrimSpace(e.Seal.KeyID) != strings.TrimSpace(expectedKeyID) {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(e.Seal.Algorithm) != strings.TrimSpace(expectedAlgorithm) {
		return fmt.Errorf("unexpected signing algorithm")
	}
	if strings.TrimSpace(e.Seal.ContentDigest) != ContentDigest(canonical) {
		return fmt.Errorf("content digest mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.Seal.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ContentDigest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
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
