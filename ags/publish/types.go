package publish

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

type CallerIdentity struct {
	Path     string
	SPIFFEID string
}

type PublishRequest struct {
	ArtifactPayloadB64 string           `json:"artifact_payload_b64"`
	Artifact           ArtifactInput    `json:"artifact"`
	Publication        PublicationInput `json:"publication"`
	Admission          AdmissionInput   `json:"admission"`
}

type ArtifactInput struct {
	ArtifactType string `json:"artifact_type"`
	IntentDigest string `json:"intent_digest"`
}

type PublicationInput struct {
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`
	BuildLogDigest  string           `json:"build_log_digest"`
}

type AdmissionInput struct {
	Runtime    RuntimeInterface `json:"runtime"`
	Derivation DerivationInput  `json:"derivation"`
	Workload   WorkloadInput    `json:"workload"`
}

type RuntimeInterface struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type DerivationInput struct {
	DerivationSpecDigest string           `json:"derivation_spec_digest"`
	OutputID             string           `json:"output_id"`
	ProducerRunID        string           `json:"producer_run_id"`
	Constraints          ConstraintsInput `json:"constraints"`
	PolicyVersion        string           `json:"policy_version"`
	ExpectedArtifactType string           `json:"expected_artifact_type,omitempty"`
}

type ConstraintsInput struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type WorkloadInput struct {
	ArtifactClass      string `json:"artifact_class"`
	WorkloadType       string `json:"workload_type"`
	ModulePath         string `json:"module_path"`
	PolicyVersion      string `json:"policy_version"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id,omitempty"`
}

type PublishResult struct {
	Published      bool   `json:"published"`
	ArtifactDigest string `json:"artifact_digest"`
	EvidenceDigest string `json:"evidence_digest"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	PayloadDigest  string `json:"payload_digest"`
}

type HealthSnapshot struct {
	ArtifactRegistryHealthy bool
	SignerReady             bool
}

type Manifest struct {
	ArtifactDigest   string           `json:"artifact_digest"`
	ArtifactType     string           `json:"artifact_type"`
	IntentDigest     string           `json:"intent_digest"`
	RuntimeInterface RuntimeInterface `json:"runtime_interface"`
}

type DerivationMetadata struct {
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
	ProducerRunID        string `json:"producer_run_id"`
}

type InvokerInfo struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}
