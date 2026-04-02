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
	ArtifactPayloadB64      string                       `json:"artifact_payload_b64"`
	Manifest                ManifestInput                `json:"manifest"`
	Provenance              ProvenanceInput              `json:"provenance"`
	DerivationMetadata      DerivationMetadataInput      `json:"derivation_metadata"`
	DerivationAttestation   DerivationAttestationInput   `json:"derivation_attestation"`
	WorkloadIdentityBinding WorkloadIdentityBindingInput `json:"workload_identity_binding"`
}

type ManifestInput struct {
	ArtifactType     string           `json:"artifact_type"`
	IntentDigest     string           `json:"intent_digest"`
	RuntimeInterface RuntimeInterface `json:"runtime_interface"`
}

type RuntimeInterface struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type ProvenanceInput struct {
	BuilderService  string           `json:"builder_service"`
	Invoker         InvokerInfo      `json:"invoker"`
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`
	BuildLogDigest  string           `json:"build_log_digest"`
}

type InvokerInfo struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type DerivationMetadataInput struct {
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
	ProducerRunID        string `json:"producer_run_id"`
}

type DerivationSpecConstraintsInfo struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type DerivationAttestationInput struct {
	Constraints          DerivationSpecConstraintsInfo `json:"constraints"`
	PolicyVersion        string                        `json:"policy_version"`
	ExpectedArtifactType string                        `json:"expected_artifact_type,omitempty"`
}

type WorkloadIdentityBindingInput struct {
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
	Published                                bool   `json:"published"`
	ArtifactDigest                           string `json:"artifact_digest"`
	ManifestDigest                           string `json:"manifest_digest"`
	ProvenanceDigest                         string `json:"provenance_digest"`
	PayloadDigest                            string `json:"payload_digest"`
	DerivationMetadataDigest                 string `json:"derivation_metadata_digest"`
	DerivationAuthorizationAttestationDigest string `json:"derivation_authorization_attestation_digest"`
	WorkloadIdentityBindingDigest            string `json:"workload_identity_binding_digest"`
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

type ProvenanceSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

type Provenance struct {
	ArtifactDigest  string              `json:"artifact_digest"`
	BuilderService  string              `json:"builder_service"`
	Invoker         InvokerInfo         `json:"invoker"`
	PolicyDecisions []PolicyDecision    `json:"policy_decisions"`
	BuildLogDigest  string              `json:"build_log_digest"`
	Signature       ProvenanceSignature `json:"signature"`
}

type DerivationMetadata struct {
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
	ProducerRunID        string `json:"producer_run_id"`
}

type SignatureInfo struct {
	PayloadDigest    string `json:"payload_digest"`
	CanonicalSpecB64 string `json:"canonical_spec_b64"`
	SignatureValue   string `json:"signature_value"`
	KeyID            string `json:"key_id"`
	Algorithm        string `json:"algorithm"`
}

type DerivationAttestation struct {
	ArtifactDigest       string                        `json:"artifact_digest"`
	DerivationSpecDigest string                        `json:"derivation_spec_digest"`
	OutputID             string                        `json:"output_id"`
	Constraints          DerivationSpecConstraintsInfo `json:"constraints"`
	PolicyVersion        string                        `json:"policy_version"`
	SignatureInfo        SignatureInfo                 `json:"signature_info"`
	ExpectedArtifactType string                        `json:"expected_artifact_type,omitempty"`
}

type WorkloadIdentityBinding struct {
	WorkloadType         string        `json:"workload_type"`
	ModulePath           string        `json:"module_path"`
	DerivationSpecDigest string        `json:"derivation_spec_digest"`
	OutputID             string        `json:"output_id"`
	ArtifactDigest       string        `json:"artifact_digest"`
	ArtifactClass        string        `json:"artifact_class"`
	PolicyVersion        string        `json:"policy_version"`
	SignatureInfo        SignatureInfo `json:"signature_info"`
	ServiceName          string        `json:"service_name,omitempty"`
	TargetPlatform       string        `json:"target_platform,omitempty"`
	Description          string        `json:"description,omitempty"`
	WorkloadIdentityID   string        `json:"workload_identity_id,omitempty"`
}
