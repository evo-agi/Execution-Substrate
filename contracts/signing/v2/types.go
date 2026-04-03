package signingv2

const (
	Version                     = "v2"
	KindProvenance              = "provenance"
	KindDerivationAttestation   = "derivation_attestation"
	KindWorkloadIdentityBinding = "workload_identity_binding"
)

type Envelope struct {
	CanonicalizationVersion string `json:"canonicalization_version"`
	Algorithm               string `json:"algorithm"`
	KeyID                   string `json:"key_id"`
	PayloadDigest           string `json:"payload_digest"`
	SignatureValue          string `json:"signature_value"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type ProvenanceSubject struct {
	ArtifactDigest string `json:"artifact_digest"`
}

type ProvenanceInvoker struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type ProvenanceClaims struct {
	BuilderService  string            `json:"builder_service"`
	Invoker         ProvenanceInvoker `json:"invoker"`
	PolicyDecisions []PolicyDecision  `json:"policy_decisions"`
	BuildLogDigest  string            `json:"build_log_digest"`
}

type ProvenancePayload struct {
	Kind    string            `json:"kind"`
	Subject ProvenanceSubject `json:"subject"`
	Claims  ProvenanceClaims  `json:"claims"`
}

type DerivationSubject struct {
	ArtifactDigest       string `json:"artifact_digest"`
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
}

type DerivationConstraints struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type DerivationPolicy struct {
	Version              string `json:"version"`
	ExpectedArtifactType string `json:"expected_artifact_type,omitempty"`
}

type DerivationAttestationClaims struct {
	Constraints DerivationConstraints `json:"constraints"`
	Policy      DerivationPolicy      `json:"policy"`
}

type DerivationAttestationPayload struct {
	Kind    string                      `json:"kind"`
	Subject DerivationSubject           `json:"subject"`
	Claims  DerivationAttestationClaims `json:"claims"`
}

type WorkloadIdentitySubject struct {
	ArtifactClass        string `json:"artifact_class"`
	ArtifactDigest       string `json:"artifact_digest"`
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
}

type WorkloadDescriptor struct {
	WorkloadType       string `json:"workload_type"`
	ModulePath         string `json:"module_path"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id,omitempty"`
}

type WorkloadPolicy struct {
	Version string `json:"version"`
}

type WorkloadIdentityBindingClaims struct {
	Descriptor WorkloadDescriptor `json:"descriptor"`
	Policy     WorkloadPolicy     `json:"policy"`
}

type WorkloadIdentityBindingPayload struct {
	Kind    string                        `json:"kind"`
	Subject WorkloadIdentitySubject       `json:"subject"`
	Claims  WorkloadIdentityBindingClaims `json:"claims"`
}
