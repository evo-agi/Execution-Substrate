package admission

type ExecutionMode string

const (
	ExecutionModeAsync ExecutionMode = "async"
	ExecutionModeSync  ExecutionMode = "sync"
)

type PrepareRequest struct {
	SchemaVersion  string              `json:"schema_version"`
	Invocation     ArtifactInvocation  `json:"invocation"`
	Mode           ExecutionMode       `json:"mode,omitempty"`
	TimeoutSeconds int                 `json:"timeout_seconds,omitempty"`
	Resources      *ExecutionResources `json:"resources,omitempty"`
}

type ArtifactInvocation struct {
	SchemaVersion        string            `json:"schema_version"`
	ArtifactDigest       string            `json:"artifact_digest"`
	DerivationSpecDigest string            `json:"derivation_spec_digest"`
	OutputID             string            `json:"output_id"`
	Argv                 []string          `json:"argv,omitempty"`
	Env                  map[string]string `json:"env,omitempty"`
	Mounts               []RuntimeMount    `json:"mounts,omitempty"`
	Annotations          map[string]string `json:"annotations,omitempty"`
}

type ExecutionResources struct {
	CPU      int `json:"cpu"`
	MemoryMB int `json:"memory_mb"`
}

type RuntimeMount struct {
	Name          string      `json:"name"`
	Source        MountSource `json:"source"`
	TargetSubpath string      `json:"target_subpath"`
}

type MountSource struct {
	Type   string `json:"type"`
	Digest string `json:"digest"`
}

// PrepareResult is the bounded response contract for the milestone
// /v1/executions:prepare surface. It proves admission and preparation facts
// only, and intentionally does not create run IDs, scheduler metadata, or any
// proto-execution state.
type PrepareResult struct {
	Success              bool              `json:"success"`
	ArtifactDigest       string            `json:"artifact_digest"`
	DerivationSpecDigest string            `json:"derivation_spec_digest"`
	OutputID             string            `json:"output_id"`
	IntentDigest         string            `json:"intent_digest"`
	ArtifactType         string            `json:"artifact_type"`
	TrustModel           TrustModelInfo    `json:"trust_model"`
	Provenance           ProvenanceInfo    `json:"provenance"`
	Workload             WorkloadInfo      `json:"workload"`
	WorkloadVault        WorkloadVaultInfo `json:"workload_vault"`
}

// SubmitResult is the bounded async submission receipt for the first real
// execution slice. It confirms that ES reused admission/prepare successfully
// and handed a real Nomad job to the scheduler, but it intentionally does not
// create a durable execution record or broader lifecycle surface.
type SubmitResult struct {
	Success        bool   `json:"success"`
	Submitted      bool   `json:"submitted"`
	RunID          string `json:"run_id"`
	NomadJobID     string `json:"nomad_job_id"`
	NomadEvalID    string `json:"nomad_eval_id"`
	ArtifactDigest string `json:"artifact_digest"`
	Status         string `json:"status"`
}

type TrustModelInfo struct {
	Version        string `json:"version"`
	UpdateRevision int    `json:"update_revision"`
}

type ProvenanceInfo struct {
	SignerKeyID string `json:"signer_key_id"`
}

type WorkloadInfo struct {
	Type               string `json:"type"`
	ServiceName        string `json:"service_name,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id"`
}

type WorkloadVaultInfo struct {
	Digest      string `json:"digest"`
	Address     string `json:"address"`
	AuthMode    string `json:"auth_mode"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
}

type HealthSnapshot struct {
	ArtifactCatalogHealthy  bool
	ArtifactRegistryHealthy bool
	TrustModelLoaded        bool
}

type RuntimeInterface struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type Manifest struct {
	ArtifactDigest   string           `json:"artifact_digest"`
	ArtifactType     string           `json:"artifact_type"`
	IntentDigest     string           `json:"intent_digest"`
	RuntimeInterface RuntimeInterface `json:"runtime_interface"`
}

type InvokerInfo struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
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
