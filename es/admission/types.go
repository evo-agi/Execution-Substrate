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
	Source     MountSource `json:"source"`
	TargetPath string      `json:"target_path"`
	ReadOnly   bool        `json:"read_only"`
}

type MountSource struct {
	ArtifactDigest string `json:"artifact_digest"`
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

// ExecutionStatusResult is the bounded Nomad-backed lifecycle view for a
// submitted execution. It intentionally reflects only minimal mapped state and
// does not imply a durable ES-owned lifecycle record.
type ExecutionStatusResult struct {
	Success                bool   `json:"success"`
	RunID                  string `json:"run_id"`
	NomadJobID             string `json:"nomad_job_id"`
	JobStatus              string `json:"job_status"`
	AllocationID           string `json:"allocation_id,omitempty"`
	AllocationClientStatus string `json:"allocation_client_status,omitempty"`
	TaskState              string `json:"task_state,omitempty"`
	ExitCode               *int   `json:"exit_code,omitempty"`
	Terminal               bool   `json:"terminal"`
}

// ExecutionCancelResult is the bounded cancellation receipt for the Nomad-
// backed lifecycle slice. It confirms that ES asked Nomad to stop the job,
// but it does not create a durable execution record or wider lifecycle model.
type ExecutionCancelResult struct {
	Success    bool   `json:"success"`
	RunID      string `json:"run_id"`
	NomadJobID string `json:"nomad_job_id"`
	Status     string `json:"status"`
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
