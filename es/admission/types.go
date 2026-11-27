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
	Success bool `json:"success"`
}

// SubmitResult is the bounded async submission receipt for the first real
// execution slice. It confirms that ES reused admission/prepare successfully
// and handed a real Nomad job to the scheduler, but it intentionally does not
// create a durable execution record or broader lifecycle surface.
type SubmitResult struct {
	Success          bool                       `json:"success"`
	Submitted        bool                       `json:"submitted"`
	RunID            string                     `json:"run_id"`
	Status           string                     `json:"status"`
	AuthorityHandoff *ExecutionAuthorityHandoff `json:"authority_handoff,omitempty"`
}

// ExecutionStatusResult is the bounded Nomad-backed lifecycle view for a
// submitted execution. It intentionally reflects only minimal mapped state and
// does not imply a durable ES-owned lifecycle record.
type ExecutionStatusResult struct {
	Success             bool                       `json:"success"`
	RunID               string                     `json:"run_id"`
	Status              string                     `json:"status"`
	LifecycleProjection LifecycleProjection        `json:"lifecycle_projection"`
	OutcomeEvidence     ExecutionOutcomeEvidence   `json:"outcome_evidence"`
	AuthorityHandoff    *ExecutionAuthorityHandoff `json:"authority_handoff,omitempty"`
	ExitCode            *int                       `json:"exit_code,omitempty"`
	Terminal            bool                       `json:"terminal"`
}

// LifecycleProjection is a bounded read-coordination fact for status
// responses. Revision is opaque to callers; it is not a scheduler identifier
// or a precondition for lifecycle writes.
type LifecycleProjection struct {
	Source   string `json:"source"`
	Revision string `json:"revision"`
}

// ExecutionOutcomeEvidence is the additive response-evidence descriptor for
// lifecycle observations and retained outputs ES can directly source today.
// It is intentionally a label surface, not a scheduler identifier, write
// precondition, policy claim, credential claim, or ES-owned lifecycle record.
type ExecutionOutcomeEvidence struct {
	Source                   string               `json:"source"`
	Observation              string               `json:"observation"`
	AccessClass              string               `json:"access_class,omitempty"`
	LifecycleProjection      *LifecycleProjection `json:"lifecycle_projection,omitempty"`
	ProviderTerminalObserved *bool                `json:"provider_terminal_observed,omitempty"`
}

// ExecutionAuthorityHandoff is the bounded non-secret read surface for the
// runtime authority path ES selected and submitted for a run. It intentionally
// avoids live credential, lease, approval, scheduler identifier, or lifecycle
// store claims.
type ExecutionAuthorityHandoff struct {
	AuthorityPath           string                              `json:"authority_path"`
	RuntimeProfile          ExecutionAuthorityRuntimeProfile    `json:"runtime_profile"`
	IdentityHandoff         ExecutionAuthorityIdentityHandoff   `json:"identity_handoff"`
	WorkloadVault           ExecutionAuthorityWorkloadVault     `json:"workload_vault"`
	RuntimeConfigRefs       ExecutionAuthorityRuntimeConfigRefs `json:"runtime_config_refs"`
	CodexCredentialLocation *ExecutionAuthorityCodexCredential  `json:"codex_credential_location,omitempty"`
	Evidence                ExecutionAuthorityEvidence          `json:"evidence"`
}

type ExecutionAuthorityRuntimeProfile struct {
	Name string `json:"name"`
}

type ExecutionAuthorityIdentityHandoff struct {
	Mode          string `json:"mode"`
	EndpointEnv   string `json:"endpoint_env"`
	EndpointURI   string `json:"endpoint_uri"`
	JWTSVIDTarget string `json:"jwt_svid_target"`
}

type ExecutionAuthorityWorkloadVault struct {
	AuthMode      string `json:"auth_mode"`
	Address       string `json:"address"`
	AuthMount     string `json:"auth_mount"`
	AuthRole      string `json:"auth_role"`
	JWTAudience   string `json:"jwt_audience"`
	CACertEnv     string `json:"ca_cert_env,omitempty"`
	CACertPath    string `json:"ca_cert_path,omitempty"`
	TLSBundleEnv  string `json:"tls_bundle_env,omitempty"`
	TLSBundlePath string `json:"tls_bundle_path,omitempty"`
}

type ExecutionAuthorityRuntimeConfigRefs struct {
	WorkloadZoneVaultConfig ExecutionAuthorityRuntimeConfigRef `json:"workload_zone_vault_config"`
}

type ExecutionAuthorityRuntimeConfigRef struct {
	Digest string `json:"digest"`
}

type ExecutionAuthorityCodexCredential struct {
	CLIPath          string `json:"cli_path"`
	CredentialSource string `json:"credential_source"`
	VaultSecretPath  string `json:"vault_secret_path"`
	VaultSecretField string `json:"vault_secret_field"`
}

type ExecutionAuthorityEvidence struct {
	Source                  string `json:"source"`
	RuntimeProfile          string `json:"runtime_profile"`
	IdentityHandoff         string `json:"identity_handoff"`
	WorkloadVault           string `json:"workload_vault"`
	RuntimeConfigRefs       string `json:"runtime_config_refs"`
	CodexCredentialLocation string `json:"codex_credential_location,omitempty"`
}

// ExecutionCancelResult is the bounded cancellation receipt for the Nomad-
// backed lifecycle slice. It confirms that ES asked Nomad to stop the job,
// but it does not create a durable execution record or wider lifecycle model.
type ExecutionCancelResult struct {
	Success         bool                     `json:"success"`
	RunID           string                   `json:"run_id"`
	Status          string                   `json:"status"`
	OutcomeEvidence ExecutionOutcomeEvidence `json:"outcome_evidence"`
}

type ExecutionLogsResult struct {
	OutcomeEvidence ExecutionOutcomeEvidence
	Payload         []byte
}

type ExecutionResultBundle struct {
	MediaType       string
	OutcomeEvidence ExecutionOutcomeEvidence
	Payload         []byte
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
}

type HealthSnapshot struct {
	ArtifactRegistryHealthy bool
	TrustModelLoaded        bool
}

// ProducerContractDeclaration is the narrow producer-side compatibility
// declaration for the current governed-execution path. It is static
// non-secret metadata, not health, readiness, run authority, credential truth,
// lifecycle write coordination, or scheduler API.
type ProducerContractDeclaration struct {
	SchemaVersion     string                                       `json:"schema_version"`
	Service           string                                       `json:"service"`
	GovernedExecution GovernedExecutionProducerContractDeclaration `json:"governed_execution"`
	NonAuthority      []string                                     `json:"non_authority"`
}

type GovernedExecutionProducerContractDeclaration struct {
	Contract        string                              `json:"contract"`
	Enabled         bool                                `json:"enabled"`
	DisabledReason  string                              `json:"disabled_reason,omitempty"`
	RuntimeProfiles []ProducerRuntimeProfileDeclaration `json:"runtime_profiles"`
	OutcomeEvidence ProducerOutcomeEvidenceDeclaration  `json:"outcome_evidence"`
}

type ProducerRuntimeProfileDeclaration struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	DisabledReason string `json:"disabled_reason,omitempty"`
}

type ProducerOutcomeEvidenceDeclaration struct {
	Required      bool                                      `json:"required"`
	StatusJSON    ProducerOutcomeEvidenceSurfaceDeclaration `json:"status_json"`
	CancelJSON    ProducerOutcomeEvidenceSurfaceDeclaration `json:"cancel_json"`
	LogsHeaders   ProducerOutcomeEvidenceSurfaceDeclaration `json:"logs_headers"`
	ResultHeaders ProducerOutcomeEvidenceSurfaceDeclaration `json:"result_headers"`
}

type ProducerOutcomeEvidenceSurfaceDeclaration struct {
	Required        bool     `json:"required"`
	Carrier         string   `json:"carrier"`
	Field           string   `json:"field,omitempty"`
	MediaType       string   `json:"media_type,omitempty"`
	RequiredFields  []string `json:"required_fields,omitempty"`
	RequiredHeaders []string `json:"required_headers,omitempty"`
	Source          string   `json:"source,omitempty"`
	Observations    []string `json:"observations,omitempty"`
	AccessClass     string   `json:"access_class,omitempty"`
}

type RuntimeInterface struct {
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
	MountTargets         []string `json:"mount_targets,omitempty"`
}

type Manifest struct {
	ArtifactDigest   string           `json:"artifact_digest"`
	ArtifactType     string           `json:"artifact_type"`
	IntentDigest     string           `json:"intent_digest"`
	RuntimeInterface RuntimeInterface `json:"runtime_interface"`
}
