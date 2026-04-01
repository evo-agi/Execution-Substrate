package api

import "time"

type AuthorizeRequest struct {
	RequestedBy           RequestedByInfo    `json:"requested_by"`
	Workload              WorkloadDescriptor `json:"workload"`
	RequestedCapabilities []string           `json:"requested_capabilities"`
	Context               map[string]any     `json:"context"`
}

type RequestedByInfo struct {
	Component string `json:"component"`
	Platform  string `json:"platform"`
	User      string `json:"user"`
}

type WorkloadDescriptor struct {
	Type               string `json:"type"`
	ServiceName        string `json:"service_name,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id,omitempty"`
	ModulePath         string `json:"module_path,omitempty"`
	FilePath           string `json:"file_path,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	Ephemeral          bool   `json:"ephemeral"`
}

type AuthorizeResponse struct {
	Allowed                bool                   `json:"allowed"`
	RequestID              string                 `json:"request_id"`
	DecisionID             string                 `json:"decision_id"`
	Credential             *AuthorizedCredential  `json:"credential,omitempty"`
	Constraints            *CredentialConstraints `json:"constraints,omitempty"`
	Audit                  AuthorizationAudit     `json:"audit"`
	CredentialPolicyDigest string                 `json:"credential_policy_digest"`
	WorkloadVaultDigest    string                 `json:"workload_vault_digest"`
	WorkloadVaultSource    string                 `json:"workload_vault_source,omitempty"`
	RecordProof            string                 `json:"record_proof,omitempty"`
	RecordProofExpiresAt   *time.Time             `json:"record_proof_expires_at,omitempty"`
	Reason                 *ReasonResponse        `json:"reason,omitempty"`
}

type AuthorizedCredential struct {
	Role             string           `json:"role"`
	AuthMethod       string           `json:"auth_method"`
	AuthPlan         VaultAuthPlan    `json:"auth_plan"`
	TokenConstraints TokenConstraints `json:"token_constraints"`
}

type VaultAuthPlan struct {
	WorkloadIdentityID string `json:"workload_identity_id"`
	VaultAddress       string `json:"vault_address"`
	AuthMount          string `json:"auth_mount"`
	AuthRole           string `json:"auth_role"`
	JWTAudience        string `json:"jwt_audience"`
}

type TokenConstraints struct {
	TTLSeconds int  `json:"ttl_seconds"`
	Renewable  bool `json:"renewable"`
}

type CredentialConstraints struct {
	ForbiddenStages []string  `json:"forbidden_stages"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type AuthorizationAudit struct {
	DecisionID     string   `json:"decision_id"`
	Reasons        []string `json:"reasons"`
	PolicyVersion  string   `json:"policy_version"`
	EvaluatedRules []string `json:"evaluated_rules"`
}

type ReasonResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
