package api

import "time"

type AuthorizeRequest struct {
	Workload              WorkloadDescriptor `json:"workload"`
	RequestedCapabilities []string           `json:"requested_capabilities"`
}

type WorkloadDescriptor struct {
	Type               string `json:"type"`
	WorkloadIdentityID string `json:"workload_identity_id,omitempty"`
}

type AuthorizeResponse struct {
	Allowed    bool                   `json:"allowed"`
	RequestID  string                 `json:"request_id"`
	DecisionID string                 `json:"decision_id"`
	Decision   *AuthorizationDecision `json:"decision,omitempty"`
	Audit      AuthorizationAudit     `json:"audit"`
	Reason     *ReasonResponse        `json:"reason,omitempty"`
}

type AuthorizationDecision struct {
	Role        string                    `json:"role"`
	Constraints *AuthorizationConstraints `json:"constraints,omitempty"`
}

type AuthorizationConstraints struct {
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
