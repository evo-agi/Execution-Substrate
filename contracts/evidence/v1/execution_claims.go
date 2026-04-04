package evidencev1

import (
	"fmt"
	"strings"
)

type ExecutionClaims struct {
	Runtime  ExecutionRuntime  `json:"runtime"`
	Workload ExecutionWorkload `json:"workload"`
	Access   ExecutionAccess   `json:"access"`
}

type ExecutionRuntime struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type ExecutionWorkload struct {
	ArtifactClass      string `json:"artifact_class"`
	WorkloadType       string `json:"workload_type"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id"`
}

type ExecutionAccess struct {
	NetworkAccess bool `json:"network_access"`
}

type canonicalExecutionClaims struct {
	Runtime  canonicalExecutionRuntime  `json:"runtime"`
	Workload canonicalExecutionWorkload `json:"workload"`
	Access   canonicalExecutionAccess   `json:"access"`
}

type canonicalExecutionRuntime struct {
	Parameters           []string `json:"parameters"`
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type canonicalExecutionWorkload struct {
	ArtifactClass      string `json:"artifact_class"`
	WorkloadType       string `json:"workload_type"`
	ServiceName        string `json:"service_name,omitempty"`
	TargetPlatform     string `json:"target_platform,omitempty"`
	Description        string `json:"description,omitempty"`
	WorkloadIdentityID string `json:"workload_identity_id"`
}

type canonicalExecutionAccess struct {
	NetworkAccess bool `json:"network_access"`
}

func (e ExecutionClaims) validate() error {
	requiredStrings := map[string]string{
		"claims.admission.execution.workload.artifact_class":       e.Workload.ArtifactClass,
		"claims.admission.execution.workload.workload_type":        e.Workload.WorkloadType,
		"claims.admission.execution.workload.workload_identity_id": e.Workload.WorkloadIdentityID,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	if strings.TrimSpace(e.Workload.WorkloadType) == "service" && strings.TrimSpace(e.Workload.ServiceName) == "" {
		return fmt.Errorf("claims.admission.execution.workload.service_name is required for service workloads")
	}

	return nil
}

func (e ExecutionClaims) canonicalize() canonicalExecutionClaims {
	return canonicalExecutionClaims{
		Runtime: canonicalExecutionRuntime{
			Parameters:           normalizeStringSet(e.Runtime.Parameters),
			EnvironmentVariables: normalizeStringSet(e.Runtime.EnvironmentVariables),
			RequiredCapabilities: normalizeStringSet(e.Runtime.RequiredCapabilities),
		},
		Workload: canonicalExecutionWorkload{
			ArtifactClass:      strings.TrimSpace(e.Workload.ArtifactClass),
			WorkloadType:       strings.TrimSpace(e.Workload.WorkloadType),
			ServiceName:        strings.TrimSpace(e.Workload.ServiceName),
			TargetPlatform:     strings.TrimSpace(e.Workload.TargetPlatform),
			Description:        strings.TrimSpace(e.Workload.Description),
			WorkloadIdentityID: strings.TrimSpace(e.Workload.WorkloadIdentityID),
		},
		Access: canonicalExecutionAccess{
			NetworkAccess: e.Access.NetworkAccess,
		},
	}
}
