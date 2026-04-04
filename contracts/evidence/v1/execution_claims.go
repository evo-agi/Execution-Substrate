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
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type ExecutionWorkload struct {
	TargetPlatform string `json:"target_platform,omitempty"`
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
	EnvironmentVariables []string `json:"environment_variables"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type canonicalExecutionWorkload struct {
	TargetPlatform string `json:"target_platform,omitempty"`
}

type canonicalExecutionAccess struct {
	NetworkAccess bool `json:"network_access"`
}

func (e ExecutionClaims) validate() error {
	if targetPlatform := strings.TrimSpace(e.Workload.TargetPlatform); targetPlatform != "" && targetPlatform != "docker" {
		return fmt.Errorf("claims.admission.execution.workload.target_platform must be empty or docker")
	}

	return nil
}

func (e ExecutionClaims) canonicalize() canonicalExecutionClaims {
	return canonicalExecutionClaims{
		Runtime: canonicalExecutionRuntime{
			EnvironmentVariables: normalizeStringSet(e.Runtime.EnvironmentVariables),
			RequiredCapabilities: normalizeStringSet(e.Runtime.RequiredCapabilities),
		},
		Workload: canonicalExecutionWorkload{
			TargetPlatform: strings.TrimSpace(e.Workload.TargetPlatform),
		},
		Access: canonicalExecutionAccess{
			NetworkAccess: e.Access.NetworkAccess,
		},
	}
}
