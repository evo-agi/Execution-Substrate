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
	// MountTargets lists the paths at which the artifact accepts a caller
	// mount. An empty or absent list accepts none. It is omitted from the
	// canonical bytes when empty, so records signed before the field existed
	// keep their canonical bytes and their seal.
	MountTargets []string `json:"mount_targets,omitempty"`
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
	MountTargets         []string `json:"mount_targets,omitempty"`
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
			MountTargets:         normalizeStringSet(e.Runtime.MountTargets),
		},
		Workload: canonicalExecutionWorkload{
			TargetPlatform: strings.TrimSpace(e.Workload.TargetPlatform),
		},
		Access: canonicalExecutionAccess{
			NetworkAccess: e.Access.NetworkAccess,
		},
	}
}
