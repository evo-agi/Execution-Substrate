package admission

import (
	"fmt"
	"strings"
)

// TODO: Do not mention "monolith"
const (
	runtimeIdentityWorkspaceTargetDir = "/monolith/runtime-identity"
	runtimeIdentityEndpointTargetPath = runtimeIdentityWorkspaceTargetDir + "/endpoint"
	runtimeIdentityEndpointEnvKey     = "MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"
	runtimeIdentityEndpointEnvValue   = "unix://" + runtimeIdentityEndpointTargetPath
)

// TODO: Do not mention "monolith"
var reservedRuntimePaths = []string{
	"/monolith/staged",
	"/monolith/run",
	runtimeIdentityWorkspaceTargetDir,
	runtimeIdentityEndpointTargetPath,
}

func ValidateReservedRuntimePaths(targetPaths []string) error {
	for _, targetPath := range targetPaths {
		normalized := strings.TrimSpace(targetPath)
		if normalized == "" {
			continue
		}
		for _, reservedPath := range reservedRuntimePaths {
			if runtimePathsOverlap(normalized, reservedPath) {
				return fmt.Errorf("runtime mount target paths must not overlap reserved runtime paths")
			}
		}
	}
	return nil
}

func runtimePathsOverlap(first string, second string) bool {
	return first == second ||
		strings.HasPrefix(first, second+"/") ||
		strings.HasPrefix(second, first+"/")
}
