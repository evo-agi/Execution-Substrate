package admission

import (
	"fmt"
	"strings"
)

const (
	// runtimeIdentityTokenTargetPath remains reserved for a future slice. The
	// workspace is tmpfs-backed in the current substrate, but ES still does not
	// populate or manage token material there.
	runtimeIdentityWorkspaceTargetDir = "/monolith/runtime-identity"
	runtimeIdentityEndpointTargetPath = runtimeIdentityWorkspaceTargetDir + "/endpoint"
	runtimeIdentityTokenTargetPath  = runtimeIdentityWorkspaceTargetDir + "/vault-token"
	runtimeIdentityEndpointEnvKey   = "MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"
	runtimeIdentityEndpointEnvValue = "unix://" + runtimeIdentityEndpointTargetPath
)

var reservedRuntimePaths = []string{
	"/monolith/staged",
	"/monolith/run",
	runtimeIdentityWorkspaceTargetDir,
	runtimeIdentityEndpointTargetPath,
	runtimeIdentityTokenTargetPath,
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
