package admission

import (
	"fmt"
	"path"
	"strings"
)

const (
	runtimeIdentityEndpointEnvKey   = "EXEC_WORKLOAD_IDENTITY_ENDPOINT"
	runtimeIdentityWorkspaceRoot    = "/run/es-runtime-identity"
	runtimeIdentityInternalDirName  = "internal"
	runtimeIdentityEndpointFilename = "endpoint"
	runtimeIdentitySPIRESocketName  = "spire-agent.sock"
)

type runtimeIdentityHandoff struct {
	endpointEnvKey string
	endpointURI    string
}

func runtimeIdentityHandoffForRun(runID string) runtimeIdentityHandoff {
	normalizedRunID := strings.TrimSpace(runID)
	if normalizedRunID == "" {
		normalizedRunID = "current"
	}
	endpointPath := path.Join(runtimeIdentityWorkspaceRoot, normalizedRunID, runtimeIdentityEndpointFilename)
	return runtimeIdentityHandoff{
		endpointEnvKey: runtimeIdentityEndpointEnvKey,
		endpointURI:    "unix://" + endpointPath,
	}
}

func currentRuntimeIdentityHandoff() runtimeIdentityHandoff {
	return runtimeIdentityHandoffForRun("current")
}

func (h runtimeIdentityHandoff) endpointPath() string {
	return strings.TrimPrefix(strings.TrimSpace(h.endpointURI), "unix://")
}

func (h runtimeIdentityHandoff) workspaceDir() string {
	return path.Dir(h.endpointPath())
}

func (h runtimeIdentityHandoff) internalDir() string {
	return path.Join(h.workspaceDir(), runtimeIdentityInternalDirName)
}

func (h runtimeIdentityHandoff) spireSocketPath() string {
	return path.Join(h.internalDir(), runtimeIdentitySPIRESocketName)
}

func (h runtimeIdentityHandoff) reservedRuntimePaths() []string {
	return reservedExecutionRuntimePaths()
}

func ValidateReservedRuntimePaths(targetPaths []string) error {
	handoff := currentRuntimeIdentityHandoff()
	for _, targetPath := range targetPaths {
		normalized := strings.TrimSpace(targetPath)
		if normalized == "" {
			continue
		}
		for _, reservedPath := range handoff.reservedRuntimePaths() {
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
