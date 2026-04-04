package admission

import (
	"fmt"
	"path"
	"strings"
)

// TODO: Do not mention "monolith"
const (
	runtimeIdentityEndpointEnvKey = "MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"
	// runtimeIdentityEndpointEnvValue is the current bounded workload-visible
	// endpoint discovery convention. ES derives its internal workspace layout
	// from this endpoint instead of treating the workspace path as a separate
	// workload contract.
	runtimeIdentityEndpointEnvValue = "unix:///monolith/runtime-identity/endpoint"
)

type runtimeIdentityHandoff struct {
	endpointEnvKey string
	endpointURI    string
}

func currentRuntimeIdentityHandoff() runtimeIdentityHandoff {
	return runtimeIdentityHandoff{
		endpointEnvKey: runtimeIdentityEndpointEnvKey,
		endpointURI:    runtimeIdentityEndpointEnvValue,
	}
}

func (h runtimeIdentityHandoff) endpointPath() string {
	return strings.TrimPrefix(strings.TrimSpace(h.endpointURI), "unix://")
}

func (h runtimeIdentityHandoff) workspaceDir() string {
	return path.Dir(h.endpointPath())
}

func (h runtimeIdentityHandoff) reservedRuntimePaths() []string {
	return []string{
		"/monolith/staged",
		"/monolith/run",
		h.workspaceDir(),
		h.endpointPath(),
	}
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
