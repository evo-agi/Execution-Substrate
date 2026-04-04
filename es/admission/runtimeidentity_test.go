package admission

import (
	"path"
	"strings"
	"testing"
)

func TestRuntimeIdentityHandoffUsesCanonicalEndpointDiscoveryAndCompatibilityAlias(t *testing.T) {
	handoff := runtimeIdentityHandoffForRun("run-0123456789abcdef")

	if handoff.endpointEnvKey != runtimeIdentityEndpointEnvKey {
		t.Fatalf("expected endpoint env key %q, got %q", runtimeIdentityEndpointEnvKey, handoff.endpointEnvKey)
	}
	if handoff.compatibilityEndpointEnvKey != runtimeIdentityEndpointCompatibilityEnvKey {
		t.Fatalf("expected compatibility endpoint env key %q, got %q", runtimeIdentityEndpointCompatibilityEnvKey, handoff.compatibilityEndpointEnvKey)
	}
	if !strings.HasPrefix(handoff.endpointURI, "unix://") {
		t.Fatalf("expected unix endpoint URI, got %q", handoff.endpointURI)
	}
	if strings.Contains(handoff.endpointURI, "/monolith/") {
		t.Fatalf("did not expect endpoint URI to expose legacy /monolith path conventions, got %q", handoff.endpointURI)
	}
	if workspaceDir := handoff.workspaceDir(); workspaceDir != path.Dir(strings.TrimPrefix(handoff.endpointURI, "unix://")) {
		t.Fatalf("expected workspace dir to be derived from endpoint URI, got %q", workspaceDir)
	}
	if !strings.HasPrefix(handoff.workspaceDir(), runtimeIdentityWorkspaceRoot+"/") {
		t.Fatalf("expected workspace dir to stay under %q, got %q", runtimeIdentityWorkspaceRoot, handoff.workspaceDir())
	}
}

func TestValidateReservedRuntimePathsRejectsRuntimeIdentityWorkspaceOverlap(t *testing.T) {
	handoff := runtimeIdentityHandoffForRun("run-0123456789abcdef")
	testCases := []string{
		runtimeIdentityWorkspaceRoot,
		handoff.workspaceDir(),
		handoff.endpointPath(),
		path.Join(handoff.workspaceDir(), "helper.sock"),
	}

	for _, targetPath := range testCases {
		targetPath := targetPath
		t.Run(targetPath, func(t *testing.T) {
			err := ValidateReservedRuntimePaths([]string{targetPath})
			if err == nil || !strings.Contains(err.Error(), "must not overlap reserved runtime paths") {
				t.Fatalf("expected reserved path overlap error for %q, got %v", targetPath, err)
			}
		})
	}
}

func TestValidateReservedRuntimePathsAllowsCallerRuntimeMountSubtree(t *testing.T) {
	err := ValidateReservedRuntimePaths([]string{"/monolith/mounts/config"})
	if err != nil {
		t.Fatalf("expected caller mount subtree to remain allowed, got %v", err)
	}
}
