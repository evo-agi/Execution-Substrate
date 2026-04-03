package admission

import (
	"strings"
	"testing"
)

func TestValidateReservedRuntimePathsRejectsRuntimeIdentityWorkspaceOverlap(t *testing.T) {
	testCases := []string{
		runtimeIdentityWorkspaceTargetDir,
		runtimeIdentityEndpointTargetPath,
		runtimeIdentityTokenTargetPath,
		runtimeIdentityWorkspaceTargetDir + "/helper.sock",
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
