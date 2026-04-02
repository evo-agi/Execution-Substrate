package admission

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	runtimeIdentityEndpointTargetDir  = "/monolith/runtime-identity"
	runtimeIdentityEndpointSocketName = "endpoint.sock"
	runtimeIdentityEndpointTargetPath = runtimeIdentityEndpointTargetDir + "/" + runtimeIdentityEndpointSocketName
	runtimeIdentityEndpointEnvKey     = "MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"
	runtimeIdentityEndpointEnvValue   = "unix://" + runtimeIdentityEndpointTargetPath
)

func validateWorkloadIdentityEndpointHostPath(hostPath string) error {
	trimmed := strings.TrimSpace(hostPath)
	if trimmed == "" {
		return fmt.Errorf("execution.workload_identity_endpoint_host_path is required")
	}
	if !filepath.IsAbs(trimmed) {
		return fmt.Errorf("execution.workload_identity_endpoint_host_path must be an absolute path")
	}
	if filepath.Base(trimmed) != runtimeIdentityEndpointSocketName {
		return fmt.Errorf("execution.workload_identity_endpoint_host_path must reference a unix socket named %s", runtimeIdentityEndpointSocketName)
	}

	info, err := os.Lstat(trimmed)
	if err != nil {
		return fmt.Errorf("execution.workload_identity_endpoint_host_path is unavailable: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("execution.workload_identity_endpoint_host_path must reference a unix socket")
	}
	return nil
}

func runtimeIdentityEndpointMountSource(hostPath string) string {
	return filepath.Dir(strings.TrimSpace(hostPath))
}
