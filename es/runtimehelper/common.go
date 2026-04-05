package runtimehelper

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	workloadUID = 10000
	workloadGID = 10000

	endpointRequestKindJWTSVID    = "jwt_svid"
	endpointRequestTargetWorkload = "workload_vault"

	identityEndpointEnvKey      = "EXEC_WORKLOAD_IDENTITY_ENDPOINT"
	workloadVaultModeEnvKey     = "EXEC_WORKLOAD_VAULT_AUTH_MODE"
	workloadVaultAudienceEnvKey = "EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"

	helperReadyLogMarker      = "RUNTIME-HELPER-READY"
	helperCapsLogPrefix       = "RUNTIME-HELPER-CAPS"
	workloadBoundaryLogPrefix = "RUNTIME-WORKLOAD-BOUNDARY"

	internalDirName = "internal"
	spireSocketName = "spire-agent.sock"
)

type endpointRequest struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type endpointResponse struct {
	JWT       string `json:"jwt,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type runtimePaths struct {
	endpointURI   string
	endpointPath  string
	workspaceDir  string
	internalDir   string
	spireSocket   string
	workspaceRoot string
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e == nil {
		return ""
	}
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit code %d", e.code)
}

func newExitError(code int, err error) *exitError {
	return &exitError{code: code, err: err}
}

func requireEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("missing required environment variable: %s", key)
	}
	return value, nil
}

func runtimePathsFromEnvironment() (runtimePaths, error) {
	endpointURI, err := requireEnv(identityEndpointEnvKey)
	if err != nil {
		return runtimePaths{}, err
	}

	parsed, err := url.Parse(endpointURI)
	if err != nil {
		return runtimePaths{}, fmt.Errorf("parse %s: %w", identityEndpointEnvKey, err)
	}
	if parsed.Scheme != "unix" {
		return runtimePaths{}, fmt.Errorf("%s must use unix://", identityEndpointEnvKey)
	}

	endpointPath := strings.TrimSpace(parsed.Path)
	if endpointPath == "" {
		return runtimePaths{}, fmt.Errorf("%s must include a unix socket path", identityEndpointEnvKey)
	}

	workspaceDir := filepath.Dir(endpointPath)

	return runtimePaths{
		endpointURI:   endpointURI,
		endpointPath:  endpointPath,
		workspaceDir:  workspaceDir,
		internalDir:   filepath.Join(workspaceDir, internalDirName),
		spireSocket:   filepath.Join(workspaceDir, internalDirName, spireSocketName),
		workspaceRoot: filepath.Dir(workspaceDir),
	}, nil
}

func normalizeUnixSocketPath(pathValue string) string {
	return filepath.Clean(strings.TrimSpace(pathValue))
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
