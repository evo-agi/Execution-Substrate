package admission

import (
	"fmt"
	"net/http"
	"strings"

	esconfig "execution-substrate/es/config"
)

const (
	runtimeProfileAnnotationKey           = "execution_substrate.runtime_profile"
	runtimeProfileDefaultStaticScript     = "static-script/default"
	runtimeProfileControlPlaneNormalShell = "control-plane-normal-shell/v1"
	codexCredentialSourceWorkloadVault    = "workload_vault"
	codexCLIPathEnvKey                    = "EXEC_CODEX_CLI_PATH"
	codexCredentialSourceEnvKey           = "EXEC_CODEX_CREDENTIAL_SOURCE"
	codexCredentialVaultSecretPathEnvKey  = "EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"
	codexCredentialVaultSecretFieldEnvKey = "EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"
)

type executionRuntimeProfile struct {
	name  string
	image string
	env   map[string]string
}

func (s *Service) validateRuntimeProfileForPrepare(req PrepareRequest, prepared preparedAdmission) *Error {
	_, err := resolveExecutionRuntimeProfile(s.cfg.Execution, req, prepared.artifact)
	return err
}

func resolveExecutionRuntimeProfile(cfg esconfig.ExecutionConfig, req PrepareRequest, artifact preparedArtifact) (executionRuntimeProfile, *Error) {
	requested := strings.TrimSpace(req.Invocation.Annotations[runtimeProfileAnnotationKey])
	if requested == "" {
		return executionRuntimeProfile{
			name:  runtimeProfileDefaultStaticScript,
			image: strings.TrimSpace(cfg.BaseImage),
		}, nil
	}

	switch requested {
	case runtimeProfileControlPlaneNormalShell:
		return resolveControlPlaneNormalShellRuntimeProfile(cfg, artifact)
	default:
		return executionRuntimeProfile{}, unsupportedRuntimeProfileError(fmt.Sprintf("unsupported runtime profile %q", requested))
	}
}

func resolveControlPlaneNormalShellRuntimeProfile(cfg esconfig.ExecutionConfig, artifact preparedArtifact) (executionRuntimeProfile, *Error) {
	profileCfg := cfg.RuntimeProfiles.ControlPlaneNormalShell
	if !profileCfg.Enabled {
		return executionRuntimeProfile{}, unsupportedRuntimeProfileError("runtime profile control-plane-normal-shell/v1 is not enabled")
	}
	if artifact.manifest.ArtifactType != "static-script" {
		return executionRuntimeProfile{}, unsupportedRuntimeProfileError("runtime profile control-plane-normal-shell/v1 requires static-script artifacts")
	}
	if !artifact.networkAccess {
		return executionRuntimeProfile{}, unsupportedRuntimeProfileError("runtime profile control-plane-normal-shell/v1 requires network_access=true")
	}

	return executionRuntimeProfile{
		name:  runtimeProfileControlPlaneNormalShell,
		image: strings.TrimSpace(profileCfg.Image),
		env: map[string]string{
			codexCLIPathEnvKey:                    strings.TrimSpace(profileCfg.CodexCLIPath),
			codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
			codexCredentialVaultSecretPathEnvKey:  strings.TrimSpace(profileCfg.CredentialVaultSecretPath),
			codexCredentialVaultSecretFieldEnvKey: strings.TrimSpace(profileCfg.CredentialVaultSecretField),
		},
	}, nil
}

func unsupportedRuntimeProfileError(message string) *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    codeUnsupportedRuntimeProfile,
		Message: message,
	}
}
