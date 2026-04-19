package admission

import (
	"strings"

	esconfig "execution-substrate/es/config"
)

const (
	executionAuthorityPathWorkloadVault          = "workload_identity_endpoint/workload_vault"
	executionAuthorityIdentityModeEndpoint       = "workload_identity_endpoint"
	executionAuthorityJWTSVIDTargetWorkloadVault = "workload_vault"

	executionAuthorityEvidenceSourceSubmittedRuntimeSpec = "submitted_runtime_spec"
	executionAuthorityEvidenceRuntimeProfile             = "es_selected_runtime_profile"
	executionAuthorityEvidenceIdentityHandoff            = "submitted_runtime_environment"
	executionAuthorityEvidenceWorkloadVault              = "submitted_runtime_environment"
	executionAuthorityEvidenceRuntimeConfigRefs          = "submitted_runtime_metadata"
	executionAuthorityEvidenceCodexCredentialLocation    = "submitted_runtime_environment"

	executionAuthorityMetadataSchemaKey                  = "execution_substrate.authority_handoff.schema"
	executionAuthorityMetadataSchemaVersion              = "v1"
	executionAuthorityMetadataRuntimeProfileKey          = "execution_substrate.authority_handoff.runtime_profile"
	executionAuthorityMetadataWorkloadZoneVaultConfigKey = "execution_substrate.authority_handoff.workload_zone_vault_config_digest"
)

func buildExecutionAuthorityHandoff(
	runtimeProfile executionRuntimeProfile,
	runtimeIdentity runtimeIdentityHandoff,
	workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan,
	workloadZoneVaultConfigDigest string,
	trustMaterial stagedWorkloadTrustMaterial,
) ExecutionAuthorityHandoff {
	runtimeProfileName := strings.TrimSpace(runtimeProfile.name)
	if runtimeProfileName == "" {
		runtimeProfileName = runtimeProfileDefaultStaticScript
	}

	workloadVault := ExecutionAuthorityWorkloadVault{
		AuthMode:    strings.TrimSpace(string(workloadVaultPlan.Mode)),
		Address:     strings.TrimSpace(workloadVaultPlan.Address),
		AuthMount:   strings.TrimSpace(workloadVaultPlan.AuthMount),
		AuthRole:    strings.TrimSpace(workloadVaultPlan.AuthRole),
		JWTAudience: strings.TrimSpace(workloadVaultPlan.JWTAudience),
	}
	if trustMaterial.vaultCACert {
		workloadVault.CACertEnv = "VAULT_CACERT"
		workloadVault.CACertPath = executionRuntimePlatformDir + "/" + executionWorkloadVaultCAName
	}
	if trustMaterial.workloadTLSBundle {
		workloadVault.TLSBundleEnv = "SSL_CERT_FILE"
		workloadVault.TLSBundlePath = executionRuntimePlatformDir + "/" + executionWorkloadTLSBundleName
	}

	result := ExecutionAuthorityHandoff{
		AuthorityPath: executionAuthorityPathWorkloadVault,
		RuntimeProfile: ExecutionAuthorityRuntimeProfile{
			Name: runtimeProfileName,
		},
		IdentityHandoff: ExecutionAuthorityIdentityHandoff{
			Mode:          executionAuthorityIdentityModeEndpoint,
			EndpointEnv:   strings.TrimSpace(runtimeIdentity.endpointEnvKey),
			EndpointURI:   strings.TrimSpace(runtimeIdentity.endpointURI),
			JWTSVIDTarget: executionAuthorityJWTSVIDTargetWorkloadVault,
		},
		WorkloadVault: workloadVault,
		RuntimeConfigRefs: ExecutionAuthorityRuntimeConfigRefs{
			WorkloadZoneVaultConfig: ExecutionAuthorityRuntimeConfigRef{
				Digest: strings.TrimSpace(workloadZoneVaultConfigDigest),
			},
		},
		Evidence: ExecutionAuthorityEvidence{
			Source:            executionAuthorityEvidenceSourceSubmittedRuntimeSpec,
			RuntimeProfile:    executionAuthorityEvidenceRuntimeProfile,
			IdentityHandoff:   executionAuthorityEvidenceIdentityHandoff,
			WorkloadVault:     executionAuthorityEvidenceWorkloadVault,
			RuntimeConfigRefs: executionAuthorityEvidenceRuntimeConfigRefs,
		},
	}

	if codex := codexCredentialLocationFromRuntimeProfile(runtimeProfile); codex != nil {
		result.CodexCredentialLocation = codex
		result.Evidence.CodexCredentialLocation = executionAuthorityEvidenceCodexCredentialLocation
	}
	return result
}

func codexCredentialLocationFromRuntimeProfile(runtimeProfile executionRuntimeProfile) *ExecutionAuthorityCodexCredential {
	source := strings.TrimSpace(runtimeProfile.env[codexCredentialSourceEnvKey])
	if source == "" {
		return nil
	}
	return &ExecutionAuthorityCodexCredential{
		CLIPath:          strings.TrimSpace(runtimeProfile.env[codexCLIPathEnvKey]),
		CredentialSource: source,
		VaultSecretPath:  strings.TrimSpace(runtimeProfile.env[codexCredentialVaultSecretPathEnvKey]),
		VaultSecretField: strings.TrimSpace(runtimeProfile.env[codexCredentialVaultSecretFieldEnvKey]),
	}
}

func executionAuthorityMetadata(runtimeProfile executionRuntimeProfile, workloadZoneVaultConfigDigest string) map[string]any {
	runtimeProfileName := strings.TrimSpace(runtimeProfile.name)
	if runtimeProfileName == "" {
		runtimeProfileName = runtimeProfileDefaultStaticScript
	}
	return map[string]any{
		executionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion,
		executionAuthorityMetadataRuntimeProfileKey:          runtimeProfileName,
		executionAuthorityMetadataWorkloadZoneVaultConfigKey: strings.TrimSpace(workloadZoneVaultConfigDigest),
	}
}

func executionAuthorityHandoffFromSubmittedRuntimeSpec(runtimeProfileName string, workloadZoneVaultConfigDigest string, env map[string]string) (*ExecutionAuthorityHandoff, bool) {
	if strings.TrimSpace(runtimeProfileName) == "" ||
		strings.TrimSpace(workloadZoneVaultConfigDigest) == "" ||
		strings.TrimSpace(env[runtimeIdentityEndpointEnvKey]) == "" ||
		strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_MODE"]) == "" ||
		strings.TrimSpace(env["VAULT_ADDR"]) == "" ||
		strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"]) == "" ||
		strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_ROLE"]) == "" ||
		strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"]) == "" {
		return nil, false
	}

	runtimeProfile := executionRuntimeProfile{
		name: strings.TrimSpace(runtimeProfileName),
		env: map[string]string{
			codexCLIPathEnvKey:                    strings.TrimSpace(env[codexCLIPathEnvKey]),
			codexCredentialSourceEnvKey:           strings.TrimSpace(env[codexCredentialSourceEnvKey]),
			codexCredentialVaultSecretPathEnvKey:  strings.TrimSpace(env[codexCredentialVaultSecretPathEnvKey]),
			codexCredentialVaultSecretFieldEnvKey: strings.TrimSpace(env[codexCredentialVaultSecretFieldEnvKey]),
		},
	}
	handoff := buildExecutionAuthorityHandoff(
		runtimeProfile,
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    strings.TrimSpace(env[runtimeIdentityEndpointEnvKey]),
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthMode(strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_MODE"])),
			Address:     strings.TrimSpace(env["VAULT_ADDR"]),
			AuthMount:   strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"]),
			AuthRole:    strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_AUTH_ROLE"]),
			JWTAudience: strings.TrimSpace(env["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"]),
		},
		strings.TrimSpace(workloadZoneVaultConfigDigest),
		stagedWorkloadTrustMaterial{
			vaultCACert:       strings.TrimSpace(env["VAULT_CACERT"]) != "",
			workloadTLSBundle: strings.TrimSpace(env["SSL_CERT_FILE"]) != "",
		},
	)
	if handoff.WorkloadVault.CACertPath != "" {
		handoff.WorkloadVault.CACertPath = strings.TrimSpace(env["VAULT_CACERT"])
	}
	if handoff.WorkloadVault.TLSBundlePath != "" {
		handoff.WorkloadVault.TLSBundlePath = strings.TrimSpace(env["SSL_CERT_FILE"])
	}
	return &handoff, true
}
