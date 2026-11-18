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

type executionAuthorityHandoffProjection struct {
	privateExecutionValue
	runtimeProfileName            string
	codexCredential               resolvedCodexCredentialLocation
	runtimeIdentity               runtimeIdentityHandoff
	workloadVault                 resolvedWorkloadVaultPlan
	workloadZoneVaultConfigDigest string
	trustMaterial                 stagedWorkloadTrustMaterial
}

type executionAuthorityMetadataProjection struct {
	privateExecutionValue
	runtimeProfileName            string
	workloadZoneVaultConfigDigest string
}

func newExecutionAuthorityHandoffProjection(
	runtimeProfile executionRuntimeProfile,
	runtimeIdentity runtimeIdentityHandoff,
	workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan,
	workloadZoneVaultConfigDigest string,
	trustMaterial stagedWorkloadTrustMaterial,
) executionAuthorityHandoffProjection {
	runtimeProfileName := strings.TrimSpace(runtimeProfile.name)
	if runtimeProfileName == "" {
		runtimeProfileName = runtimeProfileDefaultStaticScript
	}
	return executionAuthorityHandoffProjection{
		runtimeProfileName: runtimeProfileName,
		codexCredential:    resolveCodexCredentialLocation(runtimeProfile.env),
		runtimeIdentity: runtimeIdentityHandoff{
			endpointEnvKey: strings.TrimSpace(runtimeIdentity.endpointEnvKey),
			endpointURI:    strings.TrimSpace(runtimeIdentity.endpointURI),
		},
		workloadVault: resolvedWorkloadVaultPlan{
			mode:        strings.TrimSpace(string(workloadVaultPlan.Mode)),
			address:     strings.TrimSpace(workloadVaultPlan.Address),
			authMount:   strings.TrimSpace(workloadVaultPlan.AuthMount),
			authRole:    strings.TrimSpace(workloadVaultPlan.AuthRole),
			jwtAudience: strings.TrimSpace(workloadVaultPlan.JWTAudience),
		},
		workloadZoneVaultConfigDigest: strings.TrimSpace(workloadZoneVaultConfigDigest),
		trustMaterial:                 trustMaterial,
	}
}

func newExecutionAuthorityHandoffProjectionFromResolvedPlan(plan resolvedAuthorityPlan, runtimeIdentity runtimeIdentityHandoff) executionAuthorityHandoffProjection {
	return executionAuthorityHandoffProjection{
		runtimeProfileName: plan.runtimeProfileName,
		codexCredential:    plan.codexCredential,
		runtimeIdentity: runtimeIdentityHandoff{
			endpointEnvKey: strings.TrimSpace(runtimeIdentity.endpointEnvKey),
			endpointURI:    strings.TrimSpace(runtimeIdentity.endpointURI),
		},
		workloadVault:                 plan.workloadVault,
		workloadZoneVaultConfigDigest: plan.workloadZoneVaultConfigDigest,
		trustMaterial:                 plan.trustMaterial,
	}
}

func buildResolvedExecutionAuthorityHandoff(projection executionAuthorityHandoffProjection) ExecutionAuthorityHandoff {
	workloadVault := ExecutionAuthorityWorkloadVault{
		AuthMode:    projection.workloadVault.mode,
		Address:     projection.workloadVault.address,
		AuthMount:   projection.workloadVault.authMount,
		AuthRole:    projection.workloadVault.authRole,
		JWTAudience: projection.workloadVault.jwtAudience,
	}
	if projection.trustMaterial.vaultCACert {
		workloadVault.CACertEnv = "VAULT_CACERT"
		workloadVault.CACertPath = executionRuntimePlatformDir + "/" + executionWorkloadVaultCAName
	}
	if projection.trustMaterial.workloadTLSBundle {
		workloadVault.TLSBundleEnv = "SSL_CERT_FILE"
		workloadVault.TLSBundlePath = executionRuntimePlatformDir + "/" + executionWorkloadTLSBundleName
	}

	result := ExecutionAuthorityHandoff{
		AuthorityPath: executionAuthorityPathWorkloadVault,
		RuntimeProfile: ExecutionAuthorityRuntimeProfile{
			Name: projection.runtimeProfileName,
		},
		IdentityHandoff: ExecutionAuthorityIdentityHandoff{
			Mode:          executionAuthorityIdentityModeEndpoint,
			EndpointEnv:   projection.runtimeIdentity.endpointEnvKey,
			EndpointURI:   projection.runtimeIdentity.endpointURI,
			JWTSVIDTarget: executionAuthorityJWTSVIDTargetWorkloadVault,
		},
		WorkloadVault: workloadVault,
		RuntimeConfigRefs: ExecutionAuthorityRuntimeConfigRefs{
			WorkloadZoneVaultConfig: ExecutionAuthorityRuntimeConfigRef{
				Digest: projection.workloadZoneVaultConfigDigest,
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

	if codex := executionAuthorityCodexCredential(projection.codexCredential); codex != nil {
		result.CodexCredentialLocation = codex
		result.Evidence.CodexCredentialLocation = executionAuthorityEvidenceCodexCredentialLocation
	}
	return result
}

func buildExecutionAuthorityHandoff(
	runtimeProfile executionRuntimeProfile,
	runtimeIdentity runtimeIdentityHandoff,
	workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan,
	workloadZoneVaultConfigDigest string,
	trustMaterial stagedWorkloadTrustMaterial,
) ExecutionAuthorityHandoff {
	return buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		runtimeProfile,
		runtimeIdentity,
		workloadVaultPlan,
		workloadZoneVaultConfigDigest,
		trustMaterial,
	))
}

func resolveCodexCredentialLocation(environment map[string]string) resolvedCodexCredentialLocation {
	source := strings.TrimSpace(environment[codexCredentialSourceEnvKey])
	if source == "" {
		return resolvedCodexCredentialLocation{}
	}
	return resolvedCodexCredentialLocation{
		applicable:       true,
		cliPath:          strings.TrimSpace(environment[codexCLIPathEnvKey]),
		credentialSource: source,
		vaultSecretPath:  strings.TrimSpace(environment[codexCredentialVaultSecretPathEnvKey]),
		vaultSecretField: strings.TrimSpace(environment[codexCredentialVaultSecretFieldEnvKey]),
	}
}

func executionAuthorityCodexCredential(location resolvedCodexCredentialLocation) *ExecutionAuthorityCodexCredential {
	if !location.applicable {
		return nil
	}
	return &ExecutionAuthorityCodexCredential{
		CLIPath:          location.cliPath,
		CredentialSource: location.credentialSource,
		VaultSecretPath:  location.vaultSecretPath,
		VaultSecretField: location.vaultSecretField,
	}
}

func executionAuthorityMetadata(projection executionAuthorityMetadataProjection) map[string]any {
	return map[string]any{
		executionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion,
		executionAuthorityMetadataRuntimeProfileKey:          projection.runtimeProfileName,
		executionAuthorityMetadataWorkloadZoneVaultConfigKey: projection.workloadZoneVaultConfigDigest,
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
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
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
	))
	if handoff.WorkloadVault.CACertPath != "" {
		handoff.WorkloadVault.CACertPath = strings.TrimSpace(env["VAULT_CACERT"])
	}
	if handoff.WorkloadVault.TLSBundlePath != "" {
		handoff.WorkloadVault.TLSBundlePath = strings.TrimSpace(env["SSL_CERT_FILE"])
	}
	return &handoff, true
}
