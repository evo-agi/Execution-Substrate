package admission

import (
	"testing"

	esconfig "execution-substrate/es/config"
)

// testWorkloadZoneVaultConfigDigest names the shared test Vault config blob by
// the digest of its exact bytes, because ES uses a blob only when its bytes
// hash to the requested digest.
var testWorkloadZoneVaultConfigDigest = digestBytes([]byte(validWorkloadZoneVaultConfigBlob))

func TestBuildExecutionAuthorityHandoffReportsSelectedNonSecretFacts(t *testing.T) {
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		executionRuntimeProfile{
			name: runtimeProfileControlPlaneNormalShell,
			env: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "api_key",
			},
		},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{
			vaultCACert:       true,
			workloadTLSBundle: true,
		},
	))

	if handoff.AuthorityPath != executionAuthorityPathWorkloadVault {
		t.Fatalf("unexpected authority path %q", handoff.AuthorityPath)
	}
	if handoff.RuntimeProfile.Name != runtimeProfileControlPlaneNormalShell {
		t.Fatal("unexpected runtime profile")
	}
	if handoff.IdentityHandoff.EndpointEnv != runtimeIdentityEndpointEnvKey {
		t.Fatal("unexpected identity handoff endpoint environment")
	}
	if handoff.IdentityHandoff.JWTSVIDTarget != "workload_vault" {
		t.Fatal("unexpected JWT target")
	}
	if handoff.WorkloadVault.AuthMode != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) ||
		handoff.WorkloadVault.Address != "https://vault.internal:8200" ||
		handoff.WorkloadVault.CACertPath != "/execution/run/platform/workload-vault-ca.pem" ||
		handoff.WorkloadVault.TLSBundlePath != "/execution/run/platform/workload-ca-bundle.pem" {
		t.Fatal("unexpected workload Vault handoff")
	}
	if handoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != testWorkloadZoneVaultConfigDigest {
		t.Fatal("unexpected workload-zone Vault config reference")
	}
	if handoff.CodexCredentialLocation == nil ||
		handoff.CodexCredentialLocation.CredentialSource != codexCredentialSourceWorkloadVault ||
		handoff.CodexCredentialLocation.VaultSecretPath != "proof-secrets/data/codex-runtime-profile" {
		t.Fatal("unexpected Codex credential location")
	}
	if handoff.Evidence.Source != executionAuthorityEvidenceSourceSubmittedRuntimeSpec ||
		handoff.Evidence.WorkloadVault != executionAuthorityEvidenceWorkloadVault ||
		handoff.Evidence.CodexCredentialLocation == "" {
		t.Fatal("unexpected authority handoff evidence")
	}
}

func TestExecutionAuthorityHandoffFromSubmittedRuntimeSpecRequiresSubmittedFacts(t *testing.T) {
	env := map[string]string{
		runtimeIdentityEndpointEnvKey:      "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		"VAULT_ADDR":                       "https://vault.internal:8200",
		"EXEC_WORKLOAD_VAULT_AUTH_MODE":    string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
		"EXEC_WORKLOAD_VAULT_AUTH_MOUNT":   "jwt",
		"EXEC_WORKLOAD_VAULT_AUTH_ROLE":    "execution",
		"EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
		"VAULT_CACERT":                     "/execution/run/platform/workload-vault-ca.pem",
		"SSL_CERT_FILE":                    "/execution/run/platform/workload-ca-bundle.pem",
	}

	handoff, ok := executionAuthorityHandoffFromSubmittedRuntimeSpec(
		runtimeProfileDefaultStaticScript,
		testWorkloadZoneVaultConfigDigest,
		env,
	)
	if !ok {
		t.Fatalf("expected submitted runtime spec to recover authority handoff")
	}
	if handoff.RuntimeProfile.Name != runtimeProfileDefaultStaticScript {
		t.Fatal("unexpected recovered authority handoff runtime profile")
	}
	if handoff.WorkloadVault.CACertEnv != "VAULT_CACERT" || handoff.WorkloadVault.TLSBundleEnv != "SSL_CERT_FILE" {
		t.Fatal("expected trust-material labels in recovered handoff")
	}

	delete(env, runtimeIdentityEndpointEnvKey)
	if _, ok := executionAuthorityHandoffFromSubmittedRuntimeSpec(runtimeProfileDefaultStaticScript, testWorkloadZoneVaultConfigDigest, env); ok {
		t.Fatalf("did not expect recovery without submitted identity endpoint")
	}
}

func TestAuthorityHandoffFromNomadJobRequiresESMetadata(t *testing.T) {
	job := nomadJobSummary{
		Meta: map[string]string{
			executionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion,
			executionAuthorityMetadataRuntimeProfileKey:          runtimeProfileDefaultStaticScript,
			executionAuthorityMetadataWorkloadZoneVaultConfigKey: testWorkloadZoneVaultConfigDigest,
		},
		TaskGroups: []nomadJobTaskGroup{
			{
				Tasks: []nomadJobTask{
					{
						Name: nomadTaskName,
						Env: map[string]string{
							runtimeIdentityEndpointEnvKey:      "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
							"VAULT_ADDR":                       "https://vault.internal:8200",
							"EXEC_WORKLOAD_VAULT_AUTH_MODE":    string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
							"EXEC_WORKLOAD_VAULT_AUTH_MOUNT":   "jwt",
							"EXEC_WORKLOAD_VAULT_AUTH_ROLE":    "execution",
							"EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
						},
					},
				},
			},
		},
	}

	if handoff, ok := authorityHandoffFromNomadJob(job); !ok || handoff.IdentityHandoff.EndpointURI == "" {
		t.Fatal("expected authority handoff from submitted job")
	}

	job.Meta[executionAuthorityMetadataSchemaKey] = ""
	if _, ok := authorityHandoffFromNomadJob(job); ok {
		t.Fatalf("did not expect authority handoff without ES metadata schema marker")
	}
}
