package admission

import (
	"net/http"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestResolveExecutionRuntimeProfileKeepsDefaultWhenAnnotationAbsent(t *testing.T) {
	profile, err := resolveExecutionRuntimeProfile(esconfig.ExecutionConfig{
		BaseImage: "alpine:3.20",
	}, PrepareRequest{}, preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
	})
	if err != nil {
		t.Fatalf("expected default profile to resolve, got %+v", err)
	}
	if profile.name != runtimeProfileDefaultStaticScript {
		t.Fatalf("expected default profile, got %+v", profile)
	}
	if profile.image != "alpine:3.20" {
		t.Fatalf("expected base image for default profile, got %q", profile.image)
	}
	if len(profile.env) != 0 {
		t.Fatalf("expected no additional env for default profile, got %#v", profile.env)
	}
}

func TestRuntimeProfileCompatibilityMatrixKeepsDefaultImplicitAndRejectsNonSelectors(t *testing.T) {
	artifact := preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
		networkAccess: true,
	}
	cfg := controlPlaneNormalShellProfileExecutionConfig()

	for _, request := range []PrepareRequest{
		{},
		{
			Invocation: ArtifactInvocation{
				Annotations: map[string]string{
					runtimeProfileAnnotationKey: "",
				},
			},
		},
		{
			Invocation: ArtifactInvocation{
				Annotations: map[string]string{
					runtimeProfileAnnotationKey: "   ",
				},
			},
		},
	} {
		profile, err := resolveExecutionRuntimeProfile(cfg, request, artifact)
		if err != nil {
			t.Fatalf("expected omitted or empty annotation to keep default runtime profile, got %+v", err)
		}
		if profile.name != runtimeProfileDefaultStaticScript || profile.image != "alpine:3.20" || len(profile.env) != 0 {
			t.Fatalf("expected implicit default static-script profile, got %+v", profile)
		}
	}

	for _, requested := range []string{
		runtimeProfileDefaultStaticScript,
		"execution-substrate/control-plane-normal-shell:supported-local",
		"execution-substrate/control-plane-normal-shell:local",
		"future-runtime/v1",
		"unknown/v1",
	} {
		_, err := resolveExecutionRuntimeProfile(cfg, PrepareRequest{
			Invocation: ArtifactInvocation{
				Annotations: map[string]string{
					runtimeProfileAnnotationKey: requested,
				},
			},
		}, artifact)
		assertRuntimeProfileError(t, err, "unsupported runtime profile")
	}
}

func TestResolveExecutionRuntimeProfileRejectsUnknownDisabledAndNetworklessProfile(t *testing.T) {
	artifact := preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
		networkAccess: true,
	}

	_, err := resolveExecutionRuntimeProfile(esconfig.ExecutionConfig{}, PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: "unknown/v1",
			},
		},
	}, artifact)
	assertRuntimeProfileError(t, err, "unsupported runtime profile")

	_, err = resolveExecutionRuntimeProfile(esconfig.ExecutionConfig{}, PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, artifact)
	assertRuntimeProfileError(t, err, "is not enabled")

	cfg := controlPlaneNormalShellProfileExecutionConfig()
	artifact.networkAccess = false
	_, err = resolveExecutionRuntimeProfile(cfg, PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, artifact)
	assertRuntimeProfileError(t, err, "requires network_access=true")
}

func TestResolveExecutionRuntimeProfileKeepsControlPlaneNormalShellAsStaticScriptOverlay(t *testing.T) {
	cfg := controlPlaneNormalShellProfileExecutionConfig()
	_, err := resolveExecutionRuntimeProfile(cfg, PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, preparedArtifact{
		manifest: Manifest{
			ArtifactType: "workspace-archive",
		},
		networkAccess: true,
	})
	assertRuntimeProfileError(t, err, "requires static-script artifacts")
}

func TestResolveExecutionRuntimeProfileReturnsControlPlaneNormalShellMetadata(t *testing.T) {
	profile, err := resolveExecutionRuntimeProfile(controlPlaneNormalShellProfileExecutionConfig(), PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
		networkAccess: true,
	})
	if err != nil {
		t.Fatalf("expected control-plane normal-shell profile to resolve, got %+v", err)
	}
	if profile.name != runtimeProfileControlPlaneNormalShell {
		t.Fatalf("expected control-plane normal-shell profile, got %+v", profile)
	}
	if profile.image != "execution-substrate/control-plane-normal-shell:test" {
		t.Fatalf("expected profile image, got %q", profile.image)
	}
	if profile.env["EXEC_CODEX_CLI_PATH"] != "/usr/local/bin/codex" {
		t.Fatalf("expected codex cli path metadata, got %#v", profile.env)
	}
	if profile.env["EXEC_CODEX_CREDENTIAL_SOURCE"] != "workload_vault" {
		t.Fatalf("expected workload-vault credential source metadata, got %#v", profile.env)
	}
	if profile.env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"] != "proof-secrets/data/codex-runtime-profile" {
		t.Fatalf("expected credential secret path metadata, got %#v", profile.env)
	}
	if profile.env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"] != "api_key" {
		t.Fatalf("expected credential secret field metadata, got %#v", profile.env)
	}

	handoff := buildExecutionAuthorityHandoff(
		profile,
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
		stagedWorkloadTrustMaterial{},
	)
	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAll(t, payload,
		`"private_key":`,
		`"pem_body":`,
		`"raw_cert_body":`,
		`"endpoint_secret":`,
		`"vault_token":`,
		`"client_token":`,
		`"root_token":`,
		`"unseal_key":`,
		`"jwt_svid":`,
		`"x509_svid":`,
		`"lease_id":`,
		`"lease_duration":`,
		`"credential_material":`,
		`"credential_value":`,
		`"secret_material":`,
		`"secret_value":`,
		`"raw_payload":`,
		`"raw_logs":`,
		`"support_bundle_payload":`,
		`"proof_payload":`,
		`"retained_bundle_payload":`,
		`"workflow":`,
		`"review":`,
		`"checkpoint":`,
		`"finalization":`,
	)
}

func assertRuntimeProfileError(t *testing.T, err *Error, messageSubstring string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected runtime profile error")
	}
	if err.Status != http.StatusBadRequest || err.Code != codeUnsupportedRuntimeProfile {
		t.Fatalf("expected unsupported runtime profile error, got %+v", err)
	}
	if !strings.Contains(err.Message, messageSubstring) {
		t.Fatalf("expected message to contain %q, got %q", messageSubstring, err.Message)
	}
}

func controlPlaneNormalShellProfileExecutionConfig() esconfig.ExecutionConfig {
	return esconfig.ExecutionConfig{
		BaseImage: "alpine:3.20",
		RuntimeProfiles: esconfig.RuntimeProfilesConfig{
			ControlPlaneNormalShell: esconfig.ControlPlaneNormalShellProfileConfig{
				Enabled:                    true,
				Image:                      "execution-substrate/control-plane-normal-shell:test",
				CodexCLIPath:               "/usr/local/bin/codex",
				CredentialVaultSecretPath:  "proof-secrets/data/codex-runtime-profile",
				CredentialVaultSecretField: "api_key",
			},
		},
	}
}
