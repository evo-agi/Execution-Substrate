package admission

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestBuildRuntimeEnvironmentPreservesInvocationEnvAndInjectsPlatformFields(t *testing.T) {
	layout := executionPackageLayout{
		runID:          "run-0123456789abcdef",
		runtimeWorkDir: executionRuntimeWorkDir,
		runtimeIdentity: runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
		},
	}

	env := buildRuntimeEnvironment(layout, "sha256:artifact", esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	}, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{}, map[string]string{
		"USER_DEFINED": "1",
	}, &executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})

	if env["USER_DEFINED"] != "1" {
		t.Fatalf("expected invocation env to be preserved, got %#v", env)
	}
	if env["EXEC_RUN_ID"] != layout.runID {
		t.Fatalf("expected run id injection, got %#v", env["EXEC_RUN_ID"])
	}
	if env[runtimeIdentityEndpointEnvKey] != layout.runtimeIdentity.endpointURI {
		t.Fatalf("expected runtime identity endpoint injection, got %#v", env[runtimeIdentityEndpointEnvKey])
	}
	if env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) {
		t.Fatalf("expected workload vault auth mode injection, got %#v", env["EXEC_WORKLOAD_VAULT_AUTH_MODE"])
	}
	if env["VAULT_ADDR"] != "https://vault.internal:8200" {
		t.Fatalf("expected vault address injection, got %#v", env["VAULT_ADDR"])
	}
	if env[platformStateOwnerUIDEnvKey] != fmt.Sprintf("%d", os.Getuid()) {
		t.Fatalf("expected platform state owner uid injection, got %#v", env[platformStateOwnerUIDEnvKey])
	}
	if env[platformStateOwnerGIDEnvKey] != fmt.Sprintf("%d", os.Getgid()) {
		t.Fatalf("expected platform state owner gid injection, got %#v", env[platformStateOwnerGIDEnvKey])
	}
	if env[platformStateOwnerSchemaEnvKey] != platformStateOwnerSchemaV1 {
		t.Fatalf("expected platform state owner schema injection, got %#v", env[platformStateOwnerSchemaEnvKey])
	}
}

func TestBuildRuntimeEnvironmentInjectsWorkloadVaultTrustMaterial(t *testing.T) {
	layout := executionPackageLayout{
		runID:              "run-0123456789abcdef",
		runtimePlatformDir: executionRuntimePlatformDir,
		runtimeWorkDir:     executionRuntimeWorkDir,
		runtimeIdentity: runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
		},
	}

	env := buildRuntimeEnvironment(layout, "sha256:artifact", esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	}, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{
		vaultCACert:       true,
		workloadTLSBundle: true,
	}, nil, &executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})

	if env["VAULT_CACERT"] != "/execution/run/platform/workload-vault-ca.pem" {
		t.Fatalf("expected VAULT_CACERT injection, got %#v", env["VAULT_CACERT"])
	}
	if env["SSL_CERT_FILE"] != "/execution/run/platform/workload-ca-bundle.pem" {
		t.Fatalf("expected SSL_CERT_FILE injection, got %#v", env["SSL_CERT_FILE"])
	}
}

func TestBuildRuntimeEnvironmentInjectsControlPlaneNormalShellProfileMetadata(t *testing.T) {
	layout := executionPackageLayout{
		runID:          "run-0123456789abcdef",
		runtimeWorkDir: executionRuntimeWorkDir,
		runtimeIdentity: runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
		},
	}

	env := buildRuntimeEnvironment(layout, "sha256:artifact", esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	}, executionRuntimeProfile{
		name: runtimeProfileControlPlaneNormalShell,
		env: map[string]string{
			"EXEC_CODEX_CLI_PATH":                      "/usr/local/bin/codex",
			"EXEC_CODEX_CREDENTIAL_SOURCE":             "workload_vault",
			"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH":  "proof-secrets/data/codex-runtime-profile",
			"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD": "api_key",
		},
	}, stagedWorkloadTrustMaterial{}, nil, &executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})

	if env["EXEC_CODEX_CLI_PATH"] != "/usr/local/bin/codex" {
		t.Fatalf("expected codex CLI metadata, got %#v", env)
	}
	if env["EXEC_CODEX_CREDENTIAL_SOURCE"] != "workload_vault" {
		t.Fatalf("expected credential source metadata, got %#v", env)
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"] != "proof-secrets/data/codex-runtime-profile" {
		t.Fatalf("expected credential secret path metadata, got %#v", env)
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"] != "api_key" {
		t.Fatalf("expected credential secret field metadata, got %#v", env)
	}
}

func TestBuildNomadJobSpecUsesNetworkModeAndRunMetadata(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                "alpine:3.20",
			RuntimeIdentityTmpfsSize: 2 << 20,
		},
	}
	cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Digest = testWorkloadZoneVaultConfigDigest
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointURI: "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, PrepareRequest{
		Invocation: ArtifactInvocation{
			Argv: []string{"--flag"},
		},
		TimeoutSeconds: 17,
	}, true, defaultSubmitCPU, defaultSubmitMemoryMB, map[string]string{"EXEC_RUN_ID": "run-0123456789abcdef"}, executionRuntimeProfile{
		name:  runtimeProfileDefaultStaticScript,
		image: "alpine:3.20",
	})

	job, ok := jobSpec["Job"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level Nomad Job map, got %#v", jobSpec["Job"])
	}
	meta, ok := job["Meta"].(map[string]any)
	if !ok || meta["run_id"] != "run-0123456789abcdef" {
		t.Fatalf("expected run_id metadata in job spec, got %#v", job["Meta"])
	}
	if meta[executionAuthorityMetadataSchemaKey] != executionAuthorityMetadataSchemaVersion ||
		meta[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileDefaultStaticScript ||
		meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey] != testWorkloadZoneVaultConfigDigest {
		t.Fatalf("expected authority handoff metadata in job spec, got %#v", meta)
	}

	taskGroups, ok := job["TaskGroups"].([]any)
	if !ok || len(taskGroups) != 1 {
		t.Fatalf("expected a single task group, got %#v", job["TaskGroups"])
	}
	group, ok := taskGroups[0].(map[string]any)
	if !ok {
		t.Fatalf("expected task group map, got %#v", taskGroups[0])
	}
	tasks, ok := group["Tasks"].([]any)
	if !ok || len(tasks) != 1 {
		t.Fatalf("expected a single task, got %#v", group["Tasks"])
	}
	task, ok := tasks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected task map, got %#v", tasks[0])
	}
	config, ok := task["Config"].(map[string]any)
	if !ok {
		t.Fatalf("expected task config map, got %#v", task["Config"])
	}
	if config["network_mode"] != "bridge" {
		t.Fatalf("expected network access to select bridge mode, got %#v", config["network_mode"])
	}
	if config["command"] != executionRuntimeSupportPath {
		t.Fatalf("expected runtime support command, got %#v", config["command"])
	}
	if config["image"] != "alpine:3.20" {
		t.Fatalf("expected default runtime image, got %#v", config["image"])
	}
}

func TestBuildNomadJobSpecUsesSelectedRuntimeProfileImage(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
	}
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointURI: "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, PrepareRequest{}, true, defaultSubmitCPU, defaultSubmitMemoryMB, nil, executionRuntimeProfile{
		name:  runtimeProfileControlPlaneNormalShell,
		image: "execution-substrate/control-plane-normal-shell:test",
	})

	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	config := task["Config"].(map[string]any)
	if config["image"] != "execution-substrate/control-plane-normal-shell:test" {
		t.Fatalf("expected selected runtime profile image, got %#v", config["image"])
	}
}

func TestBuildNomadJobSpecKeepsRawSPIRESocketPathHelperPrivateAndOutOfWorkloadEnv(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                  "alpine:3.20",
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		},
	}
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointEnvKey: runtimeIdentityEndpointEnvKey,
				endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}
	env := buildRuntimeEnvironment(stage.layout, "sha256:artifact", esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	}, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{}, nil, &executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, PrepareRequest{}, true, defaultSubmitCPU, defaultSubmitMemoryMB, env, executionRuntimeProfile{
		name:  runtimeProfileDefaultStaticScript,
		image: "alpine:3.20",
	})

	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	taskEnv := task["Env"].(map[string]string)
	for key, value := range taskEnv {
		if strings.Contains(value, cfg.Execution.SPIREWorkloadAPISocketPath) {
			t.Fatalf("did not expect workload env %q to expose raw SPIRE path: %q", key, value)
		}
		if strings.Contains(value, runtimeIdentitySPIRESocketName) {
			t.Fatalf("did not expect workload env %q to expose helper-private SPIRE alias: %q", key, value)
		}
	}

	config := task["Config"].(map[string]any)
	mounts := config["mounts"].([]any)
	spireMount := mounts[3].(map[string]any)
	if spireMount["source"] != path.Dir(cfg.Execution.SPIREWorkloadAPISocketPath) {
		t.Fatalf("expected raw SPIRE source dir mount, got %#v", spireMount["source"])
	}
	if spireMount["target"] != path.Join(stage.layout.runtimeIdentity.internalDir(), runtimeIdentitySPIRESourceDir) {
		t.Fatalf("expected helper-private SPIRE mount target, got %#v", spireMount["target"])
	}
}
