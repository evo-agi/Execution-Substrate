package admission

import (
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
	}, map[string]string{
		"USER_DEFINED": "1",
	})

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
	}, true, defaultSubmitCPU, defaultSubmitMemoryMB, map[string]string{"EXEC_RUN_ID": "run-0123456789abcdef"})

	job, ok := jobSpec["Job"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level Nomad Job map, got %#v", jobSpec["Job"])
	}
	meta, ok := job["Meta"].(map[string]any)
	if !ok || meta["run_id"] != "run-0123456789abcdef" {
		t.Fatalf("expected run_id metadata in job spec, got %#v", job["Meta"])
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
}
