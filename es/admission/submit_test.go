package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
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
		t.Fatal("runtime environment invocation env mismatch")
	}
	if env["EXEC_RUN_ID"] != layout.runID {
		t.Fatal("runtime environment run id mismatch")
	}
	if env[runtimeIdentityEndpointEnvKey] != layout.runtimeIdentity.endpointURI {
		t.Fatal("runtime environment identity endpoint mismatch")
	}
	if env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) {
		t.Fatal("runtime environment workload vault auth mode mismatch")
	}
	if env["VAULT_ADDR"] != "https://vault.internal:8200" {
		t.Fatal("runtime environment vault address mismatch")
	}
	if env[platformStateOwnerUIDEnvKey] != fmt.Sprintf("%d", os.Getuid()) {
		t.Fatal("runtime environment platform state owner uid mismatch")
	}
	if env[platformStateOwnerGIDEnvKey] != fmt.Sprintf("%d", os.Getgid()) {
		t.Fatal("runtime environment platform state owner gid mismatch")
	}
	if env[platformStateOwnerSchemaEnvKey] != platformStateOwnerSchemaV1 {
		t.Fatal("runtime environment platform state owner schema mismatch")
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
		t.Fatal("runtime environment vault CA path mismatch")
	}
	if env["SSL_CERT_FILE"] != "/execution/run/platform/workload-ca-bundle.pem" {
		t.Fatal("runtime environment TLS bundle path mismatch")
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
		t.Fatal("runtime environment Codex CLI metadata mismatch")
	}
	if env["EXEC_CODEX_CREDENTIAL_SOURCE"] != "workload_vault" {
		t.Fatal("runtime environment Codex credential source mismatch")
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"] != "proof-secrets/data/codex-runtime-profile" {
		t.Fatal("runtime environment Codex credential secret path mismatch")
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"] != "api_key" {
		t.Fatal("runtime environment Codex credential secret field mismatch")
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

	plan := resolvedNomadJobSpecTestPlan()
	plan.command.workloadArgv = []string{"--flag"}
	plan.command.timeoutSeconds = 17
	plan.timeout.seconds = 17
	plan.network = resolvedNetworkPostureBridge
	plan.resources.cpu = defaultSubmitCPU
	plan.resources.memoryMB = defaultSubmitMemoryMB
	plan.profile.name = runtimeProfileDefaultStaticScript
	plan.profile.selectedImage = "alpine:3.20"
	plan.authority.workloadZoneVaultConfigDigest = testWorkloadZoneVaultConfigDigest

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, plan, map[string]string{"EXEC_RUN_ID": "run-0123456789abcdef"})

	job, ok := jobSpec["Job"].(map[string]any)
	if !ok {
		t.Fatal("Nomad job top-level type mismatch")
	}
	meta, ok := job["Meta"].(map[string]any)
	if !ok || meta["run_id"] != "run-0123456789abcdef" {
		t.Fatal("Nomad job run metadata mismatch")
	}
	if meta[executionAuthorityMetadataSchemaKey] != executionAuthorityMetadataSchemaVersion ||
		meta[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileDefaultStaticScript ||
		meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey] != testWorkloadZoneVaultConfigDigest {
		t.Fatal("Nomad job authority metadata mismatch")
	}

	taskGroups, ok := job["TaskGroups"].([]any)
	if !ok || len(taskGroups) != 1 {
		t.Fatalf("Nomad job task group count mismatch: got %d want 1", len(taskGroups))
	}
	group, ok := taskGroups[0].(map[string]any)
	if !ok {
		t.Fatal("Nomad job task group type mismatch")
	}
	tasks, ok := group["Tasks"].([]any)
	if !ok || len(tasks) != 1 {
		t.Fatalf("Nomad job task count mismatch: got %d want 1", len(tasks))
	}
	task, ok := tasks[0].(map[string]any)
	if !ok {
		t.Fatal("Nomad job task type mismatch")
	}
	config, ok := task["Config"].(map[string]any)
	if !ok {
		t.Fatal("Nomad job task config type mismatch")
	}
	if config["network_mode"] != "bridge" {
		t.Fatal("Nomad job network mode mismatch")
	}
	if config["command"] != executionRuntimeSupportPath {
		t.Fatal("Nomad job runtime support command mismatch")
	}
	if config["image"] != "alpine:3.20" {
		t.Fatal("Nomad job default runtime image mismatch")
	}
	args := config["args"].([]string)
	if len(args) != 13 || args[0] != executionRuntimeSupervisorOperation ||
		args[1] != "--payload-archive" || args[2] != "/execution/staged/artifact.tar.gz" ||
		args[3] != "--work-dir" || args[4] != "/execution/run/work" ||
		args[5] != "--result-dir" || args[6] != "/execution/run/result" ||
		args[7] != "--entrypoint" || args[8] != "/execution/run/work/entrypoint" ||
		args[9] != "--timeout-seconds" || args[10] != "17" ||
		args[11] != "--" || args[12] != "--flag" {
		t.Fatalf("Nomad job default supervisor args mismatch: got count %d want 13", len(args))
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

	plan := resolvedNomadJobSpecTestPlan()
	plan.profile.name = runtimeProfileControlPlaneNormalShell
	plan.profile.selectedImage = "execution-substrate/control-plane-normal-shell:test"
	plan.network = resolvedNetworkPostureBridge

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, plan, nil)

	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	config := task["Config"].(map[string]any)
	if config["image"] != "execution-substrate/control-plane-normal-shell:test" {
		t.Fatal("Nomad job selected runtime profile image mismatch")
	}
}

func TestBuildNomadJobSpecConsumesPlanCommandIdentity(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
	}
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
		},
	}

	plan := resolvedNomadJobSpecTestPlan()
	plan.command.runtimeSupportCommandIdentity = "/execution/run/platform/test-runtime-support"
	plan.command.supervisorOperationIdentity = "test-supervisor"
	plan.command.timeoutSeconds = 17
	plan.command.workloadArgv = []string{"--flag"}

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, plan, nil)
	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	config := task["Config"].(map[string]any)

	if config["command"] != "/execution/run/platform/test-runtime-support" {
		t.Fatal("Nomad job did not consume plan runtime-support command identity")
	}
	args := config["args"].([]string)
	if len(args) != 13 ||
		args[0] != "test-supervisor" ||
		args[1] != "--payload-archive" ||
		args[2] != "/execution/staged/artifact.tar.gz" ||
		args[3] != "--work-dir" ||
		args[4] != "/execution/run/work" ||
		args[5] != "--result-dir" ||
		args[6] != "/execution/run/result" ||
		args[7] != "--entrypoint" ||
		args[8] != "/execution/run/work/entrypoint" ||
		args[9] != "--timeout-seconds" ||
		args[10] != "17" ||
		args[11] != "--" ||
		args[12] != "--flag" {
		t.Fatalf("Nomad job did not consume plan supervisor operation: got count %d want 13", len(args))
	}
}

func TestSubmitPreservesExactAdmittedDerivationAndOutputMetadata(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync

	exactDerivation := " \t" + fixture.evidence.Claims.Admission.Authorization.Derivation.DerivationSpecDigest + "  "
	exactOutput := "\t" + fixture.evidence.Claims.Admission.Authorization.Derivation.OutputID + "  "
	request.Invocation.DerivationSpecDigest = exactDerivation
	request.Invocation.OutputID = exactOutput

	evidence := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Authorization.Derivation.DerivationSpecDigest = exactDerivation
		record.Claims.Admission.Authorization.Derivation.OutputID = exactOutput
	})
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal("marshal whitespace identity evidence failed")
	}
	discovery := fixture.discovery
	discovery.Evidence.Digest = digestBytes(evidenceBytes)
	discovery.Payload.Digest = evidence.Claims.Package.Identity.PayloadDigest
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/artifacts/" + discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, discovery)
		case "/v1/blobs/" + discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("unexpected ARS path during whitespace metadata test")
		}
	}))

	prepared, admissionErr := service.prepareAdmission(context.Background(), request)
	if admissionErr != nil {
		t.Fatal("whitespace identity admission failed")
	}
	plan, planErr := service.resolveCurrentSubmitExecutionPlan(prepared)
	if planErr != nil {
		t.Fatal("whitespace identity plan resolution failed")
	}
	if plan.derivation.derivationSpecDigest != exactDerivation {
		t.Fatal("resolved plan derivation identity did not preserve exact admitted value")
	}
	if plan.output.outputID != exactOutput {
		t.Fatal("resolved plan output identity did not preserve exact admitted value")
	}

	var submitted map[string]any
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatal("unexpected Nomad request during whitespace metadata test")
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal("read Nomad request body failed")
		}
		if err := json.Unmarshal(body, &submitted); err != nil {
			t.Fatal("decode Nomad request body failed")
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if submitErr != nil {
		t.Fatal("whitespace identity submit failed")
	}
	if !result.Success || !result.Submitted {
		t.Fatal("whitespace identity submit result mismatch")
	}
	job := submitted["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	taskMeta := task["Meta"].(map[string]any)
	if taskMeta["derivation_spec_digest"] != exactDerivation {
		t.Fatal("Nomad task metadata derivation identity did not preserve exact admitted value")
	}
	if taskMeta["output_id"] != exactOutput {
		t.Fatal("Nomad task metadata output identity did not preserve exact admitted value")
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

	plan := resolvedNomadJobSpecTestPlan()
	plan.profile.name = runtimeProfileDefaultStaticScript
	plan.profile.selectedImage = "alpine:3.20"
	plan.network = resolvedNetworkPostureBridge

	jobSpec := buildNomadJobSpec(cfg, "exec-run-0123456789abcdef", "run-0123456789abcdef", stage, plan, env)

	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	taskEnv := task["Env"].(map[string]string)
	for _, value := range taskEnv {
		if strings.Contains(value, cfg.Execution.SPIREWorkloadAPISocketPath) {
			t.Fatal("runtime environment exposed raw SPIRE path")
		}
		if strings.Contains(value, runtimeIdentitySPIRESocketName) {
			t.Fatal("runtime environment exposed helper-private SPIRE alias")
		}
	}

	config := task["Config"].(map[string]any)
	mounts := config["mounts"].([]any)
	spireMount := mounts[3].(map[string]any)
	if spireMount["source"] != path.Dir(cfg.Execution.SPIREWorkloadAPISocketPath) {
		t.Fatal("Nomad job raw SPIRE source mount mismatch")
	}
	if spireMount["target"] != path.Join(stage.layout.runtimeIdentity.internalDir(), runtimeIdentitySPIRESourceDir) {
		t.Fatal("Nomad job helper-private SPIRE mount target mismatch")
	}
}

func resolvedNomadJobSpecTestPlan() resolvedExecutionPlan {
	return resolvedExecutionPlan{
		resources: resolvedResourcePlan{
			cpu:      defaultSubmitCPU,
			memoryMB: defaultSubmitMemoryMB,
		},
		profile: resolvedRuntimeProfilePlan{
			name:          runtimeProfileDefaultStaticScript,
			selectedImage: "alpine:3.20",
		},
		artifact: resolvedArtifactIdentityPlan{
			artifactDigest: "sha256:artifact",
		},
		derivation: resolvedDerivationIdentityPlan{
			derivationSpecDigest: "sha256:derivation",
		},
		output: resolvedOutputIdentityPlan{
			outputID: "runtime",
		},
		command: resolvedCommandPlan{
			runtimeSupportCommandIdentity: resolvedRuntimeSupportCommandIdentity,
			supervisorOperationIdentity:   resolvedSupervisorOperationIdentity,
		},
		authority: resolvedAuthorityHandoffPlan{
			applicable:                    true,
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
		},
	}
}
