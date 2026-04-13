package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agsconfig "execution-substrate/ags/config"
	arsconfig "execution-substrate/ars/config"
	egsconfig "execution-substrate/egs/config"
	egsmodel "execution-substrate/egs/model"
	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestBringupScriptUpCheckDownFullProfile(t *testing.T) {
	requireSlice0BringupCapabilities(t)
	requireSlice1RuntimeIdentityCapabilities(t)
	keepWorkspace := os.Getenv("EXECUTION_PLATFORM_KEEP_TEST_WORKSPACE") == "1"

	repoRoot := executionPlatformRepoRoot(t)
	rootDir := newExecutionWorkspaceTempDir(t, "bringup-script-")
	fixture := newTLSFixture(t)
	dockerGateway := dockerBridgeGateway(t)
	mockSPIRE := startMockWorkloadAPIServer(t, rootDir, mockWorkloadAPIServerOptions{})
	t.Cleanup(func() { mockSPIRE.stop() })
	mockVault := startMockVaultCompatServer(t, rootDir, mockVaultCompatServerOptions{
		bindAddress: "0.0.0.0",
		publicHost:  dockerGateway,
		authMount:   "jwt",
		role:        "service_execution",
		audience:    "vault",
		subject:     "spiffe://execution.internal/workload",
		secretPath:  "proof-secrets/data/runtime-identity-vault-login",
		secretValue: "runtime-identity-ok",
	})
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		rootDir,
		"bringup-operator-client",
		fixture.runtimeCA,
		fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	arsPort := reserveTCPPort(t)
	egsPort := reserveTCPPort(t)
	agsPort := reserveTCPPort(t)
	esPort := reserveTCPPort(t)
	nomadHTTPPort := reserveTCPPort(t)
	nomadRPCPort := reserveTCPPort(t)
	nomadSerfPort := reserveTCPPort(t)

	arsRootDir := filepath.Join(rootDir, "ars-storage")
	if err := os.MkdirAll(arsRootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}
	indexPath := filepath.Join(rootDir, "artifact-index.json")
	if err := os.WriteFile(indexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write artifact index: %v", err)
	}

	workloadZoneVaultBytes := mustMarshalJSON(t, runtimeconfigv1.WorkloadZoneVaultConfigBlob{
		VaultConfig: runtimeconfigv1.WorkloadZoneVaultConfig{
			Address:     "https://" + net.JoinHostPort(dockerGateway, strconv.Itoa(mockVault.port(t))),
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
			CABundlePEM: mockVault.caBundle(t),
		},
	})
	workloadZoneVaultDigest := writeBlobBytes(t, arsRootDir, workloadZoneVaultBytes)

	arsCfg := arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   arsPort,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: arsconfig.TLSConfig{
			CertFile:     fixture.arsServerCertPath,
			KeyFile:      fixture.arsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: arsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution", "operator"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   arsRootDir,
			IndexFile: indexPath,
		},
	}

	egsCfg := egsconfig.Config{
		HTTP: egsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   egsPort,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: egsconfig.TLSConfig{
			CertFile:     fixture.egsServerCertPath,
			KeyFile:      fixture.egsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: egsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Signer: egsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.egsKeyID,
			PrivateKeyHex: fixture.egsPrivateKeyHex,
			PublicKeyHex:  fixture.egsPublicKeyHex,
		},
		RuntimeTrust: egsmodel.RuntimeTrustPolicy{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
			},
		},
		Publication: egsmodel.PublicationMetadata{
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}

	agsCfg := agsconfig.Config{
		HTTP: agsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   agsPort,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: agsconfig.TLSConfig{
			CertFile:     fixture.agsServerCertPath,
			KeyFile:      fixture.agsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: agsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: agsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"operator"},
		},
		Dependencies: agsconfig.DependenciesConfig{
			ArtifactRegistry: agsconfig.DependencyConfig{
				BaseURL:        "https://127.0.0.1:" + itoa(t, arsPort),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.agsClientCertPath,
				ClientKeyFile:  fixture.agsClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		Signer: agsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.agsKeyID,
			PrivateKeyHex: fixture.agsPrivateKeyHex,
			PublicKeyHex:  fixture.agsPublicKeyHex,
		},
	}

	esCfg := esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   esPort,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: esconfig.TLSConfig{
			CertFile:     fixture.esServerCertPath,
			KeyFile:      fixture.esServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: esconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"operator"},
		},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactRegistry: esconfig.DependencyConfig{
				BaseURL:        "https://127.0.0.1:" + itoa(t, arsPort),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ExecutionGovernance: esconfig.DependencyConfig{
				BaseURL:        "https://127.0.0.1:" + itoa(t, egsPort),
				ServerName:     fixture.egsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: workloadZoneVaultDigest,
			},
		},
		Verification: esconfig.VerificationConfig{
			TrustModel: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.egsKeyID,
				PublicKeyHex: fixture.egsPublicKeyHex,
			},
			Provenance: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			DerivationAttestation: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			WorkloadIdentityBinding: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
		Nomad: esconfig.NomadConfig{
			BaseURL:        "http://127.0.0.1:" + itoa(t, nomadHTTPPort),
			Datacenter:     "dc1",
			TimeoutSeconds: 5,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             filepath.Join(rootDir, "es-stage"),
			ResultsRootDir:             filepath.Join(rootDir, "es-results"),
			BaseImage:                  "python:3.13-alpine",
			RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
			SPIREWorkloadAPISocketPath: mockSPIRE.socketPath,
		},
	}

	nomadConfigPath := filepath.Join(rootDir, "nomad.hcl")
	nomadDataDir := filepath.Join(rootDir, "nomad-data")
	if err := os.MkdirAll(nomadDataDir, 0o755); err != nil {
		t.Fatalf("mkdir nomad data dir: %v", err)
	}
	nomadConfig := []byte(strings.TrimSpace(`
data_dir = "`+nomadDataDir+`"
bind_addr = "127.0.0.1"
server {
  enabled = true
  bootstrap_expect = 1
}
client {
  enabled = true
  options = {
    "docker.cleanup.image" = "false"
    "docker.volumes.enabled" = "true"
  }
}
ports {
  http = `+itoa(t, nomadHTTPPort)+`
  rpc  = `+itoa(t, nomadRPCPort)+`
  serf = `+itoa(t, nomadSerfPort)+`
}
advertise {
  http = "127.0.0.1:`+itoa(t, nomadHTTPPort)+`"
  rpc  = "127.0.0.1:`+itoa(t, nomadRPCPort)+`"
  serf = "127.0.0.1:`+itoa(t, nomadSerfPort)+`"
}
`) + "\n")
	if err := os.WriteFile(nomadConfigPath, nomadConfig, 0o600); err != nil {
		t.Fatalf("write nomad config: %v", err)
	}

	arsConfigPath := writeJSONConfigFile(t, rootDir, "ars.json", arsCfg)
	egsConfigPath := writeJSONConfigFile(t, rootDir, "egs.json", egsCfg)
	agsConfigPath := writeJSONConfigFile(t, rootDir, "ags.json", agsCfg)
	esConfigPath := writeJSONConfigFile(t, rootDir, "es.json", esCfg)

	arsURL := "https://" + fixture.arsServerName + ":" + itoa(t, arsPort)
	egsURL := "https://" + fixture.egsServerName + ":" + itoa(t, egsPort)
	agsURL := "https://" + fixture.agsServerName + ":" + itoa(t, agsPort)
	esURL := "https://" + fixture.esServerName + ":" + itoa(t, esPort)

	bringupDir := filepath.Join(rootDir, "bringup-state")
	baseEnv := append(
		os.Environ(),
		"BRINGUP_PROFILE=full",
		"BRINGUP_DIR="+bringupDir,
		"READY_TIMEOUT_SECONDS=60",
		"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:test-"+itoa(t, nomadHTTPPort),
		"ARS_CONFIG="+arsConfigPath,
		"EGS_CONFIG="+egsConfigPath,
		"AGS_CONFIG="+agsConfigPath,
		"ES_CONFIG="+esConfigPath,
		"NOMAD_CONFIG="+nomadConfigPath,
		"ARS_URL="+arsURL,
		"EGS_URL="+egsURL,
		"AGS_URL="+agsURL,
		"ES_URL="+esURL,
		"NOMAD_ADDR=http://127.0.0.1:"+itoa(t, nomadHTTPPort),
		"ARS_RESOLVE="+fixture.arsServerName+":"+itoa(t, arsPort)+":127.0.0.1",
		"EGS_RESOLVE="+fixture.egsServerName+":"+itoa(t, egsPort)+":127.0.0.1",
		"AGS_RESOLVE="+fixture.agsServerName+":"+itoa(t, agsPort)+":127.0.0.1",
		"ES_RESOLVE="+fixture.esServerName+":"+itoa(t, esPort)+":127.0.0.1",
		"CA_CERT="+fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"ARS_READ_CERT="+fixture.executionClientCertPath,
		"ARS_READ_KEY="+fixture.executionClientKeyPath,
	)

	bringupScript := filepath.Join(repoRoot, "scripts", "01_bringup.sh")
	down := func() {
		cmd := exec.Command(bringupScript, "down")
		cmd.Dir = repoRoot
		cmd.Env = baseEnv
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bringup down failed: %v output=%s", err, string(output))
		}
	}
	if !keepWorkspace {
		t.Cleanup(down)
	} else {
		t.Logf("keeping bring-up state for inspection under %s", rootDir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upCmd := exec.CommandContext(ctx, bringupScript, "up")
	upCmd.Dir = repoRoot
	upCmd.Env = baseEnv
	upOutput, err := upCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bringup up failed: %v output=%s", err, string(upOutput))
	}
	if !strings.Contains(string(upOutput), "bring-up complete") {
		t.Fatalf("expected successful bringup output, got %s", string(upOutput))
	}
	if !strings.Contains(string(upOutput), "prepare-ready: true") || !strings.Contains(string(upOutput), "submit-ready: true") {
		t.Fatalf("expected explicit prepare-ready and submit-ready output, got %s", string(upOutput))
	}
	if !strings.Contains(string(upOutput), "nomad-startup-mode: managed-local") {
		t.Fatalf("expected managed-local nomad startup mode in bringup output, got %s", string(upOutput))
	}
	if !strings.Contains(string(upOutput), "supported-environment: bounded-fallback") {
		t.Fatalf("expected bounded-fallback supported-environment output, got %s", string(upOutput))
	}
	if !strings.Contains(string(upOutput), "submit-ready-mode:") {
		t.Fatalf("expected submit-ready mode output, got %s", string(upOutput))
	}

	checkCmd := exec.CommandContext(ctx, bringupScript, "check")
	checkCmd.Dir = repoRoot
	checkCmd.Env = baseEnv
	checkOutput, err := checkCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bringup check failed: %v output=%s", err, string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "nomad: leader=") {
		t.Fatalf("expected nomad readiness in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "prepare-ready: true") || !strings.Contains(string(checkOutput), "submit-ready: true") {
		t.Fatalf("expected explicit prepare-ready and submit-ready output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "vault_ca_bundle=present") {
		t.Fatalf("expected workload-zone Vault CA bundle readiness in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "nomad-startup-mode: managed-local") {
		t.Fatalf("expected managed-local nomad startup mode in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "supported-environment: bounded-fallback") {
		t.Fatalf("expected bounded-fallback supported-environment in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "submit-ready-mode:") {
		t.Fatalf("expected submit-ready mode output in bringup check output, got %s", string(checkOutput))
	}

	packageCmd := exec.CommandContext(
		ctx,
		filepath.Join(repoRoot, ".examples", "runtime_identity_vault_login", "package.sh"),
	)
	packageCmd.Dir = repoRoot
	packageOutput, err := packageCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("package runtime identity vault example failed: %v output=%s", err, string(packageOutput))
	}

	runtimeIdentityWorkdirBase := filepath.Join(rootDir, "execute-loop-runtime-identity")
	runtimeIdentityCmd := exec.CommandContext(
		ctx,
		filepath.Join(repoRoot, "scripts", "60_execute_loop.sh"),
		filepath.Join(repoRoot, ".examples", "execution_loop", "runtime_identity_vault_success.input.json"),
	)
	runtimeIdentityCmd.Dir = repoRoot
	runtimeIdentityCmd.Env = append(baseEnv,
		"WORKDIR_BASE="+runtimeIdentityWorkdirBase,
	)
	runtimeIdentityOutput, err := runtimeIdentityCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runtime identity execute loop failed: %v output=%s", err, string(runtimeIdentityOutput))
	}

	runtimeIdentityResult := readExecutionLoopResultFromWorkdirBase(t, runtimeIdentityWorkdirBase)
	if !runtimeIdentityResult.Summary.OK {
		t.Fatalf("expected runtime identity execution loop success, got %+v output=%s", runtimeIdentityResult.Summary, string(runtimeIdentityOutput))
	}
	if strings.TrimSpace(runtimeIdentityResult.Summary.RunID) == "" {
		t.Fatalf("expected runtime identity execution loop run_id, got %+v output=%s", runtimeIdentityResult.Summary, string(runtimeIdentityOutput))
	}
	assertNomadBindSourcesUnderStagingRoot(
		t,
		"http://127.0.0.1:"+itoa(t, nomadHTTPPort),
		runtimeIdentityResult.Summary.RunID,
		esCfg.Execution.StagingRootDir,
		esCfg.Execution.SPIREWorkloadAPISocketPath,
	)
	assertStagingInvariantProof(t, filepath.Join(bringupDir, "staging-invariant.json"), esCfg.Execution.StagingRootDir)
	for _, marker := range []string{
		"PLATFORM-ENDPOINT-USED",
		"RAW-SPIRE-DENIED",
		"IDENTITY-JWT-RECEIVED",
		"VAULT-LOGIN-SUCCESS",
		"SECRET-READ-SUCCESS:runtime-identity-ok",
	} {
		if !strings.Contains(runtimeIdentityResult.Logs, marker) {
			t.Fatalf("expected %q in runtime identity logs, got %q", marker, runtimeIdentityResult.Logs)
		}
	}
	if attempts := mockVault.loginAttempts(); attempts != 1 {
		t.Fatalf("expected exactly one mock vault login during operator-path proof, got %d", attempts)
	}
	if reads := mockVault.secretReads(); reads != 1 {
		t.Fatalf("expected exactly one mock vault secret read during operator-path proof, got %d", reads)
	}

	stopManagedBringupService(t, bringupDir, "nomad")

	failedCheckCmd := exec.CommandContext(ctx, bringupScript, "check")
	failedCheckCmd.Dir = repoRoot
	failedCheckCmd.Env = baseEnv
	failedCheckOutput, err := failedCheckCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected bringup check to fail once nomad is stopped, got output=%s", string(failedCheckOutput))
	}
	if !strings.Contains(string(failedCheckOutput), "prepare-ready: true") {
		t.Fatalf("expected prepare-ready state to remain visible during submit-readiness failure, got %s", string(failedCheckOutput))
	}
	if !strings.Contains(string(failedCheckOutput), "nomad: leader request failed") {
		t.Fatalf("expected explicit nomad submit-readiness failure, got %s", string(failedCheckOutput))
	}
}

func TestGenerateControlPlaneDockerfile(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	outputDir := newExecutionWorkspaceTempDir(t, "control-plane-dockerfile-")
	outputPath := filepath.Join(outputDir, "Dockerfile")

	cmd := exec.Command(filepath.Join(repoRoot, "scripts", "generate_control_plane_dockerfile.sh"), outputPath)
	cmd.Dir = repoRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate control-plane Dockerfile: %v output=%s", err, string(output))
	}
	if got := strings.TrimSpace(string(output)); got != outputPath {
		t.Fatalf("generator output path = %q, want %q", got, outputPath)
	}

	dockerfileBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated Dockerfile: %v", err)
	}

	dockerfile := string(dockerfileBytes)
	for _, want := range []string{
		"# Code generated by scripts/generate_control_plane_dockerfile.sh; DO NOT EDIT.",
		"COPY go.sum ./",
		"COPY cgs ./cgs",
		"CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /out/ars ./cmd/ars",
		"CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /out/cgs ./cmd/cgs",
		"CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /out/es-runtime-support ./cmd/es-runtime-support",
		"COPY --from=build /out/es /usr/local/bin/es",
		"COPY --from=build /out/es-runtime-support /usr/local/bin/es-runtime-support",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Fatalf("generated Dockerfile missing %q", want)
		}
	}
}

func TestHealthCheckScriptPrepareOnlyReportsSubmitSkipped(t *testing.T) {
	stack := startSubmitStack(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "10_health_check.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"prepare-only-health-check-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	arsHost, arsPort, err := splitHostPort(t, stack.ars.Addr())
	if err != nil {
		t.Fatalf("split ars addr: %v", err)
	}
	egsHost, egsPort, err := splitHostPort(t, stack.egs.Addr())
	if err != nil {
		t.Fatalf("split egs addr: %v", err)
	}
	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	esConfigPath := writeJSONConfigFile(t, t.TempDir(), "es-prepare-only-health.json", map[string]any{
		"runtime_config": map[string]any{
			"workload_zone_vault_config_ref": map[string]any{
				"digest": stack.workloadZoneVaultDigest,
			},
		},
	})

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"BRINGUP_PROFILE=prepare-only",
		"VERIFY_RUNTIME_CONFIG=1",
		"ES_CONFIG="+esConfigPath,
		"ARS_URL=https://"+stack.fixture.arsServerName+":"+arsPort,
		"EGS_URL=https://"+stack.fixture.egsServerName+":"+egsPort,
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ARS_RESOLVE="+stack.fixture.arsServerName+":"+arsPort+":"+arsHost,
		"EGS_RESOLVE="+stack.fixture.egsServerName+":"+egsPort+":"+egsHost,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"ARS_READ_CERT="+stack.fixture.executionClientCertPath,
		"ARS_READ_KEY="+stack.fixture.executionClientKeyPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("prepare-only health check failed: %v output=%s", err, string(output))
	}
	if !strings.Contains(string(output), "prepare-ready: true") {
		t.Fatalf("expected prepare-ready output, got %s", string(output))
	}
	if !strings.Contains(string(output), "vault_ca_bundle=absent") {
		t.Fatalf("expected absent Vault CA bundle state, got %s", string(output))
	}
	if !strings.Contains(string(output), "submit-ready: skipped (BRINGUP_PROFILE=prepare-only)") {
		t.Fatalf("expected submit-ready skip output, got %s", string(output))
	}
}

func TestRuntimeProfileImageReadinessRejectsMissingEnabledProfileImage(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-profile-image.json", map[string]any{
		"execution": map[string]any{
			"runtime_profiles": map[string]any{
				"control_plane_normal_shell": map[string]any{
					"enabled": true,
					"image":   "execution-substrate/control-plane-normal-shell:supported-local",
				},
			},
		},
	})

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeDockerPath := writeBytesFile(t, fakeBinDir, "docker", []byte("#!/bin/sh\nif [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n  printf 'missing image: %s\\n' \"$3\" >&2\n  exit 1\nfi\nprintf 'unexpected docker invocation: %s\\n' \"$*\" >&2\nexit 64\n"))
	if err := os.Chmod(fakeDockerPath, 0o755); err != nil {
		t.Fatalf("chmod fake docker: %v", err)
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_images_once "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing runtime profile image to fail, got output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "runtime profile image: missing execution-substrate/control-plane-normal-shell:supported-local") {
		t.Fatalf("expected missing runtime profile image output, got %s", text)
	}
	if !strings.Contains(text, "execution.runtime_profiles.control_plane_normal_shell.image") {
		t.Fatalf("expected config field in missing runtime profile image output, got %s", text)
	}
}

func TestRuntimeProfileImageReadinessAcceptsPresentEnabledProfileImage(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-profile-image.json", map[string]any{
		"execution": map[string]any{
			"runtime_profiles": map[string]any{
				"control_plane_normal_shell": map[string]any{
					"enabled": true,
					"image":   "execution-substrate/control-plane-normal-shell:supported-local",
				},
			},
		},
	})

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeDockerPath := writeBytesFile(t, fakeBinDir, "docker", []byte("#!/bin/sh\nif [ \"$1\" = image ] && [ \"$2\" = inspect ] && [ \"$3\" = execution-substrate/control-plane-normal-shell:supported-local ]; then\n  exit 0\nfi\nprintf 'unexpected docker invocation: %s\\n' \"$*\" >&2\nexit 64\n"))
	if err := os.Chmod(fakeDockerPath, 0o755); err != nil {
		t.Fatalf("chmod fake docker: %v", err)
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_images_once "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected present runtime profile image to pass: %v output=%s", err, string(output))
	}
	if !strings.Contains(string(output), "runtime profile image: execution-substrate/control-plane-normal-shell:supported-local present") {
		t.Fatalf("expected present runtime profile image output, got %s", string(output))
	}
}

func TestRuntimeProfileImageReadinessRequiresNomadDockerImageCleanupDisabled(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-profile-image.json", map[string]any{
		"execution": map[string]any{
			"runtime_profiles": map[string]any{
				"control_plane_normal_shell": map[string]any{
					"enabled": true,
					"image":   "execution-substrate/control-plane-normal-shell:supported-local",
				},
			},
		},
	})

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeCurlPath := writeBytesFile(t, fakeBinDir, "curl", []byte(`#!/bin/sh
printf '%s\n' '{"config":{"Client":{"Options":{"docker.volumes.enabled":"true"}}}}'
`))
	if err := os.Chmod(fakeCurlPath, 0o755); err != nil {
		t.Fatalf("chmod fake curl: %v", err)
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_image_gc_policy_once "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
		"NOMAD_ADDR=http://127.0.0.1:4646",
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing nomad docker image cleanup guardrail to fail, got output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "runtime profile image durability: missing nomad client option docker.cleanup.image=false") {
		t.Fatalf("expected missing docker cleanup guardrail output, got %s", text)
	}
	if !strings.Contains(text, "execution-substrate/control-plane-normal-shell:supported-local") {
		t.Fatalf("expected enabled runtime profile image in output, got %s", text)
	}
}

func TestRuntimeProfileImageReadinessAcceptsNomadDockerImageCleanupDisabled(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-profile-image.json", map[string]any{
		"execution": map[string]any{
			"runtime_profiles": map[string]any{
				"control_plane_normal_shell": map[string]any{
					"enabled": true,
					"image":   "execution-substrate/control-plane-normal-shell:supported-local",
				},
			},
		},
	})

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeCurlPath := writeBytesFile(t, fakeBinDir, "curl", []byte(`#!/bin/sh
printf '%s\n' '{"config":{"Client":{"Options":{"docker.cleanup.image":"false","docker.volumes.enabled":"true"}}}}'
`))
	if err := os.Chmod(fakeCurlPath, 0o755); err != nil {
		t.Fatalf("chmod fake curl: %v", err)
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_image_gc_policy_once "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
		"NOMAD_ADDR=http://127.0.0.1:4646",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected disabled nomad docker image cleanup guardrail to pass: %v output=%s", err, string(output))
	}
	if !strings.Contains(string(output), "runtime profile image durability: nomad docker.cleanup.image=false") {
		t.Fatalf("expected docker cleanup guardrail output, got %s", string(output))
	}
}

func TestWorkloadZoneVaultBlobReadinessReportsCABundleState(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()
	_, _, caPEM := createCertificateAuthority(t, "workload-zone-vault-ca")

	output, err := runWorkloadZoneVaultBlobReadinessWithFakeCurl(t, repoRoot, rootDir, string(mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{
			"address":       "https://vault.internal:8200",
			"auth_mount":    "jwt",
			"auth_role":     "service_execution",
			"jwt_audience":  "vault",
			"ca_bundle_pem": string(caPEM),
		},
	})))
	if err != nil {
		t.Fatalf("expected workload-zone Vault blob readiness to pass: %v output=%s", err, output)
	}
	if !strings.Contains(output, "vault_ca_bundle=present") {
		t.Fatalf("expected CA bundle present state, got %s", output)
	}
}

func TestWorkloadZoneVaultBlobReadinessRejectsInvalidCABundle(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := t.TempDir()

	output, err := runWorkloadZoneVaultBlobReadinessWithFakeCurl(t, repoRoot, rootDir, `{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"service_execution","jwt_audience":"vault","ca_bundle_pem":"not pem"}}`)
	if err == nil {
		t.Fatalf("expected invalid workload-zone Vault CA bundle to fail, got output=%s", output)
	}
	if !strings.Contains(output, "invalid vault_config.ca_bundle_pem") {
		t.Fatalf("expected invalid CA bundle output, got %s", output)
	}
}

func runWorkloadZoneVaultBlobReadinessWithFakeCurl(t *testing.T, repoRoot string, rootDir string, blob string) (string, error) {
	t.Helper()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-runtime-config.json", map[string]any{
		"runtime_config": map[string]any{
			"workload_zone_vault_config_ref": map[string]any{
				"digest": labeledDigest("42"),
			},
		},
	})
	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeCurlPath := writeBytesFile(t, fakeBinDir, "curl", []byte("#!/bin/sh\nprintf '%s' \"$FAKE_ARS_BLOB\"\n"))
	if err := os.Chmod(fakeCurlPath, 0o755); err != nil {
		t.Fatalf("chmod fake curl: %v", err)
	}
	for _, name := range []string{"ca.pem", "client.pem", "client.key"} {
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte("placeholder\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_workload_zone_vault_blob "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
		"ARS_URL=https://ars.internal:8443",
		"CA_CERT="+filepath.Join(rootDir, "ca.pem"),
		"ARS_READ_CERT="+filepath.Join(rootDir, "client.pem"),
		"ARS_READ_KEY="+filepath.Join(rootDir, "client.key"),
		"FAKE_ARS_BLOB="+blob,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestHealthCheckScriptRejectsPreManagedDevNomad(t *testing.T) {
	stack := startSubmitStack(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "10_health_check.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"dev-nomad-health-check-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	arsHost, arsPort, err := splitHostPort(t, stack.ars.Addr())
	if err != nil {
		t.Fatalf("split ars addr: %v", err)
	}
	egsHost, egsPort, err := splitHostPort(t, stack.egs.Addr())
	if err != nil {
		t.Fatalf("split egs addr: %v", err)
	}
	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	nomadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status/leader":
			_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
		case "/v1/agent/self":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": map[string]any{
					"DevMode":    true,
					"Datacenter": "dc1",
					"Server":     map[string]any{"Enabled": true},
					"Client":     map[string]any{"Enabled": true},
				},
			})
		case "/v1/nodes":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"ID": "node-1", "Name": "fake-dev-node", "Status": "ready"},
			})
		case "/v1/node/node-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Attributes": map[string]any{
					"cpu.totalcompute": "4000",
				},
				"Drivers": map[string]any{
					"docker": map[string]any{
						"Healthy":           true,
						"HealthDescription": "Healthy",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer nomadServer.Close()

	rootDir := t.TempDir()
	stagingRootDir := filepath.Join(rootDir, "staging")
	if err := os.MkdirAll(stagingRootDir, 0o755); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	resultsRootDir := filepath.Join(rootDir, "results")
	if err := os.MkdirAll(resultsRootDir, 0o755); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}
	runtimeSupportPath := writeBytesFile(t, rootDir, "es-runtime-support", []byte("#!/bin/sh\nexit 0\n"))
	if err := os.Chmod(runtimeSupportPath, 0o755); err != nil {
		t.Fatalf("chmod runtime support stub: %v", err)
	}
	socketRoot, err := os.MkdirTemp(socketTestRootDir(t), "dev-nomad-")
	if err != nil {
		t.Fatalf("mkdir socket root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(socketRoot)
	})
	spireSocketPath := filepath.Join(socketRoot, "spire.sock")
	spireListener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer func() {
		_ = spireListener.Close()
	}()

	esConfigPath := writeJSONConfigFile(t, rootDir, "es-full-health.json", map[string]any{
		"nomad": map[string]any{
			"base_url":   nomadServer.URL,
			"datacenter": "dc1",
		},
		"execution": map[string]any{
			"staging_root_dir":               stagingRootDir,
			"results_root_dir":               resultsRootDir,
			"base_image":                     "python:3.13-alpine",
			"runtime_support_binary":         runtimeSupportPath,
			"spire_workload_api_socket_path": spireSocketPath,
		},
	})

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	fakeDockerPath := writeBytesFile(t, fakeBinDir, "docker", []byte("#!/bin/sh\nif [ \"$1\" = info ]; then\n  exit 0\nfi\nprintf 'unexpected docker invocation: %s\\n' \"$*\" >&2\nexit 64\n"))
	if err := os.Chmod(fakeDockerPath, 0o755); err != nil {
		t.Fatalf("chmod fake docker: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"BRINGUP_PROFILE=full",
		"BRINGUP_DIR="+filepath.Join(rootDir, "bringup"),
		"VERIFY_RUNTIME_CONFIG=0",
		"ES_CONFIG="+esConfigPath,
		"ARS_URL=https://"+stack.fixture.arsServerName+":"+arsPort,
		"EGS_URL=https://"+stack.fixture.egsServerName+":"+egsPort,
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"NOMAD_ADDR="+nomadServer.URL,
		"ARS_RESOLVE="+stack.fixture.arsServerName+":"+arsPort+":"+arsHost,
		"EGS_RESOLVE="+stack.fixture.egsServerName+":"+egsPort+":"+egsHost,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected full health check to reject pre-managed dev nomad, got output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "nomad-startup-mode: pre-managed") {
		t.Fatalf("expected pre-managed nomad startup mode, got %s", text)
	}
	if !strings.Contains(text, "nomad: agent is running in -dev mode; this is unsupported for the slice-0 supported environment") {
		t.Fatalf("expected explicit dev-mode rejection, got %s", text)
	}
	if strings.Contains(text, "supported-environment: supported") {
		t.Fatalf("did not expect supported-environment output for dev nomad, got %s", text)
	}
}

func TestBringupRunbookTroubleshootingMatrixListsCurrentFailureCategories(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	runbookPath := filepath.Join(repoRoot, ".runbooks", "system", "v1_bringup.md")

	body, err := os.ReadFile(runbookPath)
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}

	text := string(body)
	requiredSnippets := []string{
		"## 5. Operator Troubleshooting Matrix",
		"caller authorization / credential failure",
		"trust / evidence / admission failure",
		"runtime-config reference or blob failure",
		"service health / readiness failure",
		"substrate failure (Docker / Nomad / runtime availability)",
		"execution failure after successful submit",
		"operator misuse / invalid input",
		"scripts/01_bringup.sh check",
		"ars.log",
		"egs.log",
		"ags.log",
		"es.log",
		"nomad.log",
		"Docker daemon logs are outside this repo",
		"execution.staging_root_dir/<run_id>",
		"if publish, prepare, or submit failed before a `run_id` existed, staging is the wrong next step",
		"scripts/70_diagnostics.sh --category auth|trust|runtime-config|readiness|substrate|execution|input",
		"scripts/70_diagnostics.sh --run-id run-0123456789abcdef",
		"scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>",
		"bundle_json=",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(text, snippet) {
			t.Fatalf("expected %q in troubleshooting matrix, got %s", snippet, text)
		}
	}
}

func TestLinuxSetupScriptDocumentsSupportedProfileGuardrails(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "70_linux_setup.sh")

	body, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read linux setup script: %v", err)
	}

	text := string(body)
	requiredSnippets := []string{
		"tries to qualify the repo's narrow supported Linux profile",
		"systemd is required for the supported Linux profile",
		"Installing supported single-node Nomad service config",
		`"docker.cleanup.image" = "false"`,
		"root-managed nomad.service",
		"ready node(s) still report cpu.totalcompute=0 under the root-managed non-dev service",
		"SMBIOS processor Current Speed is not usable on this host",
		"current login shell still needs re-login before repo scripts can call docker without sudo",
		"disables Docker image cleanup",
		"supported-substrate: not yet qualified",
		"This VM still needs manual root investigation before it matches the repo's supported profile.",
		"Supported substrate baseline: not yet qualified from this script run.",
		"do not treat this VM as supported yet",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(text, snippet) {
			t.Fatalf("expected %q in linux setup script, got %s", snippet, text)
		}
	}
}

func TestExampleNomadConfigDisablesDockerImageCleanup(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	configPath := filepath.Join(repoRoot, ".examples", "config", "nomad.hcl")

	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read example nomad config: %v", err)
	}

	text := string(body)
	for _, snippet := range []string{
		`"docker.cleanup.image" = "false"`,
		`"docker.volumes.enabled" = "true"`,
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("expected %q in example nomad config, got %s", snippet, text)
		}
	}
}

func TestLifecycleScriptObservesExecutionViaPublicRunID(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "50_lifecycle.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"lifecycle-operator-client",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"RUN_ID="+submitted.RunID,
		"WAIT_FOR_TERMINAL=1",
		"TIMEOUT_SECONDS=60",
		"POLL_INTERVAL_SECONDS=1",
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run lifecycle script: %v output=%s", err, string(output))
	}

	text := string(output)
	if !strings.Contains(text, `"terminal": true`) {
		t.Fatalf("expected terminal lifecycle output, got %s", text)
	}
	if !strings.Contains(text, "START-BANNER") {
		t.Fatalf("expected workload logs in lifecycle output, got %s", text)
	}
}

func TestDiagnosticsScriptRuntimeConfigCategoryBundleAcceptsSurfacedFailureLabel(t *testing.T) {
	stack := startSubmitStack(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "70_diagnostics.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"diagnostics-runtime-config-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	arsHost, arsPort, err := splitHostPort(t, stack.ars.Addr())
	if err != nil {
		t.Fatalf("split ars addr: %v", err)
	}
	egsHost, egsPort, err := splitHostPort(t, stack.egs.Addr())
	if err != nil {
		t.Fatalf("split egs addr: %v", err)
	}
	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	esConfigPath := writeJSONConfigFile(t, t.TempDir(), "es-runtime-config-diagnostics.json", map[string]any{
		"runtime_config": map[string]any{
			"workload_zone_vault_config_ref": map[string]any{
				"digest": labeledDigest("99"),
			},
		},
	})

	bringupDir := t.TempDir()
	logsDir := filepath.Join(bringupDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatalf("mkdir logs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "ars.log"), []byte("ARS-RUNTIME-CONFIG-LOG\n"), 0o600); err != nil {
		t.Fatalf("write ars log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "es.log"), []byte("ES-RUNTIME-CONFIG-LOG\n"), 0o600); err != nil {
		t.Fatalf("write es log: %v", err)
	}

	bundleBase := t.TempDir()
	cmd := exec.Command(scriptPath, "--category", "runtime-config reference or blob failure", "--output-dir", bundleBase)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"BRINGUP_DIR="+bringupDir,
		"ARS_URL=https://"+stack.fixture.arsServerName+":"+arsPort,
		"EGS_URL=https://"+stack.fixture.egsServerName+":"+egsPort,
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ARS_RESOLVE="+stack.fixture.arsServerName+":"+arsPort+":"+arsHost,
		"EGS_RESOLVE="+stack.fixture.egsServerName+":"+egsPort+":"+egsHost,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"ARS_READ_CERT="+stack.fixture.executionClientCertPath,
		"ARS_READ_KEY="+stack.fixture.executionClientKeyPath,
		"ES_CONFIG="+esConfigPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run diagnostics script: %v output=%s", err, string(output))
	}

	bundleDir := diagnosticsBundleDirFromOutput(t, string(output))
	bundleJSONPath := diagnosticsBundleJSONPathFromOutput(t, string(output))
	bundle := readDiagnosticsBundleJSON(t, bundleDir)
	if bundle.CategoryKey != "runtime-config" || bundle.BundleStatus != "partial" {
		t.Fatalf("expected runtime-config partial bundle, got %+v", bundle)
	}
	assertDiagnosticsBundleComponent(t, bundle, "check:runtime-config-health", "failed", "critical")
	assertDiagnosticsBundleComponent(t, bundle, "check:runtime-config-ref", "collected", "critical")
	assertDiagnosticsBundleComponent(t, bundle, "log:ars", "collected", "optional")
	assertDiagnosticsBundleComponent(t, bundle, "log:es", "collected", "optional")
	if got := filepath.Join(bundleDir, "bundle.json"); bundleJSONPath != got {
		t.Fatalf("expected bundle_json path %s, got %s", got, bundleJSONPath)
	}
	runtimeCheck := readDiagnosticsBundleFile(t, bundleDir, "checks/runtime-config-health-check.txt")
	if !strings.Contains(runtimeCheck, "workload-zone vault blob read failed") {
		t.Fatalf("expected runtime-config failure in diagnostics bundle, got %s", runtimeCheck)
	}
	runtimeRef := readDiagnosticsBundleFile(t, bundleDir, "checks/runtime-config-ref.txt")
	if !strings.Contains(runtimeRef, labeledDigest("99")) {
		t.Fatalf("expected runtime-config digest in diagnostics bundle, got %s", runtimeRef)
	}
	if !strings.Contains(readDiagnosticsBundleFile(t, bundleDir, "logs/ars.log"), "ARS-RUNTIME-CONFIG-LOG") {
		t.Fatalf("expected copied ars log in diagnostics bundle")
	}
	if !strings.Contains(readDiagnosticsBundleFile(t, bundleDir, "logs/es.log"), "ES-RUNTIME-CONFIG-LOG") {
		t.Fatalf("expected copied es log in diagnostics bundle")
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "run", "staging-summary.txt")); !os.IsNotExist(err) {
		t.Fatalf("did not expect staging diagnostics for runtime-config bundle, err=%v", err)
	}
}

func TestDiagnosticsScriptRunIDBundleCollectsLifecycleSignalsAndStaging(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo FAIL-BANNER
echo "{\"status\":\"fail\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
exit 7
`))
	submitted := submitExecution(t, stack, 10, 128)
	stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "70_diagnostics.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"diagnostics-run-id-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	esConfigPath := writeJSONConfigFile(t, t.TempDir(), "es-run-diagnostics.json", map[string]any{
		"execution": map[string]any{
			"staging_root_dir": filepath.Join(stack.rootDir, "es-stage"),
			"results_root_dir": filepath.Join(stack.rootDir, "es-results"),
		},
	})

	bundleBase := t.TempDir()
	cmd := exec.Command(scriptPath, "--run-id", submitted.RunID, "--output-dir", bundleBase)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"ES_CONFIG="+esConfigPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run diagnostics script: %v output=%s", err, string(output))
	}

	bundleDir := diagnosticsBundleDirFromOutput(t, string(output))
	bundleJSONPath := diagnosticsBundleJSONPathFromOutput(t, string(output))
	bundle := readDiagnosticsBundleJSON(t, bundleDir)
	if bundle.RunID != submitted.RunID || bundle.BundleStatus != "complete" {
		t.Fatalf("expected complete run_id bundle, got %+v", bundle)
	}
	assertDiagnosticsBundleComponent(t, bundle, "run:status", "collected", "critical")
	assertDiagnosticsBundleComponent(t, bundle, "run:logs", "collected", "critical")
	assertDiagnosticsBundleComponent(t, bundle, "run:staging", "collected", "optional")
	if got := filepath.Join(bundleDir, "bundle.json"); bundleJSONPath != got {
		t.Fatalf("expected bundle_json path %s, got %s", got, bundleJSONPath)
	}
	var statusBody struct {
		RunID    string `json:"run_id"`
		ExitCode *int   `json:"exit_code"`
	}
	readJSONFile(t, filepath.Join(bundleDir, "run", "status.json"), &statusBody)
	if statusBody.RunID != submitted.RunID || statusBody.ExitCode == nil || *statusBody.ExitCode != 7 {
		t.Fatalf("expected status bundle to carry run_id and exit_code, got %+v", statusBody)
	}
	logsBody := readDiagnosticsBundleFile(t, bundleDir, "run/logs.txt")
	if !strings.Contains(logsBody, "FAIL-BANNER") {
		t.Fatalf("expected run logs in diagnostics bundle, got %s", logsBody)
	}
	stagingSummary := readDiagnosticsBundleFile(t, bundleDir, "run/staging-summary.txt")
	if !strings.Contains(stagingSummary, "exists=true") {
		t.Fatalf("expected retained staging in diagnostics bundle, got %s", stagingSummary)
	}
	stagingTree := readDiagnosticsBundleFile(t, bundleDir, "run/staging-tree.txt")
	if !strings.Contains(stagingTree, submitted.RunID) {
		t.Fatalf("expected staging tree for run_id in diagnostics bundle, got %s", stagingTree)
	}
}

func TestDiagnosticsSummaryScriptPrintsCompactBundleSummary(t *testing.T) {
	stack := startSubmitStack(t)

	repoRoot := executionPlatformRepoRoot(t)
	collectorPath := filepath.Join(repoRoot, "scripts", "70_diagnostics.sh")
	summaryPath := filepath.Join(repoRoot, "scripts", "71_diagnostics_summary.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"diagnostics-summary-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	arsHost, arsPort, err := splitHostPort(t, stack.ars.Addr())
	if err != nil {
		t.Fatalf("split ars addr: %v", err)
	}
	egsHost, egsPort, err := splitHostPort(t, stack.egs.Addr())
	if err != nil {
		t.Fatalf("split egs addr: %v", err)
	}
	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	esConfigPath := writeJSONConfigFile(t, t.TempDir(), "es-summary-runtime-config.json", map[string]any{
		"runtime_config": map[string]any{
			"workload_zone_vault_config_ref": map[string]any{
				"digest": labeledDigest("77"),
			},
		},
	})

	bringupDir := t.TempDir()
	logsDir := filepath.Join(bringupDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatalf("mkdir logs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "ars.log"), []byte("ARS-SUMMARY-LOG\n"), 0o600); err != nil {
		t.Fatalf("write ars log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "es.log"), []byte("ES-SUMMARY-LOG\n"), 0o600); err != nil {
		t.Fatalf("write es log: %v", err)
	}

	bundleBase := t.TempDir()
	collectCmd := exec.Command(collectorPath, "--category", "runtime-config", "--output-dir", bundleBase)
	collectCmd.Dir = repoRoot
	collectCmd.Env = append(os.Environ(),
		"BRINGUP_DIR="+bringupDir,
		"ARS_URL=https://"+stack.fixture.arsServerName+":"+arsPort,
		"EGS_URL=https://"+stack.fixture.egsServerName+":"+egsPort,
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ARS_RESOLVE="+stack.fixture.arsServerName+":"+arsPort+":"+arsHost,
		"EGS_RESOLVE="+stack.fixture.egsServerName+":"+egsPort+":"+egsHost,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"ARS_READ_CERT="+stack.fixture.executionClientCertPath,
		"ARS_READ_KEY="+stack.fixture.executionClientKeyPath,
		"ES_CONFIG="+esConfigPath,
	)

	collectOutput, err := collectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run diagnostics collector: %v output=%s", err, string(collectOutput))
	}

	bundleJSONPath := diagnosticsBundleJSONPathFromOutput(t, string(collectOutput))
	summaryCmd := exec.Command(summaryPath, bundleJSONPath)
	summaryCmd.Dir = repoRoot

	summaryOutput, err := summaryCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run diagnostics summary: %v output=%s", err, string(summaryOutput))
	}

	text := string(summaryOutput)
	if !strings.Contains(text, "Diagnostics bundle summary") {
		t.Fatalf("expected summary heading, got %s", text)
	}
	if !strings.Contains(text, "bundle_status=partial") {
		t.Fatalf("expected partial bundle status, got %s", text)
	}
	if !strings.Contains(text, "category=runtime-config reference or blob failure") {
		t.Fatalf("expected runtime-config category, got %s", text)
	}
	if !strings.Contains(text, "Critical items needing attention:") {
		t.Fatalf("expected critical items section, got %s", text)
	}
	if !strings.Contains(text, "check:runtime-config-health [failed]") {
		t.Fatalf("expected failed runtime-config health check, got %s", text)
	}
	if !strings.Contains(text, "Collected signals:") {
		t.Fatalf("expected collected signals section, got %s", text)
	}
}

func TestPublishScriptCategorizesAuthorizationFailure(t *testing.T) {
	stack := startSubmitStack(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "20_publish.sh")
	publishJSONPath := writeBytesFile(t, t.TempDir(), "publish.json", mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(buildStaticScriptArchive(t)),
		"artifact": map[string]any{
			"artifact_type": "static-script",
			"intent_digest": stack.intentDigest,
		},
		"publication": map[string]any{
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ff"),
		},
		"admission": map[string]any{
			"runtime": map[string]any{
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
			"access": map[string]any{
				"network_access": false,
			},
			"derivation": map[string]any{
				"derivation_spec_digest": stack.derivationSpecDigest,
				"output_id":              stack.outputID,
			},
			"workload": map[string]any{
				"target_platform": "docker",
			},
		},
	}))

	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+stack.fixture.executionClientCertPath,
		"OPERATOR_KEY="+stack.fixture.executionClientKeyPath,
		"PUBLISH_JSON="+publishJSONPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected publish script to fail, output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "failure category: caller authorization / credential failure") {
		t.Fatalf("expected authorization failure category, got %s", text)
	}
	if !strings.Contains(text, "Caller not authorized for this operation") {
		t.Fatalf("expected caller authorization message, got %s", text)
	}
	if !strings.Contains(text, ".runbooks/system/v1_bringup.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --category auth") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func TestPrepareScriptCategorizesRuntimeConfigFailure(t *testing.T) {
	stack := startStack(t, stackOptions{MissingVaultBlob: true})

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "30_prepare.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"prepare-runtime-config-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	prepareJSONPath := writeBytesFile(t, t.TempDir(), "prepare.json", buildPrepareRequestBody(t, stack))

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"PREPARE_JSON="+prepareJSONPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected prepare script to fail, output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "failure category: runtime-config reference or blob failure") {
		t.Fatalf("expected runtime-config failure category, got %s", text)
	}
	if !strings.Contains(text, "service code: workload_zone_vault_unavailable") {
		t.Fatalf("expected workload-zone vault error code, got %s", text)
	}
	if !strings.Contains(text, ".runbooks/system/v1_bringup.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --category runtime-config") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func TestSubmitScriptCategorizesSubstrateFailure(t *testing.T) {
	stack := startSubmitStack(t)
	stack.nomad.shutdown(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "40_submit.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"submit-substrate-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	submitJSONPath := writeBytesFile(t, t.TempDir(), "submit.json", buildSubmitRequestBody(t, stack))

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
		"SUBMIT_JSON="+submitJSONPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected submit script to fail, output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "failure category: substrate failure (Docker / Nomad / runtime availability)") {
		t.Fatalf("expected substrate failure category, got %s", text)
	}
	if !strings.Contains(text, "service code: execution_runtime_unavailable") && !strings.Contains(text, "service code: submission_failed") {
		t.Fatalf("expected runtime availability or submission failure code, got %s", text)
	}
	if !strings.Contains(text, ".runbooks/system/v1_bringup.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --category substrate") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func TestLifecycleScriptCategorizesExecutionFailure(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo FAIL-BANNER
echo "{\"status\":\"fail\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
exit 7
`))
	submitted := submitExecution(t, stack, 10, 128)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "50_lifecycle.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"lifecycle-failure-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator")},
	)

	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"RUN_ID="+submitted.RunID,
		"WAIT_FOR_TERMINAL=1",
		"TIMEOUT_SECONDS=60",
		"POLL_INTERVAL_SECONDS=1",
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected lifecycle script to fail for unsuccessful execution, output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "failure category: execution failure after successful submit") {
		t.Fatalf("expected execution failure category, got %s", text)
	}
	if !strings.Contains(text, "exit_code=7") {
		t.Fatalf("expected exit code guidance in lifecycle output, got %s", text)
	}
	if !strings.Contains(text, ".runbooks/system/v1_bringup.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --run-id <run_id>") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func writeJSONConfigFile(t *testing.T, dir string, name string, value any) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, mustMarshalJSON(t, value), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func writeBytesFile(t *testing.T, dir string, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func splitHostPort(t *testing.T, addr string) (string, string, error) {
	t.Helper()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func itoa(t *testing.T, value int) string {
	t.Helper()
	return strconv.Itoa(value)
}

func requireSlice0BringupCapabilities(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("slice 0 bringup requires docker: %v", err)
	}
	if _, err := exec.LookPath("nomad"); err != nil {
		t.Skipf("slice 0 bringup requires nomad: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("slice 0 bringup requires a reachable docker daemon: %v output=%s", err, string(output))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("slice 0 bringup requires a host loopback listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("slice0-host-loopback-ok\n"))
		}),
	}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	address := "http://" + listener.Addr().String()
	output, err := exec.Command("docker", "run", "--rm", "--network", "host", "alpine:3.20", "wget", "-q", "-O", "-", address).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "slice0-host-loopback-ok") {
		t.Skipf("slice 0 bringup requires Docker host networking that preserves host loopback; err=%v output=%s", err, string(output))
	}
}

func executionLoopRunIDFromOutput(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "execution: success run_id=") {
			pieces := strings.Split(line, "run_id=")
			if len(pieces) < 2 {
				continue
			}
			return strings.Fields(pieces[1])[0]
		}
	}
	t.Fatalf("expected execute-loop run_id in output, got %s", output)
	return ""
}

func readExecutionLoopResultFromWorkdirBase(t *testing.T, workdirBase string) executionLoopResult {
	t.Helper()

	subdirs, err := os.ReadDir(workdirBase)
	if err != nil {
		t.Fatalf("read execution loop workdir base: %v", err)
	}
	if len(subdirs) != 1 {
		t.Fatalf("expected exactly one execution loop workdir in %s, found %d", workdirBase, len(subdirs))
	}

	workdir := filepath.Join(workdirBase, subdirs[0].Name())
	summaryPath := filepath.Join(workdir, "summary.json")
	logsPath := filepath.Join(workdir, "logs.txt")

	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read execution loop summary: %v", err)
	}
	var summary executionLoopSummary
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode execution loop summary: %v body=%s", err, string(summaryBytes))
	}

	logsBytes, err := os.ReadFile(logsPath)
	if err != nil {
		t.Fatalf("read execution loop logs: %v", err)
	}

	return executionLoopResult{
		Summary: summary,
		Logs:    string(logsBytes),
	}
}

func assertNomadBindSourcesUnderStagingRoot(t *testing.T, nomadAddr string, runID string, stagingRoot string, allowedExternalSources ...string) {
	t.Helper()

	cmd := exec.Command("nomad", "job", "inspect", "-json", "exec-"+runID)
	cmd.Env = append(os.Environ(), "NOMAD_ADDR="+nomadAddr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect nomad job: %v output=%s", err, string(output))
	}

	var job struct {
		TaskGroups []struct {
			Tasks []struct {
				Config map[string]any `json:"Config"`
			} `json:"Tasks"`
		} `json:"TaskGroups"`
	}
	if err := json.Unmarshal(output, &job); err != nil {
		t.Fatalf("decode nomad job: %v", err)
	}
	if len(job.TaskGroups) == 0 || len(job.TaskGroups[0].Tasks) == 0 {
		t.Fatalf("expected task groups in nomad job, got %s", string(output))
	}

	mounts, ok := job.TaskGroups[0].Tasks[0].Config["mounts"].([]any)
	if !ok || len(mounts) == 0 {
		t.Fatalf("expected docker mounts in nomad job config, got %s", string(output))
	}

	expectedPrefix := filepath.Join(stagingRoot, runID)
	bindCount := 0
	allowedExternal := make(map[string]struct{}, len(allowedExternalSources))
	for _, source := range allowedExternalSources {
		trimmed := strings.TrimSpace(source)
		if trimmed == "" {
			continue
		}
		allowedExternal[filepath.Clean(trimmed)] = struct{}{}
	}
	seenExternal := make(map[string]struct{}, len(allowedExternal))
	for _, raw := range mounts {
		mount, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if mount["type"] != "bind" {
			continue
		}
		source, _ := mount["source"].(string)
		if source == "" {
			t.Fatalf("expected bind mount source in nomad job, got %v", mount)
		}
		cleanSource := filepath.Clean(source)
		if !strings.HasPrefix(cleanSource, expectedPrefix) {
			if _, ok := allowedExternal[cleanSource]; ok {
				seenExternal[cleanSource] = struct{}{}
				continue
			}
			t.Fatalf("expected bind mount source under %s, got %s", expectedPrefix, source)
		}
		bindCount++
	}
	if bindCount < 2 {
		t.Fatalf("expected staged payload/run bind mounts under %s, got %d", expectedPrefix, bindCount)
	}
	for _, source := range allowedExternalSources {
		trimmed := strings.TrimSpace(source)
		if trimmed == "" {
			continue
		}
		cleanSource := filepath.Clean(trimmed)
		if _, ok := seenExternal[cleanSource]; !ok {
			t.Fatalf("expected allowed external bind mount source %s in nomad job", cleanSource)
		}
	}
}

func assertStagingInvariantProof(t *testing.T, proofPath string, stagingRoot string) {
	t.Helper()

	var payload struct {
		HostStagingPath      string `json:"host_staging_path"`
		ESContainerMountPath string `json:"es_container_mount_path"`
		PathTranslation      bool   `json:"path_translation"`
	}
	data, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read staging invariant proof: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode staging invariant proof: %v", err)
	}
	if payload.HostStagingPath != stagingRoot || payload.ESContainerMountPath != stagingRoot {
		t.Fatalf("expected same-path staging proof for %s, got %+v", stagingRoot, payload)
	}
	if payload.PathTranslation {
		t.Fatalf("expected staging invariant to forbid path translation, got %+v", payload)
	}
}

func stopManagedBringupService(t *testing.T, bringupDir string, service string) {
	t.Helper()

	pidBytes, err := os.ReadFile(filepath.Join(bringupDir, "pids", service+".pid"))
	if err != nil {
		t.Fatalf("read %s pid: %v", service, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("parse %s pid: %v", service, err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatalf("stop %s pid %d: %v", service, pid, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s pid %d did not stop", service, pid)
}

func diagnosticsBundleDirFromOutput(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "bundle_dir=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "bundle_dir="))
		}
	}
	t.Fatalf("expected bundle_dir in output, got %s", output)
	return ""
}

func diagnosticsBundleJSONPathFromOutput(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "bundle_json=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "bundle_json="))
		}
	}
	t.Fatalf("expected bundle_json in output, got %s", output)
	return ""
}

func readDiagnosticsBundleFile(t *testing.T, bundleDir string, rel string) string {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(bundleDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read diagnostics bundle file %s: %v", rel, err)
	}
	return string(body)
}

type diagnosticsBundle struct {
	Category              string                       `json:"category"`
	CategoryKey           string                       `json:"category_key"`
	RunID                 string                       `json:"run_id"`
	BundleStatus          string                       `json:"bundle_status"`
	BundleDir             string                       `json:"bundle_dir"`
	TroubleshootingMatrix string                       `json:"troubleshooting_matrix"`
	SummaryPath           string                       `json:"summary_path"`
	Components            []diagnosticsBundleComponent `json:"components"`
}

type diagnosticsBundleComponent struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Criticality string `json:"criticality"`
	Detail      string `json:"detail"`
}

func readDiagnosticsBundleJSON(t *testing.T, bundleDir string) diagnosticsBundle {
	t.Helper()

	var bundle diagnosticsBundle
	readJSONFile(t, filepath.Join(bundleDir, "bundle.json"), &bundle)
	return bundle
}

func assertDiagnosticsBundleComponent(t *testing.T, bundle diagnosticsBundle, name string, status string, criticality string) diagnosticsBundleComponent {
	t.Helper()

	for _, component := range bundle.Components {
		if component.Name != name {
			continue
		}
		if component.Status != status || component.Criticality != criticality {
			t.Fatalf("expected component %s to be %s/%s, got %+v", name, status, criticality, component)
		}
		return component
	}
	t.Fatalf("expected component %s in %+v", name, bundle.Components)
	return diagnosticsBundleComponent{}
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json file %s: %v", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode json file %s: %v body=%s", path, err, string(body))
	}
}
