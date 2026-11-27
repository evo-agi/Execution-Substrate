package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	egscontract "execution-substrate/egs/contract"
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
			AllowedSPIFFEPathPrefixes: []string{"service/execution", "operator/local"},
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
		RuntimeTrust: egscontract.RuntimeTrustPolicy{
			SignerPolicy: egscontract.SignerPolicy{
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egscontract.ArtifactPolicy{
				RevokedArtifacts: []string{},
			},
		},
		Publication: egscontract.PublicationMetadata{
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
			AllowedSPIFFEPathPrefixes: []string{"operator/local"},
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

	// Bring-up starts this Nomad from NOMAD_CONFIG, with the TLS material
	// the setup script's issuer writes.
	nomadTLS, err := issueNomadTLSMaterial(filepath.Join(rootDir, "nomad-tls"))
	if err != nil {
		t.Fatal(err)
	}
	nomadAddr := "https://127.0.0.1:" + itoa(t, nomadHTTPPort)

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
			AllowedSPIFFEPathPrefixes: []string{"operator/local"},
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
		// Bring-up writes the token after it starts Nomad and before ES.
		Nomad: nomadTLS.esNomadConfig(nomadAddr, filepath.Join(rootDir, "nomad-es-token", "es-token")),
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             filepath.Join(rootDir, "es-stage"),
			ResultsRootDir:             filepath.Join(rootDir, "es-results"),
			BaseImage:                  "python:3.13-alpine",
			RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
			SPIREWorkloadAPISocketPath: mockSPIRE.socketPath,
			RetainedResultAuth:         newSubmitStackSyntheticRetainedResultAuth(t, rootDir),
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
acl {
  enabled = true
}
server {
  enabled = true
  bootstrap_expect = 1
}
client {
  enabled = true
`+supportedNomadClientNetworkInterface+`
`+supportedNomadClientOptions+`
}
`+supportedNomadDockerPluginBlock+`ports {
  http = `+itoa(t, nomadHTTPPort)+`
  rpc  = `+itoa(t, nomadRPCPort)+`
  serf = `+itoa(t, nomadSerfPort)+`
}
advertise {
  http = "127.0.0.1:`+itoa(t, nomadHTTPPort)+`"
  rpc  = "127.0.0.1:`+itoa(t, nomadRPCPort)+`"
  serf = "127.0.0.1:`+itoa(t, nomadSerfPort)+`"
}
`+supportedNomadTLSBlock(nomadTLS.dir)) + "\n")
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
		"NOMAD_ADDR="+nomadAddr,
		"NOMAD_CACERT="+nomadTLS.caFile,
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
		t.Fatalf("bringup up failed: %v output=%s%s", err, string(upOutput), bringupLogTails(filepath.Join(bringupDir, "logs")))
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
		t.Fatalf("bringup check failed: %v output=%s%s", err, string(checkOutput), bringupLogTails(filepath.Join(bringupDir, "logs")))
	}
	if !strings.Contains(string(checkOutput), "nomad: leader=") {
		t.Fatalf("expected nomad readiness in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), supportedNomadPostureLine) {
		t.Fatalf("expected the Docker-only, limited Nomad posture in bringup check output, got %s", string(checkOutput))
	}
	if !strings.Contains(string(checkOutput), "nomad tls: tls=1.3 server_name="+nomadTLSServerName+" key=pinned") {
		t.Fatalf("expected ES's pinned Nomad identity in bringup check output, got %s", string(checkOutput))
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
	assertBringupNomadACLMaterial(t, bringupDir, esCfg.Nomad.TokenFile)
	assertNomadBindSourcesUnderStagingRoot(
		t,
		nomadAddr,
		nomadTLS.caFile,
		filepath.Join(bringupDir, "nomad-acl", "observer-token"),
		runtimeIdentityResult.Summary.RunID,
		esCfg.Execution.StagingRootDir,
		filepath.Dir(esCfg.Execution.SPIREWorkloadAPISocketPath),
	)
	assertStagingInvariantProof(t, filepath.Join(bringupDir, "staging-invariant.json"), esCfg.Execution.StagingRootDir)
	assertBringupServicesRunAsOperator(t, bringupDir, arsRootDir, indexPath)
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
	trackedDockerfileBytes, err := os.ReadFile(filepath.Join(repoRoot, ".out", "Dockerfile"))
	if err != nil {
		t.Fatalf("read tracked .out/Dockerfile: %v", err)
	}
	if !bytes.Equal(dockerfileBytes, trackedDockerfileBytes) {
		t.Fatalf("tracked .out/Dockerfile is stale; run scripts/generate_control_plane_dockerfile.sh and commit the result")
	}

	for _, want := range []string{
		"# Code generated by scripts/generate_control_plane_dockerfile.sh; DO NOT EDIT.",
		"FROM golang:1.26.5-alpine3.24 AS build",
		"ENV GOTOOLCHAIN=local",
		"COPY go.sum ./",
		"COPY cgs ./cgs",
		"COPY internal ./internal",
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
	stack := startSubmitStackWithoutNomad(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "10_health_check.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"prepare-only-health-check-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
printf '%s\n' '{"config":{"Client":{"Options":{"docker.cleanup.image":"false"}},"Plugins":[{"Name":"docker","Config":{"volumes":{"enabled":true},"gc":{"image":true}}}]}}'
`))
	if err := os.Chmod(fakeCurlPath, 0o755); err != nil {
		t.Fatalf("chmod fake curl: %v", err)
	}

	cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_image_gc_policy_once "$ES_CONFIG"`)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ES_CONFIG="+esConfigPath,
		"NOMAD_ADDR=https://127.0.0.1:4646",
		"NOMAD_CACERT="+writeUnusedNomadCACertFile(rootDir),
		"NOMAD_TOKEN_FILE="+writeFakeNomadObserverTokenFile(t, rootDir),
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing nomad docker image cleanup guardrail to fail, got output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "runtime profile image durability: missing nomad docker plugin setting gc.image = false") {
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
	tokenFile := writeFakeNomadObserverTokenFile(t, rootDir)
	// Nomad 2.1 reports the plugin's gc block as an object, Nomad 2.0 as a
	// list holding one object; both shapes pass.
	for name, agentSelf := range map[string]string{
		"object (Nomad 2.1)":           `{"config":{"Plugins":[{"Name":"docker","Config":{"volumes":{"enabled":true},"gc":{"image":false}}}]}}`,
		"one-element list (Nomad 2.0)": `{"config":{"Plugins":[{"Name":"docker","Config":{"volumes":[{"enabled":true}],"gc":[{"image":false}]}}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeCurlPath := writeBytesFile(t, fakeBinDir, "curl", []byte("#!/bin/sh\nprintf '%s\\n' '"+agentSelf+"'\n"))
			if err := os.Chmod(fakeCurlPath, 0o755); err != nil {
				t.Fatalf("chmod fake curl: %v", err)
			}

			cmd := exec.Command("bash", "-c", `source scripts/internal/bringup.sh; check_runtime_profile_image_gc_policy_once "$ES_CONFIG"`)
			cmd.Dir = repoRoot
			cmd.Env = append(os.Environ(),
				"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"ES_CONFIG="+esConfigPath,
				"NOMAD_ADDR=https://127.0.0.1:4646",
				"NOMAD_CACERT="+writeUnusedNomadCACertFile(rootDir),
				"NOMAD_TOKEN_FILE="+tokenFile,
			)

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("expected disabled nomad docker image cleanup guardrail to pass: %v output=%s", err, string(output))
			}
			if !strings.Contains(string(output), "runtime profile image durability: nomad docker plugin gc.image=false") {
				t.Fatalf("expected docker cleanup guardrail output, got %s", string(output))
			}
		})
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

// runFullHealthCheckAgainstFakeNomad runs scripts/10_health_check.sh in the
// full profile against real control-plane services and a fake pre-managed,
// ACL-enforcing Nomad whose one ready node has the given networks.
func runFullHealthCheckAgainstFakeNomad(t *testing.T, devMode bool, nodeNetworks []map[string]any) (string, error) {
	t.Helper()
	stack := startSubmitStackWithoutNomad(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "10_health_check.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"dev-nomad-health-check-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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

	nomadServer, nomadTLS := startNomadTLSStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status/leader":
			_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
		case "/v1/acl/token/self":
			// An ACL-enforcing Nomad answers a request without a token as
			// the anonymous token.
			_ = json.NewEncoder(w).Encode(map[string]any{"AccessorID": "anonymous", "Name": "Anonymous Token", "Type": "client"})
		case "/v1/acl/policy/anonymous":
			http.NotFound(w, r)
		case "/v1/agent/self":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": map[string]any{
					"DevMode":    devMode,
					"Datacenter": "dc1",
					"Server":     map[string]any{"Enabled": true},
					"Client":     map[string]any{"Enabled": true, "Options": map[string]any{"driver.allowlist": "docker"}},
					"Plugins":    supportedNomadDockerPluginAgentConfig(),
					"TLSConfig":  supportedNomadTLSAgentConfig(),
				},
			})
		case "/v1/nodes":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"ID": "node-1", "Name": "fake-node", "Status": "ready"},
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
				"NodeResources": map[string]any{"Networks": nodeNetworks},
			})
		default:
			http.NotFound(w, r)
		}
	}))

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
		"nomad": nomadTLS.esNomadConfigJSON(nomadServer.URL, writeFakeNomadTokenFile(t, rootDir)),
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
		"NOMAD_CACERT="+nomadTLS.caFile,
		"NOMAD_TOKEN_FILE="+writeFakeNomadObserverTokenFile(t, rootDir),
		"ARS_RESOLVE="+stack.fixture.arsServerName+":"+arsPort+":"+arsHost,
		"EGS_RESOLVE="+stack.fixture.egsServerName+":"+egsPort+":"+egsHost,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"OPERATOR_CERT="+operatorCertPath,
		"OPERATOR_KEY="+operatorKeyPath,
	)

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// The loopback host network of the supported config, as Nomad reports it.
var fakeNomadLoopbackHostNetworks = []map[string]any{
	{"Mode": "bridge", "Device": "nomad"},
	{"Mode": "host", "Device": "lo", "CIDR": "127.0.0.1/32", "IP": "127.0.0.1"},
}

func TestHealthCheckScriptRejectsPreManagedDevNomad(t *testing.T) {
	text, err := runFullHealthCheckAgainstFakeNomad(t, true, fakeNomadLoopbackHostNetworks)
	if err == nil {
		t.Fatalf("expected full health check to reject pre-managed dev nomad, got output=%s", text)
	}
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

// A client pinned to a wired port whose cable is out has only a bridge
// network, and Nomad cannot place any ES job there ("missing network"), so
// readiness refuses it and names the loopback pin, which holds on Wi-Fi and on
// a cable alike.
func TestHealthCheckScriptRejectsNomadNodeWithoutHostNetwork(t *testing.T) {
	text, err := runFullHealthCheckAgainstFakeNomad(t, false, []map[string]any{{"Mode": "bridge", "Device": "nomad"}})
	if err == nil {
		t.Fatalf("expected full health check to reject a node without a host network, got output=%s", text)
	}
	for _, want := range []string{
		"nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network",
		"nomad: fake-node=no-host-network",
		`pin network_interface = "lo" (scripts/70_linux_setup.sh), which holds on Wi-Fi and on a cable alike`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in the health check output, got %s", want, text)
		}
	}
	if strings.Contains(text, "supported-environment: supported") || strings.Contains(text, "agent is running in -dev mode") {
		t.Fatalf("unexpected readiness output for a node without a host network: %s", text)
	}
}

func TestBringupRunbookTroubleshootingMatrixListsCurrentFailureCategories(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	runbookPath := filepath.Join(repoRoot, ".runbooks", "system", "Governed Execution ES System Bring-Up.md")

	body, err := os.ReadFile(runbookPath)
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}

	text := string(body)
	requiredSnippets := []string{
		"## What do the failures mean?",
		"This is the operator troubleshooting matrix that the operator-facing scripts point to.",
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
		`"driver.allowlist" = "docker"`,
		"allow_privileged = false",
		"gc {\n      image = false\n    }",
		"root-managed nomad.service",
		"ready node(s) still report cpu.totalcompute=0 under the root-managed non-dev service",
		"SMBIOS processor Current Speed is not usable on this host",
		"current login shell still needs re-login before repo scripts can call docker without sudo",
		"GO_REQUIRED_VERSION=\"go1.26.5\"",
		"go1.26.5.linux-amd64.tar.gz",
		"go1.26.5.linux-arm64.tar.gz",
		"env GOTOOLCHAIN=local go version",
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
	if strings.Contains(text, "golang-go") {
		t.Fatalf("linux setup script must not install distro golang-go")
	}
}

func TestLinuxSetupGoToolchainInstallerHermeticPreflightAndCleanup(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)

	t.Run("unsupported architecture before mutation", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "riscv64")
		if err == nil {
			t.Fatalf("expected unsupported architecture to fail, output=%s", output)
		}
		if !strings.Contains(output, "unsupported Linux architecture for Go go1.26.5: riscv64") {
			t.Fatalf("expected unsupported architecture diagnostic, got %s", output)
		}
		assertNoEventContains(t, harness.events(t), "sudo ", "curl ", "sha256sum ", "go version")
	})

	t.Run("fake command resolution prevents host fallthrough", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		harness.assertFakeCommandsResolve(t, "amd64")
	})

	t.Run("fake commands accept only exact bounded grammars", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		harness.assertFakeCommandsResolve(t, "amd64")

		archivePath := harness.expectedArchivePath("amd64")
		output, err := harness.runFakeCommand(t, "uname", "amd64", "", nil, "-s")
		if err != nil || strings.TrimSpace(output) != "Linux" {
			t.Fatalf("fake uname -s rejected exact grammar: %v output=%s", err, output)
		}
		output, err = harness.runFakeCommand(t, "uname", "amd64", "", nil, "-m")
		if err != nil || strings.TrimSpace(output) != "amd64" {
			t.Fatalf("fake uname -m rejected exact grammar: %v output=%s", err, output)
		}
		output, err = harness.runFakeCommand(t, "mktemp", "amd64", "", nil)
		if err != nil || strings.TrimSpace(output) != archivePath {
			t.Fatalf("fake mktemp rejected exact grammar: %v output=%s", err, output)
		}
		assertPathExists(t, archivePath)
		output, err = harness.runFakeCommand(t, "curl", "amd64", "", nil, "--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz")
		if err != nil {
			t.Fatalf("fake curl rejected exact Go archive grammar: %v output=%s", err, output)
		}
		output, err = harness.runFakeCommand(t, "sha256sum", "amd64", "", nil, archivePath)
		if err != nil || !strings.Contains(output, linuxSetupGoAMD64SHA+"  "+archivePath) {
			t.Fatalf("fake sha256sum rejected exact grammar: %v output=%s", err, output)
		}
		output, err = harness.runFakeCommand(t, "env", "amd64", "", nil, "GOTOOLCHAIN=local", "go", "version")
		if err != nil || !strings.Contains(output, "go version go1.26.5 linux/amd64") {
			t.Fatalf("fake env/go rejected exact grammar: %v output=%s", err, output)
		}

		if err := os.WriteFile(archivePath, []byte("archive\n"), 0o600); err != nil {
			t.Fatalf("write fake archive: %v", err)
		}
		output, err = harness.runFakeCommand(t, "rm", "amd64", "", nil, "-f", "--", archivePath)
		if err != nil {
			t.Fatalf("fake rm rejected expected archive cleanup: %v output=%s", err, output)
		}
		assertPathAbsent(t, archivePath)

		output, err = harness.runFakeCommand(t, "rm", "amd64", "", nil, "-f", "--", "/usr/local/go")
		if err == nil {
			t.Fatalf("fake rm accepted non-test path, output=%s", output)
		}
		if !strings.Contains(output, "reject:rm") {
			t.Fatalf("expected fake rm rejection diagnostic, got %s", output)
		}
		output, err = harness.runFakeCommand(t, "sudo", "amd64", "", nil, "apt-get", "upgrade")
		if err == nil {
			t.Fatalf("fake sudo apt-get accepted unsupported argument shape, output=%s", output)
		}
		if !strings.Contains(output, "reject:sudo") {
			t.Fatalf("expected sudo apt-get rejection diagnostic, got %s", output)
		}

		if err := os.WriteFile(archivePath, []byte("archive\n"), 0o600); err != nil {
			t.Fatalf("rewrite fake archive: %v", err)
		}
		output, err = harness.runFakeCommand(t, "tar", "amd64", "", nil, "-C", harness.installRoot, "-xzf", archivePath)
		if err != nil {
			t.Fatalf("fake tar rejected expected test-owned extraction: %v output=%s", err, output)
		}
		assertFakeTarSuccessTree(t, harness.installRoot)
		events := harness.events(t)
		assertEventExactCount(t, events, "tar -C "+harness.installRoot+" -xzf "+archivePath, 1)
		assertEventPrefixCount(t, events, "reject:tar", 0)

		installDir := harness.directInstallDir
		output, err = harness.runFakeCommand(t, "install", "amd64", "", nil, "-d", "-m", "0755", installDir)
		if err != nil {
			t.Fatalf("fake install rejected test-owned directory: %v output=%s", err, output)
		}
		if info, statErr := os.Stat(installDir); statErr != nil || !info.IsDir() {
			t.Fatalf("expected fake install to create %s, info=%v err=%v", installDir, info, statErr)
		}

		output, err = harness.runFakeCommand(t, "tee", "amd64", "profile\n", nil, harness.profilePath)
		if err != nil {
			t.Fatalf("fake tee rejected test-owned profile path: %v output=%s", err, output)
		}
		if got := mustReadFile(t, harness.profilePath); got != "profile\n" {
			t.Fatalf("fake tee wrote %q", got)
		}
		output, err = harness.runFakeCommand(t, "sudo", "amd64", "", nil, "mkdir", "-p", "/usr/local")
		if err != nil {
			t.Fatalf("fake sudo mkdir rejected exact grammar: %v output=%s", err, output)
		}
		output, err = harness.runFakeCommand(t, "sudo", "amd64", "", nil, "chmod", "0644", "/etc/profile.d/execution-substrate-go.sh")
		if err != nil {
			t.Fatalf("fake sudo chmod rejected exact grammar: %v output=%s", err, output)
		}

		events = harness.events(t)
		assertEventContains(t, events, "rm -f -- "+archivePath)
		assertEventContains(t, events, "tar -C "+harness.installRoot+" -xzf "+archivePath)
		assertEventContains(t, events, "install -d -m 0755 "+installDir)
		assertEventContains(t, events, "tee "+harness.profilePath)
	})

	t.Run("fake commands reject malformed argv without mutation", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		archivePath := harness.expectedArchivePath("amd64")
		for _, tc := range []struct {
			name    string
			command string
			stdin   string
			args    []string
		}{
			{name: "curl extra flag", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "--retry", "1", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"}},
			{name: "curl reordered flag", command: "curl", args: []string{"--location", "--fail", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"}},
			{name: "curl omitted flag", command: "curl", args: []string{"--fail", "--location", "--silent", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"}},
			{name: "curl wrong output", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", filepath.Join(harness.rootDir, "wrong.tar.gz"), "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"}},
			{name: "curl wrong archive", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-ppc64.tar.gz"}},
			{name: "curl wrong hostname", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://example.com/dl/go1.26.5.linux-amd64.tar.gz"}},
			{name: "curl query string", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz?mirror=1"}},
			{name: "curl second url", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz", "https://go.dev/dl/go1.26.5.linux-arm64.tar.gz"}},
			{name: "curl trailing argument", command: "curl", args: []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz", "trailing"}},
			{name: "mktemp extra", command: "mktemp", args: []string{"template"}},
			{name: "mktemp absolute template", command: "mktemp", args: []string{"/tmp/go.XXXXXX"}},
			{name: "mktemp unsupported flag", command: "mktemp", args: []string{"-t", "go.XXXXXX"}},
			{name: "env extra assignment", command: "env", args: []string{"PATH=/tmp", "GOTOOLCHAIN=local", "go", "version"}},
			{name: "env missing gotoolchain", command: "env", args: []string{"go", "version"}},
			{name: "env wrong gotoolchain", command: "env", args: []string{"GOTOOLCHAIN=auto", "go", "version"}},
			{name: "env alternate go subcommand", command: "env", args: []string{"GOTOOLCHAIN=local", "go", "env"}},
			{name: "env extra go arg", command: "env", args: []string{"GOTOOLCHAIN=local", "go", "version", "-m"}},
			{name: "direct go rejected", command: "go", args: []string{"version"}},
			{name: "uname empty", command: "uname"},
			{name: "uname combined flag", command: "uname", args: []string{"-sm"}},
			{name: "uname unknown flag", command: "uname", args: []string{"-x"}},
			{name: "uname extra operand", command: "uname", args: []string{"-m", "extra"}},
			{name: "sha extra arg", command: "sha256sum", args: []string{archivePath, archivePath}},
			{name: "direct apt-get rejected", command: "apt-get", args: []string{"update"}},
			{name: "sudo apt-get unsupported", command: "sudo", args: []string{"apt-get", "upgrade"}},
			{name: "systemctl unsupported", command: "systemctl", args: []string{"status", "docker"}},
			{name: "install unsupported shape", command: "install", args: []string{"-m", "0755", harness.directInstallDir}},
			{name: "tee unsupported flag", command: "tee", stdin: "bad\n", args: []string{"-a", harness.profilePath}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				output, err := harness.runFakeCommand(t, tc.command, "amd64", tc.stdin, nil, tc.args...)
				if err == nil {
					t.Fatalf("fake %s accepted malformed argv, output=%s", tc.command, output)
				}
				if !strings.Contains(output, "reject:"+tc.command) {
					t.Fatalf("expected reject ledger/output for %s, got %s events=%#v", tc.command, output, harness.events(t))
				}
			})
		}
		assertPathAbsent(t, filepath.Join(harness.rootDir, "wrong.tar.gz"))
	})

	t.Run("fake mutators reject traversal symlink and wrong contained paths", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		archivePath := harness.expectedArchivePath("amd64")
		if err := os.WriteFile(archivePath, []byte("archive\n"), 0o600); err != nil {
			t.Fatalf("write fake archive: %v", err)
		}
		outsideDir := t.TempDir()
		linkPath := filepath.Join(harness.rootDir, "link-out")
		if err := os.Symlink(outsideDir, linkPath); err != nil {
			t.Fatalf("create symlink escape fixture: %v", err)
		}
		repoPath := filepath.Join(repoRoot, "fake-harness-escape")
		candidates := []struct {
			name string
			path string
		}{
			{name: "etc", path: "/etc/execution-substrate-go.sh"},
			{name: "usr-local-go", path: "/usr/local/go"},
			{name: "repo path", path: repoPath},
			{name: "parent traversal", path: filepath.Join(harness.rootDir, "..", "escape")},
			{name: "nested traversal", path: filepath.Join(harness.rootDir, "subdir", "..", "..", "escape")},
			{name: "symlink outside", path: filepath.Join(linkPath, "leaf")},
			{name: "wrong contained", path: filepath.Join(harness.rootDir, "wrong-contained")},
			{name: "empty", path: ""},
			{name: "relative", path: "relative/path"},
		}
		for _, tc := range candidates {
			t.Run(tc.name, func(t *testing.T) {
				assertLinuxSetupMutatorRejectsPath(t, harness, "rm", tc.path)
				assertLinuxSetupMutatorRejectsPath(t, harness, "tar", tc.path)
				assertLinuxSetupMutatorRejectsPath(t, harness, "install", tc.path)
				assertLinuxSetupMutatorRejectsPath(t, harness, "tee", tc.path)
			})
		}
		assertPathAbsent(t, filepath.Join(outsideDir, "leaf"))
		assertPathAbsent(t, repoPath)
	})

	t.Run("fake tar rejects internal symlink effect paths without outside mutation", func(t *testing.T) {
		for _, tc := range []struct {
			name                  string
			setup                 func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string)
			outsideFileWant       string
			forbiddenOutsidePaths func(harness linuxSetupFakeHarness, outsideDir string) []string
		}{
			{
				name: "go symlink",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					if err := os.Symlink(outsideDir, filepath.Join(harness.installRoot, "go")); err != nil {
						t.Fatalf("create go symlink escape fixture: %v", err)
					}
				},
				forbiddenOutsidePaths: func(harness linuxSetupFakeHarness, outsideDir string) []string {
					return []string{filepath.Join(outsideDir, "bin", "go")}
				},
			},
			{
				name: "go bin symlink",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					goRoot := filepath.Join(harness.installRoot, "go")
					if err := os.Mkdir(goRoot, 0o755); err != nil {
						t.Fatalf("create go root fixture: %v", err)
					}
					if err := os.Symlink(outsideDir, filepath.Join(goRoot, "bin")); err != nil {
						t.Fatalf("create go/bin symlink escape fixture: %v", err)
					}
				},
				forbiddenOutsidePaths: func(harness linuxSetupFakeHarness, outsideDir string) []string {
					return []string{filepath.Join(outsideDir, "go")}
				},
			},
			{
				name: "go binary symlink",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					goBin := filepath.Join(harness.installRoot, "go", "bin")
					if err := os.MkdirAll(goBin, 0o755); err != nil {
						t.Fatalf("create go/bin fixture: %v", err)
					}
					if err := os.Symlink(outsideFile, filepath.Join(goBin, "go")); err != nil {
						t.Fatalf("create go/bin/go symlink escape fixture: %v", err)
					}
				},
				outsideFileWant: "outside-file-sentinel\n",
				forbiddenOutsidePaths: func(harness linuxSetupFakeHarness, outsideDir string) []string {
					return nil
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				outerDir := t.TempDir()
				harness := newLinuxSetupFakeHarnessAtRoot(t, repoRoot, filepath.Join(outerDir, "fake-root"))
				harness.assertFakeCommandsResolve(t, "amd64")
				archivePath := harness.expectedArchivePath("amd64")
				if err := os.WriteFile(archivePath, []byte("archive\n"), 0o600); err != nil {
					t.Fatalf("write fake archive: %v", err)
				}

				outsideDir := filepath.Join(outerDir, "outside")
				if err := os.Mkdir(outsideDir, 0o755); err != nil {
					t.Fatalf("create outside dir: %v", err)
				}
				outsideDirSentinel := filepath.Join(outsideDir, "sentinel.txt")
				const outsideDirSentinelBody = "outside-dir-sentinel\n"
				if err := os.WriteFile(outsideDirSentinel, []byte(outsideDirSentinelBody), 0o600); err != nil {
					t.Fatalf("write outside dir sentinel: %v", err)
				}
				outsideFile := filepath.Join(outerDir, "outside-go")
				outsideFileWant := tc.outsideFileWant
				if outsideFileWant == "" {
					outsideFileWant = "outside-file-unused\n"
				}
				if err := os.WriteFile(outsideFile, []byte(outsideFileWant), 0o600); err != nil {
					t.Fatalf("write outside file sentinel: %v", err)
				}

				tc.setup(t, harness, outsideDir, outsideFile)
				output, err := harness.runFakeCommand(t, "tar", "amd64", "", nil, "-C", harness.installRoot, "-xzf", archivePath)
				if err == nil {
					t.Fatalf("fake tar accepted internal symlink effect path, output=%s", output)
				}
				events := harness.events(t)
				assertEventPrefixCount(t, events, "reject:tar", 1)
				assertEventExactCount(t, events, "tar -C "+harness.installRoot+" -xzf "+archivePath, 0)
				if strings.Contains(output, "fake go") {
					t.Fatalf("fake tar rejection must not report fake go marker, output=%s", output)
				}
				if got := mustReadFile(t, outsideDirSentinel); got != outsideDirSentinelBody {
					t.Fatalf("outside directory sentinel changed: got %q want %q", got, outsideDirSentinelBody)
				}
				if got := mustReadFile(t, outsideFile); got != outsideFileWant {
					t.Fatalf("outside file sentinel changed: got %q want %q", got, outsideFileWant)
				}
				for _, path := range tc.forbiddenOutsidePaths(harness, outsideDir) {
					assertPathAbsent(t, path)
				}
				assertNoFakeGoRegularMarker(t, filepath.Join(harness.installRoot, "go", "bin", "go"))
			})
		}
	})

	t.Run("fake tar rejects invalid extraction root and non-regular leaf without success ledger", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			setup       func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) []string
			assertAfter func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string)
		}{
			{
				name: "extraction root symlink",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) []string {
					t.Helper()
					if err := os.Remove(harness.installRoot); err != nil {
						t.Fatalf("remove fake extraction root: %v", err)
					}
					if err := os.Symlink(outsideDir, harness.installRoot); err != nil {
						t.Fatalf("create extraction root symlink fixture: %v", err)
					}
					return []string{filepath.Join(outsideDir, "go", "bin", "go")}
				},
				assertAfter: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					info, err := os.Lstat(harness.installRoot)
					if err != nil {
						t.Fatalf("inspect extraction root symlink: %v", err)
					}
					if info.Mode()&os.ModeSymlink == 0 {
						t.Fatalf("expected extraction root to remain a symlink")
					}
				},
			},
			{
				name: "extraction root regular file",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) []string {
					t.Helper()
					if err := os.Remove(harness.installRoot); err != nil {
						t.Fatalf("remove fake extraction root: %v", err)
					}
					if err := os.WriteFile(harness.installRoot, []byte("root-file-sentinel\n"), 0o600); err != nil {
						t.Fatalf("write extraction root regular file fixture: %v", err)
					}
					return nil
				},
				assertAfter: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					if got := mustReadFile(t, harness.installRoot); got != "root-file-sentinel\n" {
						t.Fatalf("extraction root regular file changed: got %q", got)
					}
				},
			},
			{
				name: "go binary directory",
				setup: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) []string {
					t.Helper()
					goBinaryDir := filepath.Join(harness.installRoot, "go", "bin", "go")
					if err := os.MkdirAll(goBinaryDir, 0o755); err != nil {
						t.Fatalf("create go/bin/go directory fixture: %v", err)
					}
					if err := os.WriteFile(filepath.Join(goBinaryDir, "sentinel.txt"), []byte("leaf-directory-sentinel\n"), 0o600); err != nil {
						t.Fatalf("write go/bin/go directory sentinel: %v", err)
					}
					return nil
				},
				assertAfter: func(t *testing.T, harness linuxSetupFakeHarness, outsideDir string, outsideFile string) {
					t.Helper()
					goBinaryDir := filepath.Join(harness.installRoot, "go", "bin", "go")
					info, err := os.Lstat(goBinaryDir)
					if err != nil {
						t.Fatalf("inspect go/bin/go directory: %v", err)
					}
					if !info.IsDir() {
						t.Fatalf("go/bin/go fixture must remain a directory")
					}
					if got := mustReadFile(t, filepath.Join(goBinaryDir, "sentinel.txt")); got != "leaf-directory-sentinel\n" {
						t.Fatalf("go/bin/go directory sentinel changed: got %q", got)
					}
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				outerDir := t.TempDir()
				harness := newLinuxSetupFakeHarnessAtRoot(t, repoRoot, filepath.Join(outerDir, "fake-root"))
				harness.assertFakeCommandsResolve(t, "amd64")
				archivePath := harness.expectedArchivePath("amd64")
				if err := os.WriteFile(archivePath, []byte("archive\n"), 0o600); err != nil {
					t.Fatalf("write fake archive: %v", err)
				}
				outsideDir := filepath.Join(outerDir, "outside")
				if err := os.Mkdir(outsideDir, 0o755); err != nil {
					t.Fatalf("create outside dir: %v", err)
				}
				outsideDirSentinel := filepath.Join(outsideDir, "sentinel.txt")
				const outsideDirSentinelBody = "outside-dir-sentinel\n"
				if err := os.WriteFile(outsideDirSentinel, []byte(outsideDirSentinelBody), 0o600); err != nil {
					t.Fatalf("write outside dir sentinel: %v", err)
				}
				outsideFile := filepath.Join(outerDir, "outside-go")
				const outsideFileBody = "outside-file-sentinel\n"
				if err := os.WriteFile(outsideFile, []byte(outsideFileBody), 0o600); err != nil {
					t.Fatalf("write outside file sentinel: %v", err)
				}

				forbiddenPaths := tc.setup(t, harness, outsideDir, outsideFile)
				output, err := harness.runFakeCommand(t, "tar", "amd64", "", nil, "-C", harness.installRoot, "-xzf", archivePath)
				if err == nil {
					t.Fatalf("fake tar accepted invalid extraction root or leaf, output=%s", output)
				}
				events := harness.events(t)
				assertEventPrefixCount(t, events, "reject:tar", 1)
				assertEventExactCount(t, events, "tar -C "+harness.installRoot+" -xzf "+archivePath, 0)
				if strings.Contains(output, "fake go") {
					t.Fatalf("fake tar rejection must not report fake go marker, output=%s", output)
				}
				for _, path := range forbiddenPaths {
					assertPathAbsent(t, path)
				}
				if got := mustReadFile(t, outsideDirSentinel); got != outsideDirSentinelBody {
					t.Fatalf("outside directory sentinel changed: got %q want %q", got, outsideDirSentinelBody)
				}
				if got := mustReadFile(t, outsideFile); got != outsideFileBody {
					t.Fatalf("outside file sentinel changed: got %q want %q", got, outsideFileBody)
				}
				tc.assertAfter(t, harness, outsideDir, outsideFile)
			})
		}
	})

	t.Run("pre-existing cleanup traps reject without installer-invoked prior handler", func(t *testing.T) {
		for _, signal := range []string{"EXIT", "HUP", "INT", "TERM"} {
			t.Run(signal, func(t *testing.T) {
				harness := newLinuxSetupFakeHarness(t, repoRoot)
				before, after, markerBefore, markerAfter := runLinuxSetupPreexistingTrapOwnershipSeam(t, harness, signal)
				if before == "" {
					t.Fatalf("expected pre-existing %s trap representation to be captured", signal)
				}
				if before != after {
					t.Fatalf("expected pre-existing %s trap to remain unchanged\nbefore: %q\nafter:  %q", signal, before, after)
				}
				if markerBefore != "" {
					t.Fatalf("rejected installer call must not run prior %s trap, marker before deliberate shell event=%q", signal, markerBefore)
				}
				// The caller-owned EXIT trap runs only when the bounded child shell exits deliberately.
				if markerAfter != "caller-owned "+signal {
					t.Fatalf("expected caller-owned %s trap to remain functional after deliberate shell event, marker=%q", signal, markerAfter)
				}
				assertNoEventContains(t, harness.events(t),
					"mktemp",
					"sudo ",
					"apt-get",
					"curl ",
					"sha256sum ",
					"sudo rm -rf /usr/local/go",
					"sudo tar -C /usr/local -xzf",
					"sudo tee /etc/profile.d/execution-substrate-go.sh",
					"go version",
				)
				assertLinuxSetupTempArchivesAbsent(t, harness)
			})
		}
	})

	for _, tc := range []struct {
		name       string
		machine    string
		archive    string
		archiveSHA string
	}{
		{name: "amd64", machine: "amd64", archive: "go1.26.5.linux-amd64.tar.gz", archiveSHA: linuxSetupGoAMD64SHA},
		{name: "x86_64", machine: "x86_64", archive: "go1.26.5.linux-amd64.tar.gz", archiveSHA: linuxSetupGoAMD64SHA},
		{name: "arm64", machine: "arm64", archive: "go1.26.5.linux-arm64.tar.gz", archiveSHA: linuxSetupGoARM64SHA},
		{name: "aarch64", machine: "aarch64", archive: "go1.26.5.linux-arm64.tar.gz", archiveSHA: linuxSetupGoARM64SHA},
	} {
		t.Run("supported architecture selection "+tc.name, func(t *testing.T) {
			harness := newLinuxSetupFakeHarness(t, repoRoot)
			output, err := harness.run(t, tc.machine, "LINUX_SETUP_FAKE_CURL_FAIL=1")
			if err == nil {
				t.Fatalf("expected forced download failure after archive selection, output=%s", output)
			}
			events := harness.events(t)
			assertEventContains(t, events, "curl https://go.dev/dl/"+tc.archive)
			assertNoEventContains(t, events, "sudo rm -rf /usr/local/go", "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
			assertLinuxSetupTempArchivesAbsent(t, harness)
			if tc.archiveSHA != harness.expectedSHA(t, tc.machine) {
				t.Fatalf("test harness selected unexpected sha for %s", tc.machine)
			}
		})
	}

	t.Run("digest before replacement", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64")
		if err == nil {
			t.Fatalf("expected post-installer hashicorp sentinel, output=%s", output)
		}
		events := harness.events(t)
		assertEventOrder(t, events, "sha256sum ", "sudo rm -rf /usr/local/go")
		assertEventOrder(t, events, "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh")
		assertEventOrder(t, events, "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("download failure cleans archive before replacement", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_CURL_FAIL=1")
		if err == nil {
			t.Fatalf("expected download failure, output=%s", output)
		}
		events := harness.events(t)
		assertNoEventContains(t, events, "sha256sum ", "sudo rm -rf /usr/local/go", "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("digest command failure cleans archive before replacement", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_SHA_FAIL=1")
		if err == nil {
			t.Fatalf("expected digest command failure, output=%s", output)
		}
		events := harness.events(t)
		assertNoEventContains(t, events, "sudo rm -rf /usr/local/go", "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("digest mismatch cleans archive before replacement", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_SHA_MISMATCH=1")
		if err == nil {
			t.Fatalf("expected digest mismatch, output=%s", output)
		}
		events := harness.events(t)
		assertNoEventContains(t, events, "sudo rm -rf /usr/local/go", "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("extraction failure cleans archive and reports no success", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_TAR_FAIL=1")
		if err == nil {
			t.Fatalf("expected extraction failure, output=%s", output)
		}
		events := harness.events(t)
		assertEventPrefixCount(t, events, "reject:tar", 1)
		assertEventExactCount(t, events, "sudo tar -C /usr/local -xzf "+harness.expectedArchivePath("amd64"), 0)
		assertNoEventContains(t, events, "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		if strings.Contains(output, "Go go1.26.5 installed") {
			t.Fatalf("extraction failure must not report Go installation success, output=%s", output)
		}
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("profile write failure cleans archive", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_TEE_FAIL=1")
		if err == nil {
			t.Fatalf("expected profile write failure, output=%s", output)
		}
		assertNoEventContains(t, harness.events(t), "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("post install version failure cleans archive", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64", "LINUX_SETUP_FAKE_GO_VERSION=go1.26.4")
		if err == nil {
			t.Fatalf("expected post-install version failure, output=%s", output)
		}
		assertEventContains(t, harness.events(t), "go version")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("ordinary no pre-existing trap success path installs and cleans archive", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		output, err := harness.run(t, "amd64")
		if err == nil {
			t.Fatalf("expected post-installer hashicorp sentinel, output=%s", output)
		}
		events := harness.events(t)
		assertEventOrder(t, events, "uname -m", "sudo -v")
		assertEventOrder(t, events, "sudo -v", "mktemp")
		assertEventOrder(t, events, "mktemp", "curl https://go.dev/dl/go1.26.5.linux-amd64.tar.gz")
		assertEventOrder(t, events, "curl https://go.dev/dl/go1.26.5.linux-amd64.tar.gz", "sha256sum ")
		assertEventOrder(t, events, "sha256sum ", "sudo rm -rf /usr/local/go")
		assertEventOrder(t, events, "sudo rm -rf /usr/local/go", "sudo tar -C /usr/local -xzf")
		assertEventOrder(t, events, "sudo tar -C /usr/local -xzf", "sudo tee /etc/profile.d/execution-substrate-go.sh")
		assertEventOrder(t, events, "sudo tee /etc/profile.d/execution-substrate-go.sh", "go version")
		assertEventOrder(t, events, "go version", "rm -f -- ")
		assertLinuxSetupTempArchivesAbsent(t, harness)
	})

	t.Run("success cleanup and persistent path idempotence", func(t *testing.T) {
		harness := newLinuxSetupFakeHarness(t, repoRoot)
		for i := 0; i < 2; i++ {
			output, err := harness.run(t, "amd64")
			if err == nil {
				t.Fatalf("expected post-installer hashicorp sentinel, output=%s", output)
			}
			assertLinuxSetupTempArchivesAbsent(t, harness)
		}
		profileBody, err := os.ReadFile(harness.profilePath)
		if err != nil {
			t.Fatalf("read fake profile: %v", err)
		}
		const expectedProfile = "export PATH=\"/usr/local/go/bin:${PATH}\"\n"
		if string(profileBody) != expectedProfile {
			t.Fatalf("expected one deterministic Go PATH entry, got %q", string(profileBody))
		}
	})
}

func TestSupportedLocalSetupExactGoPreflightBeforeMutation(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "72_supported_local_setup.sh")

	t.Run("local build path rejects wrong Go before mutation", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.4")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err == nil {
			t.Fatalf("expected wrong Go version to fail, output=%s", output)
		}
		assertPathAbsent(t, proofDir)
		events := harness.events(t)
		assertEventContains(t, events, "go version")
		assertNoEventContains(t, events, "docker ", "go build")
	})

	t.Run("local build path rejects missing Go before mutation", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, false, "")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err == nil {
			t.Fatalf("expected missing Go to fail, output=%s", output)
		}
		if !strings.Contains(output, "go is required") {
			t.Fatalf("expected missing Go diagnostic, got %s", output)
		}
		assertPathAbsent(t, proofDir)
		assertNoEventContains(t, harness.events(t), "go version", "docker ", "go build")
	})

	t.Run("local build path accepts exact Go at bounded sentinel", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.5")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err != nil {
			t.Fatalf("expected exact Go preflight sentinel to pass: %v output=%s", err, output)
		}
		if !strings.Contains(output, "supported-local setup exact Go preflight complete") {
			t.Fatalf("expected setup sentinel output, got %s", output)
		}
		assertPathAbsent(t, proofDir)
		events := harness.events(t)
		assertEventContains(t, events, "go version")
		assertNoEventContains(t, events, "docker ", "go build")
	})

	t.Run("prebuilt inputs do not create a false no local Go bypass", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.4")
		rootDir := t.TempDir()
		proofDir := filepath.Join(rootDir, "proof")
		prebuiltRuntime := filepath.Join(rootDir, "es-runtime-support")
		prebuiltSpire := filepath.Join(rootDir, "spire.tar.gz")
		if err := os.WriteFile(prebuiltRuntime, []byte("runtime"), 0o700); err != nil {
			t.Fatalf("write prebuilt runtime: %v", err)
		}
		if err := os.WriteFile(prebuiltSpire, []byte("spire"), 0o600); err != nil {
			t.Fatalf("write prebuilt spire: %v", err)
		}
		output, err := harness.run(
			t,
			scriptPath,
			"SUPPORTED_LOCAL_PROOF_DIR="+proofDir,
			"SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY="+prebuiltRuntime,
			"SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+prebuiltSpire,
			"SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight",
		)
		if err == nil {
			t.Fatalf("expected setup to remain local-Go-required with prebuilt inputs, output=%s", output)
		}
		assertPathAbsent(t, proofDir)
		assertEventContains(t, harness.events(t), "go version")
	})
}

func TestSupportedLocalProofExactGoPreflightBeforeMutation(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "73_supported_local_proof.sh")

	t.Run("local build path rejects wrong Go before mutation", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.4")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_HOST_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err == nil {
			t.Fatalf("expected wrong Go version to fail, output=%s", output)
		}
		assertPathAbsent(t, proofDir)
		events := harness.events(t)
		assertEventContains(t, events, "go version")
		assertNoEventContains(t, events, "limactl ", "go build")
	})

	t.Run("local build path rejects missing Go before mutation", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, false, "")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_HOST_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err == nil {
			t.Fatalf("expected missing Go to fail, output=%s", output)
		}
		if !strings.Contains(output, "go is required") {
			t.Fatalf("expected missing Go diagnostic, got %s", output)
		}
		assertPathAbsent(t, proofDir)
		assertNoEventContains(t, harness.events(t), "go version", "limactl ", "go build")
	})

	t.Run("local build path accepts exact Go at bounded sentinel", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.5")
		proofDir := filepath.Join(t.TempDir(), "proof")
		output, err := harness.run(t, scriptPath, "SUPPORTED_LOCAL_HOST_PROOF_DIR="+proofDir, "SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight")
		if err != nil {
			t.Fatalf("expected exact Go preflight sentinel to pass: %v output=%s", err, output)
		}
		if !strings.Contains(output, "supported-local proof exact Go preflight complete") {
			t.Fatalf("expected proof sentinel output, got %s", output)
		}
		assertPathAbsent(t, proofDir)
		events := harness.events(t)
		assertEventContains(t, events, "go version")
		assertNoEventContains(t, events, "limactl ", "go build")
	})

	t.Run("prebuilt spire does not create a false no local Go bypass", func(t *testing.T) {
		harness := newSupportedLocalFakeHarness(t, repoRoot, true, "go1.26.4")
		rootDir := t.TempDir()
		proofDir := filepath.Join(rootDir, "proof")
		prebuiltSpire := filepath.Join(rootDir, "spire.tar.gz")
		if err := os.WriteFile(prebuiltSpire, []byte("spire"), 0o600); err != nil {
			t.Fatalf("write prebuilt spire: %v", err)
		}
		output, err := harness.run(
			t,
			scriptPath,
			"SUPPORTED_LOCAL_HOST_PROOF_DIR="+proofDir,
			"SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+prebuiltSpire,
			"SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL=after-go-preflight",
		)
		if err == nil {
			t.Fatalf("expected proof wrapper to remain local-Go-required with prebuilt SPIRE input, output=%s", output)
		}
		assertPathAbsent(t, proofDir)
		assertEventContains(t, harness.events(t), "go version")
	})
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
		supportedNomadDockerPluginBlock,
		supportedNomadClientOptions,
		"acl {\n  enabled = true\n}",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("expected %q in example nomad config, got %s", snippet, text)
		}
	}
}

func TestLifecycleScriptObservesExecutionViaPublicRunID(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	stack := startSubmitStackWithoutNomad(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "70_diagnostics.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"diagnostics-runtime-config-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	stack := startRuntimeIdentitySubmitStack(t)
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	stack := startSubmitStackWithoutNomad(t)

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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	stack := startSubmitStackWithoutNomad(t)

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
	if !strings.Contains(text, ".runbooks/system/Governed Execution ES System Bring-Up.md") {
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	if !strings.Contains(text, ".runbooks/system/Governed Execution ES System Bring-Up.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --category runtime-config") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func TestSubmitScriptCategorizesSubstrateFailure(t *testing.T) {
	stack := startSubmitStackWithoutNomad(t)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "40_submit.sh")
	operatorCertPath, operatorKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"submit-substrate-operator",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.operator",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	if !strings.Contains(text, ".runbooks/system/Governed Execution ES System Bring-Up.md") {
		t.Fatalf("expected troubleshooting matrix reference, got %s", text)
	}
	if !strings.Contains(text, "scripts/70_diagnostics.sh --category substrate") {
		t.Fatalf("expected diagnostics helper reference, got %s", text)
	}
}

func TestLifecycleScriptCategorizesExecutionFailure(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/operator/local")},
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
	if !strings.Contains(text, ".runbooks/system/Governed Execution ES System Bring-Up.md") {
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

const (
	linuxSetupGoAMD64SHA = "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
	linuxSetupGoARM64SHA = "fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49"
)

var linuxSetupFakeCommandNames = []string{"sudo", "apt-get", "curl", "sha256sum", "mktemp", "rm", "tar", "install", "tee", "env", "go", "uname", "systemctl"}

type linuxSetupFakeHarness struct {
	repoRoot         string
	rootDir          string
	fakeBinDir       string
	ledgerPath       string
	tempPathsPath    string
	profilePath      string
	homeDir          string
	archiveDir       string
	installRoot      string
	directInstallDir string
}

func TestLinuxSetupFakeCommandHelper(t *testing.T) {
	if os.Getenv("LINUX_SETUP_FAKE_COMMAND_HELPER") != "1" {
		return
	}
	helperArgs := linuxSetupFakeHelperArgs(os.Args)
	if len(helperArgs) == 0 {
		fmt.Fprintln(os.Stderr, "reject:fake missing command")
		os.Exit(64)
	}
	os.Exit(linuxSetupFakeCommandMain(helperArgs[0], helperArgs[1:], os.Stdin, os.Stdout, os.Stderr))
}

func linuxSetupFakeHelperArgs(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func linuxSetupFakeCommandMain(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	switch command {
	case "uname":
		if linuxSetupFakeArgsEqual(args, []string{"-s"}) {
			return linuxSetupFakeRecordAndPrint("uname -s", "Linux\n", stdout, stderr)
		}
		if linuxSetupFakeArgsEqual(args, []string{"-m"}) {
			return linuxSetupFakeRecordAndPrint("uname -m", linuxSetupFakeEnv("LINUX_SETUP_FAKE_MACHINE")+"\n", stdout, stderr)
		}
		return linuxSetupFakeReject(command, args, stderr, "unsupported argv")
	case "sudo":
		return linuxSetupFakeSudo(args, stdin, stdout, stderr)
	case "curl":
		return linuxSetupFakeCurl(args, stdout, stderr)
	case "mktemp":
		return linuxSetupFakeMktemp(args, stdout, stderr)
	case "sha256sum":
		return linuxSetupFakeSHA256Sum(args, stdout, stderr)
	case "env":
		return linuxSetupFakeEnvCommand(args, stdout, stderr)
	case "go", "apt-get", "systemctl":
		return linuxSetupFakeReject(command, args, stderr, "direct invocation unsupported")
	case "rm":
		return linuxSetupFakeRM(args, stderr)
	case "tar":
		expectedRoot := linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_ROOT")
		return linuxSetupFakeTar(args, stderr, expectedRoot, "tar -C "+expectedRoot+" -xzf ")
	case "install":
		return linuxSetupFakeInstall(args, stderr)
	case "tee":
		profile := linuxSetupFakeEnv("LINUX_SETUP_FAKE_PROFILE")
		return linuxSetupFakeTee(args, stdin, stderr, profile, "tee "+profile)
	default:
		return linuxSetupFakeReject(command, args, stderr, "unknown fake command")
	}
}

func linuxSetupFakeSudo(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if linuxSetupFakeArgsEqual(args, []string{"-v"}) {
		return linuxSetupFakeRecord("sudo -v", stderr)
	}
	if linuxSetupFakeArgsEqual(args, []string{"apt-get", "update"}) {
		return linuxSetupFakeRecord("sudo apt-get update", stderr)
	}
	if linuxSetupFakeArgsEqual(args, []string{"apt-get", "install", "-y", "ca-certificates", "curl", "git", "gnupg", "jq", "lsb-release", "openssh-client", "openssl", "python3", "software-properties-common", "unzip", "docker.io"}) {
		return linuxSetupFakeRecord("sudo "+strings.Join(args, " "), stderr)
	}
	if linuxSetupFakeArgsEqual(args, []string{"apt-get", "install", "-y", "nomad", "vault"}) {
		return linuxSetupFakeRecord("sudo "+strings.Join(args, " "), stderr)
	}
	if linuxSetupFakeArgsEqual(args, []string{"rm", "-rf", "/usr/local/go"}) {
		if code := linuxSetupFakeRecord("sudo rm -rf /usr/local/go", stderr); code != 0 {
			return code
		}
		if linuxSetupFakeEnv("LINUX_SETUP_FAKE_RM_FAIL") == "1" {
			return 31
		}
		target := filepath.Join(linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_ROOT"), "go")
		if err := linuxSetupFakeRequireExactPath(target, target); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, err.Error())
		}
		if err := os.RemoveAll(target); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, "remove fake go root failed")
		}
		return 0
	}
	if linuxSetupFakeArgsEqual(args, []string{"mkdir", "-p", "/usr/local"}) {
		if code := linuxSetupFakeRecord("sudo mkdir -p /usr/local", stderr); code != 0 {
			return code
		}
		target := linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_ROOT")
		if err := linuxSetupFakeRequireExactPath(target, target); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, err.Error())
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, "mkdir fake install root failed")
		}
		return 0
	}
	if linuxSetupFakeArgsEqual(args, []string{"tar", "-C", "/usr/local", "-xzf", linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")}) {
		return linuxSetupFakeTar([]string{"-C", linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_ROOT"), "-xzf", linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")}, stderr, linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_ROOT"), "sudo tar -C /usr/local -xzf ")
	}
	if linuxSetupFakeArgsEqual(args, []string{"tee", "/etc/profile.d/execution-substrate-go.sh"}) {
		return linuxSetupFakeTee([]string{linuxSetupFakeEnv("LINUX_SETUP_FAKE_PROFILE")}, stdin, stderr, linuxSetupFakeEnv("LINUX_SETUP_FAKE_PROFILE"), "sudo tee /etc/profile.d/execution-substrate-go.sh")
	}
	if linuxSetupFakeArgsEqual(args, []string{"chmod", "0644", "/etc/profile.d/execution-substrate-go.sh"}) {
		if code := linuxSetupFakeRecord("sudo chmod 0644 /etc/profile.d/execution-substrate-go.sh", stderr); code != 0 {
			return code
		}
		profile := linuxSetupFakeEnv("LINUX_SETUP_FAKE_PROFILE")
		if err := linuxSetupFakeRequireExactPath(profile, profile); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, err.Error())
		}
		if err := os.Chmod(profile, 0o644); err != nil {
			return linuxSetupFakeReject("sudo", args, stderr, "chmod fake profile failed")
		}
		return 0
	}
	if linuxSetupFakeArgsEqual(args, []string{"gpg", "--dearmor", "-o", "/usr/share/keyrings/hashicorp-archive-keyring.gpg"}) {
		_, _ = io.ReadAll(stdin)
		if code := linuxSetupFakeRecord("sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg", stderr); code != 0 {
			return code
		}
		return 77
	}
	if len(args) > 0 && args[0] == "apt-get" {
		return linuxSetupFakeReject("sudo", args, stderr, "unsupported apt-get argv")
	}
	return linuxSetupFakeReject("sudo", args, stderr, "unsupported argv")
}

func linuxSetupFakeCurl(args []string, stdout io.Writer, stderr io.Writer) int {
	archivePath := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")
	archiveURL := "https://go.dev/dl/" + linuxSetupFakeEnv("LINUX_SETUP_FAKE_SELECTED_ARCHIVE")
	if linuxSetupFakeArgsEqual(args, []string{"--fail", "--location", "--silent", "--show-error", "-o", archivePath, archiveURL}) {
		if err := linuxSetupFakeRequireExactPath(args[5], archivePath); err != nil {
			return linuxSetupFakeReject("curl", args, stderr, err.Error())
		}
		if code := linuxSetupFakeRecord("curl "+archiveURL, stderr); code != 0 {
			return code
		}
		if err := linuxSetupFakeAppendLine(linuxSetupFakeEnv("LINUX_SETUP_FAKE_TEMP_PATHS"), archivePath); err != nil {
			return linuxSetupFakeReject("curl", args, stderr, "record archive path failed")
		}
		if err := os.WriteFile(archivePath, []byte("partial archive\n"), 0o600); err != nil {
			return linuxSetupFakeReject("curl", args, stderr, "write archive failed")
		}
		if linuxSetupFakeEnv("LINUX_SETUP_FAKE_CURL_FAIL") == "1" {
			return 23
		}
		return 0
	}
	if linuxSetupFakeArgsEqual(args, []string{"-fsSL", "https://apt.releases.hashicorp.com/gpg"}) {
		if code := linuxSetupFakeRecord("curl https://apt.releases.hashicorp.com/gpg", stderr); code != 0 {
			return code
		}
		return 77
	}
	return linuxSetupFakeReject("curl", args, stderr, "unsupported argv")
}

func linuxSetupFakeMktemp(args []string, stdout io.Writer, stderr io.Writer) int {
	if !linuxSetupFakeArgsEqual(args, nil) {
		return linuxSetupFakeReject("mktemp", args, stderr, "unsupported argv")
	}
	archivePath := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")
	if err := linuxSetupFakeRequireExactPath(archivePath, archivePath); err != nil {
		return linuxSetupFakeReject("mktemp", args, stderr, err.Error())
	}
	if code := linuxSetupFakeRecord("mktemp "+archivePath, stderr); code != 0 {
		return code
	}
	if err := linuxSetupFakeAppendLine(linuxSetupFakeEnv("LINUX_SETUP_FAKE_TEMP_PATHS"), archivePath); err != nil {
		return linuxSetupFakeReject("mktemp", args, stderr, "record archive path failed")
	}
	if err := os.WriteFile(archivePath, nil, 0o600); err != nil {
		return linuxSetupFakeReject("mktemp", args, stderr, "create archive path failed")
	}
	fmt.Fprintln(stdout, archivePath)
	return 0
}

func linuxSetupFakeSHA256Sum(args []string, stdout io.Writer, stderr io.Writer) int {
	archivePath := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")
	if !linuxSetupFakeArgsEqual(args, []string{archivePath}) {
		return linuxSetupFakeReject("sha256sum", args, stderr, "unsupported argv")
	}
	if err := linuxSetupFakeRequireExactPath(args[0], archivePath); err != nil {
		return linuxSetupFakeReject("sha256sum", args, stderr, err.Error())
	}
	if code := linuxSetupFakeRecord("sha256sum "+archivePath, stderr); code != 0 {
		return code
	}
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_SHA_FAIL") == "1" {
		return 24
	}
	observed := linuxSetupFakeEnv("LINUX_SETUP_FAKE_EXPECTED_SHA")
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_SHA_MISMATCH") == "1" {
		observed = strings.Repeat("0", 64)
	}
	fmt.Fprintf(stdout, "%s  %s\n", observed, archivePath)
	return 0
}

func linuxSetupFakeEnvCommand(args []string, stdout io.Writer, stderr io.Writer) int {
	if !linuxSetupFakeArgsEqual(args, []string{"GOTOOLCHAIN=local", "go", "version"}) {
		return linuxSetupFakeReject("env", args, stderr, "unsupported argv")
	}
	if code := linuxSetupFakeRecord("go version", stderr); code != 0 {
		return code
	}
	version := linuxSetupFakeEnv("LINUX_SETUP_FAKE_GO_VERSION")
	if version == "" {
		version = "go1.26.5"
	}
	fmt.Fprintf(stdout, "go version %s linux/amd64\n", version)
	return 0
}

func linuxSetupFakeRM(args []string, stderr io.Writer) int {
	archivePath := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")
	if !linuxSetupFakeArgsEqual(args, []string{"-f", "--", archivePath}) {
		return linuxSetupFakeReject("rm", args, stderr, "unsupported argv")
	}
	if err := linuxSetupFakeRequireExactPath(args[2], archivePath); err != nil {
		return linuxSetupFakeReject("rm", args, stderr, err.Error())
	}
	if code := linuxSetupFakeRecord("rm -f -- "+archivePath, stderr); code != 0 {
		return code
	}
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_RM_FAIL") == "1" {
		return 31
	}
	if err := os.Remove(archivePath); err != nil && !os.IsNotExist(err) {
		return linuxSetupFakeReject("rm", args, stderr, "remove archive failed")
	}
	return 0
}

func linuxSetupFakeTar(args []string, stderr io.Writer, expectedRoot string, eventPrefix string) int {
	archivePath := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ARCHIVE_PATH")
	if !linuxSetupFakeArgsEqual(args, []string{"-C", expectedRoot, "-xzf", archivePath}) {
		return linuxSetupFakeReject("tar", args, stderr, "unsupported argv")
	}
	if err := linuxSetupFakeRequireExactPath(args[1], expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	if err := linuxSetupFakeRequireExactPath(args[3], archivePath); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	goRoot := filepath.Join(expectedRoot, "go")
	goBinDir := filepath.Join(expectedRoot, "go", "bin")
	goBinary := filepath.Join(goBinDir, "go")
	if err := linuxSetupFakeValidateTarExtractionRoot(expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	for _, effectPath := range []string{goRoot, goBinDir, goBinary} {
		if err := linuxSetupFakeValidateTarEffectPath(effectPath, effectPath, expectedRoot); err != nil {
			return linuxSetupFakeReject("tar", args, stderr, err.Error())
		}
	}
	if err := linuxSetupFakePreflightTarDescendants(goRoot, goBinDir, goBinary, expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_TAR_FAIL") == "1" {
		return linuxSetupFakeReject("tar", args, stderr, "forced fake tar failure")
	}
	if err := linuxSetupFakeEnsureTarDirectory(goRoot, expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	if err := linuxSetupFakeEnsureTarDirectory(goBinDir, expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	if err := linuxSetupFakeWriteTarGoBinary(goBinary, expectedRoot); err != nil {
		return linuxSetupFakeReject("tar", args, stderr, err.Error())
	}
	if code := linuxSetupFakeRecord(eventPrefix+archivePath, stderr); code != 0 {
		return code
	}
	return 0
}

func linuxSetupFakeValidateTarExtractionRoot(expectedRoot string) error {
	if !filepath.IsAbs(expectedRoot) {
		return fmt.Errorf("relative tar extraction root rejected")
	}
	if filepath.Clean(expectedRoot) != expectedRoot {
		return fmt.Errorf("unclean tar extraction root rejected")
	}
	info, err := os.Lstat(expectedRoot)
	if os.IsNotExist(err) {
		return fmt.Errorf("tar extraction root missing")
	}
	if err != nil {
		return fmt.Errorf("inspect tar extraction root failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("pre-existing symlink in tar effect path rejected")
	}
	if !info.IsDir() {
		return fmt.Errorf("tar extraction root is not a directory")
	}
	if err := linuxSetupFakeRequireExactPath(expectedRoot, expectedRoot); err != nil {
		return err
	}
	if _, err := linuxSetupFakeCanonicalContainedPath(expectedRoot); err != nil {
		return err
	}
	return nil
}

func linuxSetupFakePreflightTarDescendants(goRoot string, goBinDir string, goBinary string, extractionRoot string) error {
	for _, dir := range []string{goRoot, goBinDir} {
		if err := linuxSetupFakeValidateTarEffectPath(dir, dir, extractionRoot); err != nil {
			return err
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect tar directory effect path failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pre-existing symlink in tar effect path rejected")
		}
		if !info.IsDir() {
			return fmt.Errorf("tar effect path is not a directory")
		}
	}
	if err := linuxSetupFakeValidateTarEffectPath(goBinary, goBinary, extractionRoot); err != nil {
		return err
	}
	info, err := os.Lstat(goBinary)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect tar binary effect path failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("pre-existing symlink in tar effect path rejected")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("tar effect path is not a regular file")
	}
	return nil
}

func linuxSetupFakeEnsureTarDirectory(path string, extractionRoot string) error {
	if err := linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pre-existing symlink in tar effect path rejected")
		}
		if !info.IsDir() {
			return fmt.Errorf("tar effect path is not a directory")
		}
		return linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect tar directory effect path failed")
	}
	parent := filepath.Dir(path)
	if err := linuxSetupFakeValidateTarEffectPath(parent, parent, extractionRoot); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create fake go tree failed")
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect created tar directory failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("pre-existing symlink in tar effect path rejected")
	}
	if !info.IsDir() {
		return fmt.Errorf("tar effect path is not a directory")
	}
	return linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot)
}

func linuxSetupFakeWriteTarGoBinary(path string, extractionRoot string) error {
	if err := linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := linuxSetupFakeValidateTarEffectPath(parent, parent, extractionRoot); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pre-existing symlink in tar effect path rejected")
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("tar effect path is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect tar binary effect path failed")
	}
	if err := linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("write fake go binary failed")
	}
	if _, err := file.Write([]byte("fake go\n")); err != nil {
		_ = file.Close()
		return fmt.Errorf("write fake go binary failed")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write fake go binary failed")
	}
	return linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot)
}

func linuxSetupFakeValidateTarEffectPath(candidate string, expected string, extractionRoot string) error {
	if !filepath.IsAbs(candidate) {
		return fmt.Errorf("relative tar effect path rejected")
	}
	if candidate != expected {
		return fmt.Errorf("tar effect path %q does not match expected %q", candidate, expected)
	}
	if err := linuxSetupFakeRequireExactPath(candidate, expected); err != nil {
		return err
	}
	canonicalRoot, err := linuxSetupFakeCanonicalContainedPath(extractionRoot)
	if err != nil {
		return err
	}
	canonicalCandidate, err := linuxSetupFakeCanonicalContainedPath(candidate)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(canonicalRoot, canonicalCandidate)
	if err != nil {
		return fmt.Errorf("tar effect relative containment check failed")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("tar effect path escapes extraction root")
	}
	return linuxSetupFakeRejectExistingSymlinkInTarEffectChain(extractionRoot, candidate)
}

func linuxSetupFakeRejectExistingSymlinkInTarEffectChain(extractionRoot string, candidate string) error {
	cleanRoot := filepath.Clean(extractionRoot)
	cleanCandidate := filepath.Clean(candidate)
	rel, err := filepath.Rel(cleanRoot, cleanCandidate)
	if err != nil {
		return fmt.Errorf("tar effect lexical containment check failed")
	}
	if rel == "." {
		info, err := os.Lstat(cleanRoot)
		if os.IsNotExist(err) {
			return fmt.Errorf("tar extraction root missing")
		}
		if err != nil {
			return fmt.Errorf("inspect tar extraction root failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pre-existing symlink in tar effect path rejected")
		}
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("tar effect path escapes extraction root")
	}
	current := cleanRoot
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("ambiguous tar effect path rejected")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect tar effect path chain failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pre-existing symlink in tar effect path rejected")
		}
	}
	return nil
}

func linuxSetupFakeInstall(args []string, stderr io.Writer) int {
	target := linuxSetupFakeEnv("LINUX_SETUP_FAKE_DIRECT_INSTALL_DIR")
	if !linuxSetupFakeArgsEqual(args, []string{"-d", "-m", "0755", target}) {
		return linuxSetupFakeReject("install", args, stderr, "unsupported argv")
	}
	if err := linuxSetupFakeRequireExactPath(args[3], target); err != nil {
		return linuxSetupFakeReject("install", args, stderr, err.Error())
	}
	if code := linuxSetupFakeRecord("install -d -m 0755 "+target, stderr); code != 0 {
		return code
	}
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_INSTALL_FAIL") == "1" {
		return 34
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return linuxSetupFakeReject("install", args, stderr, "create fake install target failed")
	}
	return 0
}

func linuxSetupFakeTee(args []string, stdin io.Reader, stderr io.Writer, expectedPath string, event string) int {
	if !linuxSetupFakeArgsEqual(args, []string{expectedPath}) {
		_, _ = io.ReadAll(stdin)
		return linuxSetupFakeReject("tee", args, stderr, "unsupported argv")
	}
	if err := linuxSetupFakeRequireExactPath(args[0], expectedPath); err != nil {
		_, _ = io.ReadAll(stdin)
		return linuxSetupFakeReject("tee", args, stderr, err.Error())
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return linuxSetupFakeReject("tee", args, stderr, "read stdin failed")
	}
	if code := linuxSetupFakeRecord(event, stderr); code != 0 {
		return code
	}
	if linuxSetupFakeEnv("LINUX_SETUP_FAKE_TEE_FAIL") == "1" {
		return 33
	}
	if err := os.WriteFile(expectedPath, body, 0o644); err != nil {
		return linuxSetupFakeReject("tee", args, stderr, "write fake tee target failed")
	}
	return 0
}

func linuxSetupFakeRequireExactPath(candidate string, expected string) error {
	if candidate == "" {
		return fmt.Errorf("empty path rejected")
	}
	if filepath.Clean(candidate) != candidate {
		return fmt.Errorf("unclean path rejected")
	}
	if filepath.Clean(expected) != expected {
		return fmt.Errorf("unclean expected path")
	}
	canonicalCandidate, err := linuxSetupFakeCanonicalContainedPath(candidate)
	if err != nil {
		return err
	}
	canonicalExpected, err := linuxSetupFakeCanonicalContainedPath(expected)
	if err != nil {
		return err
	}
	if canonicalCandidate != canonicalExpected {
		return fmt.Errorf("path %q does not match expected %q", candidate, expected)
	}
	return nil
}

func linuxSetupFakeCanonicalContainedPath(candidate string) (string, error) {
	root := linuxSetupFakeEnv("LINUX_SETUP_FAKE_ROOT")
	if root == "" {
		return "", fmt.Errorf("missing fake root")
	}
	if candidate == "" {
		return "", fmt.Errorf("empty path rejected")
	}
	if !filepath.IsAbs(candidate) {
		return "", fmt.Errorf("relative path rejected")
	}
	if linuxSetupPathContainsDotDot(candidate) {
		return "", fmt.Errorf("traversal path rejected")
	}
	cleanCandidate := filepath.Clean(candidate)
	if linuxSetupFakeForbiddenHostPath(cleanCandidate) {
		return "", fmt.Errorf("forbidden host path rejected")
	}
	if repoRoot := linuxSetupFakeEnv("LINUX_SETUP_REPO_ROOT"); repoRoot != "" {
		repoAbs, err := filepath.Abs(repoRoot)
		if err != nil {
			return "", fmt.Errorf("repository root resolution failed")
		}
		repoClean := filepath.Clean(repoAbs)
		if cleanCandidate == repoClean || strings.HasPrefix(cleanCandidate, repoClean+string(os.PathSeparator)) {
			return "", fmt.Errorf("repository path rejected")
		}
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("fake root resolution failed")
	}
	rootResolved, err := filepath.EvalSymlinks(filepath.Clean(rootAbs))
	if err != nil {
		return "", fmt.Errorf("fake root symlink resolution failed")
	}
	ancestor := cleanCandidate
	var suffix []string
	for {
		if _, err := os.Lstat(ancestor); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("candidate ancestor inspection failed")
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("candidate has no existing ancestor")
		}
		base := filepath.Base(ancestor)
		if base == "." || base == ".." || base == "" {
			return "", fmt.Errorf("ambiguous path suffix rejected")
		}
		suffix = append([]string{base}, suffix...)
		ancestor = parent
	}
	ancestorResolved, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", fmt.Errorf("candidate ancestor symlink resolution failed")
	}
	resolved := filepath.Clean(ancestorResolved)
	for _, part := range suffix {
		if part == "." || part == ".." || part == "" {
			return "", fmt.Errorf("ambiguous path suffix rejected")
		}
		resolved = filepath.Join(resolved, part)
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil {
		return "", fmt.Errorf("relative containment check failed")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes fake root")
	}
	return resolved, nil
}

func linuxSetupFakeForbiddenHostPath(path string) bool {
	forbidden := []string{"/etc", "/usr/local/go"}
	for _, root := range forbidden {
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func linuxSetupPathContainsDotDot(path string) bool {
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

func linuxSetupFakeArgsEqual(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func linuxSetupFakeRecordAndPrint(event string, text string, stdout io.Writer, stderr io.Writer) int {
	if code := linuxSetupFakeRecord(event, stderr); code != 0 {
		return code
	}
	fmt.Fprint(stdout, text)
	return 0
}

func linuxSetupFakeRecord(event string, stderr io.Writer) int {
	if err := linuxSetupFakeAppendLine(linuxSetupFakeEnv("LINUX_SETUP_FAKE_LEDGER"), event); err != nil {
		fmt.Fprintf(stderr, "reject:fake ledger write failed: %v\n", err)
		return 64
	}
	return 0
}

func linuxSetupFakeReject(command string, args []string, stderr io.Writer, reason string) int {
	event := "reject:" + command
	if reason != "" {
		event += " " + reason
	}
	if len(args) > 0 {
		event += " " + strings.Join(args, " ")
	}
	_ = linuxSetupFakeAppendLine(linuxSetupFakeEnv("LINUX_SETUP_FAKE_LEDGER"), event)
	fmt.Fprintf(stderr, "%s\n", event)
	return 64
}

func linuxSetupFakeAppendLine(path string, line string) error {
	if path == "" {
		return fmt.Errorf("empty ledger path")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, line); err != nil {
		return err
	}
	return nil
}

func linuxSetupFakeEnv(name string) string {
	return os.Getenv(name)
}

func newLinuxSetupFakeHarness(t *testing.T, repoRoot string) linuxSetupFakeHarness {
	t.Helper()

	return newLinuxSetupFakeHarnessAtRoot(t, repoRoot, t.TempDir())
}

func newLinuxSetupFakeHarnessAtRoot(t *testing.T, repoRoot string, rootDir string) linuxSetupFakeHarness {
	t.Helper()

	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	harness := linuxSetupFakeHarness{
		repoRoot:         repoRoot,
		rootDir:          rootDir,
		fakeBinDir:       fakeBinDir,
		ledgerPath:       filepath.Join(rootDir, "events.log"),
		tempPathsPath:    filepath.Join(rootDir, "temp-archives.log"),
		profilePath:      filepath.Join(rootDir, "execution-substrate-go.sh"),
		homeDir:          filepath.Join(rootDir, "home"),
		archiveDir:       filepath.Join(rootDir, "archives"),
		installRoot:      filepath.Join(rootDir, "usr-local"),
		directInstallDir: filepath.Join(rootDir, "nomad-config"),
	}
	if err := os.MkdirAll(harness.homeDir, 0o755); err != nil {
		t.Fatalf("mkdir fake home: %v", err)
	}
	if err := os.MkdirAll(harness.archiveDir, 0o755); err != nil {
		t.Fatalf("mkdir fake archive dir: %v", err)
	}
	if err := os.MkdirAll(harness.installRoot, 0o755); err != nil {
		t.Fatalf("mkdir fake install root: %v", err)
	}

	for _, name := range linuxSetupFakeCommandNames {
		writeOperatorTestExecutable(t, fakeBinDir, name, fmt.Sprintf(`#!/bin/bash
set -euo pipefail
LINUX_SETUP_FAKE_COMMAND_HELPER=1 exec "${LINUX_SETUP_FAKE_TEST_BINARY:?}" -test.run=^TestLinuxSetupFakeCommandHelper$ -- %q "$@"
`, name))
	}

	return harness
}

func (h linuxSetupFakeHarness) run(t *testing.T, machine string, extraEnv ...string) (string, error) {
	t.Helper()

	h.assertFakeCommandsResolve(t, machine)
	cmd := exec.Command("/bin/bash", filepath.Join(h.repoRoot, "scripts", "70_linux_setup.sh"))
	cmd.Dir = h.repoRoot
	cmd.Env = h.env(t, machine, extraEnv...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h linuxSetupFakeHarness) runFakeCommand(t *testing.T, name string, machine string, stdin string, extraEnv []string, args ...string) (string, error) {
	t.Helper()

	h.assertFakeCommandsResolve(t, machine)
	cmd := exec.Command(filepath.Join(h.fakeBinDir, name), args...)
	cmd.Dir = h.repoRoot
	cmd.Env = h.env(t, machine, extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h linuxSetupFakeHarness) env(t *testing.T, machine string, extraEnv ...string) []string {
	t.Helper()

	env := []string{
		"PATH=" + h.fakeBinDir + string(os.PathListSeparator) + "/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + h.homeDir,
		"USER=operator",
		"LINUX_SETUP_FAKE_ROOT=" + h.rootDir,
		"LINUX_SETUP_FAKE_BIN_DIR=" + h.fakeBinDir,
		"LINUX_SETUP_FAKE_TEST_BINARY=" + mustAbsPath(t, os.Args[0]),
		"LINUX_SETUP_FAKE_MACHINE=" + machine,
		"LINUX_SETUP_FAKE_LEDGER=" + h.ledgerPath,
		"LINUX_SETUP_FAKE_TEMP_PATHS=" + h.tempPathsPath,
		"LINUX_SETUP_FAKE_PROFILE=" + h.profilePath,
		"LINUX_SETUP_FAKE_INSTALL_ROOT=" + h.installRoot,
		"LINUX_SETUP_FAKE_DIRECT_INSTALL_DIR=" + h.directInstallDir,
		"LINUX_SETUP_FAKE_EXPECTED_SHA=" + h.expectedSHA(t, machine),
		"LINUX_SETUP_FAKE_ARCHIVE_PATH=" + h.expectedArchivePath(machine),
		"LINUX_SETUP_FAKE_SELECTED_ARCHIVE=" + h.selectedArchive(machine),
		"LINUX_SETUP_FAKE_MKTEMP_DIR=" + h.archiveDir,
		"LINUX_SETUP_REPO_ROOT=" + h.repoRoot,
	}
	return append(env, extraEnv...)
}

func (h linuxSetupFakeHarness) assertFakeCommandsResolve(t *testing.T, machine string) {
	t.Helper()

	script := `set -euo pipefail
for name in "$@"; do
  resolved="$(command -v -- "${name}")"
  case "${resolved}" in
    "${LINUX_SETUP_FAKE_BIN_DIR:?}/"*) ;;
    *)
      printf '%s resolved outside fake bin: %s\n' "${name}" "${resolved}" >&2
      exit 64
      ;;
  esac
done
`
	args := append([]string{"-c", script, "resolve"}, linuxSetupFakeCommandNames...)
	cmd := exec.Command("/bin/bash", args...)
	cmd.Dir = h.repoRoot
	cmd.Env = h.env(t, machine)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("linux setup fake command resolution failed: %v output=%s", err, output)
	}
}

func (h linuxSetupFakeHarness) expectedArchivePath(machine string) string {
	return filepath.Join(h.archiveDir, "go-archive-"+machine+".tar.gz")
}

func (h linuxSetupFakeHarness) selectedArchive(machine string) string {
	switch machine {
	case "amd64", "x86_64":
		return "go1.26.5.linux-amd64.tar.gz"
	case "arm64", "aarch64":
		return "go1.26.5.linux-arm64.tar.gz"
	default:
		return "unused-for-unsupported-architecture"
	}
}

func (h linuxSetupFakeHarness) expectedSHA(t *testing.T, machine string) string {
	t.Helper()

	switch machine {
	case "amd64", "x86_64":
		return linuxSetupGoAMD64SHA
	case "arm64", "aarch64":
		return linuxSetupGoARM64SHA
	default:
		return "unused-for-unsupported-architecture"
	}
}

func (h linuxSetupFakeHarness) events(t *testing.T) []string {
	t.Helper()
	return readNonEmptyLines(t, h.ledgerPath)
}

func runLinuxSetupPreexistingTrapOwnershipSeam(t *testing.T, harness linuxSetupFakeHarness, signal string) (string, string, string, string) {
	t.Helper()

	rootDir := t.TempDir()
	beforePath := filepath.Join(rootDir, "before.trap")
	afterPath := filepath.Join(rootDir, "after.trap")
	markerPath := filepath.Join(rootDir, "marker.log")
	markerBeforeDeliberatePath := filepath.Join(rootDir, "marker-before-deliberate.log")
	prefixPath := writeLinuxSetupGoToolchainFunctionPrefix(t, harness.repoRoot, rootDir)
	seamScript := filepath.Join(rootDir, "trap-seam.sh")
	body := `#!/bin/bash
set -uo pipefail
source "${LINUX_SETUP_PREFIX_PATH:?}"
set +e
trap 'printf "caller-owned %s\n" "${LINUX_SETUP_TRAP_SIGNAL:?}" >> "${LINUX_SETUP_TRAP_MARKER:?}"' "${LINUX_SETUP_TRAP_SIGNAL}"
trap -p "${LINUX_SETUP_TRAP_SIGNAL}" > "${LINUX_SETUP_TRAP_BEFORE:?}"
select_go_toolchain_archive
if require_go_toolchain_archive_cleanup_trap_ownership; then
  status=0
else
  status=$?
fi
trap -p "${LINUX_SETUP_TRAP_SIGNAL}" > "${LINUX_SETUP_TRAP_AFTER:?}"
printf 'status=%s\n' "${status}"
if [[ "${status}" -eq 0 ]]; then
  exit 70
fi
if [[ -f "${LINUX_SETUP_TRAP_MARKER:?}" ]]; then
  /bin/cp "${LINUX_SETUP_TRAP_MARKER}" "${LINUX_SETUP_TRAP_MARKER_BEFORE_DELIBERATE:?}"
else
  : > "${LINUX_SETUP_TRAP_MARKER_BEFORE_DELIBERATE:?}"
fi
if [[ "${LINUX_SETUP_TRAP_SIGNAL}" == "EXIT" ]]; then
  exit 0
fi
kill -s "${LINUX_SETUP_TRAP_SIGNAL}" "$$"
exit 0
`
	if err := os.WriteFile(seamScript, []byte(body), 0o700); err != nil {
		t.Fatalf("write trap seam: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", seamScript)
	cmd.Dir = harness.repoRoot
	cmd.Env = append(harness.env(t, "amd64"),
		"LINUX_SETUP_REPO_ROOT="+harness.repoRoot,
		"LINUX_SETUP_PREFIX_PATH="+prefixPath,
		"LINUX_SETUP_TRAP_SIGNAL="+signal,
		"LINUX_SETUP_TRAP_BEFORE="+beforePath,
		"LINUX_SETUP_TRAP_AFTER="+afterPath,
		"LINUX_SETUP_TRAP_MARKER="+markerPath,
		"LINUX_SETUP_TRAP_MARKER_BEFORE_DELIBERATE="+markerBeforeDeliberatePath,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("trap seam timed out for %s: %v output=%s", signal, ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("trap seam failed for %s: %v output=%s", signal, err, output)
	}
	if !strings.Contains(string(output), "status=1") {
		t.Fatalf("expected trap ownership seam to reject %s trap, output=%s", signal, output)
	}
	if !strings.Contains(string(output), "pre-existing "+signal+" trap prevents Go archive installation") {
		t.Fatalf("expected bounded %s trap diagnostic, got %s", signal, output)
	}
	if !strings.Contains(string(output), "standalone installer requires exclusive cleanup-trap ownership for the bounded Go archive installation step") {
		t.Fatalf("expected exclusive trap ownership diagnostic, got %s", output)
	}

	return strings.TrimSpace(mustReadFile(t, beforePath)),
		strings.TrimSpace(mustReadFile(t, afterPath)),
		strings.TrimSpace(mustReadFile(t, markerBeforeDeliberatePath)),
		strings.TrimSpace(mustReadFile(t, markerPath))
}

func writeLinuxSetupGoToolchainFunctionPrefix(t *testing.T, repoRoot string, dir string) string {
	t.Helper()

	scriptPath := filepath.Join(repoRoot, "scripts", "70_linux_setup.sh")
	text := mustReadFile(t, scriptPath)
	marker := "# Non-mutating Go archive selection must run before the first sudo invocation."
	index := strings.Index(text, marker)
	if index < 0 {
		t.Fatalf("linux setup script missing Go toolchain main-flow marker %q", marker)
	}
	prefixPath := filepath.Join(dir, "linux-setup-go-toolchain-prefix.sh")
	if err := os.WriteFile(prefixPath, []byte(text[:index]), 0o600); err != nil {
		t.Fatalf("write linux setup function prefix: %v", err)
	}
	return prefixPath
}

type supportedLocalFakeHarness struct {
	repoRoot   string
	fakeBinDir string
	ledgerPath string
	homeDir    string
}

func newSupportedLocalFakeHarness(t *testing.T, repoRoot string, includeGo bool, goVersion string) supportedLocalFakeHarness {
	t.Helper()

	rootDir := t.TempDir()
	fakeBinDir := filepath.Join(rootDir, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	harness := supportedLocalFakeHarness{
		repoRoot:   repoRoot,
		fakeBinDir: fakeBinDir,
		ledgerPath: filepath.Join(rootDir, "events.log"),
		homeDir:    filepath.Join(rootDir, "home"),
	}
	if err := os.MkdirAll(harness.homeDir, 0o755); err != nil {
		t.Fatalf("mkdir fake home: %v", err)
	}
	writeOperatorTestExecutable(t, fakeBinDir, "uname", `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-s" ]]; then
  printf 'Linux\n'
  exit 0
fi
printf 'unexpected uname invocation: %s\n' "$*" >&2
exit 64
`)
	if includeGo {
		writeOperatorTestExecutable(t, fakeBinDir, "go", `#!/usr/bin/env bash
set -euo pipefail
printf 'go %s\n' "$*" >> "${SUPPORTED_LOCAL_FAKE_LEDGER:?}"
if [[ "${1:-}" == "version" ]]; then
  printf 'go version %s linux/amd64\n' "${SUPPORTED_LOCAL_FAKE_GO_VERSION:?}"
  exit 0
fi
printf 'unexpected go invocation: %s\n' "$*" >&2
exit 64
`)
	}
	for _, name := range []string{"openssl", "python3", "curl", "tar", "vault", "docker", "nomad", "limactl"} {
		writeOperatorTestExecutable(t, fakeBinDir, name, "#!/usr/bin/env bash\nprintf '"+name+" %s\\n' \"$*\" >> \"${SUPPORTED_LOCAL_FAKE_LEDGER:?}\"\nprintf 'unexpected "+name+" invocation: %s\\n' \"$*\" >&2\nexit 64\n")
	}
	if goVersion == "" {
		goVersion = "unused"
	}
	t.Setenv("SUPPORTED_LOCAL_FAKE_GO_VERSION", goVersion)
	return harness
}

func (h supportedLocalFakeHarness) run(t *testing.T, scriptPath string, extraEnv ...string) (string, error) {
	t.Helper()

	cmd := exec.Command("/bin/bash", scriptPath)
	cmd.Dir = h.repoRoot
	env := []string{
		"PATH=" + h.fakeBinDir + string(os.PathListSeparator) + "/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + h.homeDir,
		"SUPPORTED_LOCAL_FAKE_LEDGER=" + h.ledgerPath,
		"SUPPORTED_LOCAL_FAKE_GO_VERSION=" + os.Getenv("SUPPORTED_LOCAL_FAKE_GO_VERSION"),
	}
	env = append(env, extraEnv...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h supportedLocalFakeHarness) events(t *testing.T) []string {
	t.Helper()
	return readNonEmptyLines(t, h.ledgerPath)
}

func writeOperatorTestExecutable(t *testing.T, dir string, name string, contents string) string {
	t.Helper()

	path := writeBytesFile(t, dir, name, []byte(contents))
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func readNonEmptyLines(t *testing.T, path string) []string {
	t.Helper()

	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func assertEventContains(t *testing.T, events []string, substring string) {
	t.Helper()

	for _, event := range events {
		if strings.Contains(event, substring) {
			return
		}
	}
	t.Fatalf("expected event containing %q in %#v", substring, events)
}

func assertEventExactCount(t *testing.T, events []string, want string, expectedCount int) {
	t.Helper()

	count := 0
	for _, event := range events {
		if event == want {
			count++
		}
	}
	if count != expectedCount {
		t.Fatalf("expected exact event %q count %d, got %d in %#v", want, expectedCount, count, events)
	}
}

func assertEventPrefixCount(t *testing.T, events []string, prefix string, expectedCount int) {
	t.Helper()

	count := 0
	for _, event := range events {
		if strings.HasPrefix(event, prefix) {
			count++
		}
	}
	if count != expectedCount {
		t.Fatalf("expected event prefix %q count %d, got %d in %#v", prefix, expectedCount, count, events)
	}
}

func assertNoEventContains(t *testing.T, events []string, substrings ...string) {
	t.Helper()

	for _, event := range events {
		for _, substring := range substrings {
			if strings.Contains(event, substring) {
				t.Fatalf("unexpected event containing %q: %q in %#v", substring, event, events)
			}
		}
	}
}

func assertEventOrder(t *testing.T, events []string, first string, second string) {
	t.Helper()

	firstIndex := -1
	secondIndex := -1
	for i, event := range events {
		if firstIndex == -1 && strings.Contains(event, first) {
			firstIndex = i
		}
		if secondIndex == -1 && strings.Contains(event, second) {
			secondIndex = i
		}
	}
	if firstIndex == -1 || secondIndex == -1 || firstIndex >= secondIndex {
		t.Fatalf("expected %q before %q in %#v", first, second, events)
	}
}

func assertFakeTarSuccessTree(t *testing.T, extractionRoot string) {
	t.Helper()

	goRoot := filepath.Join(extractionRoot, "go")
	goBin := filepath.Join(extractionRoot, "go", "bin")
	goBinary := filepath.Join(goBin, "go")
	for _, dir := range []string{goRoot, goBin} {
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("expected fake tar directory %s: %v", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("fake tar directory %s must not be a symlink", dir)
		}
		if !info.IsDir() {
			t.Fatalf("fake tar path %s must be a directory", dir)
		}
	}
	info, err := os.Lstat(goBinary)
	if err != nil {
		t.Fatalf("expected fake tar go binary %s: %v", goBinary, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("fake tar go binary %s must not be a symlink", goBinary)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("fake tar go binary %s must be a regular file", goBinary)
	}
	if got := mustReadFile(t, goBinary); got != "fake go\n" {
		t.Fatalf("fake tar go binary = %q, want bounded marker", got)
	}
}

func assertLinuxSetupTempArchivesAbsent(t *testing.T, harness linuxSetupFakeHarness) {
	t.Helper()

	for _, path := range readNonEmptyLines(t, harness.tempPathsPath) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected temporary archive %s to be absent, stat err=%v", path, err)
		}
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat err=%v", path, err)
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist, stat err=%v", path, err)
	}
}

func assertNoFakeGoRegularMarker(t *testing.T, path string) {
	t.Helper()

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("inspect fake go marker %s: %v", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return
	}
	if !info.Mode().IsRegular() {
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake go marker %s: %v", path, err)
	}
	if string(body) == "fake go\n" {
		t.Fatalf("unexpected fake go marker at %s", path)
	}
}

func assertLinuxSetupMutatorRejectsPath(t *testing.T, harness linuxSetupFakeHarness, command string, path string) {
	t.Helper()

	archivePath := harness.expectedArchivePath("amd64")
	var (
		output string
		err    error
	)
	switch command {
	case "rm":
		output, err = harness.runFakeCommand(t, command, "amd64", "", nil, "-f", "--", path)
	case "tar":
		output, err = harness.runFakeCommand(t, command, "amd64", "", nil, "-C", path, "-xzf", archivePath)
	case "install":
		output, err = harness.runFakeCommand(t, command, "amd64", "", nil, "-d", "-m", "0755", path)
	case "tee":
		output, err = harness.runFakeCommand(t, command, "amd64", "profile\n", nil, path)
	default:
		t.Fatalf("unsupported mutator %q", command)
	}
	if err == nil {
		t.Fatalf("fake %s accepted path %q, output=%s", command, path, output)
	}
	if !strings.Contains(output, "reject:"+command) {
		t.Fatalf("expected reject ledger/output for %s path %q, got %s events=%#v", command, path, output, harness.events(t))
	}
}

func mustAbsPath(t *testing.T, path string) string {
	t.Helper()

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve absolute path for %s: %v", path, err)
	}
	return abs
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

// assertBringupServicesRunAsOperator checks that bring-up ran ARS, EGS, AGS
// and ES as the operator: each launcher log shows the docker run command with
// the operator's UID:GID, and every entry in ARS's storage, including the blobs
// ARS stored during the execution loop, and the index file belong to the
// operator. Before, ARS ran as root and left root-owned 0600 blobs there.
func assertBringupServicesRunAsOperator(t *testing.T, bringupDir, arsRootDir, indexPath string) {
	t.Helper()
	operator := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	for _, service := range []string{"ars", "egs", "ags", "es"} {
		data, err := os.ReadFile(filepath.Join(bringupDir, "logs", service+".log"))
		if err != nil || !strings.Contains(string(data), " --user "+operator+" ") {
			t.Fatalf("%s launcher log does not show docker run --user %s (err=%v)", service, operator, err)
		}
	}
	ownedByOperator := func(path string, info os.FileInfo) error {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid() {
			return fmt.Errorf("%s is not owned by the operator %s: %+v", path, operator, info.Sys())
		}
		return nil
	}
	files := 0
	err := filepath.Walk(arsRootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			files++
		}
		return ownedByOperator(path, info)
	})
	if err != nil {
		t.Fatalf("ARS storage ownership: %v", err)
	}
	// The test stored one blob itself; the execution loop stores more
	// through ARS.
	if files < 2 {
		t.Fatalf("ARS storage holds %d files, want the test's blob plus at least one that ARS stored", files)
	}
	info, err := os.Stat(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ownedByOperator(indexPath, info); err != nil {
		t.Fatalf("ARS index ownership: %v", err)
	}
}

func assertNomadBindSourcesUnderStagingRoot(t *testing.T, nomadAddr string, nomadCACert string, nomadTokenFile string, runID string, stagingRoot string, allowedExternalSources ...string) {
	t.Helper()

	cmd := exec.Command("nomad", "job", "inspect", "-json", "exec-"+runID)
	cmd.Env = append(os.Environ(), nomadCLIEnv(t, nomadAddr, nomadCACert, nomadTokenFile)...)
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

// bringupLogTails returns the last lines of each service log that bring-up
// wrote under logsDir, so that a failed bring-up in CI shows why a service
// did not start (bring-up itself prints only the readiness error).
func bringupLogTails(logsDir string) string {
	const tailLines = 40
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		return "\nbring-up logs: " + err.Error()
	}
	var report strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(logsDir, entry.Name()))
		if err != nil {
			fmt.Fprintf(&report, "\n==> %s: %v", entry.Name(), err)
			continue
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) > tailLines {
			lines = lines[len(lines)-tailLines:]
		}
		fmt.Fprintf(&report, "\n==> last %d lines of %s:\n%s", len(lines), entry.Name(), strings.Join(lines, "\n"))
	}
	return report.String()
}

func TestBringupLogTailsShowsTheEndOfEachLog(t *testing.T) {
	logsDir := t.TempDir()
	var nomadLog strings.Builder
	for i := 1; i <= 50; i++ {
		fmt.Fprintf(&nomadLog, "nomad line %d\n", i)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "nomad.log"), []byte(nomadLog.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "es.log"), []byte("es started\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "es.pid"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report := bringupLogTails(logsDir)
	for _, want := range []string{"last 1 lines of es.log:\nes started", "last 40 lines of nomad.log:\nnomad line 11\n", "nomad line 50"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	for _, unwanted := range []string{"nomad line 10\n", "es.pid"} {
		if strings.Contains(report, unwanted) {
			t.Errorf("report contains %q:\n%s", unwanted, report)
		}
	}
	if report := bringupLogTails(filepath.Join(logsDir, "missing")); !strings.Contains(report, "bring-up logs:") {
		t.Errorf("missing log directory gave %q", report)
	}
}
