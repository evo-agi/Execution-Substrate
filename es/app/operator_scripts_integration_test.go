package app_test

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agsconfig "execution-platform/ags/config"
	arsconfig "execution-platform/ars/config"
	runtimeconfigv1 "execution-platform/contracts/runtimeconfig/v1"
	egsconfig "execution-platform/egs/config"
	egsmodel "execution-platform/egs/model"
	esconfig "execution-platform/es/config"
)

func TestBringupScriptUpCheckDownFullProfile(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	rootDir := newExecutionWorkspaceTempDir(t, "bringup-script-")
	fixture := newTLSFixture(t)
	deploymentCertPath, deploymentKeyPath := writeLeafCertificateFiles(
		t,
		rootDir,
		"bringup-deployment-client",
		fixture.runtimeCA,
		fixture.runtimeCAKey,
		"client.service.deployment",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/deployment")},
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
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
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
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution", "service/deployment", "operator"},
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
			StagingRootDir: filepath.Join(rootDir, "es-stage"),
			BaseImage:      "alpine:3.20",
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
    "docker.volumes.enabled" = "true"
  }
}
ports {
  http = `+itoa(t, nomadHTTPPort)+`
  rpc  = `+itoa(t, nomadRPCPort)+`
  serf = `+itoa(t, nomadSerfPort)+`
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
		"DEPLOY_CERT="+deploymentCertPath,
		"DEPLOY_KEY="+deploymentKeyPath,
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
	t.Cleanup(down)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
}

func TestLifecycleScriptObservesExecutionViaPublicRunID(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "50_lifecycle.sh")
	deploymentCertPath, deploymentKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"lifecycle-deployment-client",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.service.deployment",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/deployment")},
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
		"DEPLOY_CERT="+deploymentCertPath,
		"DEPLOY_KEY="+deploymentKeyPath,
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

func writeJSONConfigFile(t *testing.T, dir string, name string, value any) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, mustMarshalJSON(t, value), 0o600); err != nil {
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
