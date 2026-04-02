package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acsapp "execution-platform/acs/app"
	acscatalog "execution-platform/acs/catalog"
	acsconfig "execution-platform/acs/config"
	agsapp "execution-platform/ags/app"
	agsconfig "execution-platform/ags/config"
	arsapp "execution-platform/ars/app"
	arsconfig "execution-platform/ars/config"
	egsapp "execution-platform/egs/app"
	egsconfig "execution-platform/egs/config"
	egsmodel "execution-platform/egs/model"
	"execution-platform/es/admission"
	esapp "execution-platform/es/app"
	esconfig "execution-platform/es/config"
)

const executionWorkspaceRoot = "/Users/ds/Repositories/Execution-Platform"

func TestSubmitFlowRunsStaticScriptInNomadDocker(t *testing.T) {
	stack := startSubmitStack(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		buildSubmitRequestBody(t, stack),
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if !payload.Success || !payload.Submitted {
		t.Fatalf("expected successful submission, got %+v", payload)
	}
	if strings.TrimSpace(payload.RunID) == "" {
		t.Fatalf("expected run_id in submit response")
	}
	if strings.TrimSpace(payload.NomadJobID) == "" {
		t.Fatalf("expected nomad_job_id in submit response")
	}
	if strings.TrimSpace(payload.NomadEvalID) == "" {
		t.Fatalf("expected nomad_eval_id in submit response")
	}
	if payload.Status != "submitted" {
		t.Fatalf("unexpected status: %q", payload.Status)
	}

	stack.nomad.waitForJob(t, payload.NomadJobID)
	alloc := stack.nomad.waitForTerminalAllocation(t, payload.NomadJobID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", alloc.ClientStatus)
	}
	task, ok := alloc.TaskStates["task"]
	if !ok {
		t.Fatalf("expected task state for task")
	}
	if task.Failed {
		t.Fatalf("expected successful task, got failed task state: %+v", task)
	}
	if exitCode := task.exitCode(); exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	logs := stack.nomad.allocLogs(t, alloc.ID)
	t.Logf("nomad allocation logs:\n%s", logs)
	if !strings.Contains(logs, "START-BANNER") {
		t.Fatalf("expected start banner in logs, got %q", logs)
	}
	if !strings.Contains(logs, "HEARTBEAT:1") || !strings.Contains(logs, "HEARTBEAT:2") || !strings.Contains(logs, "HEARTBEAT:3") {
		t.Fatalf("expected heartbeat lines in logs, got %q", logs)
	}
	if !strings.Contains(logs, `"status":"ok"`) || !strings.Contains(logs, stack.publishResponse.ArtifactDigest) {
		t.Fatalf("expected final json marker in logs, got %q", logs)
	}
}

type submitStack struct {
	fixture *tlsFixture
	rootDir string

	nomad *nomadHarness

	acs *acsapp.App
	ars *arsapp.App
	egs *egsapp.App
	ags *agsapp.App
	es  *esapp.App

	acsRunning bool
	arsRunning bool
	egsRunning bool
	agsRunning bool
	esRunning  bool

	publishResponse         submitPublishResponse
	intentDigest            string
	derivationSpecDigest    string
	outputID                string
	workloadIdentityID      string
	workloadZoneVaultDigest string
}

type submitPublishResponse struct {
	Published      bool   `json:"published"`
	ArtifactDigest string `json:"artifact_digest"`
}

func startSubmitStack(t *testing.T) *submitStack {
	t.Helper()
	rootDir := newExecutionWorkspaceTempDir(t, "es-submit-")
	fixture := newTLSFixture(t)
	nomad := startNomadHarness(t, rootDir)

	arsRootDir := filepath.Join(rootDir, "ars-storage")
	if err := os.MkdirAll(arsRootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}
	indexPath := filepath.Join(rootDir, "artifact-index.json")
	if err := os.WriteFile(indexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}

	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{
			"address":      "https://vault.internal:8200",
			"auth_mount":   "jwt",
			"auth_role":    "service_execution",
			"jwt_audience": "vault",
		},
	})
	workloadZoneVaultDigest := writeBlobBytes(t, arsRootDir, workloadZoneVaultBytes)

	stack := &submitStack{
		fixture:                 fixture,
		rootDir:                 rootDir,
		nomad:                   nomad,
		intentDigest:            labeledDigest("aa"),
		derivationSpecDigest:    labeledDigest("bb"),
		outputID:                "runtime",
		workloadIdentityID:      "spiffe://monolith.internal/service/execution",
		workloadZoneVaultDigest: workloadZoneVaultDigest,
	}

	arsCfg := arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
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
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   arsRootDir,
			IndexFile: indexPath,
		},
	}
	arsService, err := arsapp.New(arsCfg)
	if err != nil {
		t.Fatalf("build ars app: %v", err)
	}
	stack.ars = arsService
	startService(t, arsService.Start, arsService.Addr, fixture.serverTLSConfig(t, fixture.arsServerName))
	stack.arsRunning = true

	acsCfg := acsconfig.Config{
		HTTP: acsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: acsconfig.TLSConfig{
			CertFile:     fixture.acsServerCertPath,
			KeyFile:      fixture.acsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Authorization: acsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Catalog: acsconfig.CatalogConfig{
			SeedArtifactDigests: map[string]acscatalog.AssignmentKey{
				workloadZoneVaultDigest: acscatalog.RequiredWorkloadZoneVault(),
			},
		},
		Audit: acsconfig.AuditConfig{Mode: "noop"},
	}
	acsService, err := acsapp.New(acsCfg)
	if err != nil {
		t.Fatalf("build acs app: %v", err)
	}
	stack.acs = acsService
	startService(t, acsService.Start, acsService.Addr, fixture.serverTLSConfig(t, fixture.acsServerName))
	stack.acsRunning = true

	egsCfg := egsconfig.Config{
		HTTP: egsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
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
			SourceDigest:  labeledDigest("dd"),
		},
		TrustModel: egsmodel.TrustModel{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
			},
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
	egsService, err := egsapp.New(egsCfg)
	if err != nil {
		t.Fatalf("build egs app: %v", err)
	}
	stack.egs = egsService
	startService(t, egsService.Start, egsService.Addr, fixture.serverTLSConfig(t, fixture.egsServerName))
	stack.egsRunning = true

	agsCfg := agsconfig.Config{
		HTTP: agsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
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
				BaseURL:        "https://" + stack.ars.Addr(),
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
	agsService, err := agsapp.New(agsCfg)
	if err != nil {
		t.Fatalf("build ags app: %v", err)
	}
	stack.ags = agsService
	startService(t, agsService.Start, agsService.Addr, fixture.serverTLSConfig(t, fixture.agsServerName))
	stack.agsRunning = true

	esCfg := esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
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
			ArtifactCatalog: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.acs.Addr(),
				ServerName:     fixture.acsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ArtifactRegistry: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ExecutionGovernance: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.egs.Addr(),
				ServerName:     fixture.egsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
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
			BaseURL:        stack.nomad.baseURL(),
			Datacenter:     "dc1",
			TimeoutSeconds: 5,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir: filepath.Join(rootDir, "es-stage"),
			BaseImage:      "alpine:3.20",
		},
	}
	esService, err := esapp.New(esCfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = esService
	startService(t, esService.Start, esService.Addr, fixture.serverTLSConfig(t, fixture.esServerName))
	stack.esRunning = true

	publishSubmitArtifact(t, stack)

	t.Cleanup(func() { stack.shutdownAll(t) })
	return stack
}

func buildSubmitRequestBody(t *testing.T, stack *submitStack) []byte {
	t.Helper()
	return mustMarshalJSON(t, admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.publishResponse.ArtifactDigest,
			DerivationSpecDigest: stack.derivationSpecDigest,
			OutputID:             stack.outputID,
			Env: map[string]string{
				"APP_MODE": "test",
			},
		},
		Mode: admission.ExecutionModeAsync,
		Resources: &admission.ExecutionResources{
			CPU:      10,
			MemoryMB: 128,
		},
	})
}

func publishSubmitArtifact(t *testing.T, stack *submitStack) {
	t.Helper()

	requestBody := mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(buildStaticScriptArchive(t)),
		"manifest": map[string]any{
			"artifact_type": "static-script",
			"intent_digest": stack.intentDigest,
			"runtime_interface": map[string]any{
				"parameters":            []string{},
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
		},
		"provenance": map[string]any{
			"builder_service": "artifact-governance",
			"invoker": map[string]any{
				"service":   "deployment",
				"principal": "spiffe://monolith.internal/service/deployment",
			},
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ee"),
		},
		"derivation_metadata": map[string]any{
			"derivation_spec_digest": stack.derivationSpecDigest,
			"output_id":              stack.outputID,
			"producer_run_id":        "build-run-1",
		},
		"derivation_attestation": map[string]any{
			"constraints": map[string]any{
				"allowed_toolchains":      []string{},
				"forbidden_toolchains":    []string{},
				"os":                      "linux",
				"arch":                    "amd64",
				"network_access":          false,
				"writable_paths":          []string{},
				"forbidden_paths":         []string{},
				"determinism_expectation": "deterministic",
			},
			"policy_version":         "2026-03-31",
			"expected_artifact_type": "static-script",
		},
		"workload_identity_binding": map[string]any{
			"artifact_class":       "service",
			"workload_type":        "service",
			"module_path":          "services.execution.ExecutionServer",
			"policy_version":       "2026-03-31",
			"service_name":         "execution",
			"target_platform":      "docker",
			"description":          "Execution workload",
			"workload_identity_id": stack.workloadIdentityID,
		},
	})

	response := doJSONRequest(
		t,
		stack.ags.Addr(),
		http.MethodPost,
		"/v1/artifacts:publish",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, "service/deployment", false),
		requestBody,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !stack.publishResponse.Published {
		t.Fatalf("expected published response")
	}
}

func buildStaticScriptArchive(t *testing.T) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)

	script := "#!/bin/sh\nset -eu\necho START-BANNER\nfor i in 1 2 3; do\n  echo HEARTBEAT:$i\n  sleep 2\ndone\necho \"{\\\"status\\\":\\\"ok\\\",\\\"artifact_digest\\\":\\\"${EXEC_ARTIFACT_DIGEST}\\\"}\"\n"
	scriptBytes := []byte(script)
	header := &tar.Header{
		Name:    "entrypoint",
		Mode:    0o755,
		Size:    int64(len(scriptBytes)),
		ModTime: time.Unix(0, 0),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tarWriter.Write(scriptBytes); err != nil {
		t.Fatalf("write tar payload: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return archiveBuffer.Bytes()
}

type nomadHarness struct {
	addr       string
	configPath string
	cmd        *exec.Cmd
	outputPath string
}

type nomadAllocationSummary struct {
	ID           string                    `json:"ID"`
	ClientStatus string                    `json:"ClientStatus"`
	TaskStates   map[string]nomadTaskState `json:"TaskStates"`
}

type nomadTaskState struct {
	State  string           `json:"State"`
	Failed bool             `json:"Failed"`
	Events []nomadTaskEvent `json:"Events"`
}

type nomadTaskEvent struct {
	Type     string `json:"Type"`
	ExitCode int    `json:"ExitCode"`
}

func (s nomadTaskState) exitCode() int {
	for i := len(s.Events) - 1; i >= 0; i-- {
		if s.Events[i].Type == "Terminated" {
			return s.Events[i].ExitCode
		}
	}
	return -1
}

func startNomadHarness(t *testing.T, rootDir string) *nomadHarness {
	t.Helper()

	httpPort := reserveTCPPort(t)
	rpcPort := reserveTCPPort(t)
	serfPort := reserveTCPPort(t)

	configPath := filepath.Join(rootDir, "nomad.hcl")
	dataDir := filepath.Join(rootDir, "nomad-data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir nomad data dir: %v", err)
	}
	config := fmt.Sprintf(`data_dir = %q
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
  http = %d
  rpc  = %d
  serf = %d
}
`, dataDir, httpPort, rpcPort, serfPort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write nomad config: %v", err)
	}

	outputPath := filepath.Join(rootDir, "nomad.log")
	logFile, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create nomad log file: %v", err)
	}

	cmd := exec.Command("nomad", "agent", "-dev", "-config="+configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start nomad agent: %v", err)
	}
	if err := logFile.Close(); err != nil {
		t.Fatalf("close nomad log file: %v", err)
	}

	harness := &nomadHarness{
		addr:       fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		configPath: configPath,
		cmd:        cmd,
		outputPath: outputPath,
	}
	harness.waitReady(t)
	return harness
}

func (n *nomadHarness) baseURL() string {
	return n.addr
}

func (n *nomadHarness) waitReady(t *testing.T) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		leaderResponse, leaderErr := client.Get(n.addr + "/v1/status/leader")
		if leaderErr == nil {
			var leader string
			decodeErr := json.NewDecoder(leaderResponse.Body).Decode(&leader)
			leaderResponse.Body.Close()
			if decodeErr == nil && strings.TrimSpace(strings.Trim(leader, `"`)) != "" {
				nodesResponse, nodesErr := client.Get(n.addr + "/v1/nodes")
				if nodesErr == nil {
					var nodes []struct {
						Status string `json:"status"`
					}
					decodeNodesErr := json.NewDecoder(nodesResponse.Body).Decode(&nodes)
					nodesResponse.Body.Close()
					if decodeNodesErr == nil && len(nodes) > 0 && nodes[0].Status == "ready" {
						return
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	output, _ := os.ReadFile(n.outputPath)
	t.Fatalf("nomad agent did not become ready; logs=%s", strings.TrimSpace(string(output)))
}

func (n *nomadHarness) waitForJob(t *testing.T, jobID string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID)
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nomad job %s did not appear", jobID)
}

func (n *nomadHarness) waitForTerminalAllocation(t *testing.T, jobID string) nomadAllocationSummary {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID + "/allocations")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var allocations []nomadAllocationSummary
		decodeErr := json.NewDecoder(response.Body).Decode(&allocations)
		response.Body.Close()
		if decodeErr == nil && len(allocations) > 0 {
			alloc := n.fetchAllocation(t, allocations[0].ID)
			switch alloc.ClientStatus {
			case "complete", "failed", "lost":
				return alloc
			}
			for _, taskState := range alloc.TaskStates {
				if taskState.Failed || taskState.State == "dead" {
					return alloc
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("nomad allocation for job %s did not reach a terminal state", jobID)
	return nomadAllocationSummary{}
}

func (n *nomadHarness) fetchAllocation(t *testing.T, allocationID string) nomadAllocationSummary {
	t.Helper()

	response, err := (&http.Client{Timeout: 2 * time.Second}).Get(n.addr + "/v1/allocation/" + allocationID)
	if err != nil {
		t.Fatalf("fetch allocation %s: %v", allocationID, err)
	}
	defer response.Body.Close()

	var payload nomadAllocationSummary
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode allocation %s: %v", allocationID, err)
	}
	return payload
}

func (n *nomadHarness) allocLogs(t *testing.T, allocationID string) string {
	t.Helper()

	command := exec.Command("nomad", "alloc", "logs", "-stdout", allocationID)
	command.Env = append(os.Environ(), "NOMAD_ADDR="+n.addr)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fetch allocation logs: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func (n *nomadHarness) shutdown(t *testing.T) {
	t.Helper()
	if n == nil || n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- n.cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	case <-done:
	}
}

func (s *submitStack) shutdownAll(t *testing.T) {
	t.Helper()
	for _, step := range []struct {
		running *bool
		name    string
		stop    func(context.Context) error
	}{
		{&s.esRunning, "es", func(ctx context.Context) error { return s.es.Shutdown(ctx) }},
		{&s.agsRunning, "ags", func(ctx context.Context) error { return s.ags.Shutdown(ctx) }},
		{&s.egsRunning, "egs", func(ctx context.Context) error { return s.egs.Shutdown(ctx) }},
		{&s.arsRunning, "ars", func(ctx context.Context) error { return s.ars.Shutdown(ctx) }},
		{&s.acsRunning, "acs", func(ctx context.Context) error { return s.acs.Shutdown(ctx) }},
	} {
		if step.running == nil || !*step.running {
			continue
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := step.stop(shutdownCtx)
		cancel()
		if err != nil {
			t.Fatalf("shutdown %s: %v", step.name, err)
		}
		*step.running = false
	}
	s.nomad.shutdown(t)
}

func newExecutionWorkspaceTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp(executionWorkspaceRoot, prefix)
	if err != nil {
		t.Fatalf("create workspace temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
