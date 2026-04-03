package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

const (
	workloadIdentityWorkspaceTargetDir = "/monolith/runtime-identity"
	workloadIdentityEndpointEnvKey     = "MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"
	workloadIdentityEndpointEnvValue   = "unix:///monolith/runtime-identity/endpoint"
	workloadIdentityEndpointTargetPath = "/monolith/runtime-identity/endpoint"
)

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

	job := stack.nomad.fetchJobDetail(t, payload.NomadJobID)
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "none" {
		t.Fatalf("expected network_mode=none for network_access=false, got %#v", networkMode)
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

func TestSubmitFlowUsesBridgeNetworkWhenNetworkAccessEnabled(t *testing.T) {
	stack := startSubmitStackWithNetworkAccess(t, true)

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

	job := stack.nomad.fetchJobDetail(t, payload.NomadJobID)
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "bridge" {
		t.Fatalf("expected network_mode=bridge for network_access=true, got %#v", networkMode)
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
}

func TestSubmitFlowInjectsWorkloadIdentityEndpointAndLifecycleStillWorks(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
		baseImage: "python:3.13-alpine",
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo "${MONOLITH_WORKLOAD_IDENTITY_ENDPOINT}"
echo "${MONOLITH_WORKLOAD_VAULT_AUTH_MODE}"
echo "IDENTITY-ENDPOINT-ENV-OK"
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	job := stack.nomad.fetchJobDetail(t, payload.NomadJobID)
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "none" {
		t.Fatalf("expected network_mode=none, got %#v", networkMode)
	}

	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], workloadIdentityWorkspaceTargetDir)
	if mountType := mountConfig["type"]; mountType != "tmpfs" {
		t.Fatalf("expected tmpfs runtime identity workspace mount, got %#v", mountType)
	}
	if _, ok := mountConfig["source"]; ok {
		t.Fatalf("did not expect host source for tmpfs runtime identity mount, got %#v", mountConfig["source"])
	}
	if readonly, ok := mountConfig["readonly"].(bool); !ok || readonly {
		t.Fatalf("expected writable runtime identity workspace mount, got %#v", mountConfig["readonly"])
	}
	tmpfsOptions, ok := mountConfig["tmpfs_options"].(map[string]any)
	if !ok {
		t.Fatalf("expected tmpfs_options for runtime identity mount, got %#v", mountConfig["tmpfs_options"])
	}
	if size := tmpfsOptions["size"]; size != float64(1<<20) && size != int64(1<<20) && size != int(1<<20) {
		t.Fatalf("expected default tmpfs size 1048576, got %#v", size)
	}

	taskConfig := job.task(t)
	if got := taskConfig.Env[workloadIdentityEndpointEnvKey]; got != workloadIdentityEndpointEnvValue {
		t.Fatalf("expected %s=%q, got %q", workloadIdentityEndpointEnvKey, workloadIdentityEndpointEnvValue, got)
	}

	stack.nomad.waitForJob(t, payload.NomadJobID)
	allocation := stack.nomad.waitForTerminalAllocation(t, payload.NomadJobID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	statusResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}

	logsResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer logsResponse.Body.Close()
	if logsResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from logs, got %d body=%s", logsResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, logsResponse.Body))))
	}

	logs := string(mustReadBody(t, logsResponse.Body))
	if !strings.Contains(logs, workloadIdentityEndpointEnvValue) || !strings.Contains(logs, "IDENTITY-ENDPOINT-ENV-OK") {
		t.Fatalf("expected workload identity endpoint env markers in logs, got %q", logs)
	}
	if !strings.Contains(logs, "vault_identity_jwt") {
		t.Fatalf("expected bounded auth mode marker in logs, got %q", logs)
	}
}

func TestWorkloadCanCreateAndUseLocalRuntimeIdentityEndpointFromTmpfsWorkspace(t *testing.T) {
	command := exec.Command(
		"docker", "run", "--rm",
		"--tmpfs", workloadIdentityWorkspaceTargetDir+":rw,size=1048576",
		"-e", workloadIdentityEndpointEnvKey+"="+workloadIdentityEndpointEnvValue,
		"python:3.13-alpine",
		"sh", "-lc",
		`python3 - <<'PY'
import os
import socket
import threading

endpoint = os.environ["MONOLITH_WORKLOAD_IDENTITY_ENDPOINT"]
if not endpoint.startswith("unix://"):
    raise SystemExit(f"unexpected endpoint: {endpoint}")
path = endpoint[len("unix://"):]
os.makedirs(os.path.dirname(path), exist_ok=True)
try:
    os.remove(path)
except FileNotFoundError:
    pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)

def serve():
    connection, _ = server.accept()
    connection.sendall(b"identity-ok\n")
    connection.close()
    server.close()

thread = threading.Thread(target=serve, daemon=True)
thread.start()

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(path)
print(client.recv(64).decode().strip())
client.close()
print("ENDPOINT-ACCESS-OK")
PY`,
	)
	output, err := command.CombinedOutput()
	logs := string(output)
	if err != nil {
		t.Fatalf("docker runtime identity workspace smoke failed: %v output=%s", err, strings.TrimSpace(logs))
	}
	if !strings.Contains(logs, "identity-ok") || !strings.Contains(logs, "ENDPOINT-ACCESS-OK") {
		t.Fatalf("expected workload identity endpoint access markers, got %q", logs)
	}
}

func TestSubmitFlowUsesConfiguredRuntimeIdentityTmpfsSize(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
		runtimeIdentityTmpfsSize: 2 << 20,
	})

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	job := stack.nomad.fetchJobDetail(t, payload.NomadJobID)
	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], workloadIdentityWorkspaceTargetDir)
	tmpfsOptions, ok := mountConfig["tmpfs_options"].(map[string]any)
	if !ok {
		t.Fatalf("expected tmpfs_options for runtime identity mount, got %#v", mountConfig["tmpfs_options"])
	}
	if size := tmpfsOptions["size"]; size != float64(2<<20) && size != int64(2<<20) && size != int(2<<20) {
		t.Fatalf("expected configured tmpfs size %d, got %#v", 2<<20, size)
	}
}

func TestSubmitFlowMountsGovernedArtifactAndLifecycleStillWorks(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
cat /monolith/mounts/config/app.conf
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`))

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "app.conf",
			Mode: 0o644,
			Body: []byte("MOUNT-CONTENT\n"),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source: admission.MountSource{
				ArtifactDigest: mountArtifact.ArtifactDigest,
			},
			TargetPath: "/monolith/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	job := stack.nomad.fetchJobDetail(t, payload.NomadJobID)
	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], "/monolith/mounts/config")
	if readonly, ok := mountConfig["readonly"].(bool); !ok || !readonly {
		t.Fatalf("expected readonly runtime mount config, got %#v", mountConfig["readonly"])
	}
	mountArchivePath := filepath.Join(stack.rootDir, "es-stage", payload.RunID, "mounts", "00", "artifact.tar.gz")
	if _, err := os.Stat(mountArchivePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected extracted runtime mount archive residue to be removed, got err=%v", err)
	}

	stack.nomad.waitForJob(t, payload.NomadJobID)
	allocation := stack.nomad.waitForTerminalAllocation(t, payload.NomadJobID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	statusResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}

	logsResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer logsResponse.Body.Close()
	if logsResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from logs, got %d body=%s", logsResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, logsResponse.Body))))
	}

	logs := string(mustReadBody(t, logsResponse.Body))
	if !strings.Contains(logs, "START-BANNER") || !strings.Contains(logs, "MOUNT-CONTENT") {
		t.Fatalf("expected mounted content in logs, got %q", logs)
	}
}

func TestSubmitRejectsMountArtifactWithPathTraversalArchive(t *testing.T) {
	stack := startSubmitStack(t)

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "../escape",
			Mode: 0o644,
			Body: []byte("nope"),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/monolith/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

func TestSubmitRejectsMountArtifactWithSymlinkEscape(t *testing.T) {
	stack := startSubmitStack(t)

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name:     "link",
			Typeflag: tar.TypeSymlink,
			Linkname: "/etc/passwd",
			Mode:     0o777,
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/monolith/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

func TestSubmitRejectsMountArtifactThatExceedsSizeLimit(t *testing.T) {
	stack := startSubmitStack(t)

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "large.bin",
			Mode: 0o644,
			Body: bytes.Repeat([]byte("a"), 9<<20),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/monolith/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

func TestSubmitRejectsOverlappingMountTargets(t *testing.T) {
	stack := startSubmitStack(t)

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: stack.publishResponse.ArtifactDigest},
			TargetPath: "/monolith/mounts/config",
			ReadOnly:   true,
		},
		{
			Source:     admission.MountSource{ArtifactDigest: stack.publishResponse.ArtifactDigest},
			TargetPath: "/monolith/mounts/config/sub",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_conflict")
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

type submitStackOptions struct {
	networkAccess            bool
	baseImage                string
	runtimeIdentityTmpfsSize int64
}

func startSubmitStack(t *testing.T) *submitStack {
	return startSubmitStackWithOptions(t, submitStackOptions{})
}

func startSubmitStackWithNetworkAccess(t *testing.T, networkAccess bool) *submitStack {
	return startSubmitStackWithOptions(t, submitStackOptions{networkAccess: networkAccess})
}

func startSubmitStackWithOptions(t *testing.T, opts submitStackOptions) *submitStack {
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
			StagingRootDir:           filepath.Join(rootDir, "es-stage"),
			BaseImage:                firstNonEmpty(opts.baseImage, "alpine:3.20"),
			RuntimeIdentityTmpfsSize: opts.runtimeIdentityTmpfsSize,
		},
	}
	esService, err := esapp.New(esCfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = esService
	startService(t, esService.Start, esService.Addr, fixture.serverTLSConfig(t, fixture.esServerName))
	stack.esRunning = true

	publishSubmitArtifact(t, stack, opts.networkAccess)

	t.Cleanup(func() { stack.shutdownAll(t) })
	return stack
}

func firstNonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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

func buildSubmitRequestBodyWithMounts(t *testing.T, stack *submitStack, mounts []admission.RuntimeMount) []byte {
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
			Mounts: mounts,
		},
		Mode: admission.ExecutionModeAsync,
		Resources: &admission.ExecutionResources{
			CPU:      10,
			MemoryMB: 128,
		},
	})
}

func publishSubmitArtifact(t *testing.T, stack *submitStack, networkAccess bool) {
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
				"network_access":          networkAccess,
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

type archiveEntry struct {
	Name     string
	Mode     int64
	Body     []byte
	Typeflag byte
	Linkname string
}

func buildArchiveWithEntries(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, entry := range entries {
		typeflag := entry.Typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.Name,
			Mode:     entry.Mode,
			Size:     int64(len(entry.Body)),
			Typeflag: typeflag,
			Linkname: entry.Linkname,
			ModTime:  time.Unix(0, 0),
		}
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(entry.Body); err != nil {
				t.Fatalf("write tar payload: %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return archiveBuffer.Bytes()
}

func publishAuxiliaryArtifactArchive(t *testing.T, stack *submitStack, archive []byte, artifactType string) submitPublishResponse {
	t.Helper()

	requestBody := mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(archive),
		"manifest": map[string]any{
			"artifact_type": artifactType,
			"intent_digest": labeledDigest("f1"),
			"runtime_interface": map[string]any{
				"parameters":            []string{},
				"environment_variables": []string{},
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
			"build_log_digest": labeledDigest("f2"),
		},
		"derivation_metadata": map[string]any{
			"derivation_spec_digest": labeledDigest("f3"),
			"output_id":              "mount-output",
			"producer_run_id":        "build-run-mount",
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
			"policy_version":         "2026-04-02",
			"expected_artifact_type": artifactType,
		},
		"workload_identity_binding": map[string]any{
			"artifact_class":       "service",
			"workload_type":        "service",
			"module_path":          "services.execution.ExecutionServer",
			"policy_version":       "2026-04-02",
			"service_name":         "execution",
			"target_platform":      "docker",
			"description":          "Mounted runtime artifact",
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

	var payload submitPublishResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !payload.Published {
		t.Fatalf("expected auxiliary publish response")
	}
	return payload
}

func submitExecutionRequest(t *testing.T, stack *submitStack, requestBody []byte) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		requestBody,
	)
}

func assertErrorResponseCode(t *testing.T, response *http.Response, expectedStatus int, expectedCode string) {
	t.Helper()

	body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
	if response.StatusCode != expectedStatus {
		t.Fatalf("expected %d, got %d body=%s", expectedStatus, response.StatusCode, body)
	}

	var payload admission.ErrorResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, body)
	}
	if payload.Code != expectedCode {
		t.Fatalf("expected error code %q, got %q body=%s", expectedCode, payload.Code, body)
	}
}

func findTaskMountByTarget(t *testing.T, rawMounts any, target string) map[string]any {
	t.Helper()

	mounts, ok := rawMounts.([]any)
	if !ok {
		t.Fatalf("expected []any mounts config, got %#v", rawMounts)
	}
	for _, candidate := range mounts {
		mountConfig, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		if mountTarget, ok := mountConfig["target"].(string); ok && mountTarget == target {
			return mountConfig
		}
	}
	t.Fatalf("expected mount targeting %q in %#v", target, rawMounts)
	return nil
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

type nomadJobDetail struct {
	TaskGroups []nomadTaskGroupDetail `json:"TaskGroups"`
}

type nomadTaskGroupDetail struct {
	Tasks []nomadTaskDetail `json:"Tasks"`
}

type nomadTaskDetail struct {
	Name   string            `json:"Name"`
	Config map[string]any    `json:"Config"`
	Env    map[string]string `json:"Env"`
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

func (n *nomadHarness) fetchJobDetail(t *testing.T, jobID string) nomadJobDetail {
	t.Helper()

	response, err := (&http.Client{Timeout: 2 * time.Second}).Get(n.addr + "/v1/job/" + jobID)
	if err != nil {
		t.Fatalf("fetch job %s: %v", jobID, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("fetch job %s: unexpected status %d body=%s", jobID, response.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload nomadJobDetail
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode job %s: %v", jobID, err)
	}
	return payload
}

func (j nomadJobDetail) taskConfig(t *testing.T) map[string]any {
	t.Helper()

	return j.task(t).Config
}

func (j nomadJobDetail) task(t *testing.T) nomadTaskDetail {
	t.Helper()

	if len(j.TaskGroups) == 0 {
		t.Fatalf("expected at least one task group in job")
	}
	if len(j.TaskGroups[0].Tasks) == 0 {
		t.Fatalf("expected at least one task in job")
	}
	return j.TaskGroups[0].Tasks[0]
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

	_, filePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve test file path: runtime caller unavailable")
	}
	workspaceRoot := filepath.Clean(filepath.Join(filepath.Dir(filePath), "..", ".."))

	dir, err := os.MkdirTemp(workspaceRoot, prefix)
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
