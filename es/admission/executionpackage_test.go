package admission

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestTrancheB2TrustMaterializationCauseUsesFixedPublicError(t *testing.T) {
	const marker = "private-trust-location-uid-9123-env-secret"
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")

	var captured bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&captured)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	_, publicErr := materializeExecutionInputs(
		custody,
		resolvedRunProjection{layout: layout},
		resolvedExecutionMaterial{
			payloadBytes:        []byte("payload"),
			runtimeSupportBytes: []byte("runtime-support"),
			trust: resolvedTrustMaterial{
				vaultCACertBytes: []byte(marker),
			},
		},
	)
	trancheB2AssertFixedPublicError(t, publicErr, http.StatusInternalServerError, codeSubmissionFailed, "stage workload vault trust material failed", marker)
	if bytes.Contains(captured.Bytes(), []byte(marker)) {
		t.Fatalf("trust-material cause escaped into ordinary logs: %q", captured.String())
	}
}

// newExecutionPackageLayout is retained only as a test compatibility adapter
// for historical fixtures. Production layout construction accepts the frozen
// host context directly.
func newExecutionPackageLayout(cfg esconfig.Config, locator executionLocator) executionPackageLayout {
	return newExecutionPackageLayoutFromHost(hostMaterializationContext{stagingRootDir: cfg.Execution.StagingRootDir}, locator)
}

// stageExecutionInputs is a test-only compatibility adapter for the historical
// custody fixture. Production has one materialization path: Submit constructs
// the typed run/material projections and calls materializeExecutionInputs.
func (s *Service) stageExecutionInputs(locator executionLocator, payloadBytes []byte, owner executionPlatformStateOwner) (stagedExecutionInputs, error) {
	host := newHostMaterializationContext(
		s.cfg.Execution.StagingRootDir,
		s.cfg.Execution.ResultsRootDir,
		owner,
		path.Dir(s.cfg.Execution.SPIREWorkloadAPISocketPath),
		s.cfg.Nomad.Datacenter,
	)
	run := newResolvedRunProjection(newResolvedExecutionPlan(resolvedPlanFacts{}), host, locator)
	runtimeSupportBytes, _, err := captureRuntimeSupport(s.cfg.Execution.RuntimeSupportBinary)
	if err != nil {
		return stagedExecutionInputs{}, err
	}
	custody, err := claimStagingCustody(host.stagingRootDir, locator.RunID, owner)
	if err != nil {
		return stagedExecutionInputs{}, err
	}
	defer func() { _ = custody.close() }()
	stage, publicErr := materializeExecutionInputs(custody, run, resolvedExecutionMaterial{
		payloadBytes:        append([]byte(nil), payloadBytes...),
		runtimeSupportBytes: runtimeSupportBytes,
	})
	if publicErr != nil {
		return stagedExecutionInputs{}, publicErr
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		return stagedExecutionInputs{}, err
	}
	return stage, nil
}

func TestExecutionPackageLayoutLocalizesStageAndRuntimePaths(t *testing.T) {
	host := newHostMaterializationContext("/tmp/es-stage", "/tmp/es-results", executionPlatformStateOwner{}, "/run/spire/sockets", "dc1")
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")

	layout := newExecutionPackageLayoutFromHost(host, locator)

	if layout.stageRootDir != filepath.Join("/tmp/es-stage", locator.RunID) {
		t.Fatalf("expected run-scoped stage root, got %q", layout.stageRootDir)
	}
	if layout.payloadStageDir != filepath.Join(layout.stageRootDir, executionPayloadStageDirName) {
		t.Fatalf("expected payload stage dir under stage root, got %q", layout.payloadStageDir)
	}
	if layout.payloadArchivePath != filepath.Join(layout.payloadStageDir, executionPayloadArchiveName) {
		t.Fatalf("expected payload archive path under payload stage dir, got %q", layout.payloadArchivePath)
	}
	if layout.runStageDir != filepath.Join(layout.stageRootDir, executionRunStageDirName) {
		t.Fatalf("expected run stage dir under stage root, got %q", layout.runStageDir)
	}
	if layout.platformStageDir != filepath.Join(layout.runStageDir, "platform") {
		t.Fatalf("expected platform stage dir under run stage dir, got %q", layout.platformStageDir)
	}
	if layout.resultStageDir != filepath.Join(layout.runStageDir, executionResultStageDirName) {
		t.Fatalf("expected result stage dir under run stage dir, got %q", layout.resultStageDir)
	}
	if layout.runtimeSupportPath != filepath.Join(layout.platformStageDir, executionRuntimeSupportName) {
		t.Fatalf("expected runtime support binary staged under platform dir, got %q", layout.runtimeSupportPath)
	}
	if layout.mountsStageRootDir != filepath.Join(layout.stageRootDir, executionMountsStageDirName) {
		t.Fatalf("expected mounts stage root under stage root, got %q", layout.mountsStageRootDir)
	}
	if layout.runtimePayloadRoot != executionRuntimePayloadRoot {
		t.Fatalf("expected runtime payload root %q, got %q", executionRuntimePayloadRoot, layout.runtimePayloadRoot)
	}
	if layout.runtimeRunRoot != executionRuntimeRunRoot {
		t.Fatalf("expected runtime run root %q, got %q", executionRuntimeRunRoot, layout.runtimeRunRoot)
	}
	if layout.runtimePlatformDir != executionRuntimePlatformDir {
		t.Fatalf("expected runtime platform dir %q, got %q", executionRuntimePlatformDir, layout.runtimePlatformDir)
	}
	if layout.runtimeWorkDir != executionRuntimeWorkDir {
		t.Fatalf("expected runtime work dir %q, got %q", executionRuntimeWorkDir, layout.runtimeWorkDir)
	}
	if layout.runtimeResultDir != executionRuntimeResultDir {
		t.Fatalf("expected runtime result dir %q, got %q", executionRuntimeResultDir, layout.runtimeResultDir)
	}
	if layout.runtimeEntrypoint != executionRuntimeEntrypointPath {
		t.Fatalf("expected runtime entrypoint %q, got %q", executionRuntimeEntrypointPath, layout.runtimeEntrypoint)
	}
	mounts := layout.runtimeMountSpecs(resolvedRuntimeMountInputs{
		identityTmpfsSize: 2 << 20,
		spireSourceDir:    "/run/spire/sockets",
	}, []stagedRuntimeMount{
		{
			sourceDir:  "/tmp/es-stage/run-0123456789abcdef/mounts/00/contents",
			targetPath: "/execution/mounts/config",
			readOnly:   true,
		},
	})
	if len(mounts) != 5 {
		t.Fatalf("expected payload, run, identity tmpfs, SPIRE socket, and staged runtime mounts, got %d", len(mounts))
	}
	spireMount, ok := mounts[3].(map[string]any)
	if !ok {
		t.Fatal("expected SPIRE socket mount config")
	}
	if spireMount["source"] != "/run/spire/sockets" {
		t.Fatal("expected captured SPIRE socket source directory")
	}
	if spireMount["target"] != path.Join(layout.runtimeIdentity.internalDir(), runtimeIdentitySPIRESourceDir) {
		t.Fatal("expected helper-private SPIRE source-directory target")
	}
}

func TestTrancheB1ResolvedRuntimeCommandExactVectors(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		timeout int
		want    []string
	}{
		{
			name:    "empty argv",
			timeout: 0,
			want: []string{
				"supervisor",
				"--payload-archive", "/execution/staged/artifact.tar.gz",
				"--work-dir", "/execution/run/work",
				"--result-dir", "/execution/run/result",
				"--entrypoint", "/execution/run/work/entrypoint",
				"--timeout-seconds", "0",
				"--",
			},
		},
		{
			name:    "ordered argv and explicit timeout",
			argv:    []string{"first", "--second", "third"},
			timeout: 17,
			want: []string{
				"supervisor",
				"--payload-archive", "/execution/staged/artifact.tar.gz",
				"--work-dir", "/execution/run/work",
				"--result-dir", "/execution/run/result",
				"--entrypoint", "/execution/run/work/entrypoint",
				"--timeout-seconds", "17",
				"--",
				"first", "--second", "third",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			argv := append([]string(nil), test.argv...)
			command := newResolvedRuntimeCommand(argv, test.timeout)
			if command.executable != "/execution/run/platform/es-runtime-support" {
				t.Fatalf("unexpected executable %q", command.executable)
			}
			if !reflect.DeepEqual(command.arguments, test.want) {
				t.Fatalf("unexpected command arguments: got %#v want %#v", command.arguments, test.want)
			}
			if len(argv) > 0 {
				argv[0] = "mutated"
				if command.arguments[len(command.arguments)-len(argv)] == "mutated" {
					t.Fatal("typed command retained the caller argv")
				}
			}
			copied := copyResolvedRuntimeCommand(command)
			copied.arguments[0] = "mutated"
			if command.arguments[0] != "supervisor" {
				t.Fatal("typed command copy retained the source argument slice")
			}
		})
	}
}

func TestWorkloadTrustMaterialCaptureWritesVaultAndCombinedBundles(t *testing.T) {
	rootDir := physicalTestTempDir(t)
	systemBundlePath := filepath.Join(rootDir, "system-ca.pem")
	if err := os.WriteFile(systemBundlePath, []byte("-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal("write system bundle failed")
	}
	t.Setenv("SSL_CERT_FILE", systemBundlePath)

	stagingRoot := filepath.Join(rootDir, "stage")
	if err := os.Mkdir(stagingRoot, 0o700); err != nil {
		t.Fatal("create staging root failed")
	}
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	captured, err := captureWorkloadTrustMaterial(esconfig.ResolvedWorkloadVaultAuthPlan{
		CABundlePEM: "-----BEGIN CERTIFICATE-----\nvault\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatal("capture workload vault trust material failed")
	}
	expectedVaultDigest := digestBytes(captured.vaultCACertBytes)
	expectedCombinedDigest := digestBytes(captured.workloadTLSBundleBytes)
	if err := os.WriteFile(systemBundlePath, []byte("mutated-system-source"), 0o600); err != nil {
		t.Fatal("mutate system bundle source failed")
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(rootDir, "removed-system-source.pem"))
	if err := custody.ensureDirectory(executionRunStageDirName+"/platform", stableStageDirMode); err != nil {
		t.Fatal("create platform directory failed")
	}
	staged, err := layout.stageWorkloadVaultTrustMaterial(custody, captured)
	if err != nil {
		t.Fatal("stage workload vault trust material failed")
	}
	if !staged.vaultCACert || !staged.workloadTLSBundle {
		t.Fatal("expected both captured trust material files to be staged")
	}

	vaultBundle, err := os.ReadFile(layout.workloadVaultCACertStagePath())
	if err != nil {
		t.Fatal("read vault CA bundle failed")
	}
	if digestBytes(vaultBundle) != expectedVaultDigest {
		t.Fatal("staged Vault CA bytes changed after trust-source mutation")
	}

	combinedBundle, err := os.ReadFile(layout.workloadTLSBundleStagePath())
	if err != nil {
		t.Fatal("read combined CA bundle failed")
	}
	if digestBytes(combinedBundle) != expectedCombinedDigest {
		t.Fatal("staged combined trust bytes changed after trust-source mutation")
	}
	if info, err := os.Stat(layout.platformStageDir); err != nil {
		t.Fatal("stat platform stage dir failed")
	} else if info.Mode().Perm() != stableStageDirMode {
		t.Fatalf("expected platform stage dir mode %o, got %o", stableStageDirMode, info.Mode().Perm())
	}
	if info, err := os.Stat(layout.workloadVaultCACertStagePath()); err != nil {
		t.Fatal("stat vault CA bundle failed")
	} else if info.Mode().Perm() != stableStageFileMode {
		t.Fatalf("expected vault CA bundle mode %o, got %o", stableStageFileMode, info.Mode().Perm())
	}
	if layout.workloadVaultCACertRuntimePath() != "/execution/run/platform/workload-vault-ca.pem" {
		t.Fatalf("unexpected runtime Vault CA path %q", layout.workloadVaultCACertRuntimePath())
	}
}
