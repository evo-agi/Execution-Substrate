package admission

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestExecutionPackageLayoutLocalizesStageAndRuntimePaths(t *testing.T) {
	cfg := esconfig.Config{
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             "/tmp/es-stage",
			ResultsRootDir:             "/tmp/es-results",
			RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
			RuntimeIdentityTmpfsSize:   2 << 20,
		},
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")

	layout := newExecutionPackageLayout(cfg, locator)

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
	supervisorArgs := layout.runtimeSupervisorArgs([]string{"--flag"}, 17)
	if len(supervisorArgs) < 9 {
		t.Fatalf("expected bounded supervisor args, got %#v", supervisorArgs)
	}
	if supervisorArgs[0] != "supervisor" {
		t.Fatalf("expected supervisor subcommand, got %#v", supervisorArgs)
	}
	if supervisorArgs[len(supervisorArgs)-1] != "--flag" {
		t.Fatalf("expected workload args to trail supervisor args, got %#v", supervisorArgs)
	}

	mounts := layout.runtimeMountSpecs(cfg, []stagedRuntimeMount{
		{
			sourceDir:  "/tmp/es-stage/run-0123456789abcdef/mounts/00/contents",
			targetPath: "/execution/mounts/config",
		},
	})
	if len(mounts) != 5 {
		t.Fatalf("expected payload, run, identity tmpfs, SPIRE socket, and staged runtime mounts, got %d", len(mounts))
	}
	spireMount, ok := mounts[3].(map[string]any)
	if !ok {
		t.Fatalf("expected SPIRE socket mount config, got %#v", mounts[3])
	}
	if spireMount["source"] != filepath.Dir(cfg.Execution.SPIREWorkloadAPISocketPath) {
		t.Fatalf("expected SPIRE socket source dir %q, got %#v", filepath.Dir(cfg.Execution.SPIREWorkloadAPISocketPath), spireMount["source"])
	}
	if spireMount["target"] != path.Join(layout.runtimeIdentity.internalDir(), runtimeIdentitySPIRESourceDir) {
		t.Fatalf("expected helper-private SPIRE source dir target under internal dir, got %#v", spireMount["target"])
	}
}

func TestStageWorkloadVaultTrustMaterialWritesVaultAndCombinedBundles(t *testing.T) {
	rootDir := t.TempDir()
	systemBundlePath := filepath.Join(rootDir, "system-ca.pem")
	if err := os.WriteFile(systemBundlePath, []byte("-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatalf("write system bundle: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", systemBundlePath)

	layout := executionPackageLayout{
		platformStageDir:   filepath.Join(rootDir, "stage", "run", "platform"),
		runtimePlatformDir: executionRuntimePlatformDir,
	}
	staged, err := layout.stageWorkloadVaultTrustMaterial(esconfig.ResolvedWorkloadVaultAuthPlan{
		CABundlePEM: "-----BEGIN CERTIFICATE-----\nvault\n-----END CERTIFICATE-----",
	}, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatalf("stage workload vault trust material: %v", err)
	}
	if !staged.vaultCACert || !staged.workloadTLSBundle {
		t.Fatalf("expected both trust material files to be staged, got %+v", staged)
	}

	vaultBundle, err := os.ReadFile(layout.workloadVaultCACertStagePath())
	if err != nil {
		t.Fatalf("read vault CA bundle: %v", err)
	}
	if strings.Count(string(vaultBundle), "BEGIN CERTIFICATE") != 1 || !strings.Contains(string(vaultBundle), "vault") {
		t.Fatalf("unexpected vault CA bundle: %q", string(vaultBundle))
	}

	combinedBundle, err := os.ReadFile(layout.workloadTLSBundleStagePath())
	if err != nil {
		t.Fatalf("read combined CA bundle: %v", err)
	}
	if !strings.Contains(string(combinedBundle), "system") || !strings.Contains(string(combinedBundle), "vault") {
		t.Fatalf("expected combined bundle to contain system and Vault material, got %q", string(combinedBundle))
	}
	if info, err := os.Stat(layout.platformStageDir); err != nil {
		t.Fatalf("stat platform stage dir: %v", err)
	} else if info.Mode().Perm() != stableStageDirMode {
		t.Fatalf("expected platform stage dir mode %o, got %o", stableStageDirMode, info.Mode().Perm())
	}
	if info, err := os.Stat(layout.workloadVaultCACertStagePath()); err != nil {
		t.Fatalf("stat vault CA bundle: %v", err)
	} else if info.Mode().Perm() != stableStageFileMode {
		t.Fatalf("expected vault CA bundle mode %o, got %o", stableStageFileMode, info.Mode().Perm())
	}
	if layout.workloadVaultCACertRuntimePath() != "/execution/run/platform/workload-vault-ca.pem" {
		t.Fatalf("unexpected runtime Vault CA path %q", layout.workloadVaultCACertRuntimePath())
	}
}
