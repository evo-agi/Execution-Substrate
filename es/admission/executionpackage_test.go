package admission

import (
	"path"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-platform/es/config"
)

func TestExecutionPackageLayoutLocalizesStageAndRuntimePaths(t *testing.T) {
	cfg := esconfig.Config{
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:           "/tmp/es-stage",
			RuntimeIdentityTmpfsSize: 2 << 20,
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
	if layout.mountsStageRootDir != filepath.Join(layout.stageRootDir, executionMountsStageDirName) {
		t.Fatalf("expected mounts stage root under stage root, got %q", layout.mountsStageRootDir)
	}
	if layout.runtimePayloadRoot != executionRuntimePayloadRoot {
		t.Fatalf("expected runtime payload root %q, got %q", executionRuntimePayloadRoot, layout.runtimePayloadRoot)
	}
	if layout.runtimeRunRoot != executionRuntimeRunRoot {
		t.Fatalf("expected runtime run root %q, got %q", executionRuntimeRunRoot, layout.runtimeRunRoot)
	}
	if layout.runtimeWorkDir != executionRuntimeWorkDir {
		t.Fatalf("expected runtime work dir %q, got %q", executionRuntimeWorkDir, layout.runtimeWorkDir)
	}
	if layout.runtimeEntrypoint != executionRuntimeEntrypointPath {
		t.Fatalf("expected runtime entrypoint %q, got %q", executionRuntimeEntrypointPath, layout.runtimeEntrypoint)
	}

	wrapper := layout.runtimeWrapperScript()
	if !strings.Contains(wrapper, "tar -xzf "+path.Join(executionRuntimePayloadRoot, executionPayloadArchiveName)+" -C "+executionRuntimeWorkDir) {
		t.Fatalf("expected wrapper to unpack staged payload through the localized runtime layout, got %q", wrapper)
	}
	if !strings.Contains(wrapper, "exec "+executionRuntimeEntrypointPath+" \"$@\"") {
		t.Fatalf("expected wrapper to execute the localized runtime entrypoint, got %q", wrapper)
	}

	mounts := layout.runtimeMountSpecs(cfg, []stagedRuntimeMount{
		{
			sourceDir:  "/tmp/es-stage/run-0123456789abcdef/mounts/00/contents",
			targetPath: "/execution/mounts/config",
		},
	})
	if len(mounts) != 4 {
		t.Fatalf("expected payload, run, identity, and staged runtime mounts, got %d", len(mounts))
	}
}
