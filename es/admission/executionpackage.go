package admission

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	esconfig "execution-platform/es/config"
)

const (
	executionPayloadStageDirName   = "payload"
	executionRunStageDirName       = "run"
	executionMountsStageDirName    = "mounts"
	executionPayloadArchiveName    = "artifact.tar.gz"
	executionRuntimePayloadRoot    = "/monolith/staged"
	executionRuntimeRunRoot        = "/monolith/run"
	executionRuntimeWorkDir        = executionRuntimeRunRoot + "/work"
	executionRuntimeEntrypointPath = executionRuntimeWorkDir + "/entrypoint"
)

// executionPackageLayout localizes the current ES-owned mapping between a
// run-scoped host staging tree and the container-visible runtime layout used by
// the bounded submit slice.
type executionPackageLayout struct {
	runID              string
	stageRootDir       string
	payloadStageDir    string
	payloadArchivePath string
	runStageDir        string
	mountsStageRootDir string
	runtimePayloadRoot string
	runtimeRunRoot     string
	runtimeWorkDir     string
	runtimeEntrypoint  string
	runtimeIdentity    runtimeIdentityHandoff
}

type stagedExecutionInputs struct {
	layout executionPackageLayout
	mounts []stagedRuntimeMount
}

func newExecutionPackageLayout(cfg esconfig.Config, locator executionLocator) executionPackageLayout {
	stageRootDir := filepath.Join(cfg.Execution.StagingRootDir, locator.RunID)
	return executionPackageLayout{
		runID:              locator.RunID,
		stageRootDir:       stageRootDir,
		payloadStageDir:    filepath.Join(stageRootDir, executionPayloadStageDirName),
		payloadArchivePath: filepath.Join(stageRootDir, executionPayloadStageDirName, executionPayloadArchiveName),
		runStageDir:        filepath.Join(stageRootDir, executionRunStageDirName),
		mountsStageRootDir: filepath.Join(stageRootDir, executionMountsStageDirName),
		runtimePayloadRoot: executionRuntimePayloadRoot,
		runtimeRunRoot:     executionRuntimeRunRoot,
		runtimeWorkDir:     executionRuntimeWorkDir,
		runtimeEntrypoint:  executionRuntimeEntrypointPath,
		runtimeIdentity:    runtimeIdentityHandoffForRun(locator.RunID),
	}
}

func reservedExecutionRuntimePaths() []string {
	return []string{
		executionRuntimePayloadRoot,
		executionRuntimeRunRoot,
		runtimeIdentityWorkspaceRoot,
	}
}

func (l executionPackageLayout) stagePayload(payloadBytes []byte) error {
	if err := os.MkdirAll(l.payloadStageDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(l.runStageDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(l.payloadArchivePath, payloadBytes, 0o600); err != nil {
		return err
	}
	return nil
}

func (l executionPackageLayout) mountStageDir(index int) string {
	return filepath.Join(l.mountsStageRootDir, fmt.Sprintf("%02d", index))
}

func (l executionPackageLayout) mountArchivePath(index int) string {
	return filepath.Join(l.mountStageDir(index), executionPayloadArchiveName)
}

func (l executionPackageLayout) mountContentsDir(index int) string {
	return filepath.Join(l.mountStageDir(index), "contents")
}

func (l executionPackageLayout) runtimeWrapperScript() string {
	return strings.Join([]string{
		"set -eu",
		"mkdir -p " + l.runtimeWorkDir,
		"mkdir -p " + l.runtimeIdentity.workspaceDir(),
		"tar -xzf " + path.Join(l.runtimePayloadRoot, executionPayloadArchiveName) + " -C " + l.runtimeWorkDir,
		"chmod +x " + l.runtimeEntrypoint,
		"if [ \"$EXEC_TIMEOUT_SECONDS\" -gt 0 ]; then",
		"  exec timeout \"$EXEC_TIMEOUT_SECONDS\" " + l.runtimeEntrypoint + " \"$@\"",
		"fi",
		"exec " + l.runtimeEntrypoint + " \"$@\"",
	}, "\n")
}

func (l executionPackageLayout) runtimeMountSpecs(cfg esconfig.Config, stagedMounts []stagedRuntimeMount) []any {
	mounts := []any{
		map[string]any{
			"type":     "bind",
			"source":   l.payloadStageDir,
			"target":   l.runtimePayloadRoot,
			"readonly": true,
		},
		map[string]any{
			"type":     "bind",
			"source":   l.runStageDir,
			"target":   l.runtimeRunRoot,
			"readonly": false,
		},
		map[string]any{
			"type":     "tmpfs",
			"target":   l.runtimeIdentity.workspaceDir(),
			"readonly": false,
			"tmpfs_options": map[string]any{
				"size": cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
			},
		},
	}

	for _, mount := range stagedMounts {
		mounts = append(mounts, map[string]any{
			"type":     "bind",
			"source":   mount.sourceDir,
			"target":   mount.targetPath,
			"readonly": true,
		})
	}
	return mounts
}

func (s *Service) stageExecutionInputs(locator executionLocator, payloadBytes []byte) (stagedExecutionInputs, error) {
	layout := newExecutionPackageLayout(s.cfg, locator)
	if err := layout.stagePayload(payloadBytes); err != nil {
		return stagedExecutionInputs{}, err
	}
	return stagedExecutionInputs{
		layout: layout,
	}, nil
}
