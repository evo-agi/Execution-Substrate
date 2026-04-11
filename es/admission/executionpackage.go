package admission

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	esconfig "execution-substrate/es/config"
)

const (
	executionPayloadStageDirName   = "payload"
	executionRunStageDirName       = "run"
	executionResultStageDirName    = "result"
	executionMountsStageDirName    = "mounts"
	executionPayloadArchiveName    = "artifact.tar.gz"
	executionRuntimePayloadRoot    = "/execution/staged"
	executionRuntimeRunRoot        = "/execution/run"
	executionRuntimePlatformDir    = executionRuntimeRunRoot + "/platform"
	executionRuntimeWorkDir        = executionRuntimeRunRoot + "/work"
	executionRuntimeResultDir      = executionRuntimeRunRoot + "/result"
	executionRuntimeEntrypointPath = executionRuntimeWorkDir + "/entrypoint"
	executionRuntimeSupportName    = "es-runtime-support"
	executionRuntimeSupportPath    = executionRuntimePlatformDir + "/" + executionRuntimeSupportName
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
	platformStageDir   string
	resultStageDir     string
	runtimeSupportPath string
	mountsStageRootDir string
	runtimePayloadRoot string
	runtimeRunRoot     string
	runtimePlatformDir string
	runtimeWorkDir     string
	runtimeResultDir   string
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
		platformStageDir:   filepath.Join(stageRootDir, executionRunStageDirName, "platform"),
		resultStageDir:     filepath.Join(stageRootDir, executionRunStageDirName, executionResultStageDirName),
		runtimeSupportPath: filepath.Join(stageRootDir, executionRunStageDirName, "platform", executionRuntimeSupportName),
		mountsStageRootDir: filepath.Join(stageRootDir, executionMountsStageDirName),
		runtimePayloadRoot: executionRuntimePayloadRoot,
		runtimeRunRoot:     executionRuntimeRunRoot,
		runtimePlatformDir: executionRuntimePlatformDir,
		runtimeWorkDir:     executionRuntimeWorkDir,
		runtimeResultDir:   executionRuntimeResultDir,
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
	if err := os.MkdirAll(l.platformStageDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(l.resultStageDir, 0o755); err != nil {
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

func (l executionPackageLayout) runtimeSupervisorArgs(workloadArgv []string, timeoutSeconds int) []string {
	args := []string{
		"supervisor",
		"--payload-archive", filepath.ToSlash(pathJoin(l.runtimePayloadRoot, executionPayloadArchiveName)),
		"--work-dir", l.runtimeWorkDir,
		"--result-dir", l.runtimeResultDir,
		"--entrypoint", l.runtimeEntrypoint,
		"--timeout-seconds", strconv.Itoa(timeoutSeconds),
		"--",
	}
	return append(args, workloadArgv...)
}

func (l executionPackageLayout) stageRuntimeSupportBinary(sourcePath string) error {
	sourceFile, err := os.Open(filepath.Clean(sourcePath))
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.OpenFile(l.runtimeSupportPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}
	return destinationFile.Close()
}

func pathJoin(elements ...string) string {
	return filepath.ToSlash(filepath.Join(elements...))
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
		map[string]any{
			"type":     "bind",
			"source":   filepath.Dir(cfg.Execution.SPIREWorkloadAPISocketPath),
			"target":   l.runtimeIdentity.spireSourceDirPath(),
			"readonly": true,
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
	if err := layout.stageRuntimeSupportBinary(s.cfg.Execution.RuntimeSupportBinary); err != nil {
		return stagedExecutionInputs{}, err
	}
	return stagedExecutionInputs{
		layout: layout,
	}, nil
}
