package admission

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	executionWorkloadVaultCAName   = "workload-vault-ca.pem"
	executionWorkloadTLSBundleName = "workload-ca-bundle.pem"
)

var systemCABundleCandidatePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/ca-bundle.pem",
}

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
	layout        executionPackageLayout
	mounts        []stagedRuntimeMount
	trustMaterial stagedWorkloadTrustMaterial
}

type stagedWorkloadTrustMaterial struct {
	vaultCACert       bool
	workloadTLSBundle bool
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

func (l executionPackageLayout) stagePayload(payloadBytes []byte, owner executionPlatformStateOwner) error {
	for _, dir := range []string{l.stageRootDir, l.payloadStageDir, l.runStageDir, l.platformStageDir, l.resultStageDir} {
		if err := ensureOwnedDirectory(dir, stableStageDirMode, owner); err != nil {
			return err
		}
	}
	if err := os.WriteFile(l.payloadArchivePath, payloadBytes, retainedResultBundleFileMode); err != nil {
		return err
	}
	return reconcileOwnedPath(l.payloadArchivePath, owner, retainedResultBundleFileMode)
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

func (l executionPackageLayout) workloadVaultCACertStagePath() string {
	return filepath.Join(l.platformStageDir, executionWorkloadVaultCAName)
}

func (l executionPackageLayout) workloadTLSBundleStagePath() string {
	return filepath.Join(l.platformStageDir, executionWorkloadTLSBundleName)
}

func (l executionPackageLayout) workloadVaultCACertRuntimePath() string {
	return pathJoin(l.runtimePlatformDir, executionWorkloadVaultCAName)
}

func (l executionPackageLayout) workloadTLSBundleRuntimePath() string {
	return pathJoin(l.runtimePlatformDir, executionWorkloadTLSBundleName)
}

func (l executionPackageLayout) stageWorkloadVaultTrustMaterial(plan esconfig.ResolvedWorkloadVaultAuthPlan, owner executionPlatformStateOwner) (stagedWorkloadTrustMaterial, error) {
	caBundle := normalizePEMForRuntimeFile(plan.CABundlePEM)
	if len(caBundle) == 0 {
		return stagedWorkloadTrustMaterial{}, nil
	}
	systemBundle, err := readSystemCABundle()
	if err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}

	if err := ensureOwnedDirectory(l.platformStageDir, stableStageDirMode, owner); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := os.WriteFile(l.workloadVaultCACertStagePath(), caBundle, stableStageFileMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := reconcileOwnedPath(l.workloadVaultCACertStagePath(), owner, stableStageFileMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := os.WriteFile(l.workloadTLSBundleStagePath(), appendPEMBundle(systemBundle, caBundle), stableStageFileMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := reconcileOwnedPath(l.workloadTLSBundleStagePath(), owner, stableStageFileMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	return stagedWorkloadTrustMaterial{
		vaultCACert:       true,
		workloadTLSBundle: true,
	}, nil
}

func normalizePEMForRuntimeFile(value string) []byte {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return []byte(trimmed + "\n")
}

func appendPEMBundle(base []byte, extra []byte) []byte {
	normalizedBase := normalizePEMForRuntimeFile(string(base))
	normalizedExtra := normalizePEMForRuntimeFile(string(extra))
	combined := make([]byte, 0, len(normalizedBase)+len(normalizedExtra)+1)
	combined = append(combined, normalizedBase...)
	if len(combined) > 0 && len(normalizedExtra) > 0 {
		combined = append(combined, '\n')
	}
	combined = append(combined, normalizedExtra...)
	return combined
}

func readSystemCABundle() ([]byte, error) {
	candidates := make([]string, 0, len(systemCABundleCandidatePaths)+1)
	if configured := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates, systemCABundleCandidatePaths...)

	for _, candidate := range candidates {
		content, err := os.ReadFile(filepath.Clean(candidate))
		if err != nil || len(strings.TrimSpace(string(content))) == 0 {
			continue
		}
		return content, nil
	}
	return nil, fmt.Errorf("system CA bundle not found for workload TLS bundle")
}

func (l executionPackageLayout) stageRuntimeSupportBinary(sourcePath string, owner executionPlatformStateOwner) error {
	sourceFile, err := os.Open(filepath.Clean(sourcePath))
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.OpenFile(l.runtimeSupportPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, stableStageExecFileMode)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}
	if err := destinationFile.Close(); err != nil {
		return err
	}
	return reconcileOwnedPath(l.runtimeSupportPath, owner, stableStageExecFileMode)
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

func (s *Service) stageExecutionInputs(locator executionLocator, payloadBytes []byte, owner executionPlatformStateOwner) (stagedExecutionInputs, error) {
	layout := newExecutionPackageLayout(s.cfg, locator)
	if err := layout.stagePayload(payloadBytes, owner); err != nil {
		return stagedExecutionInputs{}, err
	}
	if err := layout.stageRuntimeSupportBinary(s.cfg.Execution.RuntimeSupportBinary, owner); err != nil {
		return stagedExecutionInputs{}, err
	}
	return stagedExecutionInputs{
		layout: layout,
	}, nil
}
