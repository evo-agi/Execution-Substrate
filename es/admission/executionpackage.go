package admission

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

type resolvedRuntimeCommand struct {
	privateExecutionValue
	executable string
	arguments  []string
}

func newResolvedRuntimeCommand(workloadArgv []string, timeoutSeconds int) resolvedRuntimeCommand {
	arguments := []string{
		"supervisor",
		"--payload-archive", executionRuntimePayloadRoot + "/" + executionPayloadArchiveName,
		"--work-dir", executionRuntimeWorkDir,
		"--result-dir", executionRuntimeResultDir,
		"--entrypoint", executionRuntimeEntrypointPath,
		"--timeout-seconds", strconv.Itoa(timeoutSeconds),
		"--",
	}
	return resolvedRuntimeCommand{
		executable: executionRuntimeSupportPath,
		arguments:  append(arguments, workloadArgv...),
	}
}

func copyResolvedRuntimeCommand(command resolvedRuntimeCommand) resolvedRuntimeCommand {
	command.arguments = copyStringSlice(command.arguments)
	return command
}

func newExecutionPackageLayoutFromHost(host hostMaterializationContext, locator executionLocator) executionPackageLayout {
	stageRootDir := filepath.Join(host.stagingRootDir, locator.RunID)
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

func (l executionPackageLayout) stagePayload(custody *stagingCustody, payloadBytes []byte) error {
	for _, dir := range []string{
		executionPayloadStageDirName,
		executionRunStageDirName,
		executionRunStageDirName + "/platform",
		executionRunStageDirName + "/" + executionResultStageDirName,
	} {
		if err := custody.ensureDirectory(dir, stableStageDirMode); err != nil {
			return err
		}
	}
	return custody.writeFile(executionPayloadStageDirName+"/"+executionPayloadArchiveName, payloadBytes, retainedResultBundleFileMode)
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

func (l executionPackageLayout) stageWorkloadVaultTrustMaterial(custody *stagingCustody, material resolvedTrustMaterial) (stagedWorkloadTrustMaterial, error) {
	if len(material.vaultCACertBytes) == 0 && len(material.workloadTLSBundleBytes) == 0 {
		return stagedWorkloadTrustMaterial{}, nil
	}
	if len(material.vaultCACertBytes) == 0 || len(material.workloadTLSBundleBytes) == 0 {
		return stagedWorkloadTrustMaterial{}, fmt.Errorf("captured workload trust material is incomplete")
	}

	if err := custody.ensureDirectory(executionRunStageDirName+"/platform", stableStageDirMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := custody.writeFile(executionRunStageDirName+"/platform/"+executionWorkloadVaultCAName, material.vaultCACertBytes, stableStageFileMode); err != nil {
		return stagedWorkloadTrustMaterial{}, err
	}
	if err := custody.writeFile(executionRunStageDirName+"/platform/"+executionWorkloadTLSBundleName, material.workloadTLSBundleBytes, stableStageFileMode); err != nil {
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
	normalized := make([]byte, len(trimmed)+1)
	copy(normalized, trimmed)
	normalized[len(trimmed)] = '\n'
	return normalized
}

func normalizePEMBytesForRuntimeFile(value []byte) []byte {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		return nil
	}
	normalized := make([]byte, len(trimmed)+1)
	copy(normalized, trimmed)
	normalized[len(trimmed)] = '\n'
	return normalized
}

func appendNormalizedPEMBundle(base []byte, extra []byte) []byte {
	combined := make([]byte, 0, len(base)+len(extra)+1)
	combined = append(combined, base...)
	if len(combined) > 0 && len(extra) > 0 {
		combined = append(combined, '\n')
	}
	combined = append(combined, extra...)
	return combined
}

func readSystemCABundle() ([]byte, error) {
	if configured := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); configured != "" {
		content, err := captureStableRegularFile(configured, maxSystemCABundleBytes)
		if err != nil {
			return nil, fmt.Errorf("configured system CA bundle is not a stable bounded regular file: %w", err)
		}
		normalized := normalizePEMBytesForRuntimeFile(content)
		if len(normalized) == 0 || int64(len(normalized)) > maxSystemCABundleBytes {
			return nil, fmt.Errorf("configured system CA bundle is outside the governed limit")
		}
		return normalized, nil
	}

	for _, candidate := range systemCABundleCandidatePaths {
		content, err := captureStableRegularFile(candidate, maxSystemCABundleBytes)
		if err != nil {
			continue
		}
		normalized := normalizePEMBytesForRuntimeFile(content)
		if len(normalized) == 0 || int64(len(normalized)) > maxSystemCABundleBytes {
			continue
		}
		return normalized, nil
	}
	return nil, fmt.Errorf("system CA bundle not found for workload TLS bundle")
}

func (l executionPackageLayout) stageCapturedRuntimeSupportBinary(custody *stagingCustody, content []byte) error {
	return custody.writeFile(executionRunStageDirName+"/platform/"+executionRuntimeSupportName, content, stableStageExecFileMode)
}

func pathJoin(elements ...string) string {
	return filepath.ToSlash(filepath.Join(elements...))
}

func (l executionPackageLayout) runtimeMountSpecs(inputs resolvedRuntimeMountInputs, stagedMounts []stagedRuntimeMount) []any {
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
				"size": inputs.identityTmpfsSize,
			},
		},
		map[string]any{
			"type":     "bind",
			"source":   inputs.spireSourceDir,
			"target":   l.runtimeIdentity.spireSourceDirPath(),
			"readonly": true,
		},
	}

	for _, mount := range stagedMounts {
		mounts = append(mounts, map[string]any{
			"type":     "bind",
			"source":   mount.sourceDir,
			"target":   mount.targetPath,
			"readonly": mount.readOnly,
		})
	}
	return mounts
}

func materializeExecutionInputs(custody *stagingCustody, run resolvedRunProjection, material resolvedExecutionMaterial) (stagedExecutionInputs, *Error) {
	stage := stagedExecutionInputs{layout: run.layout}
	if err := stage.layout.stagePayload(custody, material.payloadBytes); err != nil {
		return stagedExecutionInputs{}, &Error{Status: http.StatusInternalServerError, Code: codeSubmissionFailed, Message: "stage artifact payload failed"}
	}
	if err := stage.layout.stageCapturedRuntimeSupportBinary(custody, material.runtimeSupportBytes); err != nil {
		return stagedExecutionInputs{}, &Error{Status: http.StatusInternalServerError, Code: codeSubmissionFailed, Message: "stage artifact payload failed"}
	}
	mounts, mountErr := materializeValidatedRuntimeMounts(custody, stage.layout, run.mounts, material.mounts)
	if mountErr != nil {
		return stagedExecutionInputs{}, mountErr
	}
	stage.mounts = mounts
	trustMaterial, trustErr := stage.layout.stageWorkloadVaultTrustMaterial(custody, material.trust)
	if trustErr != nil {
		return stagedExecutionInputs{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage workload vault trust material failed",
		}
	}
	stage.trustMaterial = trustMaterial
	return stage, nil
}
