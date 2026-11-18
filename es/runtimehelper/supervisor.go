package runtimehelper

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"execution-substrate/es/internal/ownershipnorm"
	"execution-substrate/es/internal/staticarchive"
)

const (
	helperReadinessTimeout         = 10 * time.Second
	processKillTimeout             = 5 * time.Second
	workloadTimeoutExit            = 124
	markerFileMode                 = 0o640
	activeRunTraversalDirMode      = 0o711
	activePlatformTraversalDirMode = 0o711
	activeTrustFileMode            = 0o644
	normalizedDirMode              = 0o750
	normalizedFileMode             = 0o640
	normalizedExecFileMode         = 0o750
	platformStateOwnerUIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_UID"
	platformStateOwnerGIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_GID"
	platformStateOwnerSchemaEnvKey = "EXEC_PLATFORM_STATE_OWNER_SCHEMA"
	platformStateOwnerSchemaV1     = "v1"
)

var writeMarkerFile = os.WriteFile

func runSupervisor(args []string) error {
	cfg, err := parseSupervisorArgs(args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("runtime supervisor must start as 0:0")
	}

	paths, err := runtimePathsFromEnvironment()
	if err != nil {
		return err
	}
	if err := prepareRuntimeFilesystem(cfg, paths); err != nil {
		return err
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve runtime support path: %w", err)
	}

	helperCmd := exec.Command(executablePath, "helper")
	helperCmd.Stdout = os.Stdout
	helperCmd.Stderr = os.Stderr
	helperCmd.Env = os.Environ()
	if err := helperCmd.Start(); err != nil {
		return fmt.Errorf("start runtime identity helper: %w", err)
	}
	helperErrCh := make(chan error, 1)
	go func() {
		helperErrCh <- helperCmd.Wait()
	}()

	if err := waitForHelperReadiness(paths.endpointPath, helperErrCh); err != nil {
		terminateProcess(helperCmd.Process)
		return err
	}

	workloadArgs := append([]string{"exec-workload", "--entrypoint", cfg.entrypoint, "--work-dir", cfg.workDir, "--"}, cfg.workloadArgv...)
	workloadCmd := exec.Command(executablePath, workloadArgs...)
	workloadCmd.Stdout = os.Stdout
	workloadCmd.Stderr = os.Stderr
	workloadCmd.Env = os.Environ()
	if err := workloadCmd.Start(); err != nil {
		terminateProcess(helperCmd.Process)
		<-helperErrCh
		return fmt.Errorf("start workload process: %w", err)
	}
	workloadErrCh := make(chan error, 1)
	go func() {
		workloadErrCh <- workloadCmd.Wait()
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	var timeoutCh <-chan time.Time
	if cfg.timeoutSeconds > 0 {
		timeoutCh = time.After(time.Duration(cfg.timeoutSeconds) * time.Second)
	}

	for {
		select {
		case helperErr := <-helperErrCh:
			terminateProcess(workloadCmd.Process)
			<-workloadErrCh
			if helperErr == nil {
				return fmt.Errorf("runtime identity helper exited unexpectedly")
			}
			return fmt.Errorf("runtime identity helper exited: %w", helperErr)
		case workloadErr := <-workloadErrCh:
			workloadOutcome := workloadExitError(workloadErr)
			normalizationErr := postWorkloadNormalizationPhase(cfg)
			terminateProcess(helperCmd.Process)
			<-helperErrCh
			return combineWorkloadAndNormalizationError(workloadOutcome, normalizationErr)
		case sig := <-signalCh:
			terminateProcess(workloadCmd.Process)
			terminateProcess(helperCmd.Process)
			<-workloadErrCh
			<-helperErrCh
			return newExitError(128+int(sig.(syscall.Signal)), fmt.Errorf("received %s", sig.String()))
		case <-timeoutCh:
			terminateProcess(workloadCmd.Process)
			terminateProcess(helperCmd.Process)
			<-workloadErrCh
			<-helperErrCh
			return newExitError(workloadTimeoutExit, fmt.Errorf("workload timed out after %d seconds", cfg.timeoutSeconds))
		}
	}
}

type supervisorConfig struct {
	payloadArchive string
	workDir        string
	resultDir      string
	entrypoint     string
	timeoutSeconds int
	workloadArgv   []string
}

func parseSupervisorArgs(args []string) (supervisorConfig, error) {
	fs := flag.NewFlagSet("supervisor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := supervisorConfig{}
	fs.StringVar(&cfg.payloadArchive, "payload-archive", "", "path to the staged workload archive")
	fs.StringVar(&cfg.workDir, "work-dir", "", "path to the workload runtime directory")
	fs.StringVar(&cfg.resultDir, "result-dir", "", "path to the workload result directory")
	fs.StringVar(&cfg.entrypoint, "entrypoint", "", "path to the runtime entrypoint")
	fs.IntVar(&cfg.timeoutSeconds, "timeout-seconds", 0, "maximum workload execution time in seconds")
	if err := fs.Parse(args); err != nil {
		return supervisorConfig{}, err
	}
	if strings.TrimSpace(cfg.payloadArchive) == "" {
		return supervisorConfig{}, fmt.Errorf("--payload-archive is required")
	}
	if strings.TrimSpace(cfg.workDir) == "" {
		return supervisorConfig{}, fmt.Errorf("--work-dir is required")
	}
	if strings.TrimSpace(cfg.resultDir) == "" {
		return supervisorConfig{}, fmt.Errorf("--result-dir is required")
	}
	if strings.TrimSpace(cfg.entrypoint) == "" {
		return supervisorConfig{}, fmt.Errorf("--entrypoint is required")
	}
	cfg.workloadArgv = fs.Args()
	return cfg, nil
}

func prepareRuntimeFilesystem(cfg supervisorConfig, paths runtimePaths) error {
	targetUID, targetGID, err := runtimePlatformStateOwner()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.workspaceRoot, 0o711); err != nil {
		return fmt.Errorf("create runtime identity workspace root: %w", err)
	}
	if err := os.Chown(paths.workspaceRoot, 0, 0); err != nil {
		return fmt.Errorf("chown runtime identity workspace root: %w", err)
	}
	if err := os.Chmod(paths.workspaceRoot, 0o711); err != nil {
		return fmt.Errorf("chmod runtime identity workspace root: %w", err)
	}
	if err := os.MkdirAll(paths.workspaceDir, 0o711); err != nil {
		return fmt.Errorf("create runtime identity workspace: %w", err)
	}
	if err := os.Chown(paths.workspaceDir, 0, 0); err != nil {
		return fmt.Errorf("chown runtime identity workspace: %w", err)
	}
	if err := os.Chmod(paths.workspaceDir, 0o711); err != nil {
		return fmt.Errorf("chmod runtime identity workspace: %w", err)
	}
	if err := os.MkdirAll(paths.internalDir, 0o700); err != nil {
		return fmt.Errorf("create runtime identity internal dir: %w", err)
	}
	if err := os.Chown(paths.internalDir, 0, 0); err != nil {
		return fmt.Errorf("chown runtime identity internal dir: %w", err)
	}
	if err := os.Chmod(paths.internalDir, 0o700); err != nil {
		return fmt.Errorf("chmod runtime identity internal dir: %w", err)
	}
	if err := materializeHelperPrivateSPIRESocket(paths); err != nil {
		return err
	}

	platformDir := filepath.Join(filepath.Dir(cfg.workDir), "platform")
	if err := validateStablePlatformDir(platformDir, targetUID, targetGID); err != nil {
		return fmt.Errorf("validate platform runtime dir: %w", err)
	}
	if err := prepareActiveWorkloadVisibility(cfg.workDir, platformDir); err != nil {
		return err
	}

	if err := prepareResultDir(cfg.resultDir); err != nil {
		return err
	}

	if err := os.RemoveAll(cfg.workDir); err != nil {
		return fmt.Errorf("clear workload runtime dir: %w", err)
	}
	if err := os.MkdirAll(cfg.workDir, 0o755); err != nil {
		return fmt.Errorf("create workload runtime dir: %w", err)
	}
	if err := extractWorkloadArchive(cfg.payloadArchive, cfg.workDir); err != nil {
		return err
	}
	if err := sanitizeWorkloadTree(cfg.workDir); err != nil {
		return err
	}
	if err := os.Chmod(cfg.entrypoint, 0o755); err != nil {
		return fmt.Errorf("chmod workload entrypoint: %w", err)
	}
	return nil
}

func prepareResultDir(resultDir string) error {
	if err := os.RemoveAll(resultDir); err != nil {
		return fmt.Errorf("clear workload result dir: %w", err)
	}
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		return fmt.Errorf("create workload result dir: %w", err)
	}
	if err := os.Chown(resultDir, workloadUID, workloadGID); err != nil {
		return fmt.Errorf("chown workload result dir: %w", err)
	}
	if err := os.Chmod(resultDir, 0o755); err != nil {
		return fmt.Errorf("chmod workload result dir: %w", err)
	}
	return nil
}

func prepareActiveWorkloadVisibility(workDir string, platformDir string) error {
	runRoot := filepath.Dir(workDir)
	if err := os.Chmod(runRoot, activeRunTraversalDirMode); err != nil {
		return fmt.Errorf("prepare workload traversal for run root: %w", err)
	}

	workloadTrustPaths, err := workloadVisibleTrustPaths(platformDir)
	if err != nil {
		return err
	}
	if len(workloadTrustPaths) == 0 {
		return nil
	}
	if err := os.Chmod(platformDir, activePlatformTraversalDirMode); err != nil {
		return fmt.Errorf("prepare workload traversal for platform dir: %w", err)
	}
	for _, trustPath := range workloadTrustPaths {
		info, err := os.Lstat(trustPath)
		if err != nil {
			return fmt.Errorf("prepare workload trust file %s: %w", trustPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("prepare workload trust file %s: symlinks are unsupported", trustPath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("prepare workload trust file %s: path is not a regular file", trustPath)
		}
		if err := os.Chmod(trustPath, activeTrustFileMode); err != nil {
			return fmt.Errorf("prepare workload trust file %s: %w", trustPath, err)
		}
	}
	return nil
}

func workloadVisibleTrustPaths(platformDir string) ([]string, error) {
	cleanPlatformDir := filepath.Clean(platformDir)
	seen := map[string]struct{}{}
	paths := make([]string, 0, 2)
	for _, envKey := range []string{"VAULT_CACERT", "SSL_CERT_FILE"} {
		value := strings.TrimSpace(os.Getenv(envKey))
		if value == "" {
			continue
		}
		cleanValue := filepath.Clean(value)
		if cleanValue == cleanPlatformDir {
			continue
		}
		if filepath.Dir(cleanValue) != cleanPlatformDir {
			return nil, fmt.Errorf("%s must remain under %s", envKey, cleanPlatformDir)
		}
		if _, ok := seen[cleanValue]; ok {
			continue
		}
		seen[cleanValue] = struct{}{}
		paths = append(paths, cleanValue)
	}
	sort.Strings(paths)
	return paths, nil
}

func postWorkloadNormalizationPhase(cfg supervisorConfig) error {
	targetUID, targetGID, err := runtimePlatformStateOwner()
	if err != nil {
		return err
	}
	if targetUID < 0 || targetGID < 0 {
		return fmt.Errorf("runtime normalization target owner is invalid")
	}

	runID, err := requireEnv("EXEC_RUN_ID")
	if err != nil {
		return err
	}
	platformDir := filepath.Join(filepath.Dir(cfg.workDir), "platform")
	if err := normalizePostWorkloadTree(platformDir, targetUID, targetGID); err != nil {
		return fmt.Errorf("normalize platform runtime dir: %w", err)
	}
	if err := normalizePostWorkloadTree(cfg.workDir, targetUID, targetGID); err != nil {
		return fmt.Errorf("normalize workload runtime dir: %w", err)
	}
	if err := normalizePostWorkloadTree(cfg.resultDir, targetUID, targetGID); err != nil {
		return fmt.Errorf("normalize workload result dir: %w", err)
	}
	if err := restoreStableRunRoot(filepath.Dir(cfg.workDir), targetUID, targetGID); err != nil {
		return fmt.Errorf("normalize runtime run dir: %w", err)
	}
	if err := writeOwnershipNormalizationMarker(platformDir, strings.TrimSpace(runID), targetUID, targetGID); err != nil {
		return fmt.Errorf("write ownership-normalization marker: %w", err)
	}
	return nil
}

func restoreStableRunRoot(runRoot string, targetUID int, targetGID int) error {
	info, err := os.Lstat(runRoot)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}
	if err := os.Lchown(runRoot, targetUID, targetGID); err != nil {
		return fmt.Errorf("set ownership on %s: %w", runRoot, err)
	}
	if err := os.Chmod(runRoot, normalizedDirMode); err != nil {
		return fmt.Errorf("set directory mode on %s: %w", runRoot, err)
	}
	return nil
}

func runtimePlatformStateOwner() (int, int, error) {
	targetUID := os.Geteuid()
	targetGID := os.Getegid()

	schemaValue := strings.TrimSpace(os.Getenv(platformStateOwnerSchemaEnvKey))
	uidValue := strings.TrimSpace(os.Getenv(platformStateOwnerUIDEnvKey))
	gidValue := strings.TrimSpace(os.Getenv(platformStateOwnerGIDEnvKey))
	if schemaValue == "" && uidValue == "" && gidValue == "" {
		return targetUID, targetGID, nil
	}
	if schemaValue != platformStateOwnerSchemaV1 {
		return 0, 0, fmt.Errorf("runtime platform state owner schema must be %q", platformStateOwnerSchemaV1)
	}
	if uidValue == "" || gidValue == "" {
		return 0, 0, fmt.Errorf("runtime platform state owner uid and gid are required together")
	}

	parsedUID, err := strconv.Atoi(uidValue)
	if err != nil || parsedUID < 0 {
		return 0, 0, fmt.Errorf("runtime platform state owner uid is invalid")
	}
	parsedGID, err := strconv.Atoi(gidValue)
	if err != nil || parsedGID < 0 {
		return 0, 0, fmt.Errorf("runtime platform state owner gid is invalid")
	}
	return parsedUID, parsedGID, nil
}

func validateStablePlatformDir(platformDir string, targetUID int, targetGID int) error {
	info, err := os.Stat(platformDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("platform runtime dir is not a directory")
	}
	uid, gid, err := fileOwnerIDs(info)
	if err != nil {
		return err
	}
	if uid != targetUID || gid != targetGID {
		return fmt.Errorf("platform runtime dir is not owned by target uid:gid %d:%d (got %d:%d)", targetUID, targetGID, uid, gid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("platform runtime dir must not be group- or world-writable")
	}
	return nil
}

func normalizePostWorkloadTree(root string, targetUID int, targetGID int) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}

		if err := os.Lchown(path, targetUID, targetGID); err != nil {
			return fmt.Errorf("set ownership on %s: %w", path, err)
		}
		switch {
		case info.IsDir():
			if err := os.Chmod(path, normalizedDirMode); err != nil {
				return fmt.Errorf("set directory mode on %s: %w", path, err)
			}
		case info.Mode().IsRegular():
			if err := os.Chmod(path, normalizedRegularMode(info.Mode())); err != nil {
				return fmt.Errorf("set file mode on %s: %w", path, err)
			}
		case info.Mode()&os.ModeSymlink != 0:
			return nil
		default:
			return fmt.Errorf("path %s uses unsupported file mode %s", path, info.Mode().String())
		}
		return nil
	})
}

func writeOwnershipNormalizationMarker(platformDir string, runID string, targetUID int, targetGID int) error {
	markerPath := ownershipnorm.MarkerPath(platformDir)
	marker := ownershipnorm.NewNormalizedMarker(runID, targetUID, targetGID, time.Now())

	if err := ensureMarkerAuthorityBoundary(platformDir, "", workloadUID, workloadGID); err != nil {
		return err
	}

	payload, err := json.Marshal(marker)
	if err != nil {
		return fmt.Errorf("marshal marker: %w", err)
	}
	if err := writeMarkerFile(markerPath, append(payload, '\n'), markerFileMode); err != nil {
		return err
	}
	if err := os.Lchown(markerPath, targetUID, targetGID); err != nil {
		return fmt.Errorf("set marker ownership: %w", err)
	}
	if err := os.Chmod(markerPath, markerFileMode); err != nil {
		return fmt.Errorf("set marker mode: %w", err)
	}
	if err := ensureMarkerAuthorityBoundary(platformDir, markerPath, workloadUID, workloadGID); err != nil {
		return err
	}
	if err := ownershipnorm.Validate(marker, ownershipnorm.ValidationOptions{
		RunID:       runID,
		ExpectedUID: &targetUID,
		ExpectedGID: &targetGID,
	}); err != nil {
		return err
	}
	return nil
}

func ensureMarkerAuthorityBoundary(platformDir string, markerPath string, uid int, gid int) error {
	platformInfo, err := os.Stat(platformDir)
	if err != nil {
		return fmt.Errorf("stat platform marker directory: %w", err)
	}
	if !platformInfo.IsDir() {
		return fmt.Errorf("platform marker directory is not a directory")
	}
	if err := ensurePathIsNotWorkloadForgeable(platformDir, platformInfo, uid, gid, true); err != nil {
		return err
	}
	if strings.TrimSpace(markerPath) == "" {
		return nil
	}

	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		return fmt.Errorf("stat ownership-normalization marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return fmt.Errorf("ownership-normalization marker is not a regular file")
	}
	return ensurePathIsNotWorkloadForgeable(markerPath, markerInfo, uid, gid, false)
}

func ensurePathIsNotWorkloadForgeable(path string, info os.FileInfo, uid int, gid int, directory bool) error {
	pathUID, pathGID, err := fileOwnerIDs(info)
	if err != nil {
		return fmt.Errorf("read ownership for %s: %w", path, err)
	}
	if pathUID == uid || pathGID == gid {
		return fmt.Errorf("%s must not be workload-owned", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or world-writable", path)
	}
	if directory {
		if directoryWritableByUser(info, pathUID, pathGID, uid, gid) {
			return fmt.Errorf("%s remains workload-writable", path)
		}
		return nil
	}
	if fileWritableByUser(info, pathUID, pathGID, uid, gid) {
		return fmt.Errorf("%s remains workload-writable", path)
	}
	return nil
}

func fileOwnerIDs(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, fmt.Errorf("unsupported file ownership metadata")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func directoryWritableByUser(info os.FileInfo, pathUID int, pathGID int, uid int, gid int) bool {
	perm := info.Mode().Perm()
	switch {
	case pathUID == uid:
		return perm&0o300 == 0o300
	case pathGID == gid:
		return perm&0o030 == 0o030
	default:
		return perm&0o003 == 0o003
	}
}

func fileWritableByUser(info os.FileInfo, pathUID int, pathGID int, uid int, gid int) bool {
	perm := info.Mode().Perm()
	switch {
	case pathUID == uid:
		return perm&0o200 != 0
	case pathGID == gid:
		return perm&0o020 != 0
	default:
		return perm&0o002 != 0
	}
}

func normalizedRegularMode(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return normalizedExecFileMode
	}
	return normalizedFileMode
}

func combineWorkloadAndNormalizationError(workloadErr error, normalizationErr error) error {
	if normalizationErr == nil {
		return workloadErr
	}
	if workloadErr == nil {
		return newExitError(1, fmt.Errorf("post-workload normalization failed: %w", normalizationErr))
	}

	var exitErr *exitError
	if errors.As(workloadErr, &exitErr) {
		return newExitError(exitErr.code, fmt.Errorf("%s; post-workload normalization failed: %v", exitErr.Error(), normalizationErr))
	}
	return fmt.Errorf("%w; post-workload normalization failed: %v", workloadErr, normalizationErr)
}

func materializeHelperPrivateSPIRESocket(paths runtimePaths) error {
	entries, err := os.ReadDir(paths.spireSourceDir)
	if err != nil {
		return fmt.Errorf("read mounted spire source dir: %w", err)
	}

	candidates := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := os.Stat(filepath.Join(paths.spireSourceDir, entry.Name()))
		if infoErr != nil {
			continue
		}
		if info.Mode()&os.ModeSocket != 0 {
			candidates = append(candidates, entry.Name())
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("mounted spire source dir does not contain a unix socket")
	}
	sort.Strings(candidates)

	selected := ""
	for _, candidate := range candidates {
		if candidate == spireSocketName {
			selected = candidate
			break
		}
	}
	if selected == "" {
		if len(candidates) != 1 {
			return fmt.Errorf("mounted spire source dir contains multiple unix sockets: %s", strings.Join(candidates, ", "))
		}
		selected = candidates[0]
	}

	if err := os.Remove(paths.spireSocket); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale helper-private spire socket path: %w", err)
	}
	if err := os.Symlink(filepath.Join(paths.spireSourceDir, selected), paths.spireSocket); err != nil {
		return fmt.Errorf("link helper-private spire socket path: %w", err)
	}
	return nil
}

func extractWorkloadArchive(archivePath string, destinationRoot string) error {
	file, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		return fmt.Errorf("open workload archive: %w", err)
	}
	defer file.Close()

	archive, err := staticarchive.Open(file, 0)
	if err != nil {
		return fmt.Errorf("open workload archive gzip stream: %w", err)
	}
	defer archive.Close()

	var namespace staticarchive.Namespace
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read workload archive: %w", err)
		}

		name, err := namespace.Add(header)
		if err != nil {
			return fmt.Errorf("invalid workload archive entry: %w", err)
		}
		destinationPath, err := canonicalArchiveDestinationPath(destinationRoot, name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destinationPath, 0o755); err != nil {
				return fmt.Errorf("create workload directory %s: %w", header.Name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
				return fmt.Errorf("create workload parent directory %s: %w", header.Name, err)
			}
			destinationFile, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create workload file %s: %w", header.Name, err)
			}
			if _, err := io.Copy(destinationFile, archive); err != nil {
				destinationFile.Close()
				return fmt.Errorf("write workload file %s: %w", header.Name, err)
			}
			if err := destinationFile.Close(); err != nil {
				return fmt.Errorf("close workload file %s: %w", header.Name, err)
			}
		}
	}
	if err := archive.Finish(); err != nil {
		return fmt.Errorf("finish workload archive: %w", err)
	}
	return nil
}

func archiveDestinationPath(root string, headerName string) (string, error) {
	cleanName, err := staticarchive.CleanName(headerName)
	if err != nil {
		return "", fmt.Errorf("invalid workload archive path: %w", err)
	}
	return canonicalArchiveDestinationPath(root, cleanName)
}

// canonicalArchiveDestinationPath receives the name returned by Namespace.Add.
// Do not trim or clean it again: cleaning may expose significant component
// whitespace that a second trim would incorrectly remove.
func canonicalArchiveDestinationPath(root string, canonicalName string) (string, error) {
	if canonicalName == "" || canonicalName == "." || filepath.IsAbs(canonicalName) ||
		canonicalName == ".." || strings.HasPrefix(canonicalName, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workload archive entry %s escapes the work tree", canonicalName)
	}
	destinationPath := filepath.Join(root, filepath.FromSlash(canonicalName))
	relativePath, err := filepath.Rel(root, destinationPath)
	if err != nil {
		return "", fmt.Errorf("resolve workload archive entry %s: %w", canonicalName, err)
	}
	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workload archive entry %s escapes the work tree", canonicalName)
	}
	return destinationPath, nil
}

func sanitizeWorkloadTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workload tree must not contain symlinks: %s", path)
		}
		mode := info.Mode().Perm()
		if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
			mode = info.Mode().Perm() &^ 0o6000
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("sanitize workload mode for %s: %w", path, err)
		}
		if err := os.Lchown(path, workloadUID, workloadGID); err != nil {
			return fmt.Errorf("sanitize workload ownership for %s: %w", path, err)
		}
		return nil
	})
}

func waitForHelperReadiness(endpointPath string, helperErrCh <-chan error) error {
	deadline := time.Now().Add(helperReadinessTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-helperErrCh:
			if err == nil {
				return fmt.Errorf("runtime identity helper exited before readiness")
			}
			return fmt.Errorf("runtime identity helper failed before readiness: %w", err)
		default:
		}

		response, err := callIdentityEndpoint(endpointPath, endpointRequest{
			Kind:   endpointRequestKindJWTSVID,
			Target: endpointRequestTargetWorkload,
		})
		if err == nil && strings.TrimSpace(response.JWT) != "" {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("runtime identity helper did not become ready")
}

func callIdentityEndpoint(endpointPath string, request endpointRequest) (endpointResponse, error) {
	connection, err := net.DialTimeout("unix", endpointPath, time.Second)
	if err != nil {
		return endpointResponse{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))

	body, err := json.Marshal(request)
	if err != nil {
		return endpointResponse{}, err
	}
	if _, err := connection.Write(append(body, '\n')); err != nil {
		return endpointResponse{}, err
	}

	responseLine, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return endpointResponse{}, err
	}
	var response endpointResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(responseLine)), &response); err != nil {
		return endpointResponse{}, err
	}
	if strings.TrimSpace(response.Error) != "" {
		return endpointResponse{}, errors.New(response.Error)
	}
	return response, nil
}

func terminateProcess(process *os.Process) {
	if process == nil {
		return
	}
	_ = process.Signal(syscall.SIGTERM)
	time.AfterFunc(processKillTimeout, func() {
		_ = process.Kill()
	})
}

func workloadExitError(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return newExitError(1, err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return newExitError(1, err)
	}
	if status.Signaled() {
		return newExitError(128+int(status.Signal()), fmt.Errorf("workload terminated by signal %s", status.Signal().String()))
	}
	return newExitError(status.ExitStatus(), fmt.Errorf("workload exited with code %d", status.ExitStatus()))
}

func runExecWorkload(args []string) error {
	fs := flag.NewFlagSet("exec-workload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var entrypoint string
	var workDir string
	fs.StringVar(&entrypoint, "entrypoint", "", "path to workload entrypoint")
	fs.StringVar(&workDir, "work-dir", "", "path to workload working directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(entrypoint) == "" {
		return fmt.Errorf("--entrypoint is required")
	}
	if strings.TrimSpace(workDir) == "" {
		return fmt.Errorf("--work-dir is required")
	}

	snapshot, err := prepareWorkloadBoundary(workloadUID, workloadGID)
	if err != nil {
		return err
	}
	fmt.Printf("%s uid=%d gid=%d groups=%v cap_eff=%s cap_prm=%s cap_amb=%s cap_bnd=%s no_new_privs=%t\n",
		workloadBoundaryLogPrefix, os.Geteuid(), os.Getegid(), snapshot.SuppGroups, snapshot.CapEff, snapshot.CapPrm, snapshot.CapAmb, snapshot.CapBnd, snapshot.NoNewPrivs)

	if err := os.Chdir(workDir); err != nil {
		return fmt.Errorf("chdir workload work dir: %w", err)
	}

	argv := append([]string{entrypoint}, fs.Args()...)
	return syscall.Exec(entrypoint, argv, os.Environ())
}
