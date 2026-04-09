package runtimehelper

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
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
	"strings"
	"syscall"
	"time"
)

const (
	helperReadinessTimeout = 10 * time.Second
	processKillTimeout     = 5 * time.Second
	workloadTimeoutExit    = 124
)

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
			terminateProcess(helperCmd.Process)
			<-helperErrCh
			return workloadExitError(workloadErr)
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
	if strings.TrimSpace(cfg.entrypoint) == "" {
		return supervisorConfig{}, fmt.Errorf("--entrypoint is required")
	}
	cfg.workloadArgv = fs.Args()
	return cfg, nil
}

func prepareRuntimeFilesystem(cfg supervisorConfig, paths runtimePaths) error {
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
	if err := os.Chown(platformDir, 0, 0); err != nil {
		return fmt.Errorf("chown platform runtime dir: %w", err)
	}
	if err := os.Chmod(platformDir, 0o755); err != nil {
		return fmt.Errorf("chmod platform runtime dir: %w", err)
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

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open workload archive gzip stream: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read workload archive: %w", err)
		}

		destinationPath, err := archiveDestinationPath(destinationRoot, header.Name)
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
			destinationFile, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create workload file %s: %w", header.Name, err)
			}
			if _, err := io.Copy(destinationFile, tarReader); err != nil {
				destinationFile.Close()
				return fmt.Errorf("write workload file %s: %w", header.Name, err)
			}
			if err := destinationFile.Close(); err != nil {
				return fmt.Errorf("close workload file %s: %w", header.Name, err)
			}
		default:
			return fmt.Errorf("workload archive entry %s uses unsupported type %d", header.Name, header.Typeflag)
		}
	}
	return nil
}

func archiveDestinationPath(root string, headerName string) (string, error) {
	cleanName := filepath.Clean(strings.TrimSpace(headerName))
	if cleanName == "." || cleanName == "" {
		return "", fmt.Errorf("workload archive entry has an empty path")
	}
	if filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("workload archive entry %s must be relative", headerName)
	}

	destinationPath := filepath.Join(root, cleanName)
	relativePath, err := filepath.Rel(root, destinationPath)
	if err != nil {
		return "", fmt.Errorf("resolve workload archive entry %s: %w", headerName, err)
	}
	if strings.HasPrefix(relativePath, "..") {
		return "", fmt.Errorf("workload archive entry %s escapes the work tree", headerName)
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
