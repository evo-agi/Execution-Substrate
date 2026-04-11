package admission

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	resultBundleMediaType = "application/gzip"
	resultBundleFileName  = "result.tar.gz"
)

func (s *Service) Result(ctx context.Context, runID string) (ExecutionResultBundle, *Error) {
	locator, err := resolveExecutionLocator(runID)
	if err != nil {
		return ExecutionResultBundle{}, err
	}

	if bundle, ok, err := s.readRetainedResultBundle(locator); ok || err != nil {
		return bundle, err
	}
	if s.nomadClient == nil {
		return ExecutionResultBundle{}, nomadUnavailableError("execution runtime is unavailable")
	}

	job, err := s.nomadClient.fetchJob(ctx, locator.JobID())
	if err != nil {
		return ExecutionResultBundle{}, err
	}

	allocation, err := s.nomadClient.fetchProjectedAllocation(ctx, locator.JobID())
	if err != nil {
		if err.Status == http.StatusConflict {
			return ExecutionResultBundle{}, resultUnavailableError("execution result is not available yet")
		}
		return ExecutionResultBundle{}, err
	}

	terminal := strings.TrimSpace(job.Status) == "dead"
	if allocation != nil {
		terminal = terminal || allocationTerminal(allocation)
	}
	if !terminal {
		return ExecutionResultBundle{}, resultUnavailableError("execution is not terminal")
	}

	if retained, retainErr := s.retainTerminalResult(locator); retainErr != nil {
		log.Printf("es result retention failed run_id=%s err=%v", locator.RunID, retainErr)
		return ExecutionResultBundle{}, resultUnavailableError("execution result bundle is not available")
	} else if !retained {
		return ExecutionResultBundle{}, &Error{
			Status:  http.StatusNotFound,
			Code:    codeResultNotFound,
			Message: "execution completed without a retained result bundle",
		}
	}

	bundle, ok, readErr := s.readRetainedResultBundle(locator)
	if readErr != nil {
		return ExecutionResultBundle{}, readErr
	}
	if !ok {
		return ExecutionResultBundle{}, resultUnavailableError("execution result bundle is not available")
	}
	return bundle, nil
}

func (s *Service) maybeRetainTerminalResult(locator executionLocator, allocation *nomadAllocationDetail) {
	if !allocationTerminal(allocation) {
		return
	}
	if _, err := s.retainTerminalResult(locator); err != nil {
		log.Printf("es result retention failed run_id=%s err=%v", locator.RunID, err)
	}
}

func (s *Service) retainTerminalResult(locator executionLocator) (bool, error) {
	bundlePath := s.retainedResultBundlePath(locator)
	if _, err := os.Stat(bundlePath); err == nil {
		return true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	layout := newExecutionPackageLayout(s.cfg, locator)
	if hasFiles, err := resultDirectoryHasFiles(layout.resultStageDir); err != nil || !hasFiles {
		return false, err
	}

	resultDir := filepath.Dir(bundlePath)
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		return false, err
	}

	tempFile, err := os.CreateTemp(resultDir, ".result-*.tar.gz.tmp")
	if err != nil {
		return false, err
	}
	tempPath := tempFile.Name()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := writeResultBundle(tempFile, layout.resultStageDir); err != nil {
		_ = tempFile.Close()
		return false, err
	}
	if err := tempFile.Close(); err != nil {
		return false, err
	}

	if err := os.Link(tempPath, bundlePath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return true, nil
		}
		return false, err
	}
	cleanupTemp = true
	return true, nil
}

func (s *Service) readRetainedResultBundle(locator executionLocator) (ExecutionResultBundle, bool, *Error) {
	payload, err := os.ReadFile(s.retainedResultBundlePath(locator))
	if err == nil {
		return ExecutionResultBundle{
			MediaType: resultBundleMediaType,
			Payload:   payload,
		}, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return ExecutionResultBundle{}, false, nil
	}
	return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
}

func (s *Service) retainedResultBundlePath(locator executionLocator) string {
	return filepath.Join(s.cfg.Execution.ResultsRootDir, locator.RunID, resultBundleFileName)
}

func resultDirectoryHasFiles(root string) (bool, error) {
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("result path is not a directory")
	}

	hasFiles := false
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if !entry.IsDir() {
			hasFiles = true
			return filepath.SkipAll
		}
		return nil
	})
	return hasFiles, err
}

func writeResultBundle(writer io.Writer, root string) error {
	gzipWriter := gzip.NewWriter(writer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)

	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}

		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relativePath = filepath.ToSlash(relativePath)
		if relativePath == "." || strings.HasPrefix(relativePath, "../") {
			return fmt.Errorf("result entry escapes result directory: %s", path)
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relativePath
		header.ModTime = time.Unix(0, 0)
		header.AccessTime = time.Unix(0, 0)
		header.ChangeTime = time.Unix(0, 0)

		switch {
		case info.IsDir():
			header.Name += "/"
		case info.Mode().IsRegular():
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			header.Linkname = target
		default:
			return fmt.Errorf("result entry %s uses unsupported file mode %s", relativePath, info.Mode().String())
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tarWriter, file); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	})
	if walkErr != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return walkErr
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return err
	}
	return gzipWriter.Close()
}

func allocationTerminal(allocation *nomadAllocationDetail) bool {
	if allocation == nil {
		return false
	}
	if isTerminalAllocationStatus(strings.TrimSpace(allocation.ClientStatus)) {
		return true
	}
	taskState, ok := allocation.TaskStates[nomadTaskName]
	return ok && strings.TrimSpace(taskState.State) == "dead"
}

func resultUnavailableError(message string) *Error {
	return &Error{
		Status:  http.StatusConflict,
		Code:    codeResultUnavailable,
		Message: message,
	}
}
