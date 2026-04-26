package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"execution-substrate/es/internal/ownershipnorm"
	"golang.org/x/sys/unix"
)

const (
	ownershipNormalizationMarkerName          = ownershipnorm.MarkerFileName
	ownershipNormalizationMarkerSchemaVersion = ownershipnorm.SchemaVersion
	ownershipNormalizationMarkerStatus        = ownershipnorm.MarkerStatus
)

var ownershipNormalizationRequiredPaths = ownershipnorm.RequiredPaths()

type ownershipNormalizationMarker = ownershipnorm.Marker

type ownershipNormalizationMarkerExpectations = ownershipnorm.ValidationOptions

func preflightRetainedResultSource(root string, platformDir string, expectations ownershipNormalizationMarkerExpectations) (bool, error) {
	if _, err := preflightOptionalOwnershipNormalizationMarker(platformDir, expectations); err != nil {
		return false, err
	}

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
	if err := requireExpectedOwnership(root, info, expectations, "result path"); err != nil {
		return false, err
	}

	hasFiles := false
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		displayPath := treeDisplayPath(root, path)
		if walkErr != nil {
			return fmt.Errorf("result entry %s is not readable: %w", displayPath, walkErr)
		}
		if path == root {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("result entry %s is not readable: %w", displayPath, err)
		}
		if err := requireExpectedOwnership(path, info, expectations, "result entry "+displayPath); err != nil {
			return err
		}

		switch {
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
			file, err := os.Open(filepath.Clean(path))
			if err != nil {
				return fmt.Errorf("result entry %s is not readable: %w", displayPath, err)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("result entry %s close failed: %w", displayPath, err)
			}
			hasFiles = true
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			if _, err := os.Readlink(path); err != nil {
				return fmt.Errorf("result entry %s is not readable: %w", displayPath, err)
			}
			hasFiles = true
			return nil
		default:
			return fmt.Errorf("result entry %s uses unsupported file mode %s", displayPath, info.Mode().String())
		}
	})
	if err != nil {
		return false, err
	}
	return hasFiles, nil
}

func preflightSuccessfulStageCleanup(root string, platformDir string, expectations ownershipNormalizationMarkerExpectations) error {
	if _, err := os.Lstat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if _, err := preflightOptionalOwnershipNormalizationMarker(platformDir, expectations); err != nil {
		return err
	}

	if err := requireDirectoryCleanupAccess(filepath.Dir(root), "stage root parent"); err != nil {
		return err
	}

	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		displayPath := treeDisplayPath(root, path)
		if walkErr != nil {
			return fmt.Errorf("stage root %s is not cleanup-ready: %w", displayPath, walkErr)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stage root %s is not cleanup-ready: %w", displayPath, err)
		}
		if err := requireExpectedOwnership(path, info, expectations, "stage root "+displayPath); err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		return requireDirectoryCleanupAccess(path, displayPath)
	})
}

func preflightOptionalOwnershipNormalizationMarker(platformDir string, expectations ownershipNormalizationMarkerExpectations) (bool, error) {
	markerPath := ownershipnorm.MarkerPath(platformDir)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, validateErr := ownershipnorm.ValidateState(nil, expectations); validateErr != nil {
				return false, validateErr
			}
			return false, nil
		}
		return false, fmt.Errorf("ownership-normalization marker is not readable: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return true, fmt.Errorf("ownership-normalization marker is not a regular file")
	}
	if markerInfo.Mode().Perm()&0o022 != 0 {
		return true, fmt.Errorf("ownership-normalization marker is group- or world-writable")
	}

	platformInfo, err := os.Stat(platformDir)
	if err != nil {
		return true, fmt.Errorf("ownership-normalization platform directory is not readable: %w", err)
	}
	if !platformInfo.IsDir() {
		return true, fmt.Errorf("ownership-normalization platform directory is not a directory")
	}
	if platformInfo.Mode().Perm()&0o022 != 0 {
		return true, fmt.Errorf("ownership-normalization platform directory is group- or world-writable")
	}

	payloadBytes, err := os.ReadFile(markerPath)
	if err != nil {
		return true, fmt.Errorf("ownership-normalization marker is not readable: %w", err)
	}

	var marker ownershipNormalizationMarker
	if err := json.Unmarshal(payloadBytes, &marker); err != nil {
		return true, fmt.Errorf("ownership-normalization marker is not valid JSON: %w", err)
	}
	if err := validateOwnershipNormalizationMarker(marker, expectations); err != nil {
		return true, err
	}
	return true, nil
}

func validateOwnershipNormalizationMarker(marker ownershipNormalizationMarker, expectations ownershipNormalizationMarkerExpectations) error {
	return ownershipnorm.Validate(marker, expectations)
}

func requireExpectedOwnership(path string, info os.FileInfo, expectations ownershipNormalizationMarkerExpectations, display string) error {
	if expectations.ExpectedUID == nil || expectations.ExpectedGID == nil {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("%s ownership cannot be determined", display)
	}
	actualUID := int(stat.Uid)
	actualGID := int(stat.Gid)
	if actualUID != *expectations.ExpectedUID || actualGID != *expectations.ExpectedGID {
		return fmt.Errorf(
			"%s is not owned by expected ES uid:gid %d:%d (got %d:%d) (%s)",
			display,
			*expectations.ExpectedUID,
			*expectations.ExpectedGID,
			actualUID,
			actualGID,
			path,
		)
	}
	return nil
}

func requireDirectoryCleanupAccess(path string, displayPath string) error {
	if err := unix.Access(path, unix.R_OK|unix.W_OK|unix.X_OK); err != nil {
		return fmt.Errorf("cleanup requires read/write/execute access to %s (%s): %w", displayPath, path, err)
	}
	return nil
}

func treeDisplayPath(root string, path string) string {
	if path == root {
		return "."
	}
	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Clean(path)
	}
	relativePath = filepath.ToSlash(relativePath)
	if relativePath == "." || relativePath == "" {
		return "."
	}
	return relativePath
}
