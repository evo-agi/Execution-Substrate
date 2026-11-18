package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"execution-substrate/es/internal/ownershipnorm"
	"golang.org/x/sys/unix"
)

const (
	ownershipNormalizationMarkerName          = ownershipnorm.MarkerFileName
	ownershipNormalizationMarkerSchemaVersion = ownershipnorm.SchemaVersion
	ownershipNormalizationMarkerStatus        = ownershipnorm.MarkerStatus
	maxOwnershipNormalizationMarkerBytes      = 256 << 10
)

var ownershipNormalizationRequiredPaths = ownershipnorm.RequiredPaths()

type ownershipNormalizationMarker = ownershipnorm.Marker

type ownershipNormalizationMarkerExpectations = ownershipnorm.ValidationOptions

func loadValidatedOwnershipNormalizationMarkerAt(directoryFD int, expectations ownershipNormalizationMarkerExpectations) (*ownershipNormalizationMarker, []byte, error) {
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		return nil, nil, fmt.Errorf("ownership-normalization authority directory is not readable: %w", err)
	}
	directoryIdentity := custodyIdentityFromStat(directoryStat)
	if !custodyIdentityIsDirectory(directoryIdentity) || os.FileMode(directoryStat.Mode).Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf("ownership-normalization authority directory is not a private directory")
	}
	if expectations.ExpectedUID != nil && expectations.ExpectedGID != nil && (directoryIdentity.UID != *expectations.ExpectedUID || directoryIdentity.GID != *expectations.ExpectedGID) {
		return nil, nil, fmt.Errorf("ownership-normalization authority directory has unexpected ownership")
	}

	payloadBytes, markerIdentity, err := readStableRegularFileAt(directoryFD, ownershipNormalizationMarkerName, maxOwnershipNormalizationMarkerBytes, directoryIdentity.Device)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			if _, validateErr := ownershipnorm.ValidateState(nil, expectations); validateErr != nil {
				return nil, nil, validateErr
			}
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("ownership-normalization marker is not readable: %w", err)
	}
	if os.FileMode(markerIdentity.Mode).Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf("ownership-normalization marker is group- or world-writable")
	}
	if expectations.ExpectedUID != nil && expectations.ExpectedGID != nil && (markerIdentity.UID != *expectations.ExpectedUID || markerIdentity.GID != *expectations.ExpectedGID) {
		return nil, nil, fmt.Errorf("ownership-normalization marker has unexpected ownership")
	}

	var marker ownershipNormalizationMarker
	if err := json.Unmarshal(payloadBytes, &marker); err != nil {
		return nil, nil, fmt.Errorf("ownership-normalization marker is not valid JSON: %w", err)
	}
	if err := validateOwnershipNormalizationMarker(marker, expectations); err != nil {
		return nil, nil, err
	}
	return &marker, payloadBytes, nil
}

func preflightOptionalOwnershipNormalizationMarker(platformDir string, expectations ownershipNormalizationMarkerExpectations) (bool, error) {
	marker, _, _, err := loadValidatedOwnershipNormalizationMarker(ownershipnorm.MarkerPath(platformDir), platformDir, expectations)
	return marker != nil, err
}

func loadValidatedOwnershipNormalizationMarker(markerPath string, authorityDir string, expectations ownershipNormalizationMarkerExpectations) (*ownershipNormalizationMarker, []byte, string, error) {
	cleanMarkerPath := filepath.Clean(markerPath)
	markerParent := filepath.Dir(cleanMarkerPath)
	if authorityDir != "" && filepath.Clean(authorityDir) != markerParent {
		return nil, nil, markerPath, fmt.Errorf("ownership-normalization marker authority path does not match its parent")
	}
	directory, err := openQualifiedDirectory(markerParent, false, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			if _, validateErr := ownershipnorm.ValidateState(nil, expectations); validateErr != nil {
				return nil, nil, markerPath, validateErr
			}
			return nil, nil, markerPath, nil
		}
		return nil, nil, markerPath, fmt.Errorf("ownership-normalization authority directory is not readable: %w", err)
	}
	defer directory.close()
	if err := directory.verifyVisible(); err != nil {
		return nil, nil, markerPath, fmt.Errorf("ownership-normalization authority directory is not stable: %w", err)
	}
	marker, payloadBytes, err := loadValidatedOwnershipNormalizationMarkerAt(directory.fd, expectations)
	if err != nil {
		return nil, nil, markerPath, err
	}
	return marker, payloadBytes, markerPath, nil
}

func validateOwnershipNormalizationMarker(marker ownershipNormalizationMarker, expectations ownershipNormalizationMarkerExpectations) error {
	return ownershipnorm.Validate(marker, expectations)
}
