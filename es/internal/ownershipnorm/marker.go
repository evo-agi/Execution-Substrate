package ownershipnorm

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	MarkerFileName = "ownership-normalization.json"
	SchemaVersion  = "execution-substrate.es.runtime-ownership-normalization.v1"
	MarkerStatus   = "normalized"
)

type ValidationMode string

const (
	ValidationModeAlphaCompatibility ValidationMode = "alpha_compatibility"
	ValidationModeNonRootRequired    ValidationMode = "non_root_required"
)

var requiredPaths = []string{
	"run/platform",
	"run/work",
	"run/result",
}

type Marker struct {
	SchemaVersion   string   `json:"schema_version"`
	Status          string   `json:"status"`
	RunID           string   `json:"run_id"`
	TargetUID       *int     `json:"target_uid"`
	TargetGID       *int     `json:"target_gid"`
	PathsNormalized []string `json:"paths_normalized"`
	CompletedAt     string   `json:"completed_at"`
}

type ValidationOptions struct {
	RunID         string
	ExpectedUID   *int
	ExpectedGID   *int
	RequireMarker bool
}

type ValidationResult struct {
	Mode                ValidationMode
	MarkerPresent       bool
	MarkerValid         bool
	TargetOwnerChecked  bool
	TargetOwnerVerified bool
}

func MarkerPath(platformDir string) string {
	return filepath.Join(platformDir, MarkerFileName)
}

func RequiredPaths() []string {
	return append([]string(nil), requiredPaths...)
}

func NewNormalizedMarker(runID string, targetUID int, targetGID int, completedAt time.Time) Marker {
	return Marker{
		SchemaVersion:   SchemaVersion,
		Status:          MarkerStatus,
		RunID:           strings.TrimSpace(runID),
		TargetUID:       intPtr(targetUID),
		TargetGID:       intPtr(targetGID),
		PathsNormalized: RequiredPaths(),
		CompletedAt:     completedAt.UTC().Format(time.RFC3339),
	}
}

func Validate(marker Marker, options ValidationOptions) error {
	_, err := ValidateState(&marker, options)
	return err
}

func ValidateState(marker *Marker, options ValidationOptions) (ValidationResult, error) {
	options, mode, err := normalizeValidationOptions(options)
	result := ValidationResult{
		Mode:               mode,
		MarkerPresent:      marker != nil,
		TargetOwnerChecked: options.ExpectedUID != nil && options.ExpectedGID != nil,
	}
	if err != nil {
		return result, err
	}
	if marker == nil {
		if options.RequireMarker {
			return result, fmt.Errorf("ownership-normalization marker is required for non-root-required validation")
		}
		return result, nil
	}

	if err := validateMarkerStructure(*marker, options); err != nil {
		return result, err
	}
	result.MarkerValid = true
	if !result.TargetOwnerChecked {
		return result, nil
	}
	if *marker.TargetUID != *options.ExpectedUID {
		return result, fmt.Errorf(
			"ownership-normalization marker target_uid %d does not match expected %d",
			*marker.TargetUID,
			*options.ExpectedUID,
		)
	}
	if *marker.TargetGID != *options.ExpectedGID {
		return result, fmt.Errorf(
			"ownership-normalization marker target_gid %d does not match expected %d",
			*marker.TargetGID,
			*options.ExpectedGID,
		)
	}
	result.TargetOwnerVerified = true
	return result, nil
}

func validateMarkerStructure(marker Marker, options ValidationOptions) error {
	if strings.TrimSpace(marker.SchemaVersion) != SchemaVersion {
		return fmt.Errorf("ownership-normalization marker schema_version must be %q", SchemaVersion)
	}
	if strings.TrimSpace(marker.Status) != MarkerStatus {
		return fmt.Errorf("ownership-normalization marker status must be %q", MarkerStatus)
	}
	if strings.TrimSpace(marker.RunID) == "" {
		return fmt.Errorf("ownership-normalization marker run_id is missing")
	}
	if options.RunID != "" && strings.TrimSpace(marker.RunID) != options.RunID {
		return fmt.Errorf("ownership-normalization marker run_id %q does not match %q", marker.RunID, options.RunID)
	}
	if marker.TargetUID == nil {
		return fmt.Errorf("ownership-normalization marker target_uid is missing")
	}
	if *marker.TargetUID < 0 {
		return fmt.Errorf("ownership-normalization marker target_uid must be non-negative")
	}
	if marker.TargetGID == nil {
		return fmt.Errorf("ownership-normalization marker target_gid is missing")
	}
	if *marker.TargetGID < 0 {
		return fmt.Errorf("ownership-normalization marker target_gid must be non-negative")
	}
	if strings.TrimSpace(marker.CompletedAt) == "" {
		return fmt.Errorf("ownership-normalization marker completed_at is missing")
	}
	if _, err := time.Parse(time.RFC3339, marker.CompletedAt); err != nil {
		return fmt.Errorf("ownership-normalization marker completed_at is not RFC3339: %w", err)
	}

	observedPaths := make([]string, 0, len(marker.PathsNormalized))
	for _, path := range marker.PathsNormalized {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		observedPaths = append(observedPaths, path)
	}
	if len(observedPaths) == 0 {
		return fmt.Errorf("ownership-normalization marker paths_normalized is missing")
	}
	for _, requiredPath := range requiredPaths {
		if !slices.Contains(observedPaths, requiredPath) {
			return fmt.Errorf("ownership-normalization marker is missing required path %q", requiredPath)
		}
	}
	return nil
}

func normalizeValidationOptions(options ValidationOptions) (ValidationOptions, ValidationMode, error) {
	mode := ValidationModeAlphaCompatibility
	if options.RequireMarker {
		mode = ValidationModeNonRootRequired
	}
	hasExpectedUID := options.ExpectedUID != nil
	hasExpectedGID := options.ExpectedGID != nil
	if hasExpectedUID != hasExpectedGID {
		return ValidationOptions{}, mode, fmt.Errorf("expected_uid and expected_gid must be supplied together")
	}
	if mode == ValidationModeNonRootRequired && !hasExpectedUID {
		return ValidationOptions{}, mode, fmt.Errorf("non-root-required validation requires expected_uid and expected_gid")
	}
	return options, mode, nil
}

func intPtr(value int) *int {
	return &value
}
