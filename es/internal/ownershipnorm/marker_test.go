package ownershipnorm

import (
	"testing"
	"time"
)

func TestAlphaCompatibilityModeAcceptsMissingMarker(t *testing.T) {
	result, err := ValidateState(nil, ValidationOptions{RunID: "run-0123456789abcdef"})
	if err != nil {
		t.Fatalf("expected missing marker to remain Alpha-compatible, got %v", err)
	}
	if result.Mode != ValidationModeAlphaCompatibility {
		t.Fatalf("expected alpha mode, got %q", result.Mode)
	}
	if result.MarkerPresent {
		t.Fatal("did not expect missing marker to report present")
	}
	if result.TargetOwnerChecked || result.TargetOwnerVerified {
		t.Fatalf("did not expect target-owner proof on missing marker: %+v", result)
	}
}

func TestAlphaCompatibilityModeRejectsInvalidPresentMarker(t *testing.T) {
	marker := NewNormalizedMarker("run-0123456789abcdef", 123, 456, mustTime(t, "2026-04-25T12:00:00Z"))
	marker.CompletedAt = "not-a-timestamp"

	if _, err := ValidateState(&marker, ValidationOptions{RunID: marker.RunID}); err == nil {
		t.Fatal("expected invalid present marker to fail closed")
	}
}

func TestValidMarkerWithoutExpectedOwnerReportsTargetOwnerUnverified(t *testing.T) {
	marker := NewNormalizedMarker("run-0123456789abcdef", 123, 456, mustTime(t, "2026-04-25T12:00:00Z"))

	result, err := ValidateState(&marker, ValidationOptions{RunID: marker.RunID})
	if err != nil {
		t.Fatalf("expected structurally valid marker without expected owner to validate, got %v", err)
	}
	if !result.MarkerPresent || !result.MarkerValid {
		t.Fatalf("expected valid present marker result, got %+v", result)
	}
	if result.TargetOwnerChecked {
		t.Fatalf("did not expect target owner to be checked, got %+v", result)
	}
	if result.TargetOwnerVerified {
		t.Fatalf("did not expect target owner to be verified, got %+v", result)
	}
}

func TestFutureNonRootRequiredModeBlocksMissingMarker(t *testing.T) {
	expectedUID := 123
	expectedGID := 456
	if _, err := ValidateState(nil, ValidationOptions{
		RunID:         "run-0123456789abcdef",
		ExpectedUID:   &expectedUID,
		ExpectedGID:   &expectedGID,
		RequireMarker: true,
	}); err == nil {
		t.Fatal("expected missing marker to block in non-root-required mode")
	}
}

func TestFutureNonRootRequiredModeBlocksTargetOwnerMismatch(t *testing.T) {
	expectedUID := 123
	expectedGID := 456
	marker := NewNormalizedMarker("run-0123456789abcdef", 999, expectedGID, mustTime(t, "2026-04-25T12:00:00Z"))

	result, err := ValidateState(&marker, ValidationOptions{
		RunID:         marker.RunID,
		ExpectedUID:   &expectedUID,
		ExpectedGID:   &expectedGID,
		RequireMarker: true,
	})
	if err == nil {
		t.Fatal("expected target-owner mismatch to block in non-root-required mode")
	}
	if result.Mode != ValidationModeNonRootRequired || !result.TargetOwnerChecked || result.TargetOwnerVerified {
		t.Fatalf("unexpected mismatch result %+v", result)
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
