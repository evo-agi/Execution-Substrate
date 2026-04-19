package admission

import "testing"

func TestResolveExecutionLocatorTrimsAndDerivesCurrentJobID(t *testing.T) {
	locator, err := resolveExecutionLocator("  run-deadbeefdeadbeef  ")
	if err != nil {
		t.Fatalf("resolve execution locator: %v", err)
	}
	if locator.RunID != "run-deadbeefdeadbeef" {
		t.Fatalf("expected trimmed run id, got %q", locator.RunID)
	}
	if locator.JobID() != "exec-run-deadbeefdeadbeef" {
		t.Fatalf("expected current derived job id, got %q", locator.JobID())
	}
}

func TestResolveExecutionLocatorRejectsInvalidRunID(t *testing.T) {
	if _, err := resolveExecutionLocator("not-a-run-id"); err == nil || err.Code != codeInvalidRunID {
		t.Fatalf("expected invalid run id error, got %v", err)
	}
}

func TestCurrentLifecycleProjectionPolicySelectsLatestModifyIndex(t *testing.T) {
	selected, ok := currentLifecycleProjectionPolicy{}.selectAllocation([]nomadAllocationListEntry{
		{ID: "alloc-older", ModifyIndex: 2},
		{ID: "alloc-newest", ModifyIndex: 7},
		{ID: "alloc-middle", ModifyIndex: 5},
	})
	if !ok {
		t.Fatalf("expected a selected allocation")
	}
	if selected.ID != "alloc-newest" {
		t.Fatalf("expected latest allocation, got %+v", selected)
	}
}
