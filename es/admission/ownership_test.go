package admission

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveExecutionPlatformStateOwnerModelAcceptsMatchingRoots(t *testing.T) {
	owner, err := resolveExecutionPlatformStateOwnerModel(
		"/stage",
		"/results",
		func(path string) (executionPlatformStateOwner, error) {
			return executionPlatformStateOwner{UID: 2001, GID: 2001}, nil
		},
	)
	if err != nil {
		t.Fatalf("expected matching roots to resolve, got %v", err)
	}
	if owner != (executionPlatformStateOwner{UID: 2001, GID: 2001}) {
		t.Fatalf("unexpected owner %+v", owner)
	}
}

func TestResolveExecutionPlatformStateOwnerModelRejectsMismatchedRoots(t *testing.T) {
	_, err := resolveExecutionPlatformStateOwnerModel(
		"/stage",
		"/results",
		func(path string) (executionPlatformStateOwner, error) {
			if path == "/stage" {
				return executionPlatformStateOwner{UID: 2001, GID: 2001}, nil
			}
			return executionPlatformStateOwner{UID: 2001, GID: 2002}, nil
		},
	)
	if err == nil {
		t.Fatal("expected mismatched roots to fail")
	}
	if !strings.Contains(err.Error(), "must resolve to the same target owner uid:gid") {
		t.Fatalf("expected actionable mismatch error, got %v", err)
	}
}

func TestResolveExecutionPlatformStateOwnerModelWrapsPathLookupFailures(t *testing.T) {
	_, err := resolveExecutionPlatformStateOwnerModel(
		"/stage",
		"/results",
		func(path string) (executionPlatformStateOwner, error) {
			if path == "/stage" {
				return executionPlatformStateOwner{}, errors.New("boom")
			}
			return executionPlatformStateOwner{UID: 2001, GID: 2001}, nil
		},
	)
	if err == nil {
		t.Fatal("expected path lookup failure to be returned")
	}
	if !strings.Contains(err.Error(), "execution.staging_root_dir") {
		t.Fatalf("expected staging-root context, got %v", err)
	}
}
