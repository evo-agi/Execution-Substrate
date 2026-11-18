package admission

import (
	"fmt"
	"os"
	"syscall"
)

const (
	stableStageDirMode                    = 0o750
	stableStageFileMode                   = 0o640
	stableStageExecFileMode               = 0o750
	retainedNormalizationEvidenceFileMode = 0o640
	retainedResultBundleFileMode          = 0o600
	retainedResultRunDirMode              = 0o750
)

type executionPlatformStateOwner struct {
	UID int
	GID int
}

type executionPlatformStateOwnerResolver func(string) (executionPlatformStateOwner, error)

func executionPlatformStateOwnerFromPath(path string) (executionPlatformStateOwner, error) {
	directory, err := openQualifiedDirectory(path, false, 0)
	if err != nil {
		return executionPlatformStateOwner{}, err
	}
	defer directory.close()
	if err := directory.verifyVisible(); err != nil {
		return executionPlatformStateOwner{}, err
	}
	return executionPlatformStateOwner{
		UID: directory.identity.UID,
		GID: directory.identity.GID,
	}, nil
}

func resolveExecutionPlatformStateOwnerModel(
	stagingRootDir string,
	resultsRootDir string,
	resolve executionPlatformStateOwnerResolver,
) (executionPlatformStateOwner, error) {
	if resolve == nil {
		resolve = executionPlatformStateOwnerFromPath
	}

	stagingOwner, err := resolve(stagingRootDir)
	if err != nil {
		return executionPlatformStateOwner{}, fmt.Errorf("derive execution.staging_root_dir target owner: %w", err)
	}
	resultsOwner, err := resolve(resultsRootDir)
	if err != nil {
		return executionPlatformStateOwner{}, fmt.Errorf("derive execution.results_root_dir target owner: %w", err)
	}
	if stagingOwner != resultsOwner {
		return executionPlatformStateOwner{}, fmt.Errorf(
			"execution.staging_root_dir and execution.results_root_dir must resolve to the same target owner uid:gid for non-root ES readiness (got %d:%d vs %d:%d)",
			stagingOwner.UID,
			stagingOwner.GID,
			resultsOwner.UID,
			resultsOwner.GID,
		)
	}
	return stagingOwner, nil
}

func ownershipExpectationsForRun(runID string, owner executionPlatformStateOwner, requireMarker bool) ownershipNormalizationMarkerExpectations {
	return ownershipNormalizationMarkerExpectations{
		RunID:         runID,
		ExpectedUID:   intPtr(owner.UID),
		ExpectedGID:   intPtr(owner.GID),
		RequireMarker: requireMarker,
	}
}

func ownershipIDsFromInfo(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, fmt.Errorf("unsupported file ownership metadata")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func normalizedStableStageFileMode(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return stableStageExecFileMode
	}
	return stableStageFileMode
}

func intPtr(value int) *int {
	return &value
}
