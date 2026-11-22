package admission

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const executionRootDirectoryMode = 0o755

// nestedStagingProbeName names the directory the startup probe creates inside
// its staging probe directory (probeNestedStagingDirectory).
const nestedStagingProbeName = "nested"

type executionRootAcquisitionLedger struct {
	Count int
}

type executionRootPlatformObservation struct {
	presentation string
	sourceDevice string
	sourcePath   string
	filesystemID string
	mountedOn    string
}

type executionRootPlan struct {
	configuredPath      string
	components          []string
	componentIdentities []custodyIdentity
	existingFD          int
	existingIdentity    custodyIdentity
	parentFD            int
	parentIdentity      custodyIdentity
	leafName            string
	missingSuffix       []string
	platform            executionRootPlatformObservation
}

func (plan *executionRootPlan) observed() bool {
	return plan != nil && len(plan.missingSuffix) == 0
}

func (plan *executionRootPlan) close() error {
	if plan == nil {
		return nil
	}
	var errs []error
	if plan.existingFD >= 0 {
		errs = append(errs, unix.Close(plan.existingFD))
		plan.existingFD = -1
	}
	if plan.parentFD >= 0 {
		errs = append(errs, unix.Close(plan.parentFD))
		plan.parentFD = -1
	}
	return errors.Join(errs...)
}

type qualifiedExecutionRoots struct {
	staging      *executionRootPlan
	results      *executionRootPlan
	acquisitions *executionRootAcquisitionLedger
	closed       bool
}

func qualifyExecutionRoots(stagingPath string, resultsPath string, acquisitions *executionRootAcquisitionLedger) (*qualifiedExecutionRoots, error) {
	staging, err := planExecutionRoot(stagingPath)
	if err != nil {
		return nil, fmt.Errorf("qualify execution staging root: %w", err)
	}
	results, err := planExecutionRoot(resultsPath)
	if err != nil {
		_ = staging.close()
		return nil, fmt.Errorf("qualify execution results root: %w", err)
	}
	roots := &qualifiedExecutionRoots{staging: staging, results: results, acquisitions: acquisitions}
	if err := roots.reobserve(); err != nil {
		_ = roots.close()
		return nil, err
	}
	return roots, nil
}

func (roots *qualifiedExecutionRoots) close() error {
	if roots == nil || roots.closed {
		return nil
	}
	roots.closed = true
	return errors.Join(roots.staging.close(), roots.results.close())
}

func (roots *qualifiedExecutionRoots) reobserve() error {
	if roots == nil || roots.closed || roots.staging == nil || roots.results == nil {
		return fmt.Errorf("execution root custody is closed")
	}
	if err := verifyExecutionRootPlan(roots.staging); err != nil {
		return fmt.Errorf("execution staging root changed: %w", err)
	}
	if err := verifyExecutionRootPlan(roots.results); err != nil {
		return fmt.Errorf("execution results root changed: %w", err)
	}
	if err := classifyVisibleExecutionRootAncestry(roots.staging, roots.results); err != nil {
		return err
	}
	if roots.acquisitions != nil {
		roots.acquisitions.Count++
	}
	if err := platformObserveExecutionRoots(roots.staging, roots.results); err != nil {
		return fmt.Errorf("execution roots could not be proven physically separate: %w", err)
	}
	return classifyExecutionRootPlatformObservations(roots.staging, roots.results)
}

func planExecutionRoot(configuredPath string) (*executionRootPlan, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(configuredPath))
	if !filepath.IsAbs(cleanPath) || cleanPath == string(os.PathSeparator) {
		return nil, fmt.Errorf("execution root must be an absolute non-root path")
	}
	components := strings.Split(strings.TrimPrefix(cleanPath, string(os.PathSeparator)), string(os.PathSeparator))
	for _, component := range components {
		if !validCustodyComponent(component) {
			return nil, fmt.Errorf("execution root contains an invalid component")
		}
	}

	currentFD, err := unix.Open(string(os.PathSeparator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	plan := &executionRootPlan{
		configuredPath: cleanPath,
		components:     append([]string(nil), components...),
		existingFD:     currentFD,
		parentFD:       -1,
	}
	var currentStat unix.Stat_t
	if err := unix.Fstat(currentFD, &currentStat); err != nil {
		_ = plan.close()
		return nil, err
	}
	plan.existingIdentity = custodyIdentityFromStat(currentStat)
	plan.componentIdentities = append(plan.componentIdentities, plan.existingIdentity)

	for index, component := range components {
		nextFD, openErr := platformOpenAtNoFollow(plan.existingFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, false)
		if openErr != nil {
			if !errors.Is(openErr, unix.ENOENT) {
				_ = plan.close()
				return nil, openErr
			}
			var absent unix.Stat_t
			if err := unix.Fstatat(plan.existingFD, component, &absent, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
				_ = plan.close()
				if err == nil {
					return nil, fmt.Errorf("first missing execution-root component became visible")
				}
				return nil, err
			}
			plan.missingSuffix = append([]string(nil), components[index:]...)
			return plan, nil
		}
		var nextStat unix.Stat_t
		if err := unix.Fstat(nextFD, &nextStat); err != nil {
			_ = unix.Close(nextFD)
			_ = plan.close()
			return nil, err
		}
		nextIdentity := custodyIdentityFromStat(nextStat)
		if !custodyIdentityIsDirectory(nextIdentity) {
			_ = unix.Close(nextFD)
			_ = plan.close()
			return nil, fmt.Errorf("execution-root component is not a directory")
		}
		plan.componentIdentities = append(plan.componentIdentities, nextIdentity)
		if index == len(components)-1 {
			plan.parentFD = plan.existingFD
			plan.parentIdentity = plan.existingIdentity
			plan.existingFD = nextFD
			plan.existingIdentity = nextIdentity
			plan.leafName = component
			return plan, nil
		}
		if err := unix.Close(plan.existingFD); err != nil {
			_ = unix.Close(nextFD)
			plan.existingFD = -1
			_ = plan.close()
			return nil, err
		}
		plan.existingFD = nextFD
		plan.existingIdentity = nextIdentity
	}
	_ = plan.close()
	return nil, fmt.Errorf("execution root has no components")
}

func verifyExecutionRootPlan(plan *executionRootPlan) error {
	if plan == nil || plan.existingFD < 0 {
		return fmt.Errorf("execution root plan is closed")
	}
	var held unix.Stat_t
	if err := unix.Fstat(plan.existingFD, &held); err != nil {
		return err
	}
	if !sameCustodyObject(plan.existingIdentity, custodyIdentityFromStat(held)) {
		return fmt.Errorf("held execution-root identity changed")
	}
	if !plan.observed() {
		var absent unix.Stat_t
		if err := unix.Fstatat(plan.existingFD, plan.missingSuffix[0], &absent, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			if err == nil {
				return fmt.Errorf("missing execution-root intent became visible")
			}
			return err
		}
		return nil
	}
	if plan.parentFD < 0 {
		return fmt.Errorf("observed execution root has no held parent")
	}
	var parent unix.Stat_t
	if err := unix.Fstat(plan.parentFD, &parent); err != nil {
		return err
	}
	if !sameCustodyObject(plan.parentIdentity, custodyIdentityFromStat(parent)) {
		return fmt.Errorf("held execution-root parent changed")
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(plan.parentFD, plan.leafName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(plan.existingIdentity, custodyIdentityFromStat(visible)) {
		return fmt.Errorf("visible execution root no longer names the held object")
	}
	return nil
}

func classifyVisibleExecutionRootAncestry(staging *executionRootPlan, results *executionRootPlan) error {
	if staging.observed() && identityAppearsInChain(staging.existingIdentity, results.componentIdentities) {
		return fmt.Errorf("execution staging root aliases or contains execution results root")
	}
	if results.observed() && identityAppearsInChain(results.existingIdentity, staging.componentIdentities) {
		return fmt.Errorf("execution results root aliases or contains execution staging root")
	}
	if !staging.observed() && !results.observed() && sameCustodyObject(staging.existingIdentity, results.existingIdentity) {
		return fmt.Errorf("dual-missing execution roots share one unobserved lookup context")
	}
	return nil
}

func identityAppearsInChain(identity custodyIdentity, chain []custodyIdentity) bool {
	for _, candidate := range chain {
		if sameCustodyObject(identity, candidate) {
			return true
		}
	}
	return false
}

type executionRootPathRelation uint8

const (
	executionRootPathsDisjoint executionRootPathRelation = iota
	executionRootPathsEqual
	executionRootLeftAncestor
	executionRootRightAncestor
)

func executionRootComponentRelation(left string, right string) executionRootPathRelation {
	if left == right {
		return executionRootPathsEqual
	}
	leftPrefix := left
	if leftPrefix != "/" {
		leftPrefix += "/"
	}
	rightPrefix := right
	if rightPrefix != "/" {
		rightPrefix += "/"
	}
	if strings.HasPrefix(right, leftPrefix) {
		return executionRootLeftAncestor
	}
	if strings.HasPrefix(left, rightPrefix) {
		return executionRootRightAncestor
	}
	return executionRootPathsDisjoint
}

func classifyExecutionRootPlatformObservations(staging *executionRootPlan, results *executionRootPlan) error {
	left := staging.platform
	right := results.platform
	if left.sourceDevice != "" || right.sourceDevice != "" {
		if left.sourceDevice == "" || right.sourceDevice == "" || left.sourcePath == "" || right.sourcePath == "" {
			return fmt.Errorf("incomplete Linux execution-root topology evidence")
		}
		if left.sourceDevice != right.sourceDevice {
			return nil
		}
		return classifyExecutionRootCoordinateRelation(staging, results, executionRootComponentRelation(left.sourcePath, right.sourcePath))
	}
	if left.filesystemID == "" || right.filesystemID == "" || left.mountedOn == "" || right.mountedOn == "" {
		return fmt.Errorf("incomplete Darwin execution-root topology evidence")
	}
	if left.filesystemID != right.filesystemID {
		return nil
	}
	if left.mountedOn != right.mountedOn {
		return fmt.Errorf("same-FSID distinct execution-root presentations are unprovable")
	}
	return classifyExecutionRootCoordinateRelation(staging, results, executionRootComponentRelation(left.presentation, right.presentation))
}

func classifyExecutionRootCoordinateRelation(staging *executionRootPlan, results *executionRootPlan, relation executionRootPathRelation) error {
	if staging.observed() && results.observed() {
		if relation != executionRootPathsDisjoint {
			return fmt.Errorf("execution roots have equal or ancestor-related physical coordinates")
		}
		return nil
	}
	if !staging.observed() && !results.observed() {
		if relation != executionRootPathsDisjoint {
			return fmt.Errorf("dual-missing execution roots do not have canonically disjoint existing parents")
		}
		return nil
	}
	if !staging.observed() {
		if relation == executionRootPathsEqual || relation == executionRootRightAncestor {
			return fmt.Errorf("missing staging-root intent is within execution results root")
		}
		return nil
	}
	if relation == executionRootPathsEqual || relation == executionRootLeftAncestor {
		return fmt.Errorf("missing results-root intent is within execution staging root")
	}
	return nil
}

func provisionExecutionRoots(stagingPath string, resultsPath string, acquisitions *executionRootAcquisitionLedger) (*qualifiedExecutionRoots, error) {
	roots, err := qualifyExecutionRoots(stagingPath, resultsPath, acquisitions)
	if err != nil {
		return nil, err
	}
	for !roots.staging.observed() {
		if err := roots.createNextConfiguredRootComponent(roots.staging); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("create execution staging root component: %w", err)
		}
		_ = roots.close()
		roots, err = qualifyExecutionRoots(stagingPath, resultsPath, acquisitions)
		if err != nil {
			return nil, err
		}
	}
	for !roots.results.observed() {
		if err := roots.createNextConfiguredRootComponent(roots.results); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("create execution results root component: %w", err)
		}
		_ = roots.close()
		roots, err = qualifyExecutionRoots(stagingPath, resultsPath, acquisitions)
		if err != nil {
			return nil, err
		}
	}
	return roots, nil
}

func (roots *qualifiedExecutionRoots) createNextConfiguredRootComponent(plan *executionRootPlan) error {
	if roots == nil || plan == nil || plan.observed() || len(plan.missingSuffix) == 0 {
		return fmt.Errorf("execution root has no missing component")
	}
	if err := verifyExecutionRootPlan(plan); err != nil {
		return err
	}
	return unix.Mkdirat(plan.existingFD, plan.missingSuffix[0], executionRootDirectoryMode)
}

func (roots *qualifiedExecutionRoots) owner() (executionPlatformStateOwner, error) {
	if roots == nil || !roots.staging.observed() || !roots.results.observed() {
		return executionPlatformStateOwner{}, fmt.Errorf("execution roots are not both observed")
	}
	stagingOwner := executionPlatformStateOwner{UID: roots.staging.existingIdentity.UID, GID: roots.staging.existingIdentity.GID}
	resultsOwner := executionPlatformStateOwner{UID: roots.results.existingIdentity.UID, GID: roots.results.existingIdentity.GID}
	if stagingOwner != resultsOwner {
		return executionPlatformStateOwner{}, fmt.Errorf("execution staging and results roots must have the same owner")
	}
	return stagingOwner, nil
}

func (roots *qualifiedExecutionRoots) takeStagingQualifiedDirectory() (*qualifiedDirectory, error) {
	return takeExecutionRootQualifiedDirectory(roots.staging)
}

func (roots *qualifiedExecutionRoots) duplicateStagingQualifiedDirectory() (*qualifiedDirectory, error) {
	return duplicateExecutionRootQualifiedDirectory(roots.staging)
}

func (roots *qualifiedExecutionRoots) duplicateResultsQualifiedDirectory() (*qualifiedDirectory, error) {
	return duplicateExecutionRootQualifiedDirectory(roots.results)
}

func takeExecutionRootQualifiedDirectory(plan *executionRootPlan) (*qualifiedDirectory, error) {
	if plan == nil || !plan.observed() || plan.existingFD < 0 || plan.parentFD < 0 || plan.platform.presentation == "" {
		return nil, fmt.Errorf("execution root is not available for descriptor transfer")
	}
	presentation := plan.platform.presentation
	directory := &qualifiedDirectory{
		path:           presentation,
		fd:             plan.existingFD,
		identity:       plan.existingIdentity,
		parentPath:     filepath.Dir(presentation),
		parentFD:       plan.parentFD,
		parentIdentity: plan.parentIdentity,
		leafName:       filepath.Base(presentation),
	}
	plan.existingFD = -1
	plan.parentFD = -1
	return directory, nil
}

func duplicateExecutionRootQualifiedDirectory(plan *executionRootPlan) (*qualifiedDirectory, error) {
	if plan == nil || !plan.observed() || plan.existingFD < 0 || plan.parentFD < 0 || plan.platform.presentation == "" {
		return nil, fmt.Errorf("execution root is not available for descriptor duplication")
	}
	rootFD, err := unix.Dup(plan.existingFD)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(rootFD)
	parentFD, err := unix.Dup(plan.parentFD)
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	unix.CloseOnExec(parentFD)
	presentation := plan.platform.presentation
	return &qualifiedDirectory{
		path:           presentation,
		fd:             rootFD,
		identity:       plan.existingIdentity,
		parentPath:     filepath.Dir(presentation),
		parentFD:       parentFD,
		parentIdentity: plan.parentIdentity,
		leafName:       filepath.Base(presentation),
	}, nil
}

func (roots *qualifiedExecutionRoots) probeCapabilities(owner executionPlatformStateOwner) error {
	if roots == nil || !roots.staging.observed() || !roots.results.observed() {
		return fmt.Errorf("execution roots are unavailable for capability probes")
	}
	token, err := randomCustodyToken()
	if err != nil {
		return err
	}
	stagingName := ".execution-substrate-staging-probe-" + token
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Mkdirat(roots.staging.existingFD, stagingName, stableStageDirMode); err != nil {
		return err
	}
	stagingFD, err := platformOpenAtNoFollow(roots.staging.existingFD, stagingName, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return err
	}
	if err := roots.reobserve(); err != nil {
		_ = unix.Close(stagingFD)
		return err
	}
	if err := unix.Fchown(stagingFD, owner.UID, owner.GID); err != nil {
		_ = unix.Close(stagingFD)
		return err
	}
	if err := roots.reobserve(); err != nil {
		_ = unix.Close(stagingFD)
		return err
	}
	if err := unix.Fchmod(stagingFD, uint32(stableStageDirMode)); err != nil {
		_ = unix.Close(stagingFD)
		return err
	}
	if err := roots.probeNestedStagingDirectory(stagingFD, owner); err != nil {
		_ = unix.Close(stagingFD)
		return err
	}
	if err := unix.Close(stagingFD); err != nil {
		return err
	}
	stagingLinkName := stagingName + "-symlink"
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Symlinkat(stagingName, roots.staging.existingFD, stagingLinkName); err != nil {
		return err
	}
	if err := roots.reobserve(); err != nil {
		return err
	}
	if fd, err := platformOpenAtNoFollow(roots.staging.existingFD, stagingLinkName, unix.O_RDONLY|unix.O_DIRECTORY, 0, true); err == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("no-follow open unexpectedly traversed a staging probe symlink")
	} else if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("no-follow open did not prove staging symlink refusal: %w", err)
	}

	resultsName := ".execution-substrate-results-probe-" + token
	if err := roots.reobserve(); err != nil {
		return err
	}
	resultsFD, err := platformOpenAtNoFollow(roots.results.existingFD, resultsName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, retainedResultBundleFileMode, true)
	if err != nil {
		return err
	}
	if err := roots.reobserve(); err != nil {
		_ = unix.Close(resultsFD)
		return err
	}
	if err := unix.Fchown(resultsFD, owner.UID, owner.GID); err != nil {
		_ = unix.Close(resultsFD)
		return err
	}
	if err := roots.reobserve(); err != nil {
		_ = unix.Close(resultsFD)
		return err
	}
	if err := unix.Fchmod(resultsFD, uint32(retainedResultBundleFileMode)); err != nil {
		_ = unix.Close(resultsFD)
		return err
	}
	if err := unix.Close(resultsFD); err != nil {
		return err
	}
	collisionName := resultsName + "-collision"
	if err := roots.reobserve(); err != nil {
		return err
	}
	collisionFD, err := platformOpenAtNoFollow(roots.results.existingFD, collisionName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, retainedResultBundleFileMode, true)
	if err != nil {
		return err
	}
	if err := unix.Close(collisionFD); err != nil {
		return err
	}
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := platformRenameNoReplace(roots.results.existingFD, resultsName, roots.results.existingFD, collisionName); err == nil {
		return fmt.Errorf("no-replace rename unexpectedly replaced a result probe destination")
	}
	return roots.probeNaturalResultDirectory(owner, token)
}

// probeNestedStagingDirectory repeats, inside the staging probe directory, what
// staging does inside a run staging root: it creates a directory, gives it the
// roots' owner and the stable stage mode, and checks the result. The probe
// directory, like a claimed run staging root, has just been set to the stable
// stage mode, which carries no setgid bit, so the new directory gets this
// process's effective GID rather than the roots' GID. Giving it the roots' GID
// then needs membership of that group or the privilege to change any group.
// Probes that create entries directly in the roots cannot see this when the
// roots hand their group down through the setgid bit.
func (roots *qualifiedExecutionRoots) probeNestedStagingDirectory(stagingFD int, owner executionPlatformStateOwner) error {
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Mkdirat(stagingFD, nestedStagingProbeName, stableStageDirMode); err != nil {
		return err
	}
	nestedFD, err := platformOpenAtNoFollow(stagingFD, nestedStagingProbeName, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return err
	}
	defer unix.Close(nestedFD)
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Fchown(nestedFD, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("nested staging directory ownership is unavailable: %w", err)
	}
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Fchmod(nestedFD, uint32(stableStageDirMode)); err != nil {
		return err
	}
	var nestedStat unix.Stat_t
	if err := unix.Fstat(nestedFD, &nestedStat); err != nil {
		return err
	}
	nestedIdentity := custodyIdentityFromStat(nestedStat)
	if !custodyIdentityIsDirectory(nestedIdentity) ||
		nestedIdentity.Device != roots.staging.existingIdentity.Device ||
		nestedIdentity.Links < 1 ||
		nestedIdentity.UID != owner.UID || nestedIdentity.GID != owner.GID ||
		!sameCustodyRecordedMode(nestedIdentity.Mode, unix.S_IFDIR|uint32(stableStageDirMode)) {
		return fmt.Errorf("nested staging directory ownership is unavailable")
	}
	return nil
}

func (roots *qualifiedExecutionRoots) probeNaturalResultDirectory(owner executionPlatformStateOwner, token string) error {
	resultDirName := ".execution-substrate-result-dir-probe-" + token
	if err := roots.reobserve(); err != nil {
		return err
	}
	if err := unix.Mkdirat(roots.results.existingFD, resultDirName, uint32(retainedResultRunDirMode)); err != nil {
		return err
	}
	resultDirFD, err := platformOpenAtNoFollow(roots.results.existingFD, resultDirName, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return err
	}
	defer unix.Close(resultDirFD)
	if err := roots.reobserve(); err != nil {
		return err
	}
	var resultDirStat unix.Stat_t
	if err := unix.Fstat(resultDirFD, &resultDirStat); err != nil {
		return err
	}
	resultDirIdentity := custodyIdentityFromStat(resultDirStat)
	if !custodyIdentityIsDirectory(resultDirIdentity) ||
		resultDirIdentity.Device != roots.results.existingIdentity.Device ||
		resultDirIdentity.Links < 1 ||
		resultDirIdentity.UID != owner.UID || resultDirIdentity.GID != owner.GID ||
		os.FileMode(resultDirIdentity.Mode).Perm() != retainedResultRunDirMode {
		return fmt.Errorf("natural retained result directory creation is unavailable")
	}
	return nil
}
