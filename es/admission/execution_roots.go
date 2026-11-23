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
	stagingFD, err := roots.probeStagedDirectory(roots.staging.existingFD, stagingName, stableStageDirMode, owner, "staging probe directory")
	if err != nil {
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
	return roots.probeNaturalResultDirectory(owner, token)
}

// probeStagedDirectory creates a directory the way staging creates one, both
// a claimed run staging root (claimStagingCustodyFromQualifiedRoot) and the
// directories inside it (stagingCustody.ensureDirectory): it creates the
// directory, opens it by name, refuses it unless it already belongs to the
// roots' owning user, gives it the roots' owner and the mode, and holds it to
// staging's checks. It returns the open directory.
func (roots *qualifiedExecutionRoots) probeStagedDirectory(parentFD int, name string, mode os.FileMode, owner executionPlatformStateOwner, label string) (int, error) {
	if err := roots.reobserve(); err != nil {
		return -1, err
	}
	if err := unix.Mkdirat(parentFD, name, uint32(mode.Perm())); err != nil {
		return -1, err
	}
	fd, err := platformOpenAtNoFollow(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return -1, err
	}
	fail := func(cause error) (int, error) {
		_ = unix.Close(fd)
		return -1, cause
	}
	if err := requireOpenedDirectoryOwnedByRootsUser(fd, owner, label); err != nil {
		return fail(err)
	}
	if err := roots.reobserve(); err != nil {
		return fail(err)
	}
	if err := unix.Fchown(fd, owner.UID, owner.GID); err != nil {
		return fail(fmt.Errorf("%s ownership is unavailable: %w", label, err))
	}
	if err := roots.reobserve(); err != nil {
		return fail(err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fail(fmt.Errorf("%s mode is unavailable: %w", label, err))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	identity := custodyIdentityFromStat(stat)
	switch {
	case !custodyIdentityIsDirectory(identity) ||
		identity.Device != roots.staging.existingIdentity.Device ||
		identity.Links < 1:
		return fail(fmt.Errorf("%s has an invalid identity", label))
	case identity.UID != owner.UID || identity.GID != owner.GID:
		return fail(fmt.Errorf("%s ownership is unavailable", label))
	case !sameCustodyRecordedMode(identity.Mode, unix.S_IFDIR|uint32(mode.Perm())):
		return fail(fmt.Errorf("%s mode is unavailable", label))
	}
	return fd, nil
}

// probeNestedStagingDirectory repeats, inside the staging probe directory, what
// staging does inside a run staging root: it creates a directory, gives it the
// roots' owner and the stable stage mode, and checks the result. The probe
// directory, like a claimed run staging root, has just been set to the stable
// stage mode, which carries no setgid bit, so the new directory gets this
// process's effective GID rather than the roots' GID. Giving it the roots' GID
// then needs membership of that group or the privilege to change any group.
// Probes that create entries directly in the roots cannot see this when the
// roots hand their group down through the setgid bit. Inside the new
// directory it then stages one entry of each mode staging uses.
func (roots *qualifiedExecutionRoots) probeNestedStagingDirectory(stagingFD int, owner executionPlatformStateOwner) error {
	nestedFD, err := roots.probeStagedDirectory(stagingFD, nestedStagingProbeName, stableStageDirMode, owner, "nested staging directory")
	if err != nil {
		return err
	}
	defer unix.Close(nestedFD)
	return roots.probeStagedEntries(nestedFD, owner)
}

// probeStagedEntries stages, inside the nested staging directory, one
// directory for each directory mode staging uses beyond the stable stage mode
// of the nested directory itself, and one regular file for each file mode
// staging uses (stagedDirectoryModes and stagedFileModes), and holds each to
// staging's checks. A file system can pass the directory checks and still fail
// these: an overlay whose layers are on different file systems reports
// another device for regular files than for directories, and a file system
// that does not keep the modes it is asked for fails on the first mode it
// cannot keep. Staging would refuse submissions there: on such an overlay all
// of them, and on a file system that cannot keep a mode, those that need it.
// The governed-mount modes are needed only by submissions with governed
// mounts, so startup also refuses a staging file system that cannot keep
// them, although submissions without governed mounts would work there. That
// is the chosen rule (STARTUP-PROBE-USE-AGREEMENT-01): no submission ES
// accepts fails for want of a mode.
func (roots *qualifiedExecutionRoots) probeStagedEntries(nestedFD int, owner executionPlatformStateOwner) error {
	for _, mode := range stagedDirectoryModes() {
		if mode == stableStageDirMode {
			continue
		}
		fd, err := roots.probeStagedDirectory(nestedFD, fmt.Sprintf("directory-%04o", uint32(mode)), mode, owner, fmt.Sprintf("staged %04o directory", uint32(mode)))
		if err != nil {
			return err
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
	}
	if err := roots.reobserve(); err != nil {
		return err
	}
	for _, mode := range stagedFileModes() {
		if err := probeStagedFile(nestedFD, mode, owner, roots.staging.existingIdentity.Device); err != nil {
			return err
		}
	}
	return nil
}

// probeStagedFile creates a regular file the way staging writes one
// (stagingCustody.writeFileWithHookAndParentMode) and holds it to staging's
// checks.
func probeStagedFile(parentFD int, mode os.FileMode, owner executionPlatformStateOwner, stagingDevice uint64) error {
	fd, err := platformOpenAtNoFollow(parentFD, fmt.Sprintf("file-%04o", uint32(mode)), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(mode.Perm()), true)
	if err != nil {
		return fmt.Errorf("staged file creation is unavailable: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("staged file ownership is unavailable: %w", err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("staged file mode %04o is unavailable: %w", uint32(mode), err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	identity := custodyIdentityFromStat(stat)
	switch {
	case !custodyIdentityIsRegular(identity) || identity.Links != 1:
		return fmt.Errorf("staged file has an invalid identity")
	case identity.Device != stagingDevice:
		return fmt.Errorf("staged files report another device than the staging root")
	case identity.UID != owner.UID || identity.GID != owner.GID:
		return fmt.Errorf("staged file ownership is unavailable")
	case !sameCustodyRecordedMode(identity.Mode, unix.S_IFREG|uint32(mode.Perm())):
		return fmt.Errorf("staged file mode %04o is unavailable", uint32(mode))
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
	return roots.probeRetainedResultFiles(resultDirFD, owner)
}

// probeRetainedResultFiles repeats, inside the natural result directory probe,
// what retention does inside a retained result directory: it creates one file
// for each mode retention gives its files, gives each the roots' owner and its
// mode, and holds it to retention's checks (createTempFile,
// ensureNormalizationEvidenceWithHook and publishRetainedResultRecord). Then
// it renames the bundle-mode file with the no-replace rename, as
// publishTemporaryBundle does: onto a name that exists, which must be refused
// as existing, and onto a free name, which must succeed and keep the file.
// Linux refuses a no-replace rename onto an existing name before it asks the
// file system, so only the second rename shows that the file system supports
// the primitive. A file system whose rename accepts no flags fails it, and
// retention would then fail for every run.
func (roots *qualifiedExecutionRoots) probeRetainedResultFiles(directoryFD int, owner executionPlatformStateOwner) error {
	const (
		bundleName    = "bundle"
		evidenceName  = "evidence"
		collisionName = "collision"
		renamedName   = "renamed"
	)
	resultsDevice := roots.results.existingIdentity.Device
	if err := roots.reobserve(); err != nil {
		return err
	}
	bundleFD, err := probeRetainedResultFile(directoryFD, bundleName, retainedResultBundleFileMode, owner, resultsDevice)
	if err != nil {
		return err
	}
	defer unix.Close(bundleFD)
	evidenceFD, err := probeRetainedResultFile(directoryFD, evidenceName, retainedNormalizationEvidenceFileMode, owner, resultsDevice)
	if err != nil {
		return err
	}
	if err := unix.Close(evidenceFD); err != nil {
		return err
	}
	collisionFD, err := platformOpenAtNoFollow(directoryFD, collisionName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, retainedResultBundleFileMode, true)
	if err != nil {
		return err
	}
	if err := unix.Close(collisionFD); err != nil {
		return err
	}
	if err := platformRenameNoReplace(directoryFD, bundleName, directoryFD, collisionName); err == nil {
		return fmt.Errorf("no-replace rename unexpectedly replaced a result probe destination")
	} else if !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("no-replace rename onto an existing result name did not report it as existing: %w", err)
	}
	if err := platformRenameNoReplace(directoryFD, bundleName, directoryFD, renamedName); err != nil {
		return fmt.Errorf("no-replace rename to a free result name is unavailable: %w", err)
	}
	var held, renamed unix.Stat_t
	if err := unix.Fstat(bundleFD, &held); err != nil {
		return err
	}
	if err := unix.Fstatat(directoryFD, renamedName, &renamed, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("no-replace rename did not move the result probe file: %w", err)
	}
	renamedIdentity := custodyIdentityFromStat(renamed)
	if !sameCustodyObject(custodyIdentityFromStat(held), renamedIdentity) {
		return fmt.Errorf("no-replace rename did not move the result probe file")
	}
	if err := retainedResultFileIdentityError(renamedIdentity, retainedResultBundleFileMode, owner, resultsDevice); err != nil {
		return fmt.Errorf("no-replace rename did not keep the result probe file: %w", err)
	}
	return nil
}

// probeRetainedResultFile creates a file the way retention creates its files
// and holds it to retention's checks (validateRetainedResultStat). It returns
// the open file.
func probeRetainedResultFile(directoryFD int, name string, mode os.FileMode, owner executionPlatformStateOwner, resultsDevice uint64) (int, error) {
	fd, err := platformOpenAtNoFollow(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, uint32(mode.Perm()), true)
	if err != nil {
		return -1, fmt.Errorf("retained result file creation is unavailable: %w", err)
	}
	fail := func(cause error) (int, error) {
		_ = unix.Close(fd)
		return -1, cause
	}
	if err := unix.Fchown(fd, owner.UID, owner.GID); err != nil {
		return fail(fmt.Errorf("retained result file ownership is unavailable: %w", err))
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fail(fmt.Errorf("retained result file mode %04o is unavailable: %w", uint32(mode), err))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	if err := retainedResultFileIdentityError(custodyIdentityFromStat(stat), mode, owner, resultsDevice); err != nil {
		return fail(err)
	}
	return fd, nil
}

// retainedResultFileIdentityError applies the identity check retention applies
// to its files (retainedResultDirectory.validateRetainedResultStat) and names
// the part that fails.
func retainedResultFileIdentityError(identity custodyIdentity, mode os.FileMode, owner executionPlatformStateOwner, resultsDevice uint64) error {
	switch {
	case !custodyIdentityIsRegular(identity) || identity.Links != 1:
		return fmt.Errorf("retained result file has an invalid identity")
	case identity.Device != resultsDevice:
		return fmt.Errorf("retained result files report another device than the results root")
	case identity.UID != owner.UID || identity.GID != owner.GID:
		return fmt.Errorf("retained result file ownership is unavailable")
	case os.FileMode(identity.Mode).Perm() != mode.Perm():
		return fmt.Errorf("retained result file mode %04o is unavailable", uint32(mode))
	}
	return nil
}
