package admission

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	if err := s.lifecycleRuntimeUnavailableError(); err != nil {
		return ExecutionResultBundle{}, err
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
		log.Printf("es result retention failed run_id=%s", locator.RunID)
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
		log.Printf("es result retention failed run_id=%s", locator.RunID)
	}
}

func (s *Service) retainTerminalResult(locator executionLocator) (bool, error) {
	return s.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{})
}

func (s *Service) retainTerminalResultWithHooks(locator executionLocator, hooks retainedResultInstallHooks) (bool, error) {
	if s.resultAuth == nil {
		return false, fmt.Errorf("retained result authentication is unavailable")
	}
	if _, complete, readErr := s.readRetainedResultBundle(locator); readErr != nil {
		return false, fmt.Errorf("pre-existing retained result is not authenticated")
	} else if complete {
		return true, nil
	}
	roots, err := qualifyExecutionRoots(s.cfg.Execution.StagingRootDir, s.cfg.Execution.ResultsRootDir, nil)
	if err != nil {
		return false, err
	}
	defer roots.close()
	if !roots.staging.observed() {
		return false, nil
	}
	if !roots.results.observed() {
		return false, fmt.Errorf("execution results root is absent")
	}
	targetOwner, err := roots.owner()
	if err != nil {
		return false, err
	}
	stagingRoot, err := roots.duplicateStagingQualifiedDirectory()
	if err != nil {
		return false, err
	}
	stageTree, err := openStagingTreeFromQualifiedRoot(stagingRoot, locator.RunID)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer stageTree.close()
	expectations := ownershipExpectationsForRun(locator.RunID, targetOwner, false)
	platformFD, err := stageTree.openDirectory(executionRunStageDirName + "/platform")
	var stageMarker *ownershipNormalizationMarker
	var stageMarkerBytes []byte
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	if err == nil {
		stageMarker, stageMarkerBytes, err = loadValidatedOwnershipNormalizationMarkerAt(platformFD, expectations)
		_ = unix.Close(platformFD)
		if err != nil {
			return false, err
		}
	}

	resultSourceFD, err := stageTree.openDirectory(executionRunStageDirName + "/" + executionResultStageDirName)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(resultSourceFD)
	var resultSourceStat unix.Stat_t
	if err := unix.Fstat(resultSourceFD, &resultSourceStat); err != nil {
		return false, err
	}
	resultSourceIdentity := custodyIdentityFromStat(resultSourceStat)
	if !custodyIdentityIsDirectory(resultSourceIdentity) ||
		resultSourceIdentity.Device != stageTree.rootIdentity.Device ||
		resultSourceIdentity.UID != targetOwner.UID ||
		resultSourceIdentity.GID != targetOwner.GID {
		return false, fmt.Errorf("retained result source directory has an invalid identity")
	}
	resultDirectory, _, err := openOrCreateRetainedResultDirectory(roots, locator.RunID, targetOwner)
	if err != nil {
		return false, err
	}
	defer resultDirectory.close()

	tempName, tempFile, err := resultDirectory.createTempFile()
	if err != nil {
		return false, err
	}
	defer tempFile.Close()
	emitted := newRetainedResultEmissionWriter(tempFile)
	hasFiles, err := writeResultBundleFromDescriptor(emitted, resultSourceFD, stageTree.rootIdentity.Device, &targetOwner)
	if err != nil {
		return false, err
	}
	if !hasFiles {
		return false, nil
	}
	if err := stageTree.verifyVisible(); err != nil {
		return false, err
	}
	if err := tempFile.Sync(); err != nil {
		return false, err
	}
	fingerprint, err := resultDirectory.fingerprintTemporaryFile(tempName, tempFile)
	if err != nil {
		return false, err
	}
	if fingerprint != emitted.fingerprint() {
		return false, fmt.Errorf("retained result candidate differs from emitted archive bytes")
	}

	installed, err := resultDirectory.publishTemporaryBundle(tempName, fingerprint, tempFile, hooks)
	if err != nil {
		return false, err
	}
	if installed {
		if hooks.afterFinalInstall != nil {
			if err := hooks.afterFinalInstall(); err != nil {
				return false, err
			}
		}
		// Recheck after the installation interval: the held candidate may still
		// be intact even if the final pathname was replaced before the record.
		if err := resultDirectory.validateExistingRetainedResultBundle(resultBundleFileName, fingerprint, tempFile, nil); err != nil {
			return false, err
		}
		var held unix.Stat_t
		if err := unix.Fstat(int(tempFile.Fd()), &held); err != nil {
			return false, err
		}
		if held.Size < 0 || held.Size != fingerprint.size {
			return false, fmt.Errorf("retained result held candidate changed before commitment")
		}
		if verified, err := fingerprintOpenRegularFile(tempFile, held); err != nil || verified != fingerprint {
			return false, fmt.Errorf("retained result held candidate bytes changed before commitment")
		}
		record := retainedResultRecord{
			storeID: s.resultAuth.storeID,
			keyID:   s.resultAuth.keyID,
			runID:   locator.RunID,
			root:    resultDirectory.rootIdentity,
			run:     resultDirectory.runIdentity,
			final:   custodyIdentityFromStat(held),
			length:  uint64(fingerprint.size),
			digest:  fingerprint.digest,
		}
		if err := resultDirectory.publishRetainedResultRecord(s.resultAuth.encodeRecord(record)); err != nil {
			return false, err
		}
		if hooks.afterRecordPublish != nil {
			if err := hooks.afterRecordPublish(); err != nil {
				return false, err
			}
		}
	} else {
		// A pre-existing unmarked final is never signed or adopted. A matching
		// completed pair may be observed by a competing publisher.
		if _, ok, readErr := s.readRetainedResultBundle(locator); readErr != nil || !ok {
			return false, fmt.Errorf("pre-existing retained result is not authenticated")
		}
	}
	if err := resultDirectory.ensureNormalizationEvidence(stageMarker, stageMarkerBytes, expectations); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) readRetainedResultBundle(locator executionLocator) (ExecutionResultBundle, bool, *Error) {
	if strings.TrimSpace(s.cfg.Execution.ResultsRootDir) == "" {
		return ExecutionResultBundle{}, false, nil
	}
	if s.resultAuth == nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	roots, rootsErr := qualifyExecutionRoots(s.cfg.Execution.StagingRootDir, s.cfg.Execution.ResultsRootDir, nil)
	if rootsErr != nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	defer roots.close()
	if !roots.results.observed() {
		return ExecutionResultBundle{}, false, nil
	}
	targetOwner := executionPlatformStateOwner{UID: roots.results.existingIdentity.UID, GID: roots.results.existingIdentity.GID}
	resultDirectory, exists, err := openExistingRetainedResultDirectory(roots, locator.RunID, targetOwner)
	if err != nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	if !exists {
		return ExecutionResultBundle{}, false, nil
	}
	defer resultDirectory.close()
	if err := resultDirectory.ensureNormalizationEvidence(nil, nil, ownershipExpectationsForRun(locator.RunID, targetOwner, false)); err != nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	finalExists, err := resultDirectory.regularFileExists(resultBundleFileName, retainedResultBundleFileMode)
	if err != nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	recordExists, err := resultDirectory.regularFileExists(retainedResultRecordFileName, retainedResultBundleFileMode)
	if err != nil {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	if !finalExists && !recordExists {
		return ExecutionResultBundle{}, false, nil
	}
	if !finalExists || !recordExists {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	recordBytes, exists, err := resultDirectory.readRetainedResultRecordBytes()
	if err != nil || !exists {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	record, err := s.resultAuth.verifyRecord(recordBytes)
	if err != nil || record.runID != locator.RunID ||
		!sameCustodyObject(record.root, resultDirectory.rootIdentity) ||
		!sameCustodyObject(record.run, resultDirectory.runIdentity) {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	payload, exists, err := resultDirectory.readRegularFileExpected(resultBundleFileName, &record)
	if err == nil && exists {
		return ExecutionResultBundle{
			MediaType:       resultBundleMediaType,
			OutcomeEvidence: retainedResultOutcomeEvidence(),
			Payload:         payload,
		}, true, nil
	}
	if err == nil && !exists {
		return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
	}
	return ExecutionResultBundle{}, false, resultUnavailableError("execution result bundle is not readable")
}

func (s *Service) retainedResultBundlePath(locator executionLocator) string {
	return filepath.Join(s.retainedResultRunDir(locator), resultBundleFileName)
}

func (s *Service) retainedResultRunDir(locator executionLocator) string {
	return filepath.Join(s.cfg.Execution.ResultsRootDir, locator.RunID)
}

func (s *Service) retainedNormalizationEvidencePath(locator executionLocator) string {
	return filepath.Join(s.retainedResultRunDir(locator), ownershipNormalizationMarkerName)
}

func (s *Service) reconcileRetainedResultArtifacts(
	locator executionLocator,
	targetOwner executionPlatformStateOwner,
	stageMarker *ownershipNormalizationMarker,
	stageMarkerBytes []byte,
) error {
	roots, err := qualifyExecutionRoots(s.cfg.Execution.StagingRootDir, s.cfg.Execution.ResultsRootDir, nil)
	if err != nil {
		return err
	}
	defer roots.close()
	if !roots.results.observed() {
		return fmt.Errorf("execution results root is absent")
	}
	resultDirectory, _, err := openOrCreateRetainedResultDirectory(roots, locator.RunID, targetOwner)
	if err != nil {
		return err
	}
	defer resultDirectory.close()
	if _, err := resultDirectory.regularFileExists(resultBundleFileName, retainedResultBundleFileMode); err != nil {
		return err
	}
	return resultDirectory.ensureNormalizationEvidence(stageMarker, stageMarkerBytes, ownershipExpectationsForRun(locator.RunID, targetOwner, false))
}

type retainedResultDirectory struct {
	root         *qualifiedDirectory
	rootFD       int
	runFD        int
	runName      string
	rootIdentity custodyIdentity
	runIdentity  custodyIdentity
	owner        executionPlatformStateOwner
	verifyEffect func() error
}

type retainedResultOpenIntent uint8

const (
	retainedResultOpenExisting retainedResultOpenIntent = iota
	retainedResultOpenOrCreate
)

func openExistingRetainedResultDirectory(roots *qualifiedExecutionRoots, runID string, owner executionPlatformStateOwner) (*retainedResultDirectory, bool, error) {
	if roots == nil {
		return nil, false, fmt.Errorf("qualified execution roots are required")
	}
	root, err := roots.duplicateResultsQualifiedDirectory()
	if err != nil {
		return nil, false, err
	}
	return openRetainedResultDirectoryFromQualifiedRoot(root, runID, owner, retainedResultOpenExisting, roots.reobserve)
}

func openOrCreateRetainedResultDirectory(roots *qualifiedExecutionRoots, runID string, owner executionPlatformStateOwner) (*retainedResultDirectory, bool, error) {
	if roots == nil {
		return nil, false, fmt.Errorf("qualified execution roots are required")
	}
	root, err := roots.duplicateResultsQualifiedDirectory()
	if err != nil {
		return nil, false, err
	}
	return openRetainedResultDirectoryFromQualifiedRoot(root, runID, owner, retainedResultOpenOrCreate, roots.reobserve)
}

func openRetainedResultDirectory(rootPath string, runID string, owner executionPlatformStateOwner, create bool) (*retainedResultDirectory, bool, error) {
	root, err := openQualifiedDirectory(rootPath, false, 0)
	if err != nil {
		return nil, false, err
	}
	intent := retainedResultOpenExisting
	if create {
		intent = retainedResultOpenOrCreate
	}
	return openRetainedResultDirectoryFromQualifiedRoot(root, runID, owner, intent, nil)
}

func openRetainedResultDirectoryFromQualifiedRoot(root *qualifiedDirectory, runID string, owner executionPlatformStateOwner, intent retainedResultOpenIntent, verifyEffect func() error) (*retainedResultDirectory, bool, error) {
	if !validCustodyComponent(runID) {
		if root != nil {
			_ = root.close()
		}
		return nil, false, fmt.Errorf("run id is not a safe result name")
	}
	if root == nil {
		return nil, false, fmt.Errorf("qualified results root is required")
	}
	if err := root.verifyVisible(); err != nil {
		_ = root.close()
		return nil, false, err
	}
	runFD, err := platformOpenAtNoFollow(root.fd, runID, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil && errors.Is(err, unix.ENOENT) && intent == retainedResultOpenOrCreate {
		if verifyEffect != nil {
			if verifyErr := verifyEffect(); verifyErr != nil {
				_ = root.close()
				return nil, false, verifyErr
			}
		}
		if err := root.verifyVisible(); err != nil {
			_ = root.close()
			return nil, false, err
		}
		mkdirErr := unix.Mkdirat(root.fd, runID, uint32(retainedResultRunDirMode))
		if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			_ = root.close()
			return nil, false, mkdirErr
		}
		runFD, err = platformOpenAtNoFollow(root.fd, runID, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	}
	if err != nil {
		_ = root.close()
		if errors.Is(err, unix.ENOENT) && intent == retainedResultOpenExisting {
			return nil, false, nil
		}
		return nil, false, err
	}
	var runStat unix.Stat_t
	if err := unix.Fstat(runFD, &runStat); err != nil {
		_ = unix.Close(runFD)
		_ = root.close()
		return nil, false, err
	}
	runIdentity := custodyIdentityFromStat(runStat)
	if !custodyIdentityIsDirectory(runIdentity) ||
		runIdentity.Device != root.identity.Device ||
		runIdentity.Links < 1 ||
		runIdentity.UID != owner.UID ||
		runIdentity.GID != owner.GID ||
		os.FileMode(runIdentity.Mode).Perm() != retainedResultRunDirMode {
		_ = unix.Close(runFD)
		_ = root.close()
		return nil, false, fmt.Errorf("retained result directory has an invalid identity")
	}
	result := &retainedResultDirectory{
		root:         root,
		rootFD:       root.fd,
		runFD:        runFD,
		runName:      runID,
		rootIdentity: root.identity,
		runIdentity:  runIdentity,
		owner:        owner,
		verifyEffect: verifyEffect,
	}
	if err := result.verifyVisible(); err != nil {
		_ = result.close()
		return nil, false, err
	}
	return result, true, nil
}

func (directory *retainedResultDirectory) verifyVisible() error {
	if directory == nil || directory.root == nil || directory.runFD < 0 {
		return fmt.Errorf("retained result custody is closed")
	}
	if err := directory.root.verifyVisible(); err != nil {
		return err
	}
	var held unix.Stat_t
	if err := unix.Fstat(directory.runFD, &held); err != nil {
		return err
	}
	if !sameCustodyObject(directory.runIdentity, custodyIdentityFromStat(held)) {
		return fmt.Errorf("held retained result directory identity changed")
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.rootFD, directory.runName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(directory.runIdentity, custodyIdentityFromStat(visible)) {
		return fmt.Errorf("visible retained result directory no longer names the held directory")
	}
	return nil
}

func (directory *retainedResultDirectory) verifyBeforeEffect() error {
	if directory == nil {
		return fmt.Errorf("retained result custody is closed")
	}
	if directory.verifyEffect != nil {
		if err := directory.verifyEffect(); err != nil {
			return err
		}
	}
	return directory.verifyVisible()
}

func (directory *retainedResultDirectory) close() error {
	if directory == nil {
		return nil
	}
	var errs []error
	if directory.runFD >= 0 {
		errs = append(errs, unix.Close(directory.runFD))
		directory.runFD = -1
	}
	if directory.root != nil {
		errs = append(errs, directory.root.close())
		directory.root = nil
		directory.rootFD = -1
	}
	return errors.Join(errs...)
}

func (directory *retainedResultDirectory) regularFileExists(name string, mode os.FileMode) (bool, error) {
	if err := directory.verifyVisible(); err != nil {
		return false, err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	identity := custodyIdentityFromStat(stat)
	if !custodyIdentityIsRegular(identity) || identity.Links != 1 || identity.Device != directory.rootIdentity.Device || identity.UID != directory.owner.UID || identity.GID != directory.owner.GID || os.FileMode(identity.Mode).Perm() != mode.Perm() {
		return false, fmt.Errorf("retained result file has an invalid identity")
	}
	return true, nil
}

func (directory *retainedResultDirectory) createTempFile() (string, *os.File, error) {
	if err := directory.verifyBeforeEffect(); err != nil {
		return "", nil, err
	}
	token, err := randomCustodyToken()
	if err != nil {
		return "", nil, err
	}
	name := ".result-" + token + ".tar.gz.tmp"
	fd, err := platformOpenAtNoFollow(directory.runFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, uint32(retainedResultBundleFileMode), true)
	if err != nil {
		return "", nil, err
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		_ = unix.Close(fd)
		return "", nil, err
	}
	if err := unix.Fchown(fd, directory.owner.UID, directory.owner.GID); err != nil {
		_ = unix.Close(fd)
		return "", nil, err
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		_ = unix.Close(fd)
		return "", nil, err
	}
	if err := unix.Fchmod(fd, uint32(retainedResultBundleFileMode)); err != nil {
		_ = unix.Close(fd)
		return "", nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return "", nil, fmt.Errorf("open retained result temporary file")
	}
	return name, file, nil
}

type retainedResultFingerprint struct {
	size   int64
	digest [sha256.Size]byte
}

type retainedResultInstallHooks struct {
	beforePublish      func() error
	afterExistingOpen  func()
	afterFinalInstall  func() error
	afterRecordPublish func() error
}

type retainedResultEmissionWriter struct {
	file io.Writer
	hash hash.Hash
	size uint64
}

func newRetainedResultEmissionWriter(file io.Writer) *retainedResultEmissionWriter {
	return &retainedResultEmissionWriter{file: file, hash: sha256.New()}
}

func (writer *retainedResultEmissionWriter) Write(payload []byte) (int, error) {
	if uint64(len(payload)) > uint64(maximumInt())-writer.size {
		return 0, fmt.Errorf("retained result bundle exceeds readable size")
	}
	n, err := writer.file.Write(payload)
	if n > 0 {
		_, _ = writer.hash.Write(payload[:n])
		writer.size += uint64(n)
	}
	return n, err
}

func (writer *retainedResultEmissionWriter) fingerprint() retainedResultFingerprint {
	var digest [sha256.Size]byte
	copy(digest[:], writer.hash.Sum(nil))
	return retainedResultFingerprint{size: int64(writer.size), digest: digest}
}

func (directory *retainedResultDirectory) fingerprintTemporaryFile(name string, file *os.File) (retainedResultFingerprint, error) {
	if err := directory.verifyVisible(); err != nil {
		return retainedResultFingerprint{}, err
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return retainedResultFingerprint{}, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil {
		return retainedResultFingerprint{}, err
	}
	if !sameCustodyObject(custodyIdentityFromStat(visible), custodyIdentityFromStat(before)) {
		return retainedResultFingerprint{}, fmt.Errorf("retained result temporary file identity changed")
	}
	if err := directory.validateRetainedResultStat(before, retainedResultBundleFileMode); err != nil {
		return retainedResultFingerprint{}, err
	}
	fingerprint, err := fingerprintOpenRegularFile(file, before)
	if err != nil {
		return retainedResultFingerprint{}, err
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return retainedResultFingerprint{}, err
	}
	if !sameCustodyObject(custodyIdentityFromStat(before), custodyIdentityFromStat(afterVisible)) {
		return retainedResultFingerprint{}, fmt.Errorf("retained result temporary file path changed")
	}
	return fingerprint, nil
}

func (directory *retainedResultDirectory) publishTemporaryBundle(
	tempName string,
	expected retainedResultFingerprint,
	candidateFile *os.File,
	hooks retainedResultInstallHooks,
) (bool, error) {
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(); err != nil {
			return false, err
		}
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		return false, err
	}
	if err := platformRenameNoReplace(directory.runFD, tempName, directory.runFD, resultBundleFileName); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return false, err
		}
		if err := directory.validateExistingRetainedResultBundle(resultBundleFileName, expected, nil, hooks.afterExistingOpen); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := directory.validateExistingRetainedResultBundle(resultBundleFileName, expected, candidateFile, nil); err != nil {
		return false, err
	}
	return true, nil
}

func (directory *retainedResultDirectory) validateExistingRetainedResultBundle(
	name string,
	expected retainedResultFingerprint,
	heldCandidate *os.File,
	afterOpen func(),
) error {
	if err := directory.verifyVisible(); err != nil {
		return err
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := directory.validateRetainedResultStat(visible, retainedResultBundleFileMode); err != nil {
		return err
	}
	if visible.Size != expected.size {
		return fmt.Errorf("retained result bundle does not match the complete candidate")
	}
	fd, err := platformOpenAtNoFollow(directory.runFD, name, unix.O_RDONLY, 0, true)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open retained result bundle")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if !sameCustodyObject(custodyIdentityFromStat(visible), custodyIdentityFromStat(before)) {
		return fmt.Errorf("retained result bundle identity changed")
	}
	if heldCandidate != nil {
		var held unix.Stat_t
		if err := unix.Fstat(int(heldCandidate.Fd()), &held); err != nil {
			return err
		}
		if !sameCustodyObject(custodyIdentityFromStat(held), custodyIdentityFromStat(before)) {
			return fmt.Errorf("installed retained result is not the held candidate")
		}
	}
	if err := directory.validateRetainedResultStat(before, retainedResultBundleFileMode); err != nil {
		return err
	}
	if afterOpen != nil {
		afterOpen()
	}
	fingerprint, err := fingerprintOpenRegularFile(file, before)
	if err != nil {
		return err
	}
	if fingerprint != expected {
		return fmt.Errorf("retained result bundle does not match the complete candidate")
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(custodyIdentityFromStat(before), custodyIdentityFromStat(afterVisible)) {
		return fmt.Errorf("retained result bundle path changed during validation")
	}
	return nil
}

func (directory *retainedResultDirectory) validateRetainedResultStat(stat unix.Stat_t, mode os.FileMode) error {
	identity := custodyIdentityFromStat(stat)
	if !custodyIdentityIsRegular(identity) ||
		identity.Links != 1 ||
		identity.Device != directory.rootIdentity.Device ||
		identity.UID != directory.owner.UID ||
		identity.GID != directory.owner.GID ||
		os.FileMode(identity.Mode).Perm() != mode.Perm() ||
		stat.Size < 0 {
		return fmt.Errorf("retained result file has an invalid identity")
	}
	return nil
}

func fingerprintOpenRegularFile(file *os.File, before unix.Stat_t) (retainedResultFingerprint, error) {
	if before.Size < 0 {
		return retainedResultFingerprint{}, fmt.Errorf("retained result file has an invalid size")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return retainedResultFingerprint{}, err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, before.Size); err != nil {
		return retainedResultFingerprint{}, err
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || (err != nil && err != io.EOF) {
		return retainedResultFingerprint{}, fmt.Errorf("retained result file size changed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return retainedResultFingerprint{}, err
	}
	if !platformStatSnapshotStable(before, after) {
		return retainedResultFingerprint{}, fmt.Errorf("retained result file changed during validation")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return retainedResultFingerprint{size: before.Size, digest: digest}, nil
}

func (directory *retainedResultDirectory) ensureNormalizationEvidence(marker *ownershipNormalizationMarker, markerBytes []byte, expectations ownershipNormalizationMarkerExpectations) error {
	return directory.ensureNormalizationEvidenceWithHook(marker, markerBytes, expectations, nil)
}

func (directory *retainedResultDirectory) ensureNormalizationEvidenceWithHook(marker *ownershipNormalizationMarker, markerBytes []byte, expectations ownershipNormalizationMarkerExpectations, afterWrite func() error) error {
	if err := directory.verifyVisible(); err != nil {
		return err
	}
	existing, _, err := loadValidatedOwnershipNormalizationMarkerAt(directory.runFD, expectations)
	if err != nil {
		return err
	}
	if existing == nil && marker != nil && len(markerBytes) > 0 {
		if err := directory.verifyBeforeEffect(); err != nil {
			return err
		}
		fd, err := platformOpenAtNoFollow(directory.runFD, ownershipNormalizationMarkerName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(retainedNormalizationEvidenceFileMode), true)
		if err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return err
			}
		} else {
			if err := directory.verifyBeforeEffect(); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if err := unix.Fchown(fd, directory.owner.UID, directory.owner.GID); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if err := directory.verifyBeforeEffect(); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if err := unix.Fchmod(fd, uint32(retainedNormalizationEvidenceFileMode)); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if err := writeAllDescriptor(fd, markerBytes); err != nil {
				_ = unix.Close(fd)
				return fmt.Errorf("write retained normalization evidence: %w", err)
			}
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if afterWrite != nil {
				if err := afterWrite(); err != nil {
					_ = unix.Close(fd)
					return err
				}
			}
			if err := unix.Close(fd); err != nil {
				return err
			}
		}
	}
	validated, _, err := loadValidatedOwnershipNormalizationMarkerAt(directory.runFD, expectations)
	if err != nil {
		return err
	}
	if validated != nil {
		_, err := directory.regularFileExists(ownershipNormalizationMarkerName, retainedNormalizationEvidenceFileMode)
		return err
	}
	return nil
}

func (directory *retainedResultDirectory) readRegularFile(name string) ([]byte, bool, error) {
	return directory.readRegularFileExpected(name, nil)
}

func (directory *retainedResultDirectory) readRegularFileExpected(name string, expected *retainedResultRecord) ([]byte, bool, error) {
	return directory.readRegularFileExpectedWithHook(name, expected, nil)
}

func (directory *retainedResultDirectory) readRegularFileExpectedWithHook(name string, expected *retainedResultRecord, afterVisibleCheck func() error) ([]byte, bool, error) {
	if err := directory.verifyVisible(); err != nil {
		return nil, false, err
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if err := directory.validateRetainedResultRegularStat(visible); err != nil {
		return nil, false, err
	}
	visibleIdentity := custodyIdentityFromStat(visible)
	if expected != nil && (uint64(visible.Size) != expected.length || !sameCustodyObject(visibleIdentity, expected.final)) {
		return nil, false, fmt.Errorf("retained result file differs from authenticated commitment")
	}
	if afterVisibleCheck != nil {
		if err := afterVisibleCheck(); err != nil {
			return nil, false, err
		}
	}
	fd, err := platformOpenAtNoFollow(directory.runFD, name, unix.O_RDONLY, 0, true)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, fmt.Errorf("open retained result file")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !sameCustodyObject(visibleIdentity, custodyIdentityFromStat(before)) {
		if err != nil {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("retained result file identity changed")
	}
	if err := directory.validateRetainedResultRegularStat(before); err != nil {
		return nil, false, err
	}
	if expected != nil && (uint64(before.Size) != expected.length || !sameCustodyObject(custodyIdentityFromStat(before), expected.final)) {
		return nil, false, fmt.Errorf("retained result file differs from authenticated commitment")
	}
	payload, err := io.ReadAll(io.LimitReader(file, before.Size))
	if err != nil {
		return nil, false, err
	}
	if int64(len(payload)) != before.Size {
		return nil, false, fmt.Errorf("retained result file size changed")
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); count != 0 || (readErr != nil && readErr != io.EOF) {
		return nil, false, fmt.Errorf("retained result file size changed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !platformStatSnapshotStable(before, after) {
		if err != nil {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("retained result file changed while reading")
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameCustodyObject(visibleIdentity, custodyIdentityFromStat(afterVisible)) {
		if err != nil {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("retained result file path changed while reading")
	}
	if expected != nil && (uint64(len(payload)) != expected.length || sha256.Sum256(payload) != expected.digest) {
		return nil, false, fmt.Errorf("retained result response bytes differ from authenticated commitment")
	}
	return payload, true, nil
}

func (directory *retainedResultDirectory) validateRetainedResultRegularStat(stat unix.Stat_t) error {
	identity := custodyIdentityFromStat(stat)
	if !custodyIdentityIsRegular(identity) || identity.Links != 1 ||
		identity.Device != directory.rootIdentity.Device ||
		identity.UID != directory.owner.UID || identity.GID != directory.owner.GID ||
		os.FileMode(identity.Mode).Perm() != retainedResultBundleFileMode ||
		stat.Size < 0 || stat.Size > int64(maximumInt()) {
		return fmt.Errorf("retained result file has an invalid identity")
	}
	return nil
}

func writeResultBundle(writer io.Writer, root string) error {
	directory, err := openQualifiedDirectory(root, false, 0)
	if err != nil {
		return err
	}
	defer directory.close()
	_, err = writeResultBundleFromDescriptor(writer, directory.fd, directory.identity.Device, nil)
	return err
}

func writeResultBundleFromDescriptor(writer io.Writer, rootFD int, rootDevice uint64, expectedOwner *executionPlatformStateOwner) (bool, error) {
	gzipWriter := gzip.NewWriter(writer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)
	hasFiles, walkErr := writeResultDirectoryEntries(tarWriter, rootFD, "", rootDevice, expectedOwner)
	if walkErr != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return false, walkErr
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return false, err
	}
	if err := gzipWriter.Close(); err != nil {
		return false, err
	}
	return hasFiles, nil
}

func writeResultDirectoryEntries(tarWriter *tar.Writer, directoryFD int, prefix string, rootDevice uint64, expectedOwner *executionPlatformStateOwner) (bool, error) {
	entries, err := readDirectoryEntries(directoryFD)
	if err != nil {
		return false, err
	}
	hasFiles := false
	for _, entry := range entries {
		name := entry.Name()
		if !validCustodyComponent(name) {
			return false, fmt.Errorf("result entry has an invalid name")
		}
		relativePath := name
		if prefix != "" {
			relativePath = prefix + "/" + name
		}
		var visible unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, err
		}
		identity := custodyIdentityFromStat(visible)
		if identity.Device != rootDevice || (expectedOwner != nil && (identity.UID != expectedOwner.UID || identity.GID != expectedOwner.GID)) {
			return false, fmt.Errorf("result entry %s has an invalid identity", relativePath)
		}
		switch {
		case custodyIdentityIsDirectory(identity):
			fd, err := platformOpenAtNoFollow(directoryFD, name, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
			if err != nil {
				return false, err
			}
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return false, fmt.Errorf("open result directory %s", relativePath)
			}
			info, err := file.Stat()
			if err != nil || !sameCustodyObject(identity, custodyIdentityFromFileInfo(info)) {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("result directory %s identity changed", relativePath)
			}
			header, err := stableResultTarHeader(info, relativePath+"/")
			if err != nil || tarWriter.WriteHeader(header) != nil {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("write result directory header %s", relativePath)
			}
			childHasFiles, err := writeResultDirectoryEntries(tarWriter, fd, relativePath, rootDevice, expectedOwner)
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return false, err
			}
			var afterVisible unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameCustodyObject(identity, custodyIdentityFromStat(afterVisible)) {
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("result directory %s identity changed", relativePath)
			}
			hasFiles = hasFiles || childHasFiles
		case custodyIdentityIsRegular(identity):
			if identity.Links != 1 {
				return false, fmt.Errorf("result entry %s uses unsupported hard link", relativePath)
			}
			fd, err := platformOpenAtNoFollow(directoryFD, name, unix.O_RDONLY, 0, true)
			if err != nil {
				return false, err
			}
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return false, fmt.Errorf("open result entry %s", relativePath)
			}
			var before unix.Stat_t
			if err := unix.Fstat(fd, &before); err != nil || !sameCustodyObject(identity, custodyIdentityFromStat(before)) {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("result entry %s identity changed", relativePath)
			}
			info, err := file.Stat()
			if err != nil {
				_ = file.Close()
				return false, err
			}
			header, err := stableResultTarHeader(info, relativePath)
			if err != nil || tarWriter.WriteHeader(header) != nil {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("write result file header %s", relativePath)
			}
			if _, err := io.CopyN(tarWriter, file, before.Size); err != nil {
				_ = file.Close()
				return false, err
			}
			var extra [1]byte
			if count, readErr := file.Read(extra[:]); count != 0 || (readErr != nil && readErr != io.EOF) {
				_ = file.Close()
				return false, fmt.Errorf("result entry %s size changed", relativePath)
			}
			var after unix.Stat_t
			if err := unix.Fstat(fd, &after); err != nil || !platformStatSnapshotStable(before, after) {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("result entry %s changed while reading", relativePath)
			}
			var afterVisible unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameCustodyObject(identity, custodyIdentityFromStat(afterVisible)) {
				_ = file.Close()
				if err != nil {
					return false, err
				}
				return false, fmt.Errorf("result entry %s identity changed", relativePath)
			}
			if err := file.Close(); err != nil {
				return false, err
			}
			hasFiles = true
		default:
			if identity.Mode&unix.S_IFMT == unix.S_IFLNK {
				return false, fmt.Errorf("result entry %s uses unsupported symbolic link", relativePath)
			}
			return false, fmt.Errorf("result entry %s uses unsupported file mode", relativePath)
		}
	}
	return hasFiles, nil
}

func stableResultTarHeader(info os.FileInfo, name string) (*tar.Header, error) {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return nil, err
	}
	header.Name = name
	header.ModTime = time.Unix(0, 0)
	header.AccessTime = time.Unix(0, 0)
	header.ChangeTime = time.Unix(0, 0)
	return header, nil
}

func custodyIdentityFromFileInfo(info os.FileInfo) custodyIdentity {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return custodyIdentity{}
	}
	return custodyIdentity{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Mode:   uint32(stat.Mode),
		Links:  uint64(stat.Nlink),
		UID:    int(stat.Uid),
		GID:    int(stat.Gid),
	}
}

func resultBundleEntryName(root string, path string) (string, error) {
	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	relativePath = filepath.ToSlash(relativePath)
	if relativePath == "." || relativePath == "" || relativePath == ".." || strings.HasPrefix(relativePath, "../") || filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("result entry escapes result directory: %s", path)
	}
	return relativePath, nil
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
