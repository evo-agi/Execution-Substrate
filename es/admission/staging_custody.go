package admission

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type custodyIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
	Links  uint64
	UID    int
	GID    int
}

// custodyExpectedNode is invocation-local evidence of one object created by
// the current staging claim. A directory owns its direct-child map. Each map
// key owns one path segment for that unique parent-to-child edge; nodes retain
// neither cumulative paths nor a second copy of the child name.
type custodyExpectedNode struct {
	identity custodyIdentity
	children map[string]*custodyExpectedNode
}

func newCustodyExpectedDirectory(identity custodyIdentity) *custodyExpectedNode {
	return &custodyExpectedNode{
		identity: identity,
		children: make(map[string]*custodyExpectedNode),
	}
}

func newCustodyExpectedFile(identity custodyIdentity) *custodyExpectedNode {
	return &custodyExpectedNode{identity: identity}
}

func (node *custodyExpectedNode) isDirectory() bool {
	return node != nil && custodyIdentityIsDirectory(node.identity) && node.children != nil
}

type qualifiedDirectory struct {
	path           string
	fd             int
	identity       custodyIdentity
	parentPath     string
	parentFD       int
	parentIdentity custodyIdentity
	leafName       string
}

func (directory *qualifiedDirectory) close() error {
	if directory == nil {
		return nil
	}
	var errs []error
	if directory.fd >= 0 {
		errs = append(errs, unix.Close(directory.fd))
		directory.fd = -1
	}
	if directory.parentFD >= 0 {
		errs = append(errs, unix.Close(directory.parentFD))
		directory.parentFD = -1
	}
	return errors.Join(errs...)
}

func (directory *qualifiedDirectory) verifyVisible() error {
	if directory == nil || directory.fd < 0 || directory.parentFD < 0 {
		return fmt.Errorf("qualified directory custody is closed")
	}
	var held unix.Stat_t
	if err := unix.Fstat(directory.fd, &held); err != nil {
		return err
	}
	if !sameCustodyObject(directory.identity, custodyIdentityFromStat(held)) {
		return fmt.Errorf("qualified directory identity changed")
	}
	var heldParent unix.Stat_t
	if err := unix.Fstat(directory.parentFD, &heldParent); err != nil {
		return err
	}
	if !sameCustodyObject(directory.parentIdentity, custodyIdentityFromStat(heldParent)) {
		return fmt.Errorf("qualified directory parent identity changed")
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.parentFD, directory.leafName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(directory.identity, custodyIdentityFromStat(visible)) {
		return fmt.Errorf("visible qualified directory no longer names the held directory")
	}
	reopenedParent, err := openAbsoluteDirectoryNoFollow(directory.parentPath)
	if err != nil {
		return fmt.Errorf("qualified directory ancestry changed: %w", err)
	}
	defer unix.Close(reopenedParent)
	var reopenedParentStat unix.Stat_t
	if err := unix.Fstat(reopenedParent, &reopenedParentStat); err != nil {
		return err
	}
	if !sameCustodyObject(directory.parentIdentity, custodyIdentityFromStat(reopenedParentStat)) {
		return fmt.Errorf("qualified directory ancestry changed")
	}
	return nil
}

type stagingCustody struct {
	stagingRoot     *qualifiedDirectory
	stagingRootPath string
	runID           string
	rootName        string
	parentFD        int
	rootFD          int
	parentIdentity  custodyIdentity
	rootIdentity    custodyIdentity
	owner           executionPlatformStateOwner
	expectedRoot    *custodyExpectedNode
}

// beforeStagingHandoffValidationForTest is a narrow package-test seam used to
// inject a filesystem change after normal materialization and before the final
// read-only handoff validation. Production leaves it nil.
var beforeStagingHandoffValidationForTest func(*stagingCustody)

// beforeStagingChildRegistrationStatForTest is nil in production. Tests use it
// only after controlled creation of a new child and before its identity is
// recorded in the expected tree.
var beforeStagingChildRegistrationStatForTest func(relativePath string, fd int, directory bool)

// stagedFileModes and stagedDirectoryModes return every mode staging gives
// the entries it creates in a claimed run staging root. The configured-Submit
// startup probe stages one entry of each (probeStagedEntries in
// execution_roots.go), and ensureDirectory and writeFile refuse any other
// mode, so a mode cannot reach staging without reaching the startup probe.
func stagedFileModes() []os.FileMode {
	return []os.FileMode{
		retainedResultBundleFileMode,
		stableStageFileMode,
		stableStageExecFileMode,
		governedMountFileMode,
		governedMountExecFileMode,
	}
}

func stagedDirectoryModes() []os.FileMode {
	return []os.FileMode{
		stableStageDirMode,
		governedMountDirMode,
	}
}

func stagedModeProbedAtStartup(modes []os.FileMode, mode os.FileMode) bool {
	for _, probed := range modes {
		if mode == probed {
			return true
		}
	}
	return false
}

// requireOpenedDirectoryOwnedByRootsUser refuses a directory that this process
// created and then opened by name, unless its owning user already is the
// execution roots' owning user. There is no call that creates a directory and
// opens it in one step, so between the two another user who may rename
// entries of the parent can put a directory of somebody else's in its place.
// Every caller then changes the directory's owner and mode. ES only ever needs
// to change the group of a directory it created, because the entries it
// creates must already belong to the roots' owning user: the startup probe
// requires it, and retained result directories, which ES never gives an owner,
// need it anyway. So ES refuses before any owner or mode change, and never
// gives somebody else's directory to the roots' owner.
func requireOpenedDirectoryOwnedByRootsUser(fd int, owner executionPlatformStateOwner, label string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if custodyIdentityFromStat(stat).UID != owner.UID {
		return fmt.Errorf("%s does not belong to the execution roots' owning user", label)
	}
	return nil
}

// stagingTree is read-only descriptor custody for a run tree. Unlike
// stagingCustody it has no materialization ownership and is used only for
// read-only result packaging. Neither type confers run-root deletion authority.
type stagingTree struct {
	stagingRoot    *qualifiedDirectory
	parentFD       int
	rootFD         int
	rootName       string
	parentIdentity custodyIdentity
	rootIdentity   custodyIdentity
}

func openStagingTree(stagingRootPath string, runID string) (*stagingTree, error) {
	parent, err := openQualifiedDirectory(stagingRootPath, false, 0)
	if err != nil {
		return nil, err
	}
	return openStagingTreeFromQualifiedRoot(parent, runID)
}

func openStagingTreeFromQualifiedRoot(parent *qualifiedDirectory, runID string) (*stagingTree, error) {
	if !validCustodyComponent(runID) {
		if parent != nil {
			_ = parent.close()
		}
		return nil, fmt.Errorf("run id is not a safe staging name")
	}
	if parent == nil {
		return nil, fmt.Errorf("qualified staging root is required")
	}
	if err := parent.verifyVisible(); err != nil {
		_ = parent.close()
		return nil, err
	}
	rootFD, err := platformOpenAtNoFollow(parent.fd, runID, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		_ = parent.close()
		return nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		_ = unix.Close(rootFD)
		_ = parent.close()
		return nil, err
	}
	tree := &stagingTree{
		stagingRoot:    parent,
		parentFD:       parent.fd,
		rootFD:         rootFD,
		rootName:       runID,
		parentIdentity: parent.identity,
		rootIdentity:   custodyIdentityFromStat(rootStat),
	}
	if !custodyIdentityIsDirectory(tree.rootIdentity) || tree.rootIdentity.Device != tree.parentIdentity.Device {
		_ = tree.close()
		return nil, fmt.Errorf("staging tree root has an invalid identity")
	}
	if err := tree.verifyVisible(); err != nil {
		_ = tree.close()
		return nil, err
	}
	return tree, nil
}

func (tree *stagingTree) verifyVisible() error {
	if tree == nil || tree.parentFD < 0 || tree.rootFD < 0 {
		return fmt.Errorf("staging tree custody is closed")
	}
	if err := tree.stagingRoot.verifyVisible(); err != nil {
		return err
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(tree.parentFD, &parentStat); err != nil {
		return err
	}
	if !sameCustodyObject(tree.parentIdentity, custodyIdentityFromStat(parentStat)) {
		return fmt.Errorf("staging tree parent identity changed")
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(tree.rootFD, &rootStat); err != nil {
		return err
	}
	if !sameCustodyObject(tree.rootIdentity, custodyIdentityFromStat(rootStat)) {
		return fmt.Errorf("staging tree root identity changed")
	}
	var visibleStat unix.Stat_t
	if err := unix.Fstatat(tree.parentFD, tree.rootName, &visibleStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(tree.rootIdentity, custodyIdentityFromStat(visibleStat)) {
		return fmt.Errorf("visible staging tree no longer names the held root")
	}
	return nil
}

func (tree *stagingTree) openDirectory(relativePath string) (int, error) {
	relativePath, err := cleanCustodyRelative(relativePath, true)
	if err != nil {
		return -1, err
	}
	if err := tree.verifyVisible(); err != nil {
		return -1, err
	}
	currentFD, err := platformOpenAtNoFollow(tree.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return -1, err
	}
	if relativePath == "" {
		return currentFD, nil
	}
	for _, component := range strings.Split(relativePath, "/") {
		nextFD, err := platformOpenAtNoFollow(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
		if err != nil {
			_ = unix.Close(currentFD)
			return -1, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(nextFD, &stat); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return -1, err
		}
		identity := custodyIdentityFromStat(stat)
		if !custodyIdentityIsDirectory(identity) || identity.Device != tree.rootIdentity.Device {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return -1, fmt.Errorf("staging tree contains an invalid directory")
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}

func (tree *stagingTree) close() error {
	if tree == nil {
		return nil
	}
	var errs []error
	if tree.rootFD >= 0 {
		errs = append(errs, unix.Close(tree.rootFD))
		tree.rootFD = -1
	}
	if tree.stagingRoot != nil {
		errs = append(errs, tree.stagingRoot.close())
		tree.stagingRoot = nil
		tree.parentFD = -1
	}
	return errors.Join(errs...)
}

func custodyIdentityFromStat(stat unix.Stat_t) custodyIdentity {
	return custodyIdentity{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Mode:   uint32(stat.Mode),
		Links:  uint64(stat.Nlink),
		UID:    int(stat.Uid),
		GID:    int(stat.Gid),
	}
}

func sameCustodyObject(left custodyIdentity, right custodyIdentity) bool {
	return left.Device == right.Device && left.Inode == right.Inode && (left.Mode&unix.S_IFMT) == (right.Mode&unix.S_IFMT)
}

// sameCustodyRecordedMode compares the file type and all Unix mode bits that
// custody records as exact, without comparing unrelated stat metadata.
func sameCustodyRecordedMode(left uint32, right uint32) bool {
	const modeMask uint32 = unix.S_IFMT | 0o7777
	return left&modeMask == right&modeMask
}

func custodyIdentityIsDirectory(identity custodyIdentity) bool {
	return identity.Mode&unix.S_IFMT == unix.S_IFDIR
}

func custodyIdentityIsRegular(identity custodyIdentity) bool {
	return identity.Mode&unix.S_IFMT == unix.S_IFREG
}

func openQualifiedDirectory(path string, create bool, createMode uint32) (*qualifiedDirectory, error) {
	return openQualifiedDirectoryClean(filepath.Clean(strings.TrimSpace(path)), create, createMode)
}

func openQualifiedDirectoryExact(path string) (*qualifiedDirectory, error) {
	if filepath.Clean(path) != path {
		return nil, fmt.Errorf("qualified directory must be a clean path")
	}
	return openQualifiedDirectoryClean(path, false, 0)
}

func openQualifiedDirectoryClean(cleanPath string, create bool, createMode uint32) (*qualifiedDirectory, error) {
	if !filepath.IsAbs(cleanPath) || cleanPath == string(os.PathSeparator) {
		return nil, fmt.Errorf("qualified directory must be an absolute non-root path")
	}

	currentFD, err := unix.Open(string(os.PathSeparator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parentFD := -1
	closeCurrent := true
	defer func() {
		if closeCurrent {
			_ = unix.Close(currentFD)
			if parentFD >= 0 && parentFD != currentFD {
				_ = unix.Close(parentFD)
			}
		}
	}()

	components := strings.Split(strings.TrimPrefix(cleanPath, string(os.PathSeparator)), string(os.PathSeparator))
	parentPath := string(os.PathSeparator)
	for index, component := range components {
		if !validCustodyComponent(component) {
			return nil, fmt.Errorf("qualified directory contains an invalid component")
		}
		nextFD, openErr := platformOpenAtNoFollow(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, false)
		if openErr != nil && create && errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(currentFD, component, createMode); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return nil, mkdirErr
			}
			nextFD, openErr = platformOpenAtNoFollow(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, false)
		}
		if openErr != nil {
			return nil, openErr
		}
		if index == len(components)-1 {
			parentFD = currentFD
			currentFD = nextFD
			if index > 0 {
				parentPath = string(os.PathSeparator) + filepath.Join(components[:index]...)
			}
			break
		}
		if err := unix.Close(currentFD); err != nil {
			_ = unix.Close(nextFD)
			return nil, err
		}
		currentFD = nextFD
	}

	var stat unix.Stat_t
	if err := unix.Fstat(currentFD, &stat); err != nil {
		return nil, err
	}
	identity := custodyIdentityFromStat(stat)
	if !custodyIdentityIsDirectory(identity) {
		return nil, fmt.Errorf("qualified path is not a directory")
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return nil, err
	}
	closeCurrent = false
	return &qualifiedDirectory{
		path:           cleanPath,
		fd:             currentFD,
		identity:       identity,
		parentPath:     filepath.Clean(parentPath),
		parentFD:       parentFD,
		parentIdentity: custodyIdentityFromStat(parentStat),
		leafName:       components[len(components)-1],
	}, nil
}

func openAbsoluteDirectoryNoFollow(path string) (int, error) {
	cleanPath := filepath.Clean(path)
	if cleanPath == string(os.PathSeparator) {
		return unix.Open(cleanPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	// Callers supply custody paths or checked descriptor presentations. Rewalk
	// their exact components; configured-root normalization happens earlier.
	directory, err := openQualifiedDirectoryExact(cleanPath)
	if err != nil {
		return -1, err
	}
	fd := directory.fd
	directory.fd = -1
	_ = directory.close()
	return fd, nil
}

func validCustodyComponent(component string) bool {
	return component != "" && component != "." && component != ".." && !strings.ContainsRune(component, os.PathSeparator)
}

func cleanCustodyRelative(path string, allowRoot bool) (string, error) {
	cleaned := filepath.ToSlash(filepath.Clean(path))
	if cleaned == "." && allowRoot {
		return "", nil
	}
	if cleaned == "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("custody path is outside the claimed root")
	}
	for _, component := range strings.Split(cleaned, "/") {
		if !validCustodyComponent(component) {
			return "", fmt.Errorf("custody path contains an invalid component")
		}
	}
	return cleaned, nil
}

func claimStagingCustody(stagingRootPath string, runID string, owner executionPlatformStateOwner) (*stagingCustody, error) {
	parent, err := openQualifiedDirectory(stagingRootPath, false, 0)
	if err != nil {
		return nil, err
	}
	return claimStagingCustodyFromQualifiedRoot(parent, runID, owner)
}

func claimStagingCustodyFromQualifiedRoot(parent *qualifiedDirectory, runID string, owner executionPlatformStateOwner) (*stagingCustody, error) {
	if !validCustodyComponent(runID) {
		if parent != nil {
			_ = parent.close()
		}
		return nil, fmt.Errorf("run id is not a safe staging name")
	}
	if parent == nil {
		return nil, fmt.Errorf("qualified staging root is required")
	}
	custody := &stagingCustody{
		stagingRoot:     parent,
		stagingRootPath: parent.path,
		runID:           runID,
		rootName:        runID,
		parentFD:        parent.fd,
		rootFD:          -1,
		parentIdentity:  parent.identity,
		owner:           owner,
	}
	failAfterCreation := func(cause error) (*stagingCustody, error) {
		_ = custody.close()
		return nil, cause
	}
	if err := parent.verifyVisible(); err != nil {
		_ = custody.close()
		return nil, err
	}
	if err := unix.Mkdirat(custody.parentFD, runID, uint32(stableStageDirMode)); err != nil {
		_ = custody.close()
		return nil, fmt.Errorf("exclusively create run staging root: %w", err)
	}
	var claimedStat unix.Stat_t
	if err := unix.Fstatat(custody.parentFD, runID, &claimedStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return failAfterCreation(fmt.Errorf("verify exclusive run staging claim: %w", err))
	}
	custody.rootIdentity = custodyIdentityFromStat(claimedStat)
	if !custodyIdentityIsDirectory(custody.rootIdentity) || custody.rootIdentity.Device != custody.parentIdentity.Device {
		return failAfterCreation(fmt.Errorf("exclusive run staging claim has an invalid identity"))
	}
	rootFD, err := platformOpenAtNoFollow(custody.parentFD, runID, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return failAfterCreation(err)
	}
	custody.rootFD = rootFD
	var openedStat unix.Stat_t
	if err := unix.Fstat(rootFD, &openedStat); err != nil {
		return failAfterCreation(err)
	}
	if !sameCustodyObject(custody.rootIdentity, custodyIdentityFromStat(openedStat)) {
		return failAfterCreation(fmt.Errorf("exclusive run staging claim identity changed"))
	}
	if err := requireOpenedDirectoryOwnedByRootsUser(rootFD, owner, "claimed staging root"); err != nil {
		return failAfterCreation(err)
	}
	if err := unix.Fchown(rootFD, owner.UID, owner.GID); err != nil {
		return failAfterCreation(err)
	}
	if err := unix.Fchmod(rootFD, uint32(stableStageDirMode)); err != nil {
		return failAfterCreation(err)
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return failAfterCreation(err)
	}
	custody.rootIdentity = custodyIdentityFromStat(rootStat)
	if !custodyIdentityIsDirectory(custody.rootIdentity) ||
		custody.rootIdentity.Links < 1 ||
		custody.rootIdentity.Device != custody.parentIdentity.Device ||
		custody.rootIdentity.UID != owner.UID ||
		custody.rootIdentity.GID != owner.GID ||
		!sameCustodyRecordedMode(custody.rootIdentity.Mode, unix.S_IFDIR|uint32(stableStageDirMode)) {
		return failAfterCreation(fmt.Errorf("claimed staging root has an invalid identity"))
	}
	custody.expectedRoot = newCustodyExpectedDirectory(custody.rootIdentity)
	return custody, nil
}
func (custody *stagingCustody) ensureDirectory(relativePath string, mode os.FileMode) error {
	if !stagedModeProbedAtStartup(stagedDirectoryModes(), mode) {
		return fmt.Errorf("staging directory mode %04o is not proved by the startup probe", uint32(mode))
	}
	relativePath, err := cleanCustodyRelative(relativePath, true)
	if err != nil {
		return err
	}
	if relativePath == "" {
		return custody.verifyVisibleRootIdentity()
	}

	currentFD, currentNode, err := custody.openRegisteredDirectoryNode("")
	if err != nil {
		return err
	}
	currentRelativePath := ""
	for _, component := range strings.Split(relativePath, "/") {
		if currentRelativePath == "" {
			currentRelativePath = component
		} else {
			currentRelativePath += "/" + component
		}
		expected, known := currentNode.children[component]
		if known && (!expected.isDirectory() || os.FileMode(expected.identity.Mode).Perm() != mode.Perm()) {
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory registration conflicts with an owned child")
		}
		if !known {
			if err := unix.Mkdirat(currentFD, component, uint32(mode.Perm())); err != nil {
				_ = unix.Close(currentFD)
				return fmt.Errorf("exclusively create staging directory: %w", err)
			}
		}
		nextFD, err := platformOpenAtNoFollow(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
		if err != nil {
			_ = unix.Close(currentFD)
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(nextFD, &stat); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return err
		}
		identity := custodyIdentityFromStat(stat)
		if !custodyIdentityIsDirectory(identity) || identity.Device != custody.rootIdentity.Device {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory has an invalid identity")
		}
		if known && !sameCustodyObject(expected.identity, identity) {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory was replaced")
		}
		if err := requireOpenedDirectoryOwnedByRootsUser(nextFD, custody.owner, "staging directory"); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return err
		}
		if err := unix.Fchown(nextFD, custody.owner.UID, custody.owner.GID); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return err
		}
		if err := unix.Fchmod(nextFD, uint32(mode.Perm())); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return err
		}
		if !known && beforeStagingChildRegistrationStatForTest != nil {
			beforeStagingChildRegistrationStatForTest(currentRelativePath, nextFD, true)
		}
		if err := unix.Fstat(nextFD, &stat); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return err
		}
		identity = custodyIdentityFromStat(stat)
		if !custodyIdentityIsDirectory(identity) ||
			identity.Device != custody.rootIdentity.Device ||
			identity.UID != custody.owner.UID ||
			identity.GID != custody.owner.GID ||
			!sameCustodyRecordedMode(identity.Mode, unix.S_IFDIR|uint32(mode.Perm())) {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory has an invalid identity")
		}
		if !known {
			ownedSegment := strings.Clone(component)
			expected = newCustodyExpectedDirectory(identity)
			currentNode.children[ownedSegment] = expected
		} else if !custody.validExpectedIdentity(expected.identity, identity) {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory registration changed")
		}
		if err := unix.Close(currentFD); err != nil {
			_ = unix.Close(nextFD)
			return err
		}
		currentFD = nextFD
		currentNode = expected
	}
	return unix.Close(currentFD)
}

func (custody *stagingCustody) writeFile(relativePath string, content []byte, mode os.FileMode) error {
	return custody.writeFileWithHook(relativePath, content, mode, nil)
}

func (custody *stagingCustody) writeFileWithHook(relativePath string, content []byte, mode os.FileMode, afterCreate func(parentFD int, name string) error) error {
	return custody.writeFileWithHookAndParentMode(relativePath, content, mode, stableStageDirMode, afterCreate)
}

func (custody *stagingCustody) writeFileWithParentMode(relativePath string, content []byte, mode os.FileMode, parentMode os.FileMode) error {
	return custody.writeFileWithHookAndParentMode(relativePath, content, mode, parentMode, nil)
}

func (custody *stagingCustody) writeFileWithHookAndParentMode(relativePath string, content []byte, mode os.FileMode, parentMode os.FileMode, afterCreate func(parentFD int, name string) error) error {
	if !stagedModeProbedAtStartup(stagedFileModes(), mode) {
		return fmt.Errorf("staging file mode %04o is not proved by the startup probe", uint32(mode))
	}
	relativePath, err := cleanCustodyRelative(relativePath, false)
	if err != nil {
		return err
	}
	parentPath := pathDir(relativePath)
	if err := custody.ensureDirectory(parentPath, parentMode); err != nil {
		return err
	}
	parentFD, parentNode, err := custody.openRegisteredDirectoryNode(parentPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	name := pathBase(relativePath)
	if _, exists := parentNode.children[name]; exists {
		return fmt.Errorf("staging file is already owned")
	}
	fileFD, err := platformOpenAtNoFollow(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(mode.Perm()), true)
	if err != nil {
		return fmt.Errorf("exclusively create staging file: %w", err)
	}
	// The claimed root retains an incomplete leaf on failure. A path-based
	// unlink cannot prove that this name still denotes the object opened here.
	defer unix.Close(fileFD)
	if afterCreate != nil {
		if err := afterCreate(parentFD, name); err != nil {
			return err
		}
	}
	if err := unix.Fchown(fileFD, custody.owner.UID, custody.owner.GID); err != nil {
		return err
	}
	if err := unix.Fchmod(fileFD, uint32(mode.Perm())); err != nil {
		return err
	}
	if err := writeAllDescriptor(fileFD, content); err != nil {
		return err
	}
	if err := unix.Fsync(fileFD); err != nil {
		return err
	}
	if beforeStagingChildRegistrationStatForTest != nil {
		beforeStagingChildRegistrationStatForTest(relativePath, fileFD, false)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return err
	}
	identity := custodyIdentityFromStat(stat)
	if !custodyIdentityIsRegular(identity) ||
		identity.Links != 1 ||
		identity.Device != custody.rootIdentity.Device ||
		identity.UID != custody.owner.UID ||
		identity.GID != custody.owner.GID ||
		!sameCustodyRecordedMode(identity.Mode, unix.S_IFREG|uint32(mode.Perm())) {
		return fmt.Errorf("staging file has an invalid identity")
	}
	parentNode.children[strings.Clone(name)] = newCustodyExpectedFile(identity)
	return nil
}

func (custody *stagingCustody) openRegisteredDirectory(relativePath string) (int, error) {
	fd, _, err := custody.openRegisteredDirectoryNode(relativePath)
	return fd, err
}

func (custody *stagingCustody) openRegisteredDirectoryNode(relativePath string) (int, *custodyExpectedNode, error) {
	relativePath, err := cleanCustodyRelative(relativePath, true)
	if err != nil {
		return -1, nil, err
	}
	if err := custody.verifyVisibleRootIdentity(); err != nil {
		return -1, nil, err
	}
	if custody.expectedRoot == nil || !custody.expectedRoot.isDirectory() {
		return -1, nil, fmt.Errorf("staging custody expected tree is unavailable")
	}
	currentFD, err := platformOpenAtNoFollow(custody.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return -1, nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(currentFD, &rootStat); err != nil {
		_ = unix.Close(currentFD)
		return -1, nil, err
	}
	if !sameCustodyObject(custody.expectedRoot.identity, custodyIdentityFromStat(rootStat)) {
		_ = unix.Close(currentFD)
		return -1, nil, fmt.Errorf("staging root expected identity changed")
	}
	if relativePath == "" {
		return currentFD, custody.expectedRoot, nil
	}
	currentNode := custody.expectedRoot
	for _, component := range strings.Split(relativePath, "/") {
		expected, known := currentNode.children[component]
		if !known || !expected.isDirectory() {
			_ = unix.Close(currentFD)
			return -1, nil, fmt.Errorf("staging directory was not created by this claim")
		}
		nextFD, err := platformOpenAtNoFollow(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
		if err != nil {
			_ = unix.Close(currentFD)
			return -1, nil, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(nextFD, &stat); err != nil {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return -1, nil, err
		}
		if !sameCustodyObject(expected.identity, custodyIdentityFromStat(stat)) {
			_ = unix.Close(nextFD)
			_ = unix.Close(currentFD)
			return -1, nil, fmt.Errorf("staging directory was replaced")
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
		currentNode = expected
	}
	return currentFD, currentNode, nil
}

type custodyDirectoryValidation struct {
	node *custodyExpectedNode
	path string
}

func (custody *stagingCustody) revalidateBeforeHandoff() error {
	if beforeStagingHandoffValidationForTest != nil {
		beforeStagingHandoffValidationForTest(custody)
	}
	if err := custody.verifyVisibleRootIdentity(); err != nil {
		return err
	}
	stack := []custodyDirectoryValidation{{node: custody.expectedRoot, path: ""}}
	for len(stack) != 0 {
		index := len(stack) - 1
		current := stack[index]
		stack = stack[:index]
		currentFD, currentNode, err := custody.openRegisteredDirectoryNode(current.path)
		if err != nil {
			return err
		}
		if currentNode != current.node {
			_ = unix.Close(currentFD)
			return fmt.Errorf("staging directory registration changed during handoff validation")
		}
		children, validationErr := custody.revalidateDirectoryChildren(currentFD, current.node, current.path)
		closeErr := unix.Close(currentFD)
		if validationErr != nil {
			return validationErr
		}
		if closeErr != nil {
			return closeErr
		}
		stack = append(stack, children...)
	}
	return nil
}

func (custody *stagingCustody) revalidateDirectoryChildren(directoryFD int, expectedDirectory *custodyExpectedNode, parentPath string) ([]custodyDirectoryValidation, error) {
	if !expectedDirectory.isDirectory() {
		return nil, fmt.Errorf("staging expected tree contains a non-directory traversal node")
	}
	var directoryBefore unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryBefore); err != nil {
		return nil, err
	}
	if !custody.validExpectedIdentity(expectedDirectory.identity, custodyIdentityFromStat(directoryBefore)) {
		return nil, fmt.Errorf("staging directory changed before handoff validation")
	}

	enumerationFD, err := platformOpenAtNoFollow(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return nil, err
	}
	var enumerationStat unix.Stat_t
	if err := unix.Fstat(enumerationFD, &enumerationStat); err != nil {
		_ = unix.Close(enumerationFD)
		return nil, err
	}
	if !platformStatSnapshotStable(directoryBefore, enumerationStat) ||
		!custody.validExpectedIdentity(expectedDirectory.identity, custodyIdentityFromStat(enumerationStat)) {
		_ = unix.Close(enumerationFD)
		return nil, fmt.Errorf("staging directory changed before handoff validation")
	}
	stream := os.NewFile(uintptr(enumerationFD), "custody-directory")
	if stream == nil {
		_ = unix.Close(enumerationFD)
		return nil, fmt.Errorf("open custody directory stream")
	}
	children := make([]custodyDirectoryValidation, 0, len(expectedDirectory.children))
	validationErr := validateExpectedDirectoryEntries(stream, expectedDirectory.children, func(name string, expected *custodyExpectedNode) error {
		childFD, err := custody.revalidateExpectedChildAt(directoryFD, name, expected)
		if err != nil {
			return err
		}
		if childFD >= 0 {
			if err := unix.Close(childFD); err != nil {
				return err
			}
			childPath := name
			if parentPath != "" {
				childPath = parentPath + "/" + name
			}
			children = append(children, custodyDirectoryValidation{node: expected, path: childPath})
		}
		return nil
	})
	closeStreamErr := stream.Close()
	if validationErr != nil {
		return nil, validationErr
	}
	if closeStreamErr != nil {
		return nil, closeStreamErr
	}

	var directoryAfter unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryAfter); err != nil {
		return nil, err
	}
	if !platformStatSnapshotStable(directoryBefore, directoryAfter) ||
		!custody.validExpectedIdentity(expectedDirectory.identity, custodyIdentityFromStat(directoryAfter)) {
		return nil, fmt.Errorf("staging directory changed during handoff validation")
	}
	return children, nil
}

type directoryEntryReader interface {
	ReadDir(int) ([]os.DirEntry, error)
}

func validateExpectedDirectoryEntries(reader directoryEntryReader, expectedChildren map[string]*custodyExpectedNode, validateExpected func(name string, expected *custodyExpectedNode) error) error {
	remaining := make(map[string]*custodyExpectedNode, len(expectedChildren))
	for name, expected := range expectedChildren {
		remaining[name] = expected
	}
	maximumObserved := len(expectedChildren) + 1
	observed := 0
	for {
		entries, readErr := reader.ReadDir(1)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(entries) > 1 {
			return fmt.Errorf("staging directory enumeration exceeded its fixed batch")
		}
		if len(entries) == 0 {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return fmt.Errorf("staging directory enumeration made no progress")
		}

		observed++
		if observed > maximumObserved {
			return fmt.Errorf("staging directory contains an unexpected child")
		}
		name := entries[0].Name()
		if name == "." || name == ".." || !validCustodyComponent(name) {
			return fmt.Errorf("staging directory contains a malformed child name")
		}
		expected, known := expectedChildren[name]
		if !known {
			return fmt.Errorf("staging directory contains an unexpected child")
		}
		if _, pending := remaining[name]; !pending {
			return fmt.Errorf("staging directory contains a duplicate child name")
		}
		delete(remaining, name)
		if err := validateExpected(name, expected); err != nil {
			return err
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if len(remaining) != 0 {
		return fmt.Errorf("staging directory is missing an expected child")
	}
	return nil
}

func (custody *stagingCustody) revalidateExpectedChildAt(parentFD int, name string, expected *custodyExpectedNode) (int, error) {
	if expected == nil || (!custodyIdentityIsRegular(expected.identity) && !expected.isDirectory()) {
		return -1, fmt.Errorf("staging custody expected tree is incomplete")
	}
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, err
	}
	beforeIdentity := custodyIdentityFromStat(visibleBefore)
	if !custody.validExpectedIdentity(expected.identity, beforeIdentity) {
		return -1, fmt.Errorf("staging object changed before handoff")
	}
	flags := unix.O_RDONLY
	if expected.isDirectory() {
		flags |= unix.O_DIRECTORY
	}
	objectFD, err := platformOpenAtNoFollow(parentFD, name, flags, 0, true)
	if err != nil {
		return -1, err
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = unix.Close(objectFD)
		}
	}()
	var opened unix.Stat_t
	if err := unix.Fstat(objectFD, &opened); err != nil {
		return -1, err
	}
	openedIdentity := custodyIdentityFromStat(opened)
	if !custody.validExpectedIdentity(expected.identity, openedIdentity) || !sameCustodyObject(beforeIdentity, openedIdentity) {
		return -1, fmt.Errorf("staging object changed before handoff")
	}
	var visibleAfter unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, err
	}
	afterIdentity := custodyIdentityFromStat(visibleAfter)
	if !custody.validExpectedIdentity(expected.identity, afterIdentity) || !sameCustodyObject(openedIdentity, afterIdentity) {
		return -1, fmt.Errorf("staging object changed before handoff")
	}
	if expected.isDirectory() {
		keepOpen = true
		return objectFD, nil
	}
	return -1, nil
}

func (custody *stagingCustody) validExpectedIdentity(expected custodyIdentity, observed custodyIdentity) bool {
	if !sameCustodyObject(expected, observed) ||
		observed.Device != custody.rootIdentity.Device ||
		observed.UID != custody.owner.UID ||
		observed.GID != custody.owner.GID ||
		!sameCustodyRecordedMode(expected.Mode, observed.Mode) {
		return false
	}
	if custodyIdentityIsRegular(expected) {
		return custodyIdentityIsRegular(observed) && observed.Links == 1
	}
	if custodyIdentityIsDirectory(expected) {
		return custodyIdentityIsDirectory(observed) && observed.Links >= 1
	}
	return false
}

func (custody *stagingCustody) verifyRootIdentity() error {
	if custody == nil || custody.rootFD < 0 {
		return fmt.Errorf("staging custody is closed")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(custody.rootFD, &stat); err != nil {
		return err
	}
	identity := custodyIdentityFromStat(stat)
	if !sameCustodyObject(custody.rootIdentity, identity) ||
		identity.Links < 1 ||
		identity.Device != custody.parentIdentity.Device ||
		identity.UID != custody.owner.UID ||
		identity.GID != custody.owner.GID ||
		!sameCustodyRecordedMode(custody.rootIdentity.Mode, identity.Mode) {
		return fmt.Errorf("held staging root identity changed")
	}
	return nil
}

func (custody *stagingCustody) verifyVisibleRootIdentity() error {
	if err := custody.verifyRootIdentity(); err != nil {
		return err
	}
	if custody.stagingRoot == nil {
		return fmt.Errorf("staging root qualification is unavailable")
	}
	if err := custody.stagingRoot.verifyVisible(); err != nil {
		return err
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(custody.parentFD, &parentStat); err != nil {
		return err
	}
	if !sameCustodyObject(custody.parentIdentity, custodyIdentityFromStat(parentStat)) {
		return fmt.Errorf("held staging parent identity changed")
	}
	var visibleStat unix.Stat_t
	if err := unix.Fstatat(custody.parentFD, custody.rootName, &visibleStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameCustodyObject(custody.rootIdentity, custodyIdentityFromStat(visibleStat)) {
		return fmt.Errorf("visible staging root no longer names the held root")
	}
	return nil
}

func (custody *stagingCustody) close() error {
	if custody == nil {
		return nil
	}
	var errs []error
	if custody.rootFD >= 0 {
		errs = append(errs, unix.Close(custody.rootFD))
		custody.rootFD = -1
	}
	if custody.stagingRoot != nil {
		errs = append(errs, custody.stagingRoot.close())
		custody.stagingRoot = nil
		custody.parentFD = -1
	}
	return errors.Join(errs...)
}

// readDirectoryEntries retains the existing deterministic result-packaging
// traversal. Expected-tree handoff validation does not call this helper; its
// separate ledger-bounded stream above never materializes observed entries.
func readDirectoryEntries(directoryFD int) ([]os.DirEntry, error) {
	readFD, err := unix.Dup(directoryFD)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(readFD)
	file := os.NewFile(uintptr(readFD), "result-directory")
	if file == nil {
		_ = unix.Close(readFD)
		return nil, fmt.Errorf("open result directory stream")
	}
	var entries []os.DirEntry
	for {
		batch, readErr := file.ReadDir(64)
		entries = append(entries, batch...)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return nil, readErr
		}
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i int, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readStableRegularFileAt(parentFD int, name string, limit int64, expectedDevice uint64) ([]byte, custodyIdentity, error) {
	return readStableRegularFileAtWithHook(parentFD, name, limit, expectedDevice, nil)
}

func readStableRegularFileAtWithHook(parentFD int, name string, limit int64, expectedDevice uint64, afterSourceOpen func()) ([]byte, custodyIdentity, error) {
	var preOpen unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &preOpen, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, custodyIdentity{}, err
	}
	preOpenIdentity := custodyIdentityFromStat(preOpen)
	if !custodyIdentityIsRegular(preOpenIdentity) || preOpenIdentity.Links != 1 || (expectedDevice != 0 && preOpenIdentity.Device != expectedDevice) || preOpen.Size < 0 || preOpen.Size > limit {
		return nil, custodyIdentity{}, fmt.Errorf("source is not a bounded regular single-link file")
	}
	fd, err := platformOpenAtNoFollow(parentFD, name, unix.O_RDONLY, 0, expectedDevice != 0)
	if err != nil {
		return nil, custodyIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, custodyIdentity{}, fmt.Errorf("open stable source")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, custodyIdentity{}, err
	}
	identity := custodyIdentityFromStat(before)
	if !sameCustodyObject(preOpenIdentity, identity) || !custodyIdentityIsRegular(identity) || identity.Links != 1 || (expectedDevice != 0 && identity.Device != expectedDevice) || before.Size < 0 || before.Size > limit {
		return nil, custodyIdentity{}, fmt.Errorf("source is not a bounded regular single-link file")
	}
	if afterSourceOpen != nil {
		afterSourceOpen()
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if readErr != nil {
		return nil, custodyIdentity{}, readErr
	}
	if int64(len(payload)) > limit || int64(len(payload)) != before.Size {
		return nil, custodyIdentity{}, fmt.Errorf("source size changed during capture")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, custodyIdentity{}, err
	}
	if !platformStatSnapshotStable(before, after) {
		return nil, custodyIdentity{}, fmt.Errorf("source identity changed during capture")
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, custodyIdentity{}, fmt.Errorf("source path changed during capture: %w", err)
	}
	if !sameCustodyObject(identity, custodyIdentityFromStat(visible)) {
		return nil, custodyIdentity{}, fmt.Errorf("source path changed during capture")
	}
	return payload, identity, nil
}

func captureStableRegularFile(path string, limit int64) ([]byte, error) {
	return captureStableRegularFileWithHook(path, limit, nil)
}

func captureStableRegularFileWithHook(path string, limit int64, afterOpen func()) ([]byte, error) {
	parent, name, err := openQualifiedFileParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.close()
	if err := parent.verifyVisible(); err != nil {
		return nil, err
	}
	payload, _, err := readStableRegularFileAtWithHook(parent.fd, name, limit, 0, afterOpen)
	if err != nil {
		return nil, err
	}
	reopenedParent, err := openQualifiedDirectory(filepath.Dir(filepath.Clean(path)), false, 0)
	if err != nil {
		return nil, fmt.Errorf("source ancestry changed during capture: %w", err)
	}
	defer reopenedParent.close()
	if !sameCustodyObject(parent.identity, reopenedParent.identity) {
		return nil, fmt.Errorf("source ancestry changed during capture")
	}
	if err := parent.verifyVisible(); err != nil {
		return nil, fmt.Errorf("source ancestry changed during capture: %w", err)
	}
	return payload, nil
}

func validateBoundedRegularFile(path string, limit int64) error {
	parent, name, err := openQualifiedFileParent(path)
	if err != nil {
		return err
	}
	defer parent.close()
	if err := parent.verifyVisible(); err != nil {
		return err
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	visibleIdentity := custodyIdentityFromStat(visible)
	if !custodyIdentityIsRegular(visibleIdentity) || visibleIdentity.Links != 1 || visible.Size < 0 || visible.Size > limit {
		return fmt.Errorf("path must be a bounded regular file with one link")
	}
	fd, err := platformOpenAtNoFollow(parent.fd, name, unix.O_RDONLY, 0, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	identity := custodyIdentityFromStat(stat)
	if !sameCustodyObject(visibleIdentity, identity) || !custodyIdentityIsRegular(identity) || identity.Links != 1 || stat.Size < 0 || stat.Size > limit {
		return fmt.Errorf("path must be a bounded regular file with one link")
	}
	return nil
}

func openQualifiedFileParent(path string) (*qualifiedDirectory, string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(cleanPath) || cleanPath == string(os.PathSeparator) {
		return nil, "", fmt.Errorf("source path must be absolute")
	}
	name := filepath.Base(cleanPath)
	if !validCustodyComponent(name) {
		return nil, "", fmt.Errorf("source path has an invalid leaf")
	}
	parent, err := openQualifiedDirectory(filepath.Dir(cleanPath), false, 0)
	if err != nil {
		return nil, "", err
	}
	return parent, name, nil
}

func writeAllDescriptor(fd int, content []byte) error {
	for len(content) > 0 {
		written, err := unix.Write(fd, content)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func randomCustodyToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func pathDir(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return ""
	}
	return path[:index]
}

func pathBase(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return path
	}
	return path[index+1:]
}

func probeStagingCustodyCapabilities(stagingRootPath string, owner executionPlatformStateOwner) (resultErr error) {
	token, err := randomCustodyToken()
	if err != nil {
		return err
	}
	runID := ".execution-substrate-capability-probe-" + token
	stagingRoot, err := openQualifiedDirectory(stagingRootPath, false, 0)
	if err != nil {
		return fmt.Errorf("staging custody capability probe qualify: %w", err)
	}
	custody, err := claimStagingCustodyFromQualifiedRoot(stagingRoot, runID, owner)
	if err != nil {
		return fmt.Errorf("staging custody capability probe claim: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, custody.close()) }()

	collision := runID + "-collision"
	if err := unix.Mkdirat(custody.parentFD, collision, 0o700); err != nil {
		return err
	}
	if err := platformRenameNoReplace(custody.parentFD, runID, custody.parentFD, collision); err == nil {
		return fmt.Errorf("no-replace rename unexpectedly replaced a destination")
	}

	symlinkName := runID + "-symlink"
	if err := unix.Symlinkat(".", custody.parentFD, symlinkName); err != nil {
		return err
	}
	if fd, err := platformOpenAtNoFollow(custody.parentFD, symlinkName, unix.O_RDONLY|unix.O_DIRECTORY, 0, true); err == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("no-follow open unexpectedly accepted a symbolic link")
	}
	return nil
}

type operationalStageEntry struct {
	path      string
	directory bool
	mode      uint32
	bytes     []byte
}

func qualifyOperationalStageParent(d *qualifiedDirectory, anchor custodyIdentity, owner executionPlatformStateOwner) (unix.Stat_t, error) {
	var held, visible, final unix.Stat_t
	if d == nil || d.verifyVisible() != nil || unix.Fstat(d.fd, &held) != nil ||
		unix.Fstatat(d.parentFD, d.leafName, &visible, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(d.fd, &final) != nil {
		return unix.Stat_t{}, errPrivateReplayUnavailable
	}
	identity := custodyIdentityFromStat(held)
	if !operationalStageParentIdentityMatches(identity, anchor, owner) ||
		identity != custodyIdentityFromStat(visible) || !platformStatSnapshotStable(held, final) {
		return unix.Stat_t{}, errPrivateReplayUnavailable
	}
	return held, nil
}

func operationalStageParentIdentityMatches(identity, anchor custodyIdentity, owner executionPlatformStateOwner) bool {
	return custodyIdentityIsDirectory(identity) && sameCustodyObject(anchor, identity) && identity.Mode&0o022 == 0 &&
		sameCustodyRecordedMode(identity.Mode, anchor.Mode) && identity.UID == owner.UID && identity.GID == owner.GID
}

func measureOperationalStage(c *stagingCustody, material resolvedExecutionMaterial, original [32]byte,
	run string, intent, project [32]byte, parentLinks *uint64, sync bool) ([]byte, error) {
	if c == nil || c.rootFD < 0 || run != c.runID || parentLinks == nil || !sync && *parentLinks == 0 || c.revalidateBeforeHandoff() != nil {
		return nil, errPrivateReplayUnavailable
	}
	entries := []operationalStageEntry{
		{path: "payload", directory: true, mode: 0o750},
		{path: "payload/artifact.tar.gz", mode: 0o600, bytes: material.payloadBytes},
		{path: "run", directory: true, mode: 0o750},
		{path: "run/platform", directory: true, mode: 0o750},
		{path: "run/platform/es-runtime-support", mode: 0o750, bytes: material.runtimeSupportBytes},
		{path: "run/result", directory: true, mode: 0o750},
	}
	if len(material.trust.vaultCACertBytes) > 0 && len(material.trust.workloadTLSBundleBytes) > 0 {
		entries = append(entries,
			operationalStageEntry{path: "run/platform/workload-vault-ca.pem", mode: 0o640, bytes: material.trust.vaultCACertBytes},
			operationalStageEntry{path: "run/platform/workload-ca-bundle.pem", mode: 0o640, bytes: material.trust.workloadTLSBundleBytes})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	parent, err := qualifyOperationalStageParent(c.stagingRoot, c.parentIdentity, c.owner)
	var root unix.Stat_t
	if err != nil || unix.Fstat(c.rootFD, &root) != nil || uint32(root.Mode)&0o7777 != 0o750 ||
		sync && (unix.Fsync(c.rootFD) != nil || unix.Fsync(c.parentFD) != nil) {
		return nil, errPrivateReplayUnavailable
	}
	out := append([]byte("ESOHSTG1"), original[:]...)
	out = operationalFrame(out, []byte(run))
	out = append(out, intent[:]...)
	out = append(out, project[:]...)
	parentIdentity := custodyIdentityFromStat(parent)
	if !sync {
		parentIdentity.Links = *parentLinks
	}
	out = appendOperationalStageIdentity(out, parentIdentity, true)
	out = appendOperationalStageIdentity(out, custodyIdentityFromStat(root), true)
	out = binary.BigEndian.AppendUint16(out, uint16(len(entries)))
	total := 0
	for _, entry := range entries {
		out = operationalFrame(out, []byte(entry.path))
		identity, digest, err := c.operationalStageEntry(entry, sync)
		total += len(entry.bytes)
		if err != nil || total > 1048576 {
			return nil, errPrivateReplayUnavailable
		}
		out = appendOperationalStageIdentity(out, identity, entry.directory)
		out = binary.BigEndian.AppendUint64(out, uint64(len(entry.bytes)))
		out = append(out, digest[:]...)
	}
	var finalRoot unix.Stat_t
	finalParent, err := qualifyOperationalStageParent(c.stagingRoot, c.parentIdentity, c.owner)
	if err != nil || c.revalidateBeforeHandoff() != nil || unix.Fstat(c.rootFD, &finalRoot) != nil ||
		!platformStatSnapshotStable(root, finalRoot) || !platformStatSnapshotStable(parent, finalParent) {
		return nil, errPrivateReplayUnavailable
	}
	if sync {
		*parentLinks = parentIdentity.Links
	}
	return out, nil
}

func (c *stagingCustody) operationalStageEntry(entry operationalStageEntry, sync bool) (custodyIdentity, [32]byte, error) {
	fail := func() (custodyIdentity, [32]byte, error) {
		return custodyIdentity{}, [32]byte{}, errPrivateReplayUnavailable
	}
	var digest [32]byte
	var identity custodyIdentity
	if entry.directory {
		fd, err := c.openRegisteredDirectory(entry.path)
		if err != nil {
			return fail()
		}
		var info unix.Stat_t
		statErr := unix.Fstat(fd, &info)
		var syncErr error
		if sync {
			syncErr = unix.Fsync(fd)
		}
		if unix.Close(fd) != nil || statErr != nil || syncErr != nil {
			return fail()
		}
		identity = custodyIdentityFromStat(info)
		if !custodyIdentityIsDirectory(identity) {
			return fail()
		}
	} else {
		if len(entry.bytes) > 262144 {
			return fail()
		}
		fd, err := c.openRegisteredDirectory(pathDir(entry.path))
		if err != nil {
			return fail()
		}
		actual, current, err := readStableRegularFileAt(fd, pathBase(entry.path), 262144, c.rootIdentity.Device)
		if unix.Close(fd) != nil || err != nil || !bytes.Equal(actual, entry.bytes) {
			return fail()
		}
		identity = current
		digest = sha256.Sum256(actual)
	}
	if identity.Mode&0o7777 != entry.mode || identity.Device != c.rootIdentity.Device || identity.UID != c.owner.UID || identity.GID != c.owner.GID {
		return fail()
	}
	return identity, digest, nil
}

func appendOperationalStageIdentity(out []byte, identity custodyIdentity, directory bool) []byte {
	tag := byte(2)
	if directory {
		tag = 1
	}
	out = append(out, tag)
	out = binary.BigEndian.AppendUint64(out, identity.Device)
	out = binary.BigEndian.AppendUint64(out, identity.Inode)
	out = binary.BigEndian.AppendUint32(out, uint32(identity.UID))
	out = binary.BigEndian.AppendUint32(out, uint32(identity.GID))
	out = binary.BigEndian.AppendUint32(out, identity.Mode&0o7777)
	return binary.BigEndian.AppendUint64(out, identity.Links)
}
