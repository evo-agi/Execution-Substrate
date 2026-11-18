//go:build darwin

package admission

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const darwinMountRecordLimit = 65536

type darwinMountRecord struct {
	filesystemID string
	mountedOn    string
}

func platformObserveExecutionRoots(staging *executionRootPlan, results *executionRootPlan) error {
	records, err := readStableDarwinMounts()
	if err != nil {
		return err
	}
	if err := observeDarwinExecutionRoot(staging, records); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	if err := observeDarwinExecutionRoot(results, records); err != nil {
		return fmt.Errorf("results: %w", err)
	}
	return nil
}

func readStableDarwinMounts() ([]darwinMountRecord, error) {
	first, err := readBoundedDarwinMounts()
	if err != nil {
		return nil, err
	}
	second, err := readBoundedDarwinMounts()
	if err != nil {
		return nil, err
	}
	if len(first) != len(second) {
		return nil, fmt.Errorf("getfsstat changed during acquisition")
	}
	for index := range first {
		if first[index] != second[index] {
			return nil, fmt.Errorf("getfsstat changed during acquisition")
		}
	}
	return first, nil
}

func readBoundedDarwinMounts() ([]darwinMountRecord, error) {
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	if count < 0 || count > darwinMountRecordLimit {
		return nil, fmt.Errorf("getfsstat exceeds the bounded record limit")
	}
	if count == 0 {
		return nil, fmt.Errorf("getfsstat returned no records")
	}
	raw := make([]unix.Statfs_t, count)
	returned, err := unix.Getfsstat(raw, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	if returned < 0 || returned > count || returned > darwinMountRecordLimit {
		return nil, fmt.Errorf("getfsstat changed or overflowed the bounded buffer")
	}
	raw = raw[:returned]
	records := make([]darwinMountRecord, 0, len(raw))
	for _, record := range raw {
		mountedOn := darwinCString(record.Mntonname[:])
		if !filepath.IsAbs(mountedOn) || filepath.Clean(mountedOn) != mountedOn {
			return nil, fmt.Errorf("getfsstat contains an invalid mounted-on path")
		}
		records = append(records, darwinMountRecord{
			filesystemID: darwinFilesystemID(record.Fsid),
			mountedOn:    mountedOn,
		})
	}
	return records, nil
}

func observeDarwinExecutionRoot(plan *executionRootPlan, records []darwinMountRecord) error {
	var held unix.Stat_t
	if err := unix.Fstat(plan.existingFD, &held); err != nil {
		return err
	}
	if !sameCustodyObject(plan.existingIdentity, custodyIdentityFromStat(held)) {
		return fmt.Errorf("held descriptor identity changed")
	}
	presentation, err := darwinDescriptorPath(plan.existingFD)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(presentation) || filepath.Clean(presentation) != presentation {
		return fmt.Errorf("descriptor presentation is not absolute and component-clean")
	}
	reopenedFD, err := openAbsoluteDirectoryNoFollow(presentation)
	if err != nil {
		return fmt.Errorf("rewalk descriptor presentation: %w", err)
	}
	defer unix.Close(reopenedFD)
	var reopened unix.Stat_t
	if err := unix.Fstat(reopenedFD, &reopened); err != nil {
		return err
	}
	if !sameCustodyObject(plan.existingIdentity, custodyIdentityFromStat(reopened)) {
		return fmt.Errorf("descriptor presentation rewalk changed identity")
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(plan.existingFD, &filesystem); err != nil {
		return err
	}
	filesystemID := darwinFilesystemID(filesystem.Fsid)
	mountedOn := darwinCString(filesystem.Mntonname[:])
	if !filepath.IsAbs(mountedOn) || filepath.Clean(mountedOn) != mountedOn {
		return fmt.Errorf("fstatfs returned an invalid mounted-on path")
	}
	selected := 0
	for _, record := range records {
		if record.filesystemID == filesystemID && record.mountedOn == mountedOn {
			selected++
		}
	}
	if selected != 1 {
		return fmt.Errorf("descriptor filesystem does not select exactly one getfsstat record")
	}
	if plan.observed() && darwinHasDescendantMount(presentation, records) {
		return fmt.Errorf("execution root contains a descendant mountpoint")
	}
	plan.platform = executionRootPlatformObservation{
		presentation: presentation,
		filesystemID: filesystemID,
		mountedOn:    mountedOn,
	}
	return nil
}

func darwinHasDescendantMount(presentation string, records []darwinMountRecord) bool {
	for _, record := range records {
		if executionRootComponentRelation(presentation, record.mountedOn) == executionRootLeftAncestor {
			return true
		}
	}
	return false
}

func darwinDescriptorPath(fd int) (string, error) {
	var buffer [1024]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])))
	if errno != 0 {
		return "", errno
	}
	path := darwinCString(buffer[:])
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("F_GETPATH returned an invalid path")
	}
	return path, nil
}

func darwinFilesystemID(fsid unix.Fsid) string {
	return fmt.Sprintf("%d:%d", fsid.Val[0], fsid.Val[1])
}

func darwinCString(value []byte) string {
	for index, current := range value {
		if current == 0 {
			return string(value[:index])
		}
	}
	return string(value)
}
