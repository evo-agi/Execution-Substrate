//go:build linux

package admission

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	linuxMountInfoByteLimit   = 8 << 20
	linuxMountInfoRecordLimit = 65536
)

type linuxMountInfoRootKind uint8

const (
	linuxMountInfoRootPathname linuxMountInfoRootKind = iota + 1
	linuxMountInfoRootNamespaceObject
)

type linuxMountInfoRoot struct {
	kind  linuxMountInfoRootKind
	value string
}

type linuxMountInfoRecord struct {
	mountID        uint64
	parentID       uint64
	major          uint32
	minor          uint32
	root           linuxMountInfoRoot
	mountPoint     string
	filesystemType string
}

func platformObserveExecutionRoots(staging *executionRootPlan, results *executionRootPlan) error {
	snapshot, err := readStableLinuxMountInfo()
	if err != nil {
		return err
	}
	records, err := parseLinuxMountInfo(snapshot)
	if err != nil {
		return err
	}
	if err := observeLinuxExecutionRoot(staging, records); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	if err := observeLinuxExecutionRoot(results, records); err != nil {
		return fmt.Errorf("results: %w", err)
	}
	return nil
}

func readStableLinuxMountInfo() ([]byte, error) {
	first, err := readBoundedLinuxMountInfo()
	if err != nil {
		return nil, err
	}
	second, err := readBoundedLinuxMountInfo()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, fmt.Errorf("mountinfo changed during acquisition")
	}
	return first, nil
}

func readBoundedLinuxMountInfo() ([]byte, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, linuxMountInfoByteLimit+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > linuxMountInfoByteLimit {
		return nil, fmt.Errorf("mountinfo exceeds the bounded byte limit")
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return nil, fmt.Errorf("mountinfo is empty or truncated")
	}
	return payload, nil
}

func parseLinuxMountInfo(payload []byte) ([]linuxMountInfoRecord, error) {
	if len(payload) == 0 || len(payload) > linuxMountInfoByteLimit || payload[len(payload)-1] != '\n' {
		return nil, fmt.Errorf("mountinfo is empty, oversized, or truncated")
	}
	lines := bytes.Split(payload[:len(payload)-1], []byte{'\n'})
	if len(lines) > linuxMountInfoRecordLimit {
		return nil, fmt.Errorf("mountinfo exceeds the bounded record limit")
	}
	records := make([]linuxMountInfoRecord, 0, len(lines))
	byID := make(map[uint64]int, len(lines))
	for _, rawLine := range lines {
		if len(rawLine) == 0 {
			return nil, fmt.Errorf("mountinfo contains an empty record")
		}
		for _, value := range rawLine {
			if value < ' ' || value == 0x7f {
				return nil, fmt.Errorf("mountinfo contains an invalid control byte")
			}
		}
		fields := strings.Fields(string(rawLine))
		separator := -1
		for index, field := range fields {
			if field == "-" {
				if separator >= 0 {
					return nil, fmt.Errorf("mountinfo record contains multiple separators")
				}
				separator = index
			}
		}
		if separator < 6 || len(fields)-separator-1 != 3 {
			return nil, fmt.Errorf("mountinfo record is missing mandatory fields")
		}
		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mountID == 0 {
			return nil, fmt.Errorf("mountinfo record has an invalid mount ID")
		}
		if _, duplicate := byID[mountID]; duplicate {
			return nil, fmt.Errorf("mountinfo contains a duplicate mount ID")
		}
		parentID, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || parentID == 0 {
			return nil, fmt.Errorf("mountinfo record has an invalid parent ID")
		}
		major, minor, err := parseLinuxMountInfoDevice(fields[2])
		if err != nil {
			return nil, err
		}
		mountPoint, err := decodeLinuxMountInfoPath(fields[4])
		if err != nil {
			return nil, err
		}
		for _, token := range append(append([]string{fields[5]}, fields[6:separator]...), fields[separator+1:]...) {
			if !validLinuxMountInfoToken(token) {
				return nil, fmt.Errorf("mountinfo contains an invalid bounded token")
			}
		}
		filesystemType := fields[separator+1]
		var root linuxMountInfoRoot
		if filesystemType == "nsfs" {
			for _, namespaceKind := range [...]string{"mnt", "net", "uts", "ipc", "pid", "user", "cgroup", "time"} {
				prefix := namespaceKind + ":["
				if !strings.HasPrefix(fields[3], prefix) {
					continue
				}
				label := fields[3][len(prefix):]
				if len(label) < 2 || label[len(label)-1] != ']' {
					break
				}
				digits := label[:len(label)-1]
				if len(digits) > 1 && digits[0] == '0' {
					break
				}
				validDigits := len(digits) != 0
				for index := 0; index < len(digits); index++ {
					if digits[index] < '0' || digits[index] > '9' {
						validDigits = false
						break
					}
				}
				if validDigits {
					root = linuxMountInfoRoot{kind: linuxMountInfoRootNamespaceObject, value: fields[3]}
				}
				break
			}
			if root.kind == 0 {
				return nil, fmt.Errorf("mountinfo nsfs root is not a supported namespace-object label")
			}
		} else {
			rootPath, err := decodeLinuxMountInfoPath(fields[3])
			if err != nil {
				return nil, err
			}
			root = linuxMountInfoRoot{kind: linuxMountInfoRootPathname, value: rootPath}
		}
		record := linuxMountInfoRecord{
			mountID:        mountID,
			parentID:       parentID,
			major:          major,
			minor:          minor,
			root:           root,
			mountPoint:     mountPoint,
			filesystemType: filesystemType,
		}
		byID[mountID] = len(records)
		records = append(records, record)
	}

	topSelfParents := 0
	for _, record := range records {
		if record.parentID == record.mountID {
			if record.mountPoint != "/" {
				return nil, fmt.Errorf("mountinfo contains a non-top self-parent record")
			}
			topSelfParents++
			if topSelfParents > 1 {
				return nil, fmt.Errorf("mountinfo contains multiple top self-parent records")
			}
		}
	}
	state := make(map[uint64]uint8, len(records))
	for _, record := range records {
		if state[record.mountID] == 2 {
			continue
		}
		current := record
		pathIDs := make([]uint64, 0, 8)
		for {
			if state[current.mountID] == 1 {
				return nil, fmt.Errorf("mountinfo contains a nontrivial parent cycle")
			}
			if state[current.mountID] == 2 {
				break
			}
			state[current.mountID] = 1
			pathIDs = append(pathIDs, current.mountID)
			if current.parentID == current.mountID {
				break
			}
			parentIndex, present := byID[current.parentID]
			if !present {
				break
			}
			current = records[parentIndex]
		}
		for _, mountID := range pathIDs {
			state[mountID] = 2
		}
	}
	return records, nil
}

func validLinuxMountInfoToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= ' ' || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func parseLinuxMountInfoDevice(value string) (uint32, uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, fmt.Errorf("mountinfo record has an invalid device")
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("mountinfo record has an invalid device")
	}
	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("mountinfo record has an invalid device")
	}
	return uint32(major), uint32(minor), nil
}

func decodeLinuxMountInfoPath(value string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("mountinfo path contains a truncated escape")
		}
		escape := value[index : index+4]
		switch escape {
		case `\040`:
			decoded.WriteByte(' ')
		case `\011`:
			decoded.WriteByte('\t')
		case `\012`:
			decoded.WriteByte('\n')
		case `\134`:
			decoded.WriteByte('\\')
		default:
			return "", fmt.Errorf("mountinfo path contains an unsupported escape")
		}
		index += 3
	}
	result := decoded.String()
	if strings.IndexByte(result, 0) >= 0 || !strings.HasPrefix(result, "/") || path.Clean(result) != result {
		return "", fmt.Errorf("mountinfo path is not absolute and component-clean")
	}
	return result, nil
}

func observeLinuxExecutionRoot(plan *executionRootPlan, records []linuxMountInfoRecord) error {
	var held unix.Stat_t
	if err := unix.Fstat(plan.existingFD, &held); err != nil {
		return err
	}
	if !sameCustodyObject(plan.existingIdentity, custodyIdentityFromStat(held)) {
		return fmt.Errorf("held descriptor identity changed")
	}
	requiredMask := uint32(unix.STATX_BASIC_STATS | unix.STATX_MNT_ID)
	var statx unix.Statx_t
	if err := unix.Statx(plan.existingFD, "", unix.AT_EMPTY_PATH, int(requiredMask), &statx); err != nil {
		return err
	}
	major := unix.Major(uint64(held.Dev))
	minor := unix.Minor(uint64(held.Dev))
	if err := validateLinuxStatxIdentity(held, statx, major, minor); err != nil {
		return err
	}
	presentation, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", plan.existingFD))
	if err != nil {
		return err
	}
	if !path.IsAbs(presentation) || path.Clean(presentation) != presentation {
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
	var reopenedStatx unix.Statx_t
	if err := unix.Statx(reopenedFD, "", unix.AT_EMPTY_PATH, int(requiredMask), &reopenedStatx); err != nil {
		return err
	}
	if reopenedStatx.Mask&requiredMask != requiredMask || reopenedStatx.Mnt_id != statx.Mnt_id {
		return fmt.Errorf("descriptor presentation rewalk changed mount identity")
	}

	var selected *linuxMountInfoRecord
	for index := range records {
		if records[index].mountID == statx.Mnt_id {
			if selected != nil {
				return fmt.Errorf("mount ID selects more than one mountinfo record")
			}
			selected = &records[index]
		}
	}
	if selected == nil {
		return fmt.Errorf("mount ID has no mountinfo record")
	}
	if selected.root.kind != linuxMountInfoRootPathname {
		return fmt.Errorf("selected mountinfo root is not path-coordinate eligible")
	}
	if selected.major != major || selected.minor != minor || selected.major != statx.Dev_major || selected.minor != statx.Dev_minor {
		return fmt.Errorf("descriptor and mountinfo devices disagree")
	}
	relation := executionRootComponentRelation(selected.mountPoint, presentation)
	if relation != executionRootPathsEqual && relation != executionRootLeftAncestor {
		return fmt.Errorf("descriptor presentation is outside its selected mountpoint")
	}
	relative := ""
	if relation == executionRootLeftAncestor {
		relative = strings.TrimPrefix(presentation, selected.mountPoint)
		relative = strings.TrimPrefix(relative, "/")
	}
	sourcePath := selected.root.value
	if relative != "" {
		sourcePath = path.Join(selected.root.value, relative)
	}
	if !path.IsAbs(sourcePath) || path.Clean(sourcePath) != sourcePath {
		return fmt.Errorf("derived mount source coordinate is invalid")
	}
	if plan.observed() && linuxHasDescendantMount(presentation, records) {
		return fmt.Errorf("execution root contains a descendant mountpoint")
	}
	plan.platform = executionRootPlatformObservation{
		presentation: presentation,
		sourceDevice: fmt.Sprintf("%d:%d", major, minor),
		sourcePath:   sourcePath,
	}
	return nil
}

func validateLinuxStatxIdentity(held unix.Stat_t, statx unix.Statx_t, major uint32, minor uint32) error {
	requiredMask := uint32(unix.STATX_BASIC_STATS | unix.STATX_MNT_ID)
	if statx.Mask&requiredMask != requiredMask {
		return fmt.Errorf("statx returned an incomplete identity mask")
	}
	if statx.Ino != uint64(held.Ino) || uint32(statx.Mode)&unix.S_IFMT != uint32(held.Mode)&unix.S_IFMT {
		return fmt.Errorf("fstat and statx identity disagree")
	}
	if statx.Dev_major != major || statx.Dev_minor != minor {
		return fmt.Errorf("fstat and statx device disagree")
	}
	return nil
}

func linuxHasDescendantMount(presentation string, records []linuxMountInfoRecord) bool {
	for _, record := range records {
		if executionRootComponentRelation(presentation, record.mountPoint) == executionRootLeftAncestor {
			return true
		}
	}
	return false
}
