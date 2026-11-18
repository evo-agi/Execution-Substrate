//go:build linux

package admission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxExecutionRootPresentationBindsFDPathStatxAndMountRecord(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	if roots.staging.platform.presentation == "" || roots.staging.platform.sourceDevice == "" || roots.staging.platform.sourcePath == "" {
		t.Fatalf("Linux descriptor proof is incomplete: %+v", roots.staging.platform)
	}
}

func TestLinuxMountInfoSourceCoordinatesAcceptCanonicalSiblingBindSources(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/view/staging", "8:1", "/source/staging")
	right := modeledLinuxExecutionRoot(true, "/view/results", "8:1", "/source/results")
	if err := classifyExecutionRootPlatformObservations(left, right); err != nil {
		t.Fatalf("canonical sibling bind sources rejected: %v", err)
	}
}

func TestLinuxMountInfoSourceCoordinatesRejectExactBindAlias(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/view/one", "8:1", "/source/shared")
	right := modeledLinuxExecutionRoot(true, "/view/two", "8:1", "/source/shared")
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("exact bind alias was accepted")
	}
}

func TestLinuxMountInfoSourceCoordinatesRejectSubtreeBindAlias(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/view/one", "8:1", "/source")
	right := modeledLinuxExecutionRoot(true, "/view/two", "8:1", "/source/child")
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("subtree bind alias was accepted")
	}
}

func TestLinuxMountInfoSourceCoordinatesRejectSeparatelyPresentedCaseAliasAncestry(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/s-view/area", "8:1", "/canonical/Area")
	right := modeledLinuxExecutionRoot(true, "/r-view/child", "8:1", "/canonical/Area/child")
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("canonical case-alias ancestry was accepted")
	}
}

func TestLinuxMountInfoSourceCoordinatesRejectReverseCaseAliasAncestry(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/s-view/child", "8:1", "/canonical/Area/child")
	right := modeledLinuxExecutionRoot(true, "/r-view/area", "8:1", "/canonical/Area")
	if err := classifyExecutionRootPlatformObservations(left, right); err == nil {
		t.Fatal("reverse canonical case-alias ancestry was accepted")
	}
}

func TestLinuxMountInfoSourceCoordinatesHandleMixedLookupContexts(t *testing.T) {
	left := modeledLinuxExecutionRoot(true, "/view/Area", "8:1", "/source/Area")
	right := modeledLinuxExecutionRoot(true, "/view/area", "8:1", "/source/area")
	if err := classifyExecutionRootPlatformObservations(left, right); err != nil {
		t.Fatalf("case-sensitive canonical siblings were rejected: %v", err)
	}
	missing := modeledLinuxExecutionRoot(false, "/view", "8:1", "/source")
	missing.missingSuffix = []string{"Area"}
	if err := classifyExecutionRootPlatformObservations(missing, right); err != nil {
		t.Fatalf("proved-absent sibling intent was rejected: %v", err)
	}
}

func TestLinuxExecutionRootsRejectCanonicallyDescendantMountpoint(t *testing.T) {
	records := []linuxMountInfoRecord{
		{mountID: 1, parentID: 1, mountPoint: "/"},
		{mountID: 2, parentID: 1, mountPoint: "/s-view/Area/child"},
	}
	if !linuxHasDescendantMount("/s-view/Area", records) {
		t.Fatal("canonical descendant mountpoint was not detected")
	}
	if linuxHasDescendantMount("/s-view/area", records) {
		t.Fatal("case-sensitive sibling control was treated as ancestry")
	}
}

func TestLinuxMountInfoParserRetainsSourceValidNSFSNamespaceObjectRoots(t *testing.T) {
	payload := []byte(strings.Join([]string{
		"1 1 8:1 / / rw - ext4 /dev/root rw",
		"2 1 8:1 /source/staging /view/staging rw - ext4 /dev/root rw",
		"3 1 8:1 /source/results /view/results rw - ext4 /dev/root rw",
		"4 99 0:4 mnt:[101] /run/ns/mnt rw - nsfs nsfs rw",
		"5 1 0:4 net:[202] /run/ns/net rw - nsfs nsfs rw",
		"6 1 0:4 uts:[303] /run/ns/uts rw - nsfs nsfs rw",
		"7 1 0:4 ipc:[404] /run/ns/ipc rw - nsfs nsfs rw",
		"8 1 0:4 pid:[505] /run/ns/pid rw - nsfs nsfs rw",
		"9 1 0:4 user:[606] /run/ns/user rw - nsfs nsfs rw",
		"10 1 0:4 cgroup:[707] /run/ns/cgroup rw - nsfs nsfs rw",
		"11 1 0:4 time:[808] /run/ns/time rw - nsfs nsfs rw",
	}, "\n") + "\n")
	records, err := parseLinuxMountInfo(payload)
	if err != nil {
		t.Fatalf("source-valid mixed mountinfo rejected: %v", err)
	}
	if len(records) != 11 {
		t.Fatalf("record retention changed: got %d want 11", len(records))
	}
	if records[1].root.kind != linuxMountInfoRootPathname || records[1].root.value != "/source/staging" || records[1].filesystemType != "ext4" {
		t.Fatalf("ordinary path root was not retained and classified: %+v", records[1])
	}
	expectedOpaque := []string{
		"mnt:[101]", "net:[202]", "uts:[303]", "ipc:[404]",
		"pid:[505]", "user:[606]", "cgroup:[707]", "time:[808]",
	}
	for index, expected := range expectedOpaque {
		record := records[index+3]
		if record.root.kind != linuxMountInfoRootNamespaceObject || record.root.value != expected || record.filesystemType != "nsfs" {
			t.Fatalf("opaque record %d was not preserved exactly: %+v", index, record)
		}
	}
	left := modeledLinuxExecutionRoot(true, records[1].mountPoint, "8:1", records[1].root.value)
	right := modeledLinuxExecutionRoot(true, records[2].mountPoint, "8:1", records[2].root.value)
	if err := classifyExecutionRootPlatformObservations(left, right); err != nil {
		t.Fatalf("ordinary disjoint coordinates were poisoned by retained opaque records: %v", err)
	}
}

func TestLinuxMountInfoOpaqueRecordsRemainInDescendantClassification(t *testing.T) {
	t.Run("beneath staging", func(t *testing.T) {
		records, err := parseLinuxMountInfo([]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 1 0:4 mnt:[101] /view/staging/ns rw - nsfs nsfs rw\n"))
		if err != nil || !linuxHasDescendantMount("/view/staging", records) {
			t.Fatalf("opaque staging descendant was not retained: records=%v err=%v", records, err)
		}
	})
	t.Run("beneath results", func(t *testing.T) {
		records, err := parseLinuxMountInfo([]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 1 0:4 net:[202] /view/results/ns rw - nsfs nsfs rw\n"))
		if err != nil || !linuxHasDescendantMount("/view/results", records) {
			t.Fatalf("opaque results descendant was not retained: records=%v err=%v", records, err)
		}
	})
	t.Run("canonical presentation not configured spelling", func(t *testing.T) {
		records, err := parseLinuxMountInfo([]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 1 0:4 pid:[303] /canonical/Area/ns rw - nsfs nsfs rw\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !linuxHasDescendantMount("/canonical/Area", records) {
			t.Fatal("canonical descriptor presentation lost its opaque descendant")
		}
		if linuxHasDescendantMount("/configured/area", records) {
			t.Fatal("configured spelling replaced canonical descriptor presentation")
		}
	})
	t.Run("exact root is not a proper descendant", func(t *testing.T) {
		records, err := parseLinuxMountInfo([]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 1 0:4 user:[404] /view/staging rw - nsfs nsfs rw\n"))
		if err != nil || linuxHasDescendantMount("/view/staging", records) {
			t.Fatalf("exact mountpoint was classified as a proper descendant: records=%v err=%v", records, err)
		}
	})
	t.Run("stacked opaque records stay represented", func(t *testing.T) {
		records, err := parseLinuxMountInfo([]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 1 0:4 cgroup:[505] /view/staging/ns rw - nsfs nsfs rw\n3 1 0:4 time:[606] /view/staging/ns rw - nsfs nsfs rw\n"))
		if err != nil || len(records) != 3 || !linuxHasDescendantMount("/view/staging", records) {
			t.Fatalf("stacked opaque records were not retained: records=%v err=%v", records, err)
		}
	})
}

func TestLinuxMountInfoSelectedOpaqueRootRefusesCoordinateProofBeforeDeviceMismatch(t *testing.T) {
	root := physicalTestTempDir(t)
	plan, err := planExecutionRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	var held unix.Stat_t
	if err := unix.Fstat(plan.existingFD, &held); err != nil {
		t.Fatal(err)
	}
	var identity unix.Statx_t
	requiredMask := uint32(unix.STATX_BASIC_STATS | unix.STATX_MNT_ID)
	if err := unix.Statx(plan.existingFD, "", unix.AT_EMPTY_PATH, int(requiredMask), &identity); err != nil {
		t.Fatal(err)
	}
	base := linuxMountInfoRecord{
		mountID:        identity.Mnt_id,
		parentID:       identity.Mnt_id,
		major:          unix.Major(uint64(held.Dev)),
		minor:          unix.Minor(uint64(held.Dev)),
		root:           linuxMountInfoRoot{kind: linuxMountInfoRootNamespaceObject, value: "mnt:[909]"},
		mountPoint:     "/",
		filesystemType: "nsfs",
	}
	for _, record := range []linuxMountInfoRecord{base, func() linuxMountInfoRecord {
		mismatched := base
		mismatched.major++
		return mismatched
	}()} {
		err := observeLinuxExecutionRoot(plan, []linuxMountInfoRecord{record})
		if err == nil || !strings.Contains(err.Error(), "selected mountinfo root is not path-coordinate eligible") {
			t.Fatalf("selected opaque root did not win before device/coordinate handling: %v", err)
		}
		if plan.platform.sourcePath != "" {
			t.Fatalf("opaque root manufactured a source path: %+v", plan.platform)
		}
	}
}

func TestLinuxMountInfoParserRejectsMalformedOpaqueAndGraphRecords(t *testing.T) {
	validTop := "1 1 8:1 / / rw - ext4 /dev/root rw\n"
	malformedRoots := map[string]string{
		"empty inode label":          "mnt:[]",
		"non-decimal inode label":    "mnt:[abc]",
		"noncanonical leading zero":  "mnt:[01]",
		"unterminated label":         "mnt:[1",
		"missing opening bracket":    "mnt:1]",
		"trailing label data":        "mnt:[1]/tail",
		"unsupported namespace kind": "mount:[1]",
		"pid child-view alias":       "pid_for_children:[1]",
		"time child-view alias":      "time_for_children:[1]",
		"pathname root for nsfs":     "/",
	}
	for name, root := range malformedRoots {
		t.Run(name, func(t *testing.T) {
			payload := []byte(validTop + "2 1 0:4 " + root + " /run/ns/object rw - nsfs nsfs rw\n")
			if _, err := parseLinuxMountInfo(payload); err == nil {
				t.Fatalf("malformed nsfs root was accepted: %q", root)
			}
		})
	}
	t.Run("non-nsfs non-path root", func(t *testing.T) {
		if _, err := parseLinuxMountInfo([]byte(validTop + "2 1 8:1 mnt:[1] /other rw - ext4 /dev/root rw\n")); err == nil {
			t.Fatal("non-path root from a non-nsfs record was accepted")
		}
	})
	t.Run("invalid opaque mountpoint", func(t *testing.T) {
		if _, err := parseLinuxMountInfo([]byte(validTop + "2 1 0:4 mnt:[1] relative rw - nsfs nsfs rw\n")); err == nil {
			t.Fatal("opaque record with invalid mountpoint was accepted")
		}
	})
	t.Run("duplicate ID with opaque record", func(t *testing.T) {
		payload := []byte(validTop + "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n2 1 8:1 / /other rw - ext4 /dev/root rw\n")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("duplicate ID escaped through an opaque record")
		}
	})
	t.Run("non-top opaque self-parent", func(t *testing.T) {
		if _, err := parseLinuxMountInfo([]byte(validTop + "2 2 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n")); err == nil {
			t.Fatal("opaque non-top self-parent was accepted")
		}
	})
	t.Run("cycle through opaque record", func(t *testing.T) {
		payload := []byte(validTop + "2 3 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n3 2 8:1 / /other rw - ext4 /dev/root rw\n")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("cycle through opaque record was accepted")
		}
	})
	t.Run("malformed path escape beside opaque record", func(t *testing.T) {
		payload := []byte(validTop + "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n3 1 8:1 /bad\\999 /other rw - ext4 /dev/root rw\n")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("malformed path escape was reclassified as opaque")
		}
	})
	t.Run("malformed separator beside opaque record", func(t *testing.T) {
		payload := []byte(validTop + "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n3 1 8:1 / /other rw ext4 /dev/root rw\n")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("malformed separator escaped through an opaque neighbor")
		}
	})
	t.Run("truncation after opaque record", func(t *testing.T) {
		payload := []byte(validTop + "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("truncated snapshot with an opaque record was accepted")
		}
	})
	t.Run("record limit includes opaque records", func(t *testing.T) {
		line := "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n"
		if _, err := parseLinuxMountInfo([]byte(validTop + strings.Repeat(line, linuxMountInfoRecordLimit))); err == nil {
			t.Fatal("opaque records escaped the record limit")
		}
	})
	t.Run("byte limit includes opaque records", func(t *testing.T) {
		prefix := validTop + "2 1 0:4 mnt:[1] /run/ns/mnt rw - nsfs nsfs rw\n"
		payload := []byte(prefix + strings.Repeat("x", linuxMountInfoByteLimit-len(prefix)+1) + "\n")
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatal("opaque records escaped the byte limit")
		}
	})
}

func TestLinuxMountInfoParserAllowsParentOutsideVisibleRoot(t *testing.T) {
	payload := []byte("7 99 8:1 / / rw - ext4 /dev/root rw\n")
	records, err := parseLinuxMountInfo(payload)
	if err != nil || len(records) != 1 {
		t.Fatalf("external parent was rejected: records=%v err=%v", records, err)
	}
	top := []byte("1 1 8:1 / / rw - ext4 /dev/root rw\n")
	if _, err := parseLinuxMountInfo(top); err != nil {
		t.Fatalf("unique top self-parent was rejected: %v", err)
	}
	for _, malformed := range [][]byte{
		[]byte("2 2 8:1 / /not-top rw - ext4 /dev/root rw\n"),
		[]byte("1 1 8:1 / / rw - ext4 /dev/root rw\n2 2 8:1 / / rw - ext4 /dev/root rw\n"),
		[]byte("2 3 8:1 / /a rw - ext4 /dev/root rw\n3 2 8:1 / /b rw - ext4 /dev/root rw\n"),
	} {
		if _, err := parseLinuxMountInfo(malformed); err == nil {
			t.Fatalf("malformed parent graph accepted: %q", malformed)
		}
	}
}

func TestLinuxMountInfoParserIgnoresUnknownOptionalFields(t *testing.T) {
	payload := []byte("7 99 8:1 / / rw shared:1 future:value - ext4 /dev/root rw\n")
	if _, err := parseLinuxMountInfo(payload); err != nil {
		t.Fatalf("bounded unknown optional fields were rejected: %v", err)
	}
}

func TestLinuxMountInfoParserRejectsDuplicateIDsMalformedEscapesAndTruncation(t *testing.T) {
	testCases := [][]byte{
		[]byte("7 99 8:1 / / rw - ext4 /dev/root rw\n7 99 8:1 / /other rw - ext4 /dev/root rw\n"),
		[]byte("7 99 8:1 /bad\\999 / rw - ext4 /dev/root rw\n"),
		[]byte("7 99 8:1 / / rw - ext4 /dev/root rw"),
		[]byte("7 99 8:1 / / rw ext4 /dev/root rw\n"),
		[]byte("7 99 8:1 / / rw - ext4 /dev/root rw extra\n"),
		[]byte("7 99 8:1 /bad\x00 / rw - ext4 /dev/root rw\n"),
		[]byte("7\t99 8:1 / / rw - ext4 /dev/root rw\n"),
	}
	for _, payload := range testCases {
		if _, err := parseLinuxMountInfo(payload); err == nil {
			t.Fatalf("malformed mountinfo accepted: %q", payload)
		}
	}
	oversized := append(bytesOf('x', linuxMountInfoByteLimit), '\n')
	if _, err := parseLinuxMountInfo(oversized); err == nil {
		t.Fatal("oversized mountinfo was accepted")
	}
}

func TestLinuxMountInfoClassifierHandlesStackedRecordsByDescriptorMountID(t *testing.T) {
	payload := []byte("7 99 8:1 /old /stack rw - ext4 /dev/root rw\n8 99 8:1 /active /stack rw - ext4 /dev/root rw\n")
	records, err := parseLinuxMountInfo(payload)
	if err != nil || len(records) != 2 || records[0].mountPoint != records[1].mountPoint || records[0].mountID == records[1].mountID {
		t.Fatalf("stacked records were not retained for mount-ID selection: records=%v err=%v", records, err)
	}
}

func TestLinuxExecutionRootsRejectInvalidStatxMaskAndDeviceDisagreement(t *testing.T) {
	held := unix.Stat_t{Ino: 12, Mode: unix.S_IFDIR, Dev: 1}
	base := unix.Statx_t{
		Mask:      uint32(unix.STATX_BASIC_STATS | unix.STATX_MNT_ID),
		Ino:       12,
		Mode:      unix.S_IFDIR,
		Dev_major: 8,
		Dev_minor: 1,
	}
	missingMask := base
	missingMask.Mask &^= unix.STATX_MNT_ID
	if err := validateLinuxStatxIdentity(held, missingMask, 8, 1); err == nil {
		t.Fatal("partial statx mask was accepted")
	}
	wrongDevice := base
	wrongDevice.Dev_minor = 2
	if err := validateLinuxStatxIdentity(held, wrongDevice, 8, 1); err == nil {
		t.Fatal("statx device disagreement was accepted")
	}
}

func modeledLinuxExecutionRoot(observed bool, presentation string, device string, source string) *executionRootPlan {
	plan := &executionRootPlan{platform: executionRootPlatformObservation{presentation: presentation, sourceDevice: device, sourcePath: source}}
	if !observed {
		plan.missingSuffix = []string{"missing"}
	}
	return plan
}

func bytesOf(value byte, count int) []byte {
	return []byte(strings.Repeat(string([]byte{value}), count))
}
