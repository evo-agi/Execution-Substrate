package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidateRuntimeMountsRejectsOverlappingTargets(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := validateRuntimeMounts([]RuntimeMount{
		{
			Source:     MountSource{ArtifactDigest: digest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
		{
			Source:     MountSource{ArtifactDigest: digest},
			TargetPath: "/execution/mounts/config/env",
			ReadOnly:   true,
		},
	})
	if err == nil {
		t.Fatalf("expected overlapping runtime mounts to be rejected")
	}
	if err.Status != http.StatusConflict || err.Code != codeMountConflict {
		t.Fatal("expected mount conflict error")
	}
}

func TestRuntimeMountArchiveValidatesThenMaterializesWithinLimits(t *testing.T) {
	root := physicalTestTempDir(t)
	archiveBytes := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "config", typeflag: tar.TypeDir, mode: 0o755},
		runtimeMountArchiveEntry{name: "config/settings.env", body: []byte("KEY=value\n"), typeflag: tar.TypeReg, mode: 0o644},
	)

	validated, extractedBytes, err := validateRuntimeMountArchive(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
	if err != nil {
		t.Fatal("validate runtime mount archive failed")
	}
	if extractedBytes != int64(len("KEY=value\n")) {
		t.Fatalf("expected extracted byte count %d, got %d", len("KEY=value\n"), extractedBytes)
	}
	if len(validated.entries) != 2 || validated.entries[0].name != "config" || validated.entries[1].name != "config/settings.env" {
		t.Fatal("validated mount representation did not preserve archive entry order")
	}
	layout := executionPackageLayout{mountsStageRootDir: filepath.Join(root, "mounts")}
	if _, err := os.Stat(layout.mountsStageRootDir); !os.IsNotExist(err) {
		t.Fatal("archive validation created a staging root")
	}
	custody, claimedLayout := claimTestStagingCustody(t, root, "run-0123456789abcdef")
	layout = claimedLayout
	staged, materializeErr := materializeValidatedRuntimeMounts(
		custody,
		layout,
		[]resolvedMountPlan{{targetPath: "/execution/mounts/config", readOnly: true}},
		[]validatedMountArchive{validated},
	)
	if materializeErr != nil {
		t.Fatal("materialize validated runtime mount failed")
	}
	if len(staged) != 1 {
		t.Fatalf("expected one staged mount, got %d", len(staged))
	}

	content, err := os.ReadFile(filepath.Join(staged[0].sourceDir, "config", "settings.env"))
	if err != nil {
		t.Fatal("read extracted file failed")
	}
	if string(content) != "KEY=value\n" {
		t.Fatal("expected extracted file contents to round-trip")
	}
	assertStagedExactMode(t, filepath.Join(staged[0].sourceDir, "config", "settings.env"), governedMountFileMode, false)
}

func TestRuntimeMountMaterializationUsesWorkloadReadableModesOnlyWithinClaimedRoot(t *testing.T) {
	root := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, root, "run-0123456789abcdef")
	if err := custody.writeFile("payload/private.txt", []byte("private"), stableStageFileMode); err != nil {
		t.Fatalf("stage private payload: %v", err)
	}
	if err := custody.writeFile("run/platform/es-runtime-support", []byte("executable"), stableStageExecFileMode); err != nil {
		t.Fatalf("stage private runtime support: %v", err)
	}
	archiveBytes := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "config", typeflag: tar.TypeDir, mode: 0o1750},
		runtimeMountArchiveEntry{name: "config/app.conf", typeflag: tar.TypeReg, mode: 0o2600, body: []byte("MOUNT-CONTENT\n")},
		runtimeMountArchiveEntry{name: "config/nested/tool", typeflag: tar.TypeReg, mode: 0o6751, body: []byte("#!/bin/sh\nexit 0\n")},
	)
	archive, _, err := validateRuntimeMountArchive(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
	if err != nil {
		t.Fatalf("validate mount archive: %v", err)
	}
	staged, materializeErr := materializeValidatedRuntimeMounts(custody, layout,
		[]resolvedMountPlan{{targetPath: "/execution/mounts/config", readOnly: true}},
		[]validatedMountArchive{archive})
	if materializeErr != nil {
		t.Fatalf("materialize mount: %v", materializeErr)
	}
	if len(staged) != 1 || !staged[0].readOnly || staged[0].targetPath != "/execution/mounts/config" {
		t.Fatalf("staged mount lost read-only target policy: %#v", staged)
	}
	paths := []struct {
		path      string
		mode      os.FileMode
		directory bool
	}{
		{layout.stageRootDir, stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "payload"), stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "payload/private.txt"), stableStageFileMode, false},
		{filepath.Join(layout.stageRootDir, "run"), stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "run/platform"), stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "run/platform/es-runtime-support"), stableStageExecFileMode, false},
		{layout.mountsStageRootDir, governedMountDirMode, true},
		{filepath.Join(layout.mountsStageRootDir, "00"), governedMountDirMode, true},
		{staged[0].sourceDir, governedMountDirMode, true},
		{filepath.Join(staged[0].sourceDir, "config"), governedMountDirMode, true},
		{filepath.Join(staged[0].sourceDir, "config/nested"), governedMountDirMode, true},
		{filepath.Join(staged[0].sourceDir, "config/app.conf"), governedMountFileMode, false},
		{filepath.Join(staged[0].sourceDir, "config/nested/tool"), governedMountExecFileMode, false},
	}
	for _, check := range paths {
		info := assertStagedExactMode(t, check.path, check.mode, check.directory)
		uid, gid, err := ownershipIDsFromInfo(info)
		if err != nil || uid != os.Getuid() || gid != os.Getgid() {
			t.Errorf("%s owner = %d:%d, error %v; want %d:%d", check.path, uid, gid, err, os.Getuid(), os.Getgid())
		}
	}
	for path, want := range map[string]string{
		filepath.Join(staged[0].sourceDir, "config/app.conf"):    "MOUNT-CONTENT\n",
		filepath.Join(staged[0].sourceDir, "config/nested/tool"): "#!/bin/sh\nexit 0\n",
	} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) != want {
			t.Errorf("%s content = %q, error %v; want %q", path, content, err, want)
		}
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("complete-tree custody revalidation: %v", err)
	}
}

func TestResolvedPlanCustodyRepairMountNamesPreserveValidatedComponents(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "implicit directory"
		if explicit {
			name = "explicit directory"
		}
		t.Run(name, func(t *testing.T) {
			entries := []runtimeMountArchiveEntry{}
			if explicit {
				entries = append(entries, runtimeMountArchiveEntry{name: "dir /", typeflag: tar.TypeDir, mode: 0o755})
			}
			entries = append(entries,
				runtimeMountArchiveEntry{name: "dir /a", body: []byte("space"), typeflag: tar.TypeReg, mode: 0o644},
				runtimeMountArchiveEntry{name: "dir/a", body: []byte("plain"), typeflag: tar.TypeReg, mode: 0o644},
			)
			validated, _, err := validateRuntimeMountArchive(mustRuntimeMountArchiveBytes(t, entries...), maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
			if err != nil {
				t.Fatalf("validate distinct archive names: %v", err)
			}
			if got := validated.entries[len(validated.entries)-2].name; got != "dir /a" {
				t.Fatalf("validated name = %q", got)
			}
			root := physicalTestTempDir(t)
			custody, layout := claimTestStagingCustody(t, root, "run-0123456789abcdef")
			staged, materializeErr := materializeValidatedRuntimeMounts(custody, layout,
				[]resolvedMountPlan{{targetPath: "/execution/mounts/config", readOnly: true}},
				[]validatedMountArchive{validated})
			if materializeErr != nil {
				t.Fatalf("materialize validated names: %v", materializeErr)
			}
			if len(staged) != 1 {
				t.Fatalf("staged mounts = %d", len(staged))
			}
			assertFileContent(t, filepath.Join(staged[0].sourceDir, "dir ", "a"), "space")
			assertFileContent(t, filepath.Join(staged[0].sourceDir, "dir", "a"), "plain")
			if err := custody.revalidateBeforeHandoff(); err != nil {
				t.Fatalf("revalidate exact materialized tree: %v", err)
			}
		})
	}
}

func TestRuntimeMountArchiveRejectsPathTraversalAndSymlinksBeforeMaterialization(t *testing.T) {
	testCases := []struct {
		name        string
		archive     []byte
		errorSubstr string
	}{
		{
			name: "path traversal",
			archive: mustRuntimeMountArchiveBytes(t,
				runtimeMountArchiveEntry{name: "../escape", body: []byte("oops"), typeflag: tar.TypeReg, mode: 0o644},
			),
			errorSubstr: "path traversal",
		},
		{
			name: "symlink entry",
			archive: mustRuntimeMountArchiveBytes(t,
				runtimeMountArchiveEntry{name: "config-link", typeflag: tar.TypeSymlink, linkname: "config/settings.env", mode: 0o777},
			),
			errorSubstr: "symbolic or hard links",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := validateRuntimeMountArchive(tc.archive, maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
			if err == nil {
				t.Fatalf("expected archive extraction to fail for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errorSubstr) {
				t.Fatal("archive refusal did not preserve the expected fixed failure class")
			}
		})
	}
}

func TestRuntimeMountArchiveMaterializerDoesNotReparseCompressedBytes(t *testing.T) {
	validated, _, err := validateRuntimeMountArchive(mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "settings.env", body: []byte("KEY=value\n"), typeflag: tar.TypeReg, mode: 0o644},
	), maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
	if err != nil {
		t.Fatal("validate runtime mount archive failed")
	}
	validated.compressedBytes = []byte("captured-compressed-bytes-are-not-reparsed")
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	staged, materializeErr := materializeValidatedRuntimeMounts(
		custody,
		layout,
		[]resolvedMountPlan{{targetPath: "/execution/mounts/config", readOnly: true}},
		[]validatedMountArchive{validated},
	)
	if materializeErr != nil {
		t.Fatal("materialize prevalidated mount entries failed")
	}
	content, readErr := os.ReadFile(filepath.Join(staged[0].sourceDir, "settings.env"))
	if readErr != nil || string(content) != "KEY=value\n" {
		t.Fatal("materializer did not use captured parsed entries")
	}
}

func TestRuntimeMountArchiveRejectsDeclaredSizeBeforeContentAllocation(t *testing.T) {
	archive := mustRuntimeMountArchiveWithDeclaredSize(t, maxRuntimeMountBytes+1)
	_, _, err := validateRuntimeMountArchive(archive, maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
	if err == nil || err.Error() != "mount payload exceeds the per-mount size limit" {
		t.Fatal("declared mount size was not refused by the remaining budget before content copy")
	}
}

func TestRuntimeMountArchiveAggregateBodyEqualityAllowsOnlyZeroBodyEntries(t *testing.T) {
	zeroBodyArchive := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "directory", typeflag: tar.TypeDir, mode: 0o700},
		runtimeMountArchiveEntry{name: "directory/empty", typeflag: tar.TypeReg, mode: 0o600},
	)
	archive, extracted, _, err := validateRuntimeMountArchiveWithinBudgets(
		zeroBodyArchive,
		maxRuntimeMountBytes,
		0,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		nil,
	)
	if err != nil || extracted != 0 || len(archive.entries) != 2 {
		t.Fatal("zero-body archive did not remain valid at aggregate equality")
	}

	positiveBodyArchive := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "positive", body: []byte("x"), typeflag: tar.TypeReg, mode: 0o600},
	)
	if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(
		positiveBodyArchive,
		maxRuntimeMountBytes,
		0,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		nil,
	); err == nil || err.Error() != "mount payloads exceed the total size limit" {
		t.Fatal("positive body was not rejected before allocation at aggregate equality")
	}
}

func TestRuntimeMountArchiveRejectsFileAfterImplicitParentDirectoryBeforeFreeze(t *testing.T) {
	archive := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "config/settings.env", body: []byte("KEY=value\n"), typeflag: tar.TypeReg, mode: 0o644},
		runtimeMountArchiveEntry{name: "config", body: []byte("not-a-directory"), typeflag: tar.TypeReg, mode: 0o644},
	)
	if _, _, err := validateRuntimeMountArchive(archive, maxRuntimeMountBytes, maxRuntimeMountTotalBytes); err == nil || err.Error() != "mount payload file creation failed" {
		t.Fatal("archive namespace collision was not rejected during pre-freeze validation")
	}
}

func TestRuntimeMountArchiveWholeStreamBudgetCountsPAXGNUAndTrailingBytesAtEqualityAndPlusOne(t *testing.T) {
	formats := []struct {
		name   string
		format tar.Format
	}{
		{name: "pax", format: tar.FormatPAX},
		{name: "gnu", format: tar.FormatGNU},
	}
	for _, format := range formats {
		t.Run(format.name, func(t *testing.T) {
			longName := strings.Repeat("segment/", 650) + "material.txt"
			archiveBytes := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, format.format, longName, []byte("body"), []byte("governed-trailing-bytes"))
			streamBytes := decompressedRuntimeMountArchiveBytes(t, archiveBytes)

			archive, extracted, consumed, err := validateRuntimeMountArchiveWithinBudgets(
				archiveBytes,
				maxRuntimeMountBytes,
				maxRuntimeMountTotalBytes,
				int64(len(streamBytes)),
				maxRuntimeMountTotalStreamBytes,
				nil,
			)
			if err != nil {
				t.Fatalf("exact whole-stream budget failed: %v", err)
			}
			if extracted != int64(len("body")) || consumed != int64(len(streamBytes)) || len(archive.entries) != 1 || archive.entries[0].name != longName {
				t.Fatal("whole-stream accounting did not preserve the governed archive")
			}
			if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(
				archiveBytes,
				maxRuntimeMountBytes,
				maxRuntimeMountTotalBytes,
				int64(len(streamBytes))-1,
				maxRuntimeMountTotalStreamBytes,
				nil,
			); err == nil || err.Error() != "mount payload exceeds the per-mount decompressed-stream size limit" {
				t.Fatalf("expected exact plus-one stream refusal, got %v", err)
			}
			if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(
				archiveBytes,
				maxRuntimeMountBytes,
				maxRuntimeMountTotalBytes,
				int64(len(streamBytes))+1,
				int64(len(streamBytes))-1,
				nil,
			); err == nil || err.Error() != "mount payload streams exceed the total decompressed-stream size limit" {
				t.Fatalf("expected aggregate stream plus-one refusal, got %v", err)
			}
		})
	}
}

func TestRuntimeMountArchiveHasNoCandidateOnlyEntryCountLimit(t *testing.T) {
	const entryCount = 4097
	entries := make([]runtimeMountArchiveEntry, 0, entryCount)
	for index := 0; index < entryCount; index++ {
		entries = append(entries, runtimeMountArchiveEntry{
			name:     fmt.Sprintf("entry-%04d", index),
			typeflag: tar.TypeReg,
			mode:     0o600,
		})
	}
	archive, _, err := validateRuntimeMountArchive(mustRuntimeMountArchiveBytes(t, entries...), maxRuntimeMountBytes, maxRuntimeMountTotalBytes)
	if err != nil {
		t.Fatalf("whole-stream-governed archive was rejected by a candidate-only entry limit: %v", err)
	}
	if len(archive.entries) != entryCount {
		t.Fatalf("expected %d entries, got %d", entryCount, len(archive.entries))
	}
}

func TestRuntimeMountArchiveCompressedRadixPreservesNamespaceSemantics(t *testing.T) {
	testCases := []struct {
		name      string
		entries   []runtimeMountArchiveEntry
		wantError string
	}{
		{
			name: "repeated explicit directory and normalized alias",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeDir, mode: 0o700},
				{name: "./a/", typeflag: tar.TypeDir, mode: 0o700},
			},
		},
		{
			name: "descendant then explicit implicit parent directory",
			entries: []runtimeMountArchiveEntry{
				{name: "a/b", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeDir, mode: 0o700},
			},
		},
		{
			name: "explicit directory then descendant",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeDir, mode: 0o700},
				{name: "a/b", typeflag: tar.TypeReg, mode: 0o600},
			},
		},
		{
			name: "duplicate regular file",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
				{name: "./a", typeflag: tar.TypeReg, mode: 0o600},
			},
			wantError: "mount payload file creation failed",
		},
		{
			name: "directory then same path file",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeDir, mode: 0o700},
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
			},
			wantError: "mount payload file creation failed",
		},
		{
			name: "file then same path directory",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeDir, mode: 0o700},
			},
			wantError: "mount payload directory creation failed",
		},
		{
			name: "descendant then file at ancestor",
			entries: []runtimeMountArchiveEntry{
				{name: "a/b", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
			},
			wantError: "mount payload file creation failed",
		},
		{
			name: "file ancestor wins before descendant type refusal",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a/b", typeflag: tar.TypeSymlink, linkname: "target", mode: 0o777},
			},
			wantError: "mount payload directory creation failed",
		},
		{
			name: "slash boundary a and ab",
			entries: []runtimeMountArchiveEntry{
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
				{name: "ab", typeflag: tar.TypeReg, mode: 0o600},
			},
		},
		{
			name: "reverse slash boundary ab then a",
			entries: []runtimeMountArchiveEntry{
				{name: "ab", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
			},
		},
		{
			name: "branch split does not invent descendant",
			entries: []runtimeMountArchiveEntry{
				{name: "ab", typeflag: tar.TypeReg, mode: 0o600},
				{name: "ac", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
			},
		},
		{
			name: "slash branch is descendant",
			entries: []runtimeMountArchiveEntry{
				{name: "a/b", typeflag: tar.TypeReg, mode: 0o600},
				{name: "a", typeflag: tar.TypeReg, mode: 0o600},
			},
			wantError: "mount payload file creation failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			archiveBytes := mustRuntimeMountArchiveBytes(t, testCase.entries...)
			work := &mountArchiveRadixWork{}
			archive, _, _, err := validateRuntimeMountArchiveWithinBudgets(
				archiveBytes,
				maxRuntimeMountBytes,
				maxRuntimeMountTotalBytes,
				maxRuntimeMountStreamBytes,
				maxRuntimeMountTotalStreamBytes,
				work,
			)
			if testCase.wantError != "" {
				if err == nil || err.Error() != testCase.wantError {
					t.Fatalf("expected %q, got %v", testCase.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("archive rejected: %v", err)
			}
			if len(archive.entries) != len(testCase.entries) || work.ProbeCount != uint64(len(testCase.entries)) || work.CommitCount != uint64(len(testCase.entries)) {
				t.Fatalf("returned headers did not reach production probe and commit sites: entries=%d probes=%d commits=%d", len(archive.entries), work.ProbeCount, work.CommitCount)
			}
		})
	}
}

func TestRuntimeMountArchiveCompressedRadixMaximumFlatWorkIsLinear(t *testing.T) {
	const entryCount = 32768
	exactStream := mustRuntimeMountFlatTarStream(t, entryCount, false)
	if len(exactStream) != int(maxRuntimeMountStreamBytes) {
		t.Fatalf("EOF fixture is %d bytes, want %d", len(exactStream), maxRuntimeMountStreamBytes)
	}
	work := &mountArchiveRadixWork{}
	archive, extracted, consumed, err := validateRuntimeMountArchiveWithinBudgets(
		gzipRuntimeMountBytes(t, exactStream),
		maxRuntimeMountBytes,
		maxRuntimeMountTotalBytes,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		work,
	)
	if err != nil {
		t.Fatalf("exact EOF boundary rejected: %v", err)
	}
	if len(archive.entries) != entryCount || extracted != 0 || consumed != maxRuntimeMountStreamBytes || work.ProbeCount != entryCount || work.CommitCount != entryCount {
		t.Fatalf("exact boundary did not reach every production ledger site: entries=%d extracted=%d consumed=%d probes=%d commits=%d", len(archive.entries), extracted, consumed, work.ProbeCount, work.CommitCount)
	}
	normalizedNameBytes := uint64(entryCount * len("f00000"))
	if work.ByteComparisons > normalizedNameBytes || work.ChildLookups > normalizedNameBytes || work.RetainedLabelBytes > normalizedNameBytes || work.NodeAllocations > 2*entryCount {
		t.Fatalf("flat radix work exceeded structural bounds: %+v name_bytes=%d", *work, normalizedNameBytes)
	}

	footerStream := mustRuntimeMountFlatTarStream(t, entryCount-2, true)
	if len(footerStream) != int(maxRuntimeMountStreamBytes) {
		t.Fatalf("canonical-footer fixture is %d bytes, want %d", len(footerStream), maxRuntimeMountStreamBytes)
	}
	footerWork := &mountArchiveRadixWork{}
	footerArchive, _, _, err := validateRuntimeMountArchiveWithinBudgets(
		gzipRuntimeMountBytes(t, footerStream),
		maxRuntimeMountBytes,
		maxRuntimeMountTotalBytes,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		footerWork,
	)
	if err != nil || len(footerArchive.entries) != entryCount-2 || footerWork.ProbeCount != entryCount-2 || footerWork.CommitCount != entryCount-2 {
		t.Fatalf("canonical-footer boundary did not reach every entry: err=%v entries=%d work=%+v", err, len(footerArchive.entries), *footerWork)
	}

	plusOneWork := &mountArchiveRadixWork{}
	plusOne := append(append([]byte(nil), exactStream...), 1)
	if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(
		gzipRuntimeMountBytes(t, plusOne),
		maxRuntimeMountBytes,
		maxRuntimeMountTotalBytes,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		plusOneWork,
	); err == nil || err.Error() != "mount payload exceeds the per-mount decompressed-stream size limit" {
		t.Fatalf("expected plus-one stream refusal, got %v", err)
	}
	if plusOneWork.ProbeCount != entryCount || plusOneWork.CommitCount != entryCount {
		t.Fatalf("plus-one refusal occurred before every header reached the ledger: %+v", *plusOneWork)
	}
}

func TestRuntimeMountArchiveCompressedRadixDeepPAXGNUUsesEntryBoundedState(t *testing.T) {
	deepName := strings.Repeat("d/", 500000) + "z"
	if len(deepName) != 1000001 {
		t.Fatalf("deep fixture length is %d", len(deepName))
	}
	for _, format := range []struct {
		name   string
		format tar.Format
	}{
		{name: "pax", format: tar.FormatPAX},
		{name: "gnu", format: tar.FormatGNU},
	} {
		t.Run(format.name, func(t *testing.T) {
			archiveBytes := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, format.format, deepName, nil, nil)
			work := &mountArchiveRadixWork{}
			archive, _, _, err := validateRuntimeMountArchiveWithinBudgets(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, work)
			if err != nil {
				t.Fatalf("reachable deep archive rejected: %v", err)
			}
			if len(archive.entries) != 1 || archive.entries[0].name != deepName || work.ProbeCount != 1 || work.CommitCount != 1 || work.NodeAllocations != 1 || work.MapAllocations != 1 || work.BranchSplits != 0 || work.RetainedLabelBytes != uint64(len(deepName)) {
				t.Fatalf("deep archive did not use entry-bounded radix state: %+v", *work)
			}
		})
	}

	t.Run("pax exact dependency limit and plus one refusal", func(t *testing.T) {
		exactName := strings.Repeat("p", 1048562)
		archiveBytes := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, tar.FormatPAX, exactName, nil, nil)
		if got := runtimeMountFirstTarEntrySize(t, decompressedRuntimeMountArchiveBytes(t, archiveBytes)); got != 1048576 {
			t.Fatalf("PAX special record size is %d", got)
		}
		work := &mountArchiveRadixWork{}
		if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, work); err != nil {
			t.Fatalf("exact PAX dependency boundary rejected: %v", err)
		}
		if work.ProbeCount != 1 || work.CommitCount != 1 {
			t.Fatalf("exact PAX boundary did not reach the ledger: %+v", *work)
		}
		if _, err := runtimeMountArchiveWithFormat(tar.FormatPAX, strings.Repeat("p", 1048563)); !errors.Is(err, tar.ErrFieldTooLong) {
			t.Fatalf("PAX writer did not refuse the first oversized record: %v", err)
		}
		readerWork := &mountArchiveRadixWork{}
		manual := append(runtimeMountRawSpecialHeader("PaxHeaders.0/plus-one", tar.TypeXHeader, 1048577), bytes.Repeat([]byte{'x'}, 1048577)...)
		if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(gzipRuntimeMountBytes(t, manual), maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, readerWork); err == nil || err.Error() != "mount payload archive could not be read" {
			t.Fatalf("oversized PAX reader record was not refused: %v", err)
		}
		if readerWork.ProbeCount != 0 || readerWork.CommitCount != 0 {
			t.Fatalf("PAX dependency refusal reached the ES ledger: %+v", *readerWork)
		}
	})

	t.Run("gnu exact dependency limit and plus one refusal", func(t *testing.T) {
		exactName := strings.Repeat("g", 1048575)
		archiveBytes := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, tar.FormatGNU, exactName, nil, nil)
		if got := runtimeMountFirstTarEntrySize(t, decompressedRuntimeMountArchiveBytes(t, archiveBytes)); got != 1048576 {
			t.Fatalf("GNU long-name body size is %d", got)
		}
		work := &mountArchiveRadixWork{}
		if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, work); err != nil {
			t.Fatalf("exact GNU dependency boundary rejected: %v", err)
		}
		if work.ProbeCount != 1 || work.CommitCount != 1 {
			t.Fatalf("exact GNU boundary did not reach the ledger: %+v", *work)
		}
		plusOne := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, tar.FormatGNU, exactName+"g", nil, nil)
		readerWork := &mountArchiveRadixWork{}
		if _, _, _, err := validateRuntimeMountArchiveWithinBudgets(plusOne, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, readerWork); err == nil || err.Error() != "mount payload archive could not be read" {
			t.Fatalf("oversized GNU reader record was not refused: %v", err)
		}
		if readerWork.ProbeCount != 0 || readerWork.CommitCount != 0 {
			t.Fatalf("GNU dependency refusal reached the ES ledger: %+v", *readerWork)
		}
	})
}

func TestRuntimeMountArchiveCompressedRadixSharedPrefixWorkIsLinear(t *testing.T) {
	prefix := strings.Repeat("q/", 250000) + "root"
	names := []string{prefix + "/left", prefix + "/right"}
	if len(prefix) != 500004 || len(names[0]) != 500009 || len(names[1]) != 500010 {
		t.Fatal("shared-prefix fixture has the wrong shape")
	}
	for _, format := range []struct {
		name   string
		format tar.Format
	}{
		{name: "pax", format: tar.FormatPAX},
		{name: "gnu", format: tar.FormatGNU},
	} {
		t.Run(format.name, func(t *testing.T) {
			archiveBytes := mustRuntimeMountArchiveNamesWithFormat(t, format.format, names)
			work := &mountArchiveRadixWork{}
			archive, _, _, err := validateRuntimeMountArchiveWithinBudgets(archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes, work)
			if err != nil {
				t.Fatalf("reachable shared-prefix archive rejected: %v", err)
			}
			nameBytes := uint64(len(names[0]) + len(names[1]))
			if len(archive.entries) != 2 || work.ProbeCount != 2 || work.CommitCount != 2 || work.BranchSplits != 1 || work.NodeAllocations != 3 || work.ByteComparisons > nameBytes || work.ChildLookups > nameBytes || work.RetainedLabelBytes > nameBytes {
				t.Fatalf("shared-prefix archive exceeded compressed-radix bounds: %+v", *work)
			}
		})
	}
}

func TestRuntimeMountArchiveRejectsDirectoryBody(t *testing.T) {
	body := []byte("directory-body")
	archive := mustRuntimeMountDirectoryBodyArchive(t, body)
	if _, _, err := validateRuntimeMountArchive(archive, maxRuntimeMountBytes, maxRuntimeMountTotalBytes); err == nil || err.Error() != "mount payload archive could not be read" {
		t.Fatalf("expected directory body refusal, got %v", err)
	}
}

func mustRuntimeMountDirectoryBodyArchive(t *testing.T, body []byte) []byte {
	t.Helper()
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	if err := writer.WriteHeader(&tar.Header{Name: "directory", Typeflag: tar.TypeReg, Mode: 0o700, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := stream.Bytes()
	raw[156] = tar.TypeDir
	for index := 148; index < 156; index++ {
		raw[index] = ' '
	}
	checksum := 0
	for _, value := range raw[:512] {
		checksum += int(value)
	}
	copy(raw[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
	return gzipRuntimeMountBytes(t, raw)
}

func TestRuntimeMountArchiveRejectsTruncatedPAXExtensionRecord(t *testing.T) {
	valid := mustRuntimeMountArchiveWithFormatAndTrailingBytes(t, tar.FormatPAX, strings.Repeat("long/", 80)+"file", []byte("body"), nil)
	stream := decompressedRuntimeMountArchiveBytes(t, valid)
	if len(stream) < 1024 {
		t.Fatal("PAX fixture did not contain an extension record")
	}
	truncatedStream := stream[:700]
	truncated := gzipRuntimeMountBytes(t, truncatedStream)
	if _, _, err := validateRuntimeMountArchive(truncated, maxRuntimeMountBytes, maxRuntimeMountTotalBytes); err == nil || err.Error() != "mount payload archive could not be read" {
		t.Fatalf("expected truncated PAX extension refusal, got %v", err)
	}
}

func mustRuntimeMountArchiveWithFormatAndTrailingBytes(t *testing.T, format tar.Format, name string, body []byte, trailing []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: format}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gzipWriter.Write(trailing); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func decompressedRuntimeMountArchiveBytes(t *testing.T, archive []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return payload
}

func gzipRuntimeMountBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := gzip.NewWriter(&archive)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func mustRuntimeMountFlatTarStream(t *testing.T, count int, closeArchive bool) []byte {
	t.Helper()
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	for index := 0; index < count; index++ {
		if err := writer.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%05d", index), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
	}
	if closeArchive {
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), stream.Bytes()...)
}

func mustRuntimeMountArchiveNamesWithFormat(t *testing.T, format tar.Format, names []string) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range names {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Typeflag: tar.TypeReg, Format: format}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func runtimeMountArchiveWithFormat(format tar.Format, name string) ([]byte, error) {
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Typeflag: tar.TypeReg, Format: format}); err != nil {
		return archive.Bytes(), err
	}
	if err := tarWriter.Close(); err != nil {
		return archive.Bytes(), err
	}
	if err := gzipWriter.Close(); err != nil {
		return archive.Bytes(), err
	}
	return archive.Bytes(), nil
}

func runtimeMountFirstTarEntrySize(t *testing.T, stream []byte) int64 {
	t.Helper()
	if len(stream) < 512 {
		t.Fatal("tar stream has no complete header")
	}
	field := strings.Trim(string(bytes.Trim(stream[124:136], "\x00 ")), " ")
	value, err := strconv.ParseInt(field, 8, 64)
	if err != nil {
		t.Fatalf("parse tar size %q: %v", field, err)
	}
	return value
}

func runtimeMountRawSpecialHeader(name string, typeflag byte, size int64) []byte {
	header := make([]byte, 512)
	copy(header[0:100], name)
	runtimeMountPutOctal(header[100:108], 0o600)
	runtimeMountPutOctal(header[108:116], 0)
	runtimeMountPutOctal(header[116:124], 0)
	runtimeMountPutOctal(header[124:136], size)
	runtimeMountPutOctal(header[136:148], 0)
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	header[156] = typeflag
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	checksum := int64(0)
	for _, value := range header {
		checksum += int64(value)
	}
	copy(header[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
	return header
}

func runtimeMountPutOctal(field []byte, value int64) {
	for index := range field {
		field[index] = 0
	}
	formatted := fmt.Sprintf("%0*o", len(field)-1, value)
	copy(field[len(field)-1-len(formatted):len(field)-1], formatted)
}

type runtimeMountArchiveEntry struct {
	name     string
	body     []byte
	typeflag byte
	mode     int64
	linkname string
}

func mustRuntimeMountArchiveBytes(t *testing.T, entries ...runtimeMountArchiveEntry) []byte {
	t.Helper()

	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Mode:     entry.mode,
			Linkname: entry.linkname,
		}
		if entry.typeflag == tar.TypeReg || entry.typeflag == tar.TypeRegA {
			header.Size = int64(len(entry.body))
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal("write runtime mount tar header failed")
		}
		if len(entry.body) > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal("write runtime mount tar body failed")
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal("close runtime mount tar writer failed")
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal("close runtime mount gzip writer failed")
	}
	return archive.Bytes()
}

func mustRuntimeMountArchiveWithDeclaredSize(t *testing.T, declaredSize int64) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "oversized", Typeflag: tar.TypeReg, Mode: 0o644, Size: declaredSize}); err != nil {
		t.Fatal("write oversized tar header failed")
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal("close oversized gzip writer failed")
	}
	return archive.Bytes()
}
