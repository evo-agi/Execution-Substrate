package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	egsmodel "execution-substrate/egs/model"
)

const (
	runtimeMountRoot                      = "/execution/mounts"
	governedMountDirMode                  = 0o755
	governedMountFileMode                 = 0o644
	governedMountExecFileMode             = 0o755
	maxRuntimeMounts                      = 8
	maxRuntimeMountBytes            int64 = 8 << 20
	maxRuntimeMountTotalBytes       int64 = 32 << 20
	maxRuntimeMountStreamBytes      int64 = 16 << 20
	maxRuntimeMountTotalStreamBytes       = 64 << 20
)

func normalizedGovernedMountFileMode(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return governedMountExecFileMode
	}
	return governedMountFileMode
}

type stagedRuntimeMount struct {
	sourceDir  string
	targetPath string
	readOnly   bool
}

func validateRuntimeMounts(mounts []RuntimeMount) *Error {
	if len(mounts) == 0 {
		return nil
	}
	if len(mounts) > maxRuntimeMounts {
		return &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: fmt.Sprintf("invocation.mounts exceeds the maximum supported count (%d)", maxRuntimeMounts),
		}
	}

	targets := make([]string, 0, len(mounts))
	for index := range mounts {
		mount := &mounts[index]
		if !isLabeledSHA256Digest(mount.Source.ArtifactDigest) {
			return &Error{
				Status:  http.StatusBadRequest,
				Code:    codeInvalidRequest,
				Message: "mount source.artifact_digest must be a labeled sha256 digest",
			}
		}
		if !mount.ReadOnly {
			return &Error{
				Status:  http.StatusBadRequest,
				Code:    codeInvalidRequest,
				Message: "mount read_only must be true in this execution slice",
			}
		}

		targetPath, err := normalizeRuntimeMountTargetPath(mount.TargetPath)
		if err != nil {
			return &Error{
				Status:  http.StatusBadRequest,
				Code:    codeInvalidRequest,
				Message: err.Error(),
			}
		}
		mount.TargetPath = targetPath
		targets = append(targets, targetPath)
	}

	if hasOverlappingRuntimeMountTargets(targets) {
		return &Error{
			Status:  http.StatusConflict,
			Code:    codeMountConflict,
			Message: "mount target paths must not overlap",
		}
	}
	return nil
}

func normalizeRuntimeMountTargetPath(targetPath string) (string, error) {
	trimmed := strings.TrimSpace(targetPath)
	if trimmed == "" {
		return "", fmt.Errorf("mount target_path is required")
	}
	if !path.IsAbs(trimmed) {
		return "", fmt.Errorf("mount target_path must be absolute")
	}
	cleaned := path.Clean(trimmed)
	if cleaned != trimmed {
		return "", fmt.Errorf("mount target_path must already be cleaned")
	}
	if cleaned == runtimeMountRoot || !strings.HasPrefix(cleaned, runtimeMountRoot+"/") {
		return "", fmt.Errorf("mount target_path must remain under %s", runtimeMountRoot)
	}
	if !nomadPassesAsWritten(cleaned) {
		return "", fmt.Errorf("mount target_path %s", nomadEvaluatedText)
	}
	return cleaned, nil
}

func hasOverlappingRuntimeMountTargets(targets []string) bool {
	if len(targets) < 2 {
		return false
	}

	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		previous := sorted[i-1]
		current := sorted[i]
		if current == previous || strings.HasPrefix(current, previous+"/") {
			return true
		}
	}
	return false
}

func stagedRuntimeMountTargets(mounts []stagedRuntimeMount) []string {
	targets := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		targets = append(targets, mount.targetPath)
	}
	return targets
}

func resolvedRuntimeMountTargets(mounts []resolvedMountPlan) []string {
	targets := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		targets = append(targets, mount.targetPath)
	}
	return targets
}

func (s *Service) resolveRuntimeMounts(ctx context.Context, trustModel egsmodel.RuntimeTrustPolicy, mounts []RuntimeMount) ([]resolvedMountPlan, []validatedMountArchive, *Error) {
	if mounts == nil {
		return nil, nil, nil
	}
	if len(mounts) == 0 {
		return []resolvedMountPlan{}, []validatedMountArchive{}, nil
	}
	var totalArchiveBytes int64
	var totalExtractedBytes int64
	var totalStreamBytes int64
	plans := make([]resolvedMountPlan, 0, len(mounts))
	archives := make([]validatedMountArchive, 0, len(mounts))

	for _, mount := range mounts {
		remainingArchiveBytes := maxRuntimeMountTotalBytes - totalArchiveBytes
		if remainingArchiveBytes <= 0 {
			return nil, nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payloads exceed the total size limit")
		}
		acquisitionLimit := minInt64(maxRuntimeMountBytes, remainingArchiveBytes)
		payloadBytes, verifiedArtifactDigest, payloadDigest, acquisitionErr, err := s.fetchValidatedMountPayload(ctx, trustModel, mount.Source.ArtifactDigest, acquisitionLimit)
		if err != nil {
			if boundedResponseTooLarge(acquisitionErr) {
				if remainingArchiveBytes < maxRuntimeMountBytes {
					return nil, nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payloads exceed the total size limit")
				}
				return nil, nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payload exceeds the per-mount size limit")
			}
			return nil, nil, err
		}

		archiveSize := int64(len(payloadBytes))
		var ok bool
		totalArchiveBytes, ok = addWithinLimit(totalArchiveBytes, archiveSize, maxRuntimeMountTotalBytes)
		if !ok {
			return nil, nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payloads exceed the total size limit")
		}

		remainingTotalBytes := maxRuntimeMountTotalBytes - totalExtractedBytes
		remainingStreamBytes := maxRuntimeMountTotalStreamBytes - totalStreamBytes
		archive, extractedBytes, streamBytes, archiveErr := validateRuntimeMountArchiveWithinBudgets(
			payloadBytes,
			maxRuntimeMountBytes,
			remainingTotalBytes,
			maxRuntimeMountStreamBytes,
			remainingStreamBytes,
			nil,
		)
		if archiveErr != nil {
			return nil, nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, archiveErr.Error())
		}
		totalExtractedBytes += extractedBytes
		totalStreamBytes += streamBytes
		plans = append(plans, resolvedMountPlan{
			artifactDigest:         strings.TrimSpace(mount.Source.ArtifactDigest),
			verifiedArtifactDigest: verifiedArtifactDigest,
			payloadDigest:          payloadDigest,
			targetPath:             mount.TargetPath,
			readOnly:               mount.ReadOnly,
		})
		archives = append(archives, archive)
	}

	return plans, archives, nil
}

func materializeValidatedRuntimeMounts(custody *stagingCustody, layout executionPackageLayout, plans []resolvedMountPlan, archives []validatedMountArchive) ([]stagedRuntimeMount, *Error) {
	if len(plans) == 0 && len(archives) == 0 {
		return nil, nil
	}
	if len(plans) != len(archives) {
		return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "runtime mount material did not match the resolved plan")
	}
	if err := custody.ensureDirectory(executionMountsStageDirName, governedMountDirMode); err != nil {
		return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "create runtime mount staging root failed")
	}

	staged := make([]stagedRuntimeMount, 0, len(plans))
	for index, plan := range plans {
		archive := archives[index]
		mountContentsDir := layout.mountContentsDir(index)
		mountContentsRelative := executionMountsStageDirName + "/" + fmt.Sprintf("%02d", index) + "/contents"
		if err := custody.ensureDirectory(mountContentsRelative, governedMountDirMode); err != nil {
			return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "create runtime mount staging directory failed")
		}
		if err := materializeValidatedMountEntries(custody, mountContentsRelative, archive.entries); err != nil {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, err.Error())
		}
		staged = append(staged, stagedRuntimeMount{sourceDir: mountContentsDir, targetPath: plan.targetPath, readOnly: plan.readOnly})
	}
	return staged, nil
}

func (s *Service) fetchValidatedMountPayload(ctx context.Context, trustModel egsmodel.RuntimeTrustPolicy, artifactDigest string, limit int64) ([]byte, string, string, error, *Error) {
	trimmedDigest := strings.TrimSpace(artifactDigest)
	prepared, err := s.prepareMountArtifact(ctx, trustModel, trimmedDigest)
	if err != nil {
		return nil, "", "", nil, err
	}

	payloadBytes, acquisitionErr, fetchErr := s.fetchPayloadBytesWithin(ctx, prepared.payloadDigest, limit)
	if fetchErr != nil {
		return nil, "", "", acquisitionErr, fetchErr
	}
	return payloadBytes, prepared.manifest.ArtifactDigest, prepared.payloadDigest, acquisitionErr, nil
}

func (s *Service) prepareMountArtifact(ctx context.Context, trustModel egsmodel.RuntimeTrustPolicy, artifactDigest string) (preparedArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscovery(ctx, artifactDigest)
	if err != nil {
		return preparedArtifact{}, remapMountArtifactPreparationError(err)
	}
	// The discovery record is not verified (contracts section 5A). Without
	// this check ARS could answer for the requested mount with any other
	// sealed artifact, and ES would stage that artifact's bytes as the mount.
	if discovery.discovery.Artifact.ArtifactDigest != artifactDigest {
		return preparedArtifact{}, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "artifact digest mismatch between mount source and artifact discovery")
	}

	artifact, err := s.prepareArtifactFromEvidenceRecord(trustModel, discovery.discovery, discovery.evidence)
	if err != nil {
		return preparedArtifact{}, remapMountArtifactPreparationError(err)
	}
	return artifact, nil
}

func remapMountArtifactPreparationError(err *Error) *Error {
	if err == nil {
		return nil
	}

	switch err.Code {
	case codeArtifactEvidenceNotFound,
		codeArtifactEvidenceInvalid,
		codeSignerNotAllowed,
		codeSignerRevoked,
		codeArtifactRevoked:
		return mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, err.Message)
	default:
		return err
	}
}

type checkedMountEntrySize int

type mountArchiveRadixKind uint8

const (
	mountArchiveRadixNone mountArchiveRadixKind = iota
	mountArchiveRadixDirectory
	mountArchiveRadixRegular
)

// mountArchiveRadixWork is optional test-visible accounting at the real
// production work sites. A nil ledger has no production cost beyond the nil
// checks and does not change validation behavior.
type mountArchiveRadixWork struct {
	ProbeCount         uint64
	CommitCount        uint64
	ByteComparisons    uint64
	ChildLookups       uint64
	NodeAllocations    uint64
	MapAllocations     uint64
	BranchSplits       uint64
	RetainedLabelBytes uint64
}

type mountArchiveRadixNode struct {
	label    string
	kind     mountArchiveRadixKind
	children map[byte]*mountArchiveRadixNode
}

type mountArchiveRadixLedger struct {
	root mountArchiveRadixNode
	work *mountArchiveRadixWork
}

type mountArchiveRadixCommitKind uint8

const (
	mountArchiveRadixCommitExisting mountArchiveRadixCommitKind = iota
	mountArchiveRadixCommitTerminal
	mountArchiveRadixCommitChild
	mountArchiveRadixCommitSplitTerminal
	mountArchiveRadixCommitSplitBranch
)

type mountArchiveRadixCommitPlan struct {
	kind       mountArchiveRadixCommitKind
	parent     *mountArchiveRadixNode
	child      *mountArchiveRadixNode
	node       *mountArchiveRadixNode
	name       string
	nameOffset int
	common     int
}

type mountArchiveRadixProbe struct {
	regularAncestor bool
	exactKind       mountArchiveRadixKind
	hasDescendant   bool
	commit          mountArchiveRadixCommitPlan
}

func newMountArchiveRadixLedger(work *mountArchiveRadixWork) *mountArchiveRadixLedger {
	return &mountArchiveRadixLedger{work: work}
}

// probe scans name once from left to right. It does not mutate the ledger, so
// the caller can preserve validation error precedence and commit only after
// every other fallible step has succeeded.
func (ledger *mountArchiveRadixLedger) probe(name string) mountArchiveRadixProbe {
	if ledger.work != nil {
		ledger.work.ProbeCount++
	}
	node := &ledger.root
	offset := 0
	for {
		if node.kind == mountArchiveRadixRegular && offset < len(name) && name[offset] == '/' {
			return mountArchiveRadixProbe{regularAncestor: true}
		}
		if offset == len(name) {
			hasDescendant := false
			if node.children != nil {
				if ledger.work != nil {
					ledger.work.ChildLookups++
				}
				_, hasDescendant = node.children['/']
			}
			commitKind := mountArchiveRadixCommitTerminal
			if node.kind != mountArchiveRadixNone {
				commitKind = mountArchiveRadixCommitExisting
			}
			return mountArchiveRadixProbe{
				exactKind:     node.kind,
				hasDescendant: hasDescendant,
				commit: mountArchiveRadixCommitPlan{
					kind: commitKind,
					node: node,
					name: name,
				},
			}
		}

		if ledger.work != nil {
			ledger.work.ChildLookups++
		}
		child := node.children[name[offset]]
		if child == nil {
			return mountArchiveRadixProbe{commit: mountArchiveRadixCommitPlan{
				kind:       mountArchiveRadixCommitChild,
				parent:     node,
				name:       name,
				nameOffset: offset,
			}}
		}

		common := 0
		remaining := len(name) - offset
		limit := len(child.label)
		if remaining < limit {
			limit = remaining
		}
		for common < limit {
			if ledger.work != nil {
				ledger.work.ByteComparisons++
			}
			if name[offset+common] != child.label[common] {
				break
			}
			common++
		}
		if common == len(child.label) {
			offset += common
			node = child
			continue
		}
		if offset+common == len(name) {
			return mountArchiveRadixProbe{
				hasDescendant: child.label[common] == '/',
				commit: mountArchiveRadixCommitPlan{
					kind:       mountArchiveRadixCommitSplitTerminal,
					parent:     node,
					child:      child,
					name:       name,
					nameOffset: offset,
					common:     common,
				},
			}
		}
		return mountArchiveRadixProbe{commit: mountArchiveRadixCommitPlan{
			kind:       mountArchiveRadixCommitSplitBranch,
			parent:     node,
			child:      child,
			name:       name,
			nameOffset: offset,
			common:     common,
		}}
	}
}

func (ledger *mountArchiveRadixLedger) commit(plan mountArchiveRadixCommitPlan, kind mountArchiveRadixKind) {
	if ledger.work != nil {
		ledger.work.CommitCount++
	}
	switch plan.kind {
	case mountArchiveRadixCommitExisting:
		return
	case mountArchiveRadixCommitTerminal:
		plan.node.kind = kind
		return
	case mountArchiveRadixCommitChild:
		if plan.parent.children == nil {
			plan.parent.children = make(map[byte]*mountArchiveRadixNode)
			if ledger.work != nil {
				ledger.work.MapAllocations++
			}
		}
		label := plan.name[plan.nameOffset:]
		plan.parent.children[label[0]] = &mountArchiveRadixNode{label: label, kind: kind}
		if ledger.work != nil {
			ledger.work.NodeAllocations++
			ledger.work.RetainedLabelBytes += uint64(len(label))
		}
		return
	case mountArchiveRadixCommitSplitTerminal, mountArchiveRadixCommitSplitBranch:
		oldLabel := plan.child.label
		prefix := plan.name[plan.nameOffset : plan.nameOffset+plan.common]
		plan.child.label = oldLabel[plan.common:]
		branch := &mountArchiveRadixNode{
			label:    prefix,
			children: make(map[byte]*mountArchiveRadixNode),
		}
		branch.children[plan.child.label[0]] = plan.child
		if plan.kind == mountArchiveRadixCommitSplitTerminal {
			branch.kind = kind
		} else {
			newLabel := plan.name[plan.nameOffset+plan.common:]
			branch.children[newLabel[0]] = &mountArchiveRadixNode{label: newLabel, kind: kind}
			if ledger.work != nil {
				ledger.work.NodeAllocations++
				ledger.work.RetainedLabelBytes += uint64(len(newLabel))
			}
		}
		plan.parent.children[prefix[0]] = branch
		if ledger.work != nil {
			ledger.work.NodeAllocations++
			ledger.work.MapAllocations++
			ledger.work.BranchSplits++
		}
	}
}

func validateRuntimeMountArchive(archiveBytes []byte, perMountLimit int64, remainingTotalLimit int64) (validatedMountArchive, int64, error) {
	archive, extractedBytes, _, err := validateRuntimeMountArchiveWithinBudgets(
		archiveBytes,
		perMountLimit,
		remainingTotalLimit,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		nil,
	)
	return archive, extractedBytes, err
}

func validateRuntimeMountArchiveWithinBudgets(
	archiveBytes []byte,
	perMountBodyLimit int64,
	remainingTotalBodyLimit int64,
	perMountStreamLimit int64,
	remainingTotalStreamLimit int64,
	radixWork *mountArchiveRadixWork,
) (validatedMountArchive, int64, int64, error) {
	if remainingTotalBodyLimit < 0 {
		return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payloads exceed the total size limit")
	}
	if remainingTotalStreamLimit <= 0 {
		return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload streams exceed the total decompressed-stream size limit")
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload must be a valid tar.gz archive")
	}

	effectiveStreamLimit := minInt64(perMountStreamLimit, remainingTotalStreamLimit)
	streamReader := &io.LimitedReader{R: gzipReader, N: effectiveStreamLimit + 1}
	tarReader := tar.NewReader(streamReader)
	var extractedBytes int64
	entries := make([]validatedMountEntry, 0)
	namespace := newMountArchiveRadixLedger(radixWork)

	streamLimitError := func() error {
		if remainingTotalStreamLimit < perMountStreamLimit {
			return fmt.Errorf("mount payload streams exceed the total decompressed-stream size limit")
		}
		return fmt.Errorf("mount payload exceeds the per-mount decompressed-stream size limit")
	}
	streamExceeded := func() bool {
		return streamReader.N == 0
	}

	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			_ = gzipReader.Close()
			if streamExceeded() {
				return validatedMountArchive{}, 0, 0, streamLimitError()
			}
			return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive could not be read")
		}
		if header == nil {
			continue
		}

		entryName, normalizeErr := normalizeArchiveEntryName(header.Name)
		if normalizeErr != nil {
			_ = gzipReader.Close()
			return validatedMountArchive{}, 0, 0, normalizeErr
		}
		probe := namespace.probe(entryName)
		if probe.regularAncestor {
			_ = gzipReader.Close()
			return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload directory creation failed")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if probe.exactKind == mountArchiveRadixRegular {
				_ = gzipReader.Close()
				return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload directory creation failed")
			}
			entries = append(entries, validatedMountEntry{name: entryName, directory: true, mode: governedMountDirMode})
			namespace.commit(probe.commit, mountArchiveRadixDirectory)
		case tar.TypeReg, tar.TypeRegA:
			entrySize, sizeErr := checkMountEntrySize(header.Size, extractedBytes, perMountBodyLimit, remainingTotalBodyLimit)
			if sizeErr != nil {
				_ = gzipReader.Close()
				return validatedMountArchive{}, 0, 0, sizeErr
			}
			if probe.exactKind != mountArchiveRadixNone || probe.hasDescendant {
				_ = gzipReader.Close()
				return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload file creation failed")
			}
			contents, readErr := readCheckedMountEntry(tarReader, entrySize)
			if readErr != nil {
				_ = gzipReader.Close()
				if streamExceeded() {
					return validatedMountArchive{}, 0, 0, streamLimitError()
				}
				return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload file extraction failed")
			}
			extractedBytes += int64(entrySize)
			entries = append(entries, validatedMountEntry{
				name:     entryName,
				mode:     normalizedGovernedMountFileMode(header.FileInfo().Mode()),
				contents: contents,
			})
			namespace.commit(probe.commit, mountArchiveRadixRegular)
		case tar.TypeSymlink, tar.TypeLink:
			_ = gzipReader.Close()
			return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive contains symbolic or hard links, which are unsupported")
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			_ = gzipReader.Close()
			return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive contains unsupported special files")
		default:
			_ = gzipReader.Close()
			return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive contains an unsupported entry type")
		}
	}

	if _, drainErr := io.Copy(io.Discard, streamReader); drainErr != nil {
		_ = gzipReader.Close()
		if streamExceeded() {
			return validatedMountArchive{}, 0, 0, streamLimitError()
		}
		return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive could not be read")
	}
	if streamExceeded() {
		_ = gzipReader.Close()
		return validatedMountArchive{}, 0, 0, streamLimitError()
	}
	if closeErr := gzipReader.Close(); closeErr != nil {
		return validatedMountArchive{}, 0, 0, fmt.Errorf("mount payload archive could not be read")
	}
	streamBytes := effectiveStreamLimit + 1 - streamReader.N

	return validatedMountArchive{
		compressedBytes: archiveBytes,
		entries:         entries,
	}, extractedBytes, streamBytes, nil
}

func checkMountEntrySize(size int64, extractedBytes int64, perMountLimit int64, remainingTotalLimit int64) (checkedMountEntrySize, error) {
	if size < 0 || size > int64(maximumInt()) {
		return 0, fmt.Errorf("mount payload archive contains an invalid file size")
	}
	if extractedBytes < 0 || extractedBytes > perMountLimit || size > perMountLimit-extractedBytes {
		return 0, fmt.Errorf("mount payload exceeds the per-mount size limit")
	}
	if extractedBytes > remainingTotalLimit || size > remainingTotalLimit-extractedBytes {
		return 0, fmt.Errorf("mount payloads exceed the total size limit")
	}
	return checkedMountEntrySize(size), nil
}

func readCheckedMountEntry(reader io.Reader, size checkedMountEntrySize) ([]byte, error) {
	contents := make([]byte, int(size))
	if _, err := io.ReadFull(reader, contents); err != nil {
		return nil, err
	}
	return contents, nil
}

func materializeValidatedMountEntries(custody *stagingCustody, destinationRoot string, entries []validatedMountEntry) error {
	for _, entry := range entries {
		relativePath := destinationRoot + "/" + entry.name
		if entry.directory {
			if err := custody.ensureDirectory(relativePath, governedMountDirMode); err != nil {
				return fmt.Errorf("mount payload directory creation failed")
			}
			continue
		}
		if err := custody.ensureDirectory(pathDir(relativePath), governedMountDirMode); err != nil {
			return fmt.Errorf("mount payload directory creation failed")
		}
		if err := custody.writeFileWithParentMode(relativePath, entry.contents, entry.mode, governedMountDirMode); err != nil {
			return fmt.Errorf("mount payload file creation failed")
		}
	}
	return nil
}

func maximumInt() int {
	return int(^uint(0) >> 1)
}

func normalizeArchiveEntryName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	trimmed = strings.TrimPrefix(trimmed, "./")
	if trimmed == "" {
		return "", fmt.Errorf("mount payload archive contains an empty path")
	}
	if path.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("mount payload archive contains absolute paths")
	}

	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("mount payload archive contains path traversal")
	}
	if cleaned == "" {
		return "", fmt.Errorf("mount payload archive contains an empty path")
	}
	return cleaned, nil
}

func mountArtifactError(status int, code string, message string) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
	}
}
