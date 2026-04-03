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
	"path/filepath"
	"sort"
	"strings"

	egsmodel "execution-platform/egs/model"
)

// TODO: Do not mention "monolith"
const (
	runtimeMountRoot          = "/monolith/mounts"
	maxRuntimeMounts          = 8
	maxRuntimeMountBytes      = 8 << 20
	maxRuntimeMountTotalBytes = 32 << 20
)

type stagedRuntimeMount struct {
	sourceArtifactDigest string
	sourceDir            string
	targetPath           string
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
	for _, mount := range mounts {
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

func (s *Service) stageRuntimeMounts(ctx context.Context, trustModel egsmodel.TrustModel, stageRoot string, mounts []RuntimeMount) ([]stagedRuntimeMount, *Error) {
	if len(mounts) == 0 {
		return nil, nil
	}

	stageMountRoot := filepath.Join(stageRoot, "mounts")
	if err := os.MkdirAll(stageMountRoot, 0o755); err != nil {
		return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "create runtime mount staging root failed")
	}

	var totalArchiveBytes int64
	var totalExtractedBytes int64
	staged := make([]stagedRuntimeMount, 0, len(mounts))

	for index, mount := range mounts {
		payloadBytes, err := s.fetchValidatedMountPayload(ctx, trustModel, mount.Source.ArtifactDigest)
		if err != nil {
			return nil, err
		}

		archiveSize := int64(len(payloadBytes))
		if archiveSize > maxRuntimeMountBytes {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payload exceeds the per-mount size limit")
		}
		totalArchiveBytes += archiveSize
		if totalArchiveBytes > maxRuntimeMountTotalBytes {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "mount payloads exceed the total size limit")
		}

		targetPath, normalizeErr := normalizeRuntimeMountTargetPath(mount.TargetPath)
		if normalizeErr != nil {
			return nil, &Error{
				Status:  http.StatusBadRequest,
				Code:    codeInvalidRequest,
				Message: normalizeErr.Error(),
			}
		}

		mountStageDir := filepath.Join(stageMountRoot, fmt.Sprintf("%02d", index))
		mountArchivePath := filepath.Join(mountStageDir, "artifact.tar.gz")
		mountContentsDir := filepath.Join(mountStageDir, "contents")
		if err := os.MkdirAll(mountContentsDir, 0o755); err != nil {
			return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "create runtime mount staging directory failed")
		}
		if err := os.WriteFile(mountArchivePath, payloadBytes, 0o600); err != nil {
			return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "write runtime mount payload failed")
		}

		remainingTotalBytes := maxRuntimeMountTotalBytes - totalExtractedBytes
		extractedBytes, extractErr := extractRuntimeMountArchive(mountContentsDir, payloadBytes, maxRuntimeMountBytes, remainingTotalBytes)
		if extractErr != nil {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, extractErr.Error())
		}
		totalExtractedBytes += extractedBytes
		if err := os.Remove(mountArchivePath); err != nil {
			return nil, mountArtifactError(http.StatusInternalServerError, codeSubmissionFailed, "remove runtime mount payload archive failed")
		}

		realPath, realPathErr := filepath.EvalSymlinks(mountContentsDir)
		if realPathErr != nil {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "runtime mount extraction path validation failed")
		}
		if !isWithinFilesystemRoot(stageMountRoot, realPath) {
			return nil, mountArtifactError(http.StatusConflict, codeMountArtifactInvalid, "runtime mount extraction escaped the staging root")
		}

		staged = append(staged, stagedRuntimeMount{
			sourceArtifactDigest: strings.TrimSpace(mount.Source.ArtifactDigest),
			sourceDir:            mountContentsDir,
			targetPath:           targetPath,
		})
	}

	return staged, nil
}

func (s *Service) fetchValidatedMountPayload(ctx context.Context, trustModel egsmodel.TrustModel, artifactDigest string) ([]byte, *Error) {
	trimmedDigest := strings.TrimSpace(artifactDigest)
	prepared, err := s.prepareMountArtifact(ctx, trustModel, trimmedDigest)
	if err != nil {
		return nil, err
	}

	payloadBytes, err := s.fetchPayloadBytes(ctx, prepared.payloadDigest)
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}

func (s *Service) prepareMountArtifact(ctx context.Context, trustModel egsmodel.TrustModel, artifactDigest string) (preparedArtifact, *Error) {
	evidence, err := s.fetchArtifactEvidence(ctx, artifactDigest)
	if err != nil {
		return preparedArtifact{}, remapMountArtifactPreparationError(err)
	}

	artifact, err := s.prepareArtifactFromEvidenceRecord(trustModel, artifactDigest, evidence)
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

func extractRuntimeMountArchive(destinationRoot string, archiveBytes []byte, perMountLimit int64, remainingTotalLimit int64) (int64, error) {
	if remainingTotalLimit <= 0 {
		return 0, fmt.Errorf("mount payloads exceed the total size limit")
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return 0, fmt.Errorf("mount payload must be a valid tar.gz archive")
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	var extractedBytes int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("mount payload archive could not be read")
		}
		if header == nil {
			continue
		}

		entryName, normalizeErr := normalizeArchiveEntryName(header.Name)
		if normalizeErr != nil {
			return 0, normalizeErr
		}

		absolutePath := filepath.Join(destinationRoot, filepath.FromSlash(entryName))
		if !isWithinFilesystemRoot(destinationRoot, absolutePath) {
			return 0, fmt.Errorf("mount payload archive contains a path outside the extraction root")
		}

		switch header.Typeflag {
			case tar.TypeDir:
				if err := os.MkdirAll(absolutePath, 0o755); err != nil {
					return 0, fmt.Errorf("mount payload directory creation failed")
				}
				if err := ensureRealPathWithin(destinationRoot, absolutePath); err != nil {
					return 0, err
				}
			case tar.TypeReg, tar.TypeRegA:
				if header.Size < 0 {
					return 0, fmt.Errorf("mount payload archive contains an invalid file size")
				}
				extractedBytes += header.Size
				if extractedBytes > perMountLimit {
					return 0, fmt.Errorf("mount payload exceeds the per-mount size limit")
				}
				if extractedBytes > remainingTotalLimit {
					return 0, fmt.Errorf("mount payloads exceed the total size limit")
				}

				if err := os.MkdirAll(filepath.Dir(absolutePath), 0o755); err != nil {
					return 0, fmt.Errorf("mount payload directory creation failed")
				}
				file, err := os.OpenFile(absolutePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, header.FileInfo().Mode().Perm())
				if err != nil {
					return 0, fmt.Errorf("mount payload file creation failed")
				}
				if _, err := io.CopyN(file, tarReader, header.Size); err != nil {
					file.Close()
					return 0, fmt.Errorf("mount payload file extraction failed")
				}
				if err := file.Close(); err != nil {
					return 0, fmt.Errorf("mount payload file extraction failed")
				}
				if err := ensureRealPathWithin(destinationRoot, absolutePath); err != nil {
					return 0, err
				}
			case tar.TypeSymlink, tar.TypeLink:
				return 0, fmt.Errorf("mount payload archive contains symbolic or hard links, which are unsupported")
			case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
				return 0, fmt.Errorf("mount payload archive contains unsupported special files")
			default:
				return 0, fmt.Errorf("mount payload archive contains an unsupported entry type")
		}
	}

	return extractedBytes, nil
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

func ensureRealPathWithin(root string, candidate string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("mount payload extraction path validation failed")
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fmt.Errorf("mount payload extraction path validation failed")
	}
	if !isWithinFilesystemRoot(resolvedRoot, resolvedCandidate) {
		return fmt.Errorf("mount payload extraction escaped the staging root")
	}
	return nil
}

func isWithinFilesystemRoot(root string, candidate string) bool {
	cleanRoot := filepath.Clean(root)
	cleanCandidate := filepath.Clean(candidate)
	rel, err := filepath.Rel(cleanRoot, cleanCandidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func mountArtifactError(status int, code string, message string) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
	}
}
