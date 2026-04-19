package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type FilesystemStore struct {
	rootDir string
}

func NewFilesystemStore(rootDir string) (*FilesystemStore, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, fmt.Errorf("storage.root_dir is required")
	}

	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, fmt.Errorf("stat storage root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("storage.root_dir must be a directory")
	}

	return &FilesystemStore{rootDir: rootDir}, nil
}

func (s *FilesystemStore) RootDir() string {
	return s.rootDir
}

func (s *FilesystemStore) Exists(digest string) (bool, error) {
	blobPath, err := ResolvePath(s.rootDir, digest)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(blobPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat blob: %w", err)
}

func (s *FilesystemStore) Read(digest string) ([]byte, error) {
	blobPath, err := ResolvePath(s.rootDir, digest)
	if err != nil {
		return nil, err
	}

	// TODO: This slice fully buffers blobs into memory and verifies integrity by
	// 		 hashing the entire byte stream on every read. That keeps the current
	// 		 read-only ARS contract correct for small blobs, but it is not the intended
	// 		 long-term scaling strategy. Revisit with streaming verification or explicit
	// 		 read limits before supporting larger runtime artifacts.
	data, err := os.ReadFile(blobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("read blob: %w", err)
	}

	actual := DigestBytes(data)
	if actual != digest {
		return nil, BlobCorruptError{
			Digest: digest,
			Actual: actual,
		}
	}

	return data, nil
}

func (s *FilesystemStore) Write(digest string, data []byte) (bool, error) {
	blobPath, err := ResolvePath(s.rootDir, digest)
	if err != nil {
		return false, err
	}

	actual := DigestBytes(data)
	if actual != digest {
		return false, BlobDigestMismatchError{
			Digest: digest,
			Actual: actual,
		}
	}

	existing, err := os.ReadFile(blobPath)
	if err == nil {
		existingDigest := DigestBytes(existing)
		if existingDigest != digest {
			return false, BlobCorruptError{
				Digest: digest,
				Actual: existingDigest,
			}
		}
		if bytes.Equal(existing, data) {
			return false, nil
		}

		// A valid blob is already stored at this digest. The content-addressed
		// contract treats the digest as authoritative, so this is an idempotent
		// success even if the caller re-sends equivalent content via a different
		// byte representation path.
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read existing blob: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		return false, fmt.Errorf("create blob directory: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(blobPath), ".ars-upload-*")
	if err != nil {
		return false, fmt.Errorf("create temp blob: %w", err)
	}

	tempPath := tempFile.Name()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return false, fmt.Errorf("write temp blob: %w", err)
	}
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		return false, fmt.Errorf("chmod temp blob: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return false, fmt.Errorf("close temp blob: %w", err)
	}

	if err := os.Rename(tempPath, blobPath); err != nil {
		return false, fmt.Errorf("commit blob: %w", err)
	}

	cleanupTemp = false
	return true, nil
}

func ValidateDigest(digest string) error {
	if !sha256DigestPattern.MatchString(digest) {
		return InvalidDigestError{Digest: digest}
	}
	return nil
}

func ResolvePath(rootDir string, digest string) (string, error) {
	if err := ValidateDigest(digest); err != nil {
		return "", err
	}

	sum := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(rootDir, "sha256", sum[:2], sum[2:4], digest), nil
}

func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
