package store

import (
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
	// hashing the entire byte stream on every read. That keeps the current
	// read-only ARS contract correct for small blobs, but it is not the intended
	// long-term scaling strategy. Revisit with streaming verification or explicit
	// read limits before supporting larger runtime artifacts.
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
