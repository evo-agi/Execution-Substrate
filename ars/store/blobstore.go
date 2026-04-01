package store

import (
	"errors"
	"fmt"
)

var ErrBlobNotFound = errors.New("blob not found")

type BlobStore interface {
	RootDir() string
	Exists(digest string) (bool, error)
	Read(digest string) ([]byte, error)
	Write(digest string, data []byte) (bool, error)
}

type InvalidDigestError struct {
	Digest string
}

func (e InvalidDigestError) Error() string {
	return fmt.Sprintf("invalid digest: %s", e.Digest)
}

type BlobCorruptError struct {
	Digest string
	Actual string
}

func (e BlobCorruptError) Error() string {
	return fmt.Sprintf("stored blob digest mismatch: expected=%s actual=%s", e.Digest, e.Actual)
}

type BlobDigestMismatchError struct {
	Digest string
	Actual string
}

func (e BlobDigestMismatchError) Error() string {
	return fmt.Sprintf("blob digest does not match request path: expected=%s actual=%s", e.Digest, e.Actual)
}
