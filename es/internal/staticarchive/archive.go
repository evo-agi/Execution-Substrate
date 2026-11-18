// Package staticarchive contains the private pathname and stream integrity
// mechanics shared by ES static-script admission and runtime extraction.
package staticarchive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"
)

// Namespace records effective tar destinations, including implicit parent
// directories. Duplicate file destinations and file/directory conflicts fail.
type Namespace struct {
	files map[string]struct{}
	dirs  map[string]struct{}
}

func CleanName(headerName string) (string, error) {
	if strings.ContainsRune(headerName, '\x00') {
		return "", fmt.Errorf("archive entry path contains NUL")
	}
	trimmed := strings.TrimSpace(headerName)
	if trimmed == "" {
		return "", fmt.Errorf("archive entry has an empty path")
	}
	name := path.Clean(trimmed)
	if name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("archive entry path is outside the work tree")
	}
	return name, nil
}

func (n *Namespace) Add(header *tar.Header) (string, error) {
	if header == nil {
		return "", fmt.Errorf("archive entry header is missing")
	}
	// archive/tar returns PAX GNU sparse files as ordinary TypeReg headers.
	// Reject their retained metadata before any consumer reads the logical
	// body, whose holes are synthesized above our gzip-stream byte counter.
	if header.Typeflag == tar.TypeGNUSparse {
		return "", fmt.Errorf("GNU sparse archive entry is unsupported")
	}
	for key := range header.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return "", fmt.Errorf("GNU sparse archive metadata is unsupported")
		}
	}
	name, err := CleanName(header.Name)
	if err != nil {
		return "", err
	}
	typeflag := header.Typeflag
	if typeflag != tar.TypeDir && typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
		return "", fmt.Errorf("archive entry uses unsupported type %d", typeflag)
	}
	if n.files == nil {
		n.files = make(map[string]struct{})
		n.dirs = make(map[string]struct{})
	}
	for i := strings.IndexByte(name, '/'); i >= 0; i = nextSeparator(name, i) {
		parent := name[:i]
		if _, exists := n.files[parent]; exists {
			return "", fmt.Errorf("archive path conflicts with a file parent")
		}
		n.dirs[parent] = struct{}{}
	}
	if typeflag == tar.TypeDir {
		if _, exists := n.files[name]; exists {
			return "", fmt.Errorf("archive directory conflicts with a file")
		}
		n.dirs[name] = struct{}{}
		return name, nil
	}
	if _, exists := n.files[name]; exists {
		return "", fmt.Errorf("archive file destination is duplicated")
	}
	if _, exists := n.dirs[name]; exists {
		return "", fmt.Errorf("archive file conflicts with a directory")
	}
	n.files[name] = struct{}{}
	return name, nil
}

func nextSeparator(name string, after int) int {
	next := strings.IndexByte(name[after+1:], '/')
	if next < 0 {
		return -1
	}
	return after + 1 + next
}

// Reader exposes effective tar headers and their bodies while retaining the
// compressed source so the caller can verify decoded and compressed tails.
// maxDecoded <= 0 leaves the decoded byte count unrestricted for the generic
// runtime extractor; policy supplies its explicit positive bound.
type Reader struct {
	source  *bufio.Reader
	gzip    *gzip.Reader
	decoded io.Reader
	limit   *io.LimitedReader
	tar     *tar.Reader
}

func Open(source io.Reader, maxDecoded int64) (*Reader, error) {
	buffered := bufio.NewReader(source)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	gzipReader.Multistream(false)
	r := &Reader{source: buffered, gzip: gzipReader, decoded: gzipReader}
	if maxDecoded > 0 {
		r.limit = &io.LimitedReader{R: gzipReader, N: maxDecoded + 1}
		r.decoded = r.limit
	}
	r.tar = tar.NewReader(r.decoded)
	return r, nil
}

func (r *Reader) Next() (*tar.Header, error)    { return r.tar.Next() }
func (r *Reader) Read(body []byte) (int, error) { return r.tar.Read(body) }
func (r *Reader) Close() error                  { return r.gzip.Close() }

// Finish must follow tar EOF. It checks all remaining decoded bytes (normally
// tar padding), the gzip checksum, the decoded budget, and any second gzip
// member or arbitrary trailing compressed bytes.
func (r *Reader) Finish() error {
	var buf [32 * 1024]byte
	for {
		n, err := r.decoded.Read(buf[:])
		for _, b := range buf[:n] {
			if b != 0 {
				return fmt.Errorf("nonzero bytes after tar end")
			}
		}
		if r.limit != nil && r.limit.N == 0 {
			return fmt.Errorf("decoded archive exceeds policy bound")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read decoded archive tail: %w", err)
		}
	}
	if _, err := r.source.Peek(1); err == nil {
		return fmt.Errorf("compressed bytes follow first gzip member")
	} else if err != io.EOF {
		return fmt.Errorf("read compressed tail: %w", err)
	}
	return nil
}
