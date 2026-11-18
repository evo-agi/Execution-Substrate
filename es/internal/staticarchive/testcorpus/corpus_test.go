package testcorpus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

// These small raw-header fixtures prove what the pinned archive/tar reader
// returns. The large logical case is inspected only at Next; its body is never
// read or expanded by this test.
func TestA2SparseFixtureHeaders(t *testing.T) {
	seen := map[SparseFormat]bool{}
	for _, fixture := range Cases() {
		index := -1
		for i, entry := range fixture.Entries {
			if entry.Sparse != "" {
				index = i
				break
			}
		}
		if index < 0 {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			entry := fixture.Entries[index]
			seen[entry.Sparse] = true
			decoded, err := Tar(fixture.Entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) >= 16*1024*1024 {
				t.Fatalf("sparse fixture has oversized physical tar: %d", len(decoded))
			}
			compressed, err := Gzip(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if len(compressed) >= 256*1024 {
				t.Fatalf("sparse fixture has oversized compressed tar: %d", len(compressed))
			}
			gz, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			reader := tar.NewReader(gz)
			var header *tar.Header
			for i := 0; i <= index; i++ {
				header, err = reader.Next()
				if err != nil {
					t.Fatal(err)
				}
			}
			if entry.Sparse == SparseOldGNU {
				if header.Typeflag != tar.TypeGNUSparse {
					t.Fatalf("old GNU sparse type lost: %d", header.Typeflag)
				}
			} else {
				if header.Typeflag != tar.TypeReg {
					t.Fatalf("PAX sparse must appear as ordinary TypeReg, got %d", header.Typeflag)
				}
				found := false
				for key := range header.PAXRecords {
					if strings.HasPrefix(key, "GNU.sparse.") {
						found = true
					}
				}
				if !found {
					t.Fatal("raw fixture lost GNU.sparse.* metadata")
				}
			}
			if entry.Sparse != SparsePAXUnknownVersion && entry.Sparse != SparsePAXUnknownKey && header.Size != entry.LogicalSize {
				t.Fatalf("reader did not adopt sparse logical size: got %d want %d", header.Size, entry.LogicalSize)
			}
			if entry.LogicalSize > 16*1024*1024 {
				return
			} // Never read the large logical hole.
			if entry.Sparse == SparsePAXUnknownVersion || entry.Sparse == SparsePAXUnknownKey {
				return
			}
			body, err := io.ReadAll(io.LimitReader(reader, entry.LogicalSize+1))
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(body)) != entry.LogicalSize {
				t.Fatalf("sparse logical body length %d", len(body))
			}
			if entry.Sparse == SparseOldGNU || entry.Sparse == SparsePAXAllHole {
				if !bytes.Equal(body, make([]byte, len(body))) {
					t.Fatal("all-hole sparse body not zero filled")
				}
			} else if body[0] != 'A' || !bytes.Equal(body[1:], make([]byte, len(body)-1)) {
				t.Fatal("sparse data/hole interpretation mismatch")
			}
		})
	}
	for _, kind := range []SparseFormat{SparseOldGNU, SparsePAX00, SparsePAX01, SparsePAX10, SparsePAXAllHole, SparsePAXUnknownVersion, SparsePAXUnknownKey} {
		if !seen[kind] {
			t.Fatalf("missing sparse fixture %q", kind)
		}
	}
}
