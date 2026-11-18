package runtimehelper

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"execution-substrate/es/internal/staticarchive/testcorpus"
)

func TestA2RuntimeEntrypointInterpretation(t *testing.T) {
	for _, fixture := range testcorpus.Cases() {
		t.Run(fixture.Name, func(t *testing.T) {
			archive, err := testcorpus.Archive(fixture.Entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			workDir := t.TempDir()
			err = extractWorkloadArchive(a2RuntimeArchivePath(t, archive), workDir)
			content, readErr := os.ReadFile(filepath.Join(workDir, "entrypoint"))
			if fixture.Valid {
				if err != nil || readErr != nil {
					t.Fatalf("accepted corpus item did not materialize entrypoint: extraction=%v read=%v", err, readErr)
				}
				if string(content) != fixture.WantText {
					t.Fatalf("runtime bytes differ from shared policy corpus: length=%d", len(content))
				}
				return
			}
			if err == nil {
				t.Fatal("ambiguous archive extracted without error")
			}
			// A later member must not replace an earlier regular entrypoint.
			if len(fixture.Entries) > 0 && fixture.Entries[0].Name == "entrypoint" && fixture.Entries[0].Type == 0 {
				if readErr != nil || !bytes.Equal(content, fixture.Entries[0].Body) {
					t.Fatalf("earlier entrypoint was replaced: read=%v length=%d", readErr, len(content))
				}
			}
		})
	}
}

func TestA2SparseRuntimeRefusal(t *testing.T) {
	for _, fixture := range testcorpus.SparseCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			workDir := t.TempDir()
			err := extractWorkloadArchive(a2RuntimeArchivePath(t, a2RuntimeArchive(t, fixture.Entries, nil)), workDir)
			if err == nil {
				t.Fatal("sparse archive extracted successfully")
			}
			if _, statErr := os.Lstat(filepath.Join(workDir, "support", "sparse")); !os.IsNotExist(statErr) {
				t.Fatalf("sparse destination was created before refusal: %v", statErr)
			}
			if fixture.Entries[0].Sparse == "" {
				content, readErr := os.ReadFile(filepath.Join(workDir, "entrypoint"))
				if readErr != nil || string(content) != testcorpus.BenignText {
					t.Fatalf("earlier benign entrypoint changed: read=%v length=%d", readErr, len(content))
				}
			} else if _, statErr := os.Lstat(filepath.Join(workDir, "entrypoint")); !os.IsNotExist(statErr) {
				t.Fatalf("later entrypoint was reached after sparse refusal: %v", statErr)
			}
		})
	}
}

func TestA2OnceOnlyDestinationAgreement(t *testing.T) {
	for _, fixture := range testcorpus.OnceOnlyCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			workDir := t.TempDir()
			if err := extractWorkloadArchive(a2RuntimeArchivePath(t, a2RuntimeArchive(t, fixture.Entries, nil)), workDir); err != nil {
				t.Fatalf("once-cleaned archive refused: %v", err)
			}
			entrypoint, err := os.ReadFile(filepath.Join(workDir, "entrypoint"))
			if err != nil || string(entrypoint) != fixture.WantText {
				t.Fatalf("runtime entrypoint differs from policy corpus: read=%v length=%d", err, len(entrypoint))
			}
			rootNames := map[string]bool{"entrypoint": true}
			for literal, body := range fixture.WantFiles {
				content, readErr := os.ReadFile(filepath.Join(workDir, filepath.FromSlash(literal)))
				if readErr != nil || string(content) != body {
					t.Fatalf("literal destination %q missing or changed: read=%v length=%d", literal, readErr, len(content))
				}
				rootNames[strings.SplitN(literal, "/", 2)[0]] = true
			}
			for _, literal := range fixture.WantDirs {
				info, statErr := os.Stat(filepath.Join(workDir, filepath.FromSlash(literal)))
				if statErr != nil || !info.IsDir() {
					t.Fatalf("literal directory %q missing: %v", literal, statErr)
				}
				rootNames[strings.SplitN(literal, "/", 2)[0]] = true
			}
			entries, err := os.ReadDir(workDir)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(entries))
			want := make([]string, 0, len(rootNames))
			for _, entry := range entries {
				got = append(got, entry.Name())
			}
			for name := range rootNames {
				want = append(want, name)
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("runtime root names %q, want literal %q", got, want)
			}
		})
	}
}

func TestA2RuntimeStreamTailRefusal(t *testing.T) {
	benign := testcorpus.Entry{Name: "entrypoint", Body: []byte(testcorpus.BenignText)}
	base, err := testcorpus.Archive([]testcorpus.Entry{benign, {Name: "support/data", Body: []byte("ok")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	decodedLate, err := testcorpus.Tar([]testcorpus.Entry{benign, {Name: "late", Body: bytes.Repeat([]byte("a"), 1024)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	truncatedLate, err := testcorpus.Gzip(decodedLate[:1536+10])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		payload []byte
		valid   bool
	}{
		{"ordinary archive", base, true},
		{"truncated late gzip", base[:len(base)-5], false},
		{"truncated late member with valid gzip", truncatedLate, false},
		{"concatenated gzip", append(bytes.Clone(base), base...), false},
		{"nonzero decoded tar tail", a2RuntimeArchive(t, []testcorpus.Entry{benign}, []byte{1}), false},
		{"zero decoded tar tail", a2RuntimeArchive(t, []testcorpus.Entry{benign}, []byte{0}), true},
		{"late unsupported", a2RuntimeArchive(t, []testcorpus.Entry{benign, {Name: "support/link", Type: tar.TypeSymlink}}, nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := extractWorkloadArchive(a2RuntimeArchivePath(t, tc.payload), t.TempDir())
			if tc.valid && err != nil {
				t.Fatalf("valid archive rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid tail or late member accepted")
			}
		})
	}
}

func a2RuntimeArchive(t *testing.T, entries []testcorpus.Entry, trailing []byte) []byte {
	t.Helper()
	payload, err := testcorpus.Archive(entries, trailing)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func a2RuntimeArchivePath(t *testing.T, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload.tar.gz")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
