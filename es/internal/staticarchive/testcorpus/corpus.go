// Package testcorpus supplies ordered static-script tar fixtures shared by the
// admission and runtime-helper tests. It is imported only by tests.
package testcorpus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strconv"
	"strings"
)

const (
	BenignText = "#!/bin/sh\necho a2-benign\n"
	DeniedText = "#!/bin/sh\necho A2_INERT_DENY_MARKER\n"
)

type Entry struct {
	Name        string
	Body        []byte
	Type        byte
	Format      tar.Format
	Sparse      SparseFormat
	LogicalSize int64
}

type SparseFormat string

const (
	SparseOldGNU            SparseFormat = "old-gnu"
	SparsePAX00             SparseFormat = "pax-0.0"
	SparsePAX01             SparseFormat = "pax-0.1"
	SparsePAX10             SparseFormat = "pax-1.0"
	SparsePAXAllHole        SparseFormat = "pax-all-hole"
	SparsePAXUnknownVersion SparseFormat = "pax-unknown-version"
	SparsePAXUnknownKey     SparseFormat = "pax-unknown-key"
)

type Case struct {
	Name      string
	Entries   []Entry
	WantText  string
	Valid     bool
	WantFiles map[string]string
	WantDirs  []string
}

func Cases() []Case {
	benign := Entry{Name: "entrypoint", Body: []byte(BenignText)}
	denied := Entry{Name: "entrypoint", Body: []byte(DeniedText)}
	return []Case{
		{Name: "single benign", Entries: []Entry{benign}, WantText: BenignText, Valid: true},
		{Name: "single dot alias", Entries: []Entry{{Name: "./entrypoint", Body: []byte(BenignText)}}, WantText: BenignText, Valid: true},
		{Name: "single cleaned alias", Entries: []Entry{{Name: "support/../entrypoint", Body: []byte(BenignText)}}, WantText: BenignText, Valid: true},
		{Name: "single whitespace alias", Entries: []Entry{{Name: " entrypoint ", Body: []byte(BenignText)}}, WantText: BenignText, Valid: true},
		{Name: "single PAX alias", Entries: []Entry{{Name: longAlias(), Body: []byte(BenignText), Format: tar.FormatPAX}}, WantText: BenignText, Valid: true},
		{Name: "single GNU alias", Entries: []Entry{{Name: longAlias(), Body: []byte(BenignText), Format: tar.FormatGNU}}, WantText: BenignText, Valid: true},
		{Name: "benign nested opaque archive", Entries: []Entry{benign, {Name: "workspace/nested.tgz", Body: []byte(DeniedText)}}, WantText: BenignText, Valid: true},
		{Name: "benign support files", Entries: []Entry{{Name: "support", Type: tar.TypeDir}, {Name: "support/data.txt", Body: []byte("data")}, benign}, WantText: BenignText, Valid: true},
		{Name: "repeated support directory", Entries: []Entry{{Name: "support", Type: tar.TypeDir}, {Name: "support/", Type: tar.TypeDir}, benign}, WantText: BenignText, Valid: true},
		{Name: "cleaned leading-space file before entrypoint", Entries: []Entry{{Name: "./ entrypoint", Body: []byte("inert sidecar")}, benign}, WantText: BenignText, Valid: true, WantFiles: map[string]string{" entrypoint": "inert sidecar", "entrypoint": BenignText}},
		{Name: "cleaned leading-space file after entrypoint", Entries: []Entry{benign, {Name: "./ entrypoint", Body: []byte("inert sidecar")}}, WantText: BenignText, Valid: true, WantFiles: map[string]string{" entrypoint": "inert sidecar", "entrypoint": BenignText}},
		{Name: "cleaned support leading-space component", Entries: []Entry{benign, {Name: "support/../ support.txt", Body: []byte("support data")}}, WantText: BenignText, Valid: true, WantFiles: map[string]string{" support.txt": "support data"}},
		{Name: "cleaned directory trailing-space component", Entries: []Entry{benign, {Name: "support /.", Type: tar.TypeDir}, {Name: "support /data.txt", Body: []byte("directory data")}}, WantText: BenignText, Valid: true, WantDirs: []string{"support "}, WantFiles: map[string]string{"support /data.txt": "directory data"}},
		{Name: "benign first denied second", Entries: []Entry{benign, denied}},
		{Name: "denied first benign second", Entries: []Entry{denied, benign}},
		{Name: "identical duplicate", Entries: []Entry{benign, benign}},
		{Name: "dot duplicate", Entries: []Entry{benign, {Name: "./entrypoint", Body: []byte(DeniedText)}}},
		{Name: "cleaned duplicate", Entries: []Entry{benign, {Name: "support/../entrypoint", Body: []byte(DeniedText)}}},
		{Name: "whitespace duplicate", Entries: []Entry{benign, {Name: " entrypoint ", Body: []byte(DeniedText)}}},
		{Name: "PAX duplicate", Entries: []Entry{benign, {Name: longAlias(), Body: []byte(DeniedText), Format: tar.FormatPAX}}},
		{Name: "GNU duplicate", Entries: []Entry{benign, {Name: longAlias(), Body: []byte(DeniedText), Format: tar.FormatGNU}}},
		{Name: "directory after file", Entries: []Entry{benign, {Name: "entrypoint/", Type: tar.TypeDir}}},
		{Name: "directory before file", Entries: []Entry{{Name: "entrypoint/", Type: tar.TypeDir}, benign}},
		{Name: "implicit directory after file", Entries: []Entry{benign, {Name: "entrypoint/child", Body: []byte("data")}}},
		{Name: "implicit directory before file", Entries: []Entry{{Name: "entrypoint/child", Body: []byte("data")}, benign}},
		{Name: "late unsupported link", Entries: []Entry{benign, {Name: "support/link", Type: tar.TypeSymlink}}},
		{Name: "late hard link", Entries: []Entry{benign, {Name: "support/link", Type: tar.TypeLink}}},
		{Name: "late special entry", Entries: []Entry{benign, {Name: "support/device", Type: tar.TypeChar}}},
		{Name: "late traversal", Entries: []Entry{benign, {Name: "../entrypoint", Body: []byte(DeniedText)}}},
		{Name: "duplicate support file", Entries: []Entry{benign, {Name: "support/data", Body: []byte("first")}, {Name: "support/./data", Body: []byte("second")}}},
		{Name: "old GNU sparse after entrypoint", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparseOldGNU, LogicalSize: 64}}},
		{Name: "PAX sparse 0.0 after entrypoint", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAX00, LogicalSize: 64}}},
		{Name: "PAX sparse 0.1 before entrypoint", Entries: []Entry{{Name: "support/sparse", Sparse: SparsePAX01, LogicalSize: 64}, benign}},
		{Name: "PAX sparse 1.0 after entrypoint", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAX10, LogicalSize: 64}}},
		{Name: "PAX sparse all-hole after entrypoint", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAXAllHole, LogicalSize: 64}}},
		{Name: "PAX sparse over policy budget", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAX01, LogicalSize: 16*1024*1024 + 4096}}},
		{Name: "PAX unknown sparse version", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAXUnknownVersion, LogicalSize: 64}}},
		{Name: "PAX unknown sparse key", Entries: []Entry{benign, {Name: "support/sparse", Sparse: SparsePAXUnknownKey, LogicalSize: 64}}},
	}
}

func longAlias() string { return strings.Repeat("support/../", 10) + "entrypoint" }

func SparseCases() []Case {
	var selected []Case
	for _, fixture := range Cases() {
		for _, entry := range fixture.Entries {
			if entry.Sparse != "" {
				selected = append(selected, fixture)
				break
			}
		}
	}
	return selected
}

func OnceOnlyCases() []Case {
	var selected []Case
	for _, fixture := range Cases() {
		if len(fixture.WantFiles) > 0 || len(fixture.WantDirs) > 0 {
			selected = append(selected, fixture)
		}
	}
	return selected
}

func Tar(entries []Entry, trailing []byte) ([]byte, error) {
	for _, entry := range entries {
		if entry.Sparse != "" {
			return mixedTar(entries, trailing)
		}
	}
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	for _, entry := range entries {
		typeflag := entry.Type
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.Name, Typeflag: typeflag, Mode: 0o755, Format: entry.Format}
		if typeflag == tar.TypeReg || typeflag == tar.TypeRegA {
			header.Size = int64(len(entry.Body))
		}
		if err := w.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write %q header: %w", entry.Name, err)
		}
		if len(entry.Body) != 0 {
			if _, err := w.Write(entry.Body); err != nil {
				return nil, fmt.Errorf("write %q body: %w", entry.Name, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	output.Write(trailing)
	return output.Bytes(), nil
}

// mixedTar writes ordinary entries with tar.Writer and sparse entries with
// literal raw headers. Go's tar.Writer deliberately omits GNU.sparse.* local
// PAX records, so it cannot produce the reader counterexamples by itself.
func mixedTar(entries []Entry, trailing []byte) ([]byte, error) {
	var output bytes.Buffer
	for _, entry := range entries {
		if entry.Sparse == "" {
			fragment, err := Tar([]Entry{entry}, nil)
			if err != nil {
				return nil, err
			}
			output.Write(fragment[:len(fragment)-1024])
			continue
		}
		fragment, err := rawSparseEntry(entry)
		if err != nil {
			return nil, err
		}
		output.Write(fragment)
	}
	output.Write(make([]byte, 1024))
	output.Write(trailing)
	return output.Bytes(), nil
}

func rawSparseEntry(entry Entry) ([]byte, error) {
	logical := entry.LogicalSize
	if logical <= 0 {
		return nil, fmt.Errorf("sparse fixture requires positive logical size")
	}
	if entry.Sparse == SparseOldGNU {
		header, err := rawHeader(entry.Name, tar.TypeGNUSparse, 0, true, logical)
		if err != nil {
			return nil, err
		}
		return header, nil
	}
	var records [][2]string
	var stored []byte
	switch entry.Sparse {
	case SparsePAX00:
		records = [][2]string{{"GNU.sparse.size", strconv.FormatInt(logical, 10)}, {"GNU.sparse.numblocks", "1"}, {"GNU.sparse.offset", "0"}, {"GNU.sparse.numbytes", "1"}}
		stored = []byte("A")
	case SparsePAX01:
		records = [][2]string{{"GNU.sparse.major", "0"}, {"GNU.sparse.minor", "1"}, {"GNU.sparse.size", strconv.FormatInt(logical, 10)}, {"GNU.sparse.numblocks", "1"}, {"GNU.sparse.map", "0,1"}}
		stored = []byte("A")
	case SparsePAX10, SparsePAXAllHole:
		records = [][2]string{{"GNU.sparse.major", "1"}, {"GNU.sparse.minor", "0"}, {"GNU.sparse.realsize", strconv.FormatInt(logical, 10)}, {"GNU.sparse.name", entry.Name}}
		stored = make([]byte, 512)
		if entry.Sparse == SparsePAXAllHole {
			copy(stored, []byte("0\n"))
		} else {
			copy(stored, []byte("1\n0\n1\n"))
			stored = append(stored, 'A')
		}
	case SparsePAXUnknownVersion:
		records = [][2]string{{"GNU.sparse.major", "9"}, {"GNU.sparse.minor", "9"}, {"GNU.sparse.realsize", strconv.FormatInt(logical, 10)}}
		stored = []byte("A")
	case SparsePAXUnknownKey:
		records = [][2]string{{"GNU.sparse.future", "1"}}
		stored = []byte("A")
	default:
		return nil, fmt.Errorf("unknown sparse fixture format %q", entry.Sparse)
	}
	var pax bytes.Buffer
	for _, record := range records {
		pax.WriteString(paxRecord(record[0], record[1]))
	}
	extension, err := rawHeader("PaxHeader", tar.TypeXHeader, int64(pax.Len()), false, 0)
	if err != nil {
		return nil, err
	}
	regular, err := rawHeader(entry.Name, tar.TypeReg, int64(len(stored)), false, 0)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Write(extension)
	writePadded(&output, pax.Bytes())
	output.Write(regular)
	writePadded(&output, stored)
	return output.Bytes(), nil
}

func paxRecord(key, value string) string {
	body := key + "=" + value + "\n"
	length := len(body) + 2
	for {
		next := len(body) + len(strconv.Itoa(length)) + 1
		if next == length {
			break
		}
		length = next
	}
	return strconv.Itoa(length) + " " + body
}

func rawHeader(name string, typeflag byte, size int64, gnu bool, logical int64) ([]byte, error) {
	if len(name) > 100 || size < 0 {
		return nil, fmt.Errorf("invalid raw fixture header")
	}
	b := make([]byte, 512)
	copy(b[:100], name)
	writeOctal(b[100:108], 0o755)
	writeOctal(b[108:116], 0)
	writeOctal(b[116:124], 0)
	writeOctal(b[124:136], size)
	writeOctal(b[136:148], 0)
	b[156] = typeflag
	if gnu {
		copy(b[257:263], "ustar ")
		copy(b[263:265], " \x00")
		writeOctal(b[483:495], logical)
	} else {
		copy(b[257:263], "ustar\x00")
		copy(b[263:265], "00")
	}
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	sum := 0
	for _, x := range b {
		sum += int(x)
	}
	copy(b[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	return b, nil
}

func writeOctal(field []byte, value int64) {
	for i := range field {
		field[i] = '0'
	}
	digits := strconv.FormatInt(value, 8)
	copy(field[len(field)-len(digits)-1:], digits)
	field[len(field)-1] = 0
}

func writePadded(output *bytes.Buffer, body []byte) {
	output.Write(body)
	if remainder := len(body) % 512; remainder != 0 {
		output.Write(make([]byte, 512-remainder))
	}
}

func Gzip(decoded []byte) ([]byte, error) {
	var output bytes.Buffer
	w := gzip.NewWriter(&output)
	if _, err := w.Write(decoded); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func Archive(entries []Entry, trailing []byte) ([]byte, error) {
	decoded, err := Tar(entries, trailing)
	if err != nil {
		return nil, err
	}
	return Gzip(decoded)
}
