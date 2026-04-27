package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
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
		t.Fatalf("expected mount conflict error, got %+v", err)
	}
}

func TestExtractRuntimeMountArchiveExtractsRegularFilesWithinLimits(t *testing.T) {
	destinationRoot := t.TempDir()
	archiveBytes := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "config", typeflag: tar.TypeDir, mode: 0o755},
		runtimeMountArchiveEntry{name: "config/settings.env", body: []byte("KEY=value\n"), typeflag: tar.TypeReg, mode: 0o644},
	)

	extractedBytes, err := extractRuntimeMountArchive(destinationRoot, archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatalf("extract runtime mount archive: %v", err)
	}
	if extractedBytes != int64(len("KEY=value\n")) {
		t.Fatalf("expected extracted byte count %d, got %d", len("KEY=value\n"), extractedBytes)
	}

	content, err := os.ReadFile(filepath.Join(destinationRoot, "config", "settings.env"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "KEY=value\n" {
		t.Fatalf("expected extracted file contents to round-trip, got %q", string(content))
	}
	if info, err := os.Stat(filepath.Join(destinationRoot, "config", "settings.env")); err != nil {
		t.Fatalf("stat extracted file: %v", err)
	} else if info.Mode().Perm() != stableStageFileMode {
		t.Fatalf("expected extracted file mode %o, got %o", stableStageFileMode, info.Mode().Perm())
	}
}

func TestExtractRuntimeMountArchiveRejectsPathTraversalAndSymlinks(t *testing.T) {
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
			_, err := extractRuntimeMountArchive(t.TempDir(), tc.archive, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
			if err == nil {
				t.Fatalf("expected archive extraction to fail for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errorSubstr) {
				t.Fatalf("expected %q error, got %v", tc.errorSubstr, err)
			}
		})
	}
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
			t.Fatalf("write tar header for %q: %v", entry.name, err)
		}
		if len(entry.body) > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatalf("write tar body for %q: %v", entry.name, err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return archive.Bytes()
}
