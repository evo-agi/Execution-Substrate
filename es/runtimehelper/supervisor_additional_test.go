package runtimehelper

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestParseSupervisorArgsRequiresFieldsAndPreservesWorkloadArgv(t *testing.T) {
	_, err := parseSupervisorArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "--payload-archive is required") {
		t.Fatalf("expected missing payload-archive validation, got %v", err)
	}

	cfg, err := parseSupervisorArgs([]string{
		"--payload-archive", "/tmp/payload.tgz",
		"--work-dir", "/execution/run/work",
		"--result-dir", "/execution/run/result",
		"--entrypoint", "/execution/run/work/entrypoint",
		"--timeout-seconds", "17",
		"--",
		"--flag",
		"arg",
	})
	if err != nil {
		t.Fatalf("parse supervisor args: %v", err)
	}
	if cfg.payloadArchive != "/tmp/payload.tgz" || cfg.workDir != "/execution/run/work" || cfg.resultDir != "/execution/run/result" || cfg.entrypoint != "/execution/run/work/entrypoint" {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}
	if cfg.timeoutSeconds != 17 {
		t.Fatalf("expected parsed timeout, got %d", cfg.timeoutSeconds)
	}
	if len(cfg.workloadArgv) != 2 || cfg.workloadArgv[0] != "--flag" || cfg.workloadArgv[1] != "arg" {
		t.Fatalf("expected workload argv to be preserved, got %#v", cfg.workloadArgv)
	}
}

func TestArchiveDestinationPathRejectsAbsoluteAndEscapingPaths(t *testing.T) {
	root := t.TempDir()

	validPath, err := archiveDestinationPath(root, "bin/entrypoint")
	if err != nil {
		t.Fatalf("expected relative workload path to succeed, got %v", err)
	}
	if validPath != filepath.Join(root, "bin", "entrypoint") {
		t.Fatalf("unexpected resolved workload path %q", validPath)
	}

	_, err = archiveDestinationPath(root, "/etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "must be relative") {
		t.Fatalf("expected absolute path rejection, got %v", err)
	}

	_, err = archiveDestinationPath(root, "../escape")
	if err == nil || !strings.Contains(err.Error(), "escapes the work tree") {
		t.Fatalf("expected escape rejection, got %v", err)
	}
}

func TestExtractWorkloadArchiveExtractsFilesAndRejectsUnsupportedEntries(t *testing.T) {
	successArchive := writeSupervisorArchive(t,
		supervisorArchiveEntry{name: "bin", typeflag: tar.TypeDir, mode: 0o755},
		supervisorArchiveEntry{name: "bin/entrypoint", typeflag: tar.TypeReg, mode: 0o755, body: []byte("#!/bin/sh\necho ok\n")},
	)
	destination := t.TempDir()
	if err := extractWorkloadArchive(successArchive, destination); err != nil {
		t.Fatalf("extract workload archive: %v", err)
	}
	entrypointPath := filepath.Join(destination, "bin", "entrypoint")
	content, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("read extracted entrypoint: %v", err)
	}
	if string(content) != "#!/bin/sh\necho ok\n" {
		t.Fatalf("unexpected extracted content %q", string(content))
	}

	unsupportedArchive := writeSupervisorArchive(t,
		supervisorArchiveEntry{name: "bin/link", typeflag: tar.TypeSymlink, linkname: "entrypoint", mode: 0o777},
	)
	err = extractWorkloadArchive(unsupportedArchive, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("expected unsupported entry type error, got %v", err)
	}
}

func TestWorkloadExitErrorMapsExitCodeAndSignal(t *testing.T) {
	exitCmd := exec.Command("/bin/sh", "-c", "exit 7")
	exitErr := runCommandForExitError(t, exitCmd)
	mapped := workloadExitError(exitErr)

	var codeErr *exitError
	if !errors.As(mapped, &codeErr) {
		t.Fatalf("expected exitError, got %T %v", mapped, mapped)
	}
	if codeErr.code != 7 || !strings.Contains(codeErr.Error(), "code 7") {
		t.Fatalf("expected exit code 7 mapping, got %+v", codeErr)
	}

	signalCmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	signalErr := runCommandForExitError(t, signalCmd)
	mapped = workloadExitError(signalErr)
	if !errors.As(mapped, &codeErr) {
		t.Fatalf("expected signal mapping to exitError, got %T %v", mapped, mapped)
	}
	if codeErr.code != 128+int(syscall.SIGTERM) || !strings.Contains(codeErr.Error(), "terminated by signal") {
		t.Fatalf("expected SIGTERM mapping, got %+v", codeErr)
	}
}

type supervisorArchiveEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	linkname string
}

func writeSupervisorArchive(t *testing.T, entries ...supervisorArchiveEntry) string {
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

	archivePath := filepath.Join(t.TempDir(), "payload.tar.gz")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
		t.Fatalf("write workload archive: %v", err)
	}
	return archivePath
}

func runCommandForExitError(t *testing.T, cmd *exec.Cmd) error {
	t.Helper()

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected command to fail: %#v", cmd.Args)
	}
	return err
}
