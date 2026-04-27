package runtimehelper

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeHelperPrivateSPIRESocketCreatesStableAliasForMountedSourceDir(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "es-runtimehelper-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(rootDir)
	})
	internalDir := filepath.Join(rootDir, "internal")
	if err := os.MkdirAll(internalDir, 0o700); err != nil {
		t.Fatalf("mkdir internal dir: %v", err)
	}
	sourceDir := filepath.Join(internalDir, "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}

	sourceSocket := filepath.Join(sourceDir, "api.sock")
	listener, err := net.Listen("unix", sourceSocket)
	if err != nil {
		t.Fatalf("listen on source socket: %v", err)
	}
	defer listener.Close()

	paths := runtimePaths{
		internalDir:    internalDir,
		spireSourceDir: sourceDir,
		spireSocket:    filepath.Join(internalDir, spireSocketName),
	}
	if err := materializeHelperPrivateSPIRESocket(paths); err != nil {
		t.Fatalf("materialize helper-private spire socket: %v", err)
	}

	linkTarget, err := os.Readlink(paths.spireSocket)
	if err != nil {
		t.Fatalf("read helper-private spire socket symlink: %v", err)
	}
	if linkTarget != sourceSocket {
		t.Fatalf("expected helper-private spire socket link target %q, got %q", sourceSocket, linkTarget)
	}

	info, err := os.Stat(paths.spireSocket)
	if err != nil {
		t.Fatalf("stat helper-private spire socket alias: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected helper-private alias to resolve to a unix socket, got mode %v", info.Mode())
	}
}

func TestMaterializeHelperPrivateSPIRESocketFailsClosedWhenMountedSourceDirHasNoSocket(t *testing.T) {
	rootDir := t.TempDir()
	internalDir := filepath.Join(rootDir, "internal")
	if err := os.MkdirAll(internalDir, 0o700); err != nil {
		t.Fatalf("mkdir internal dir: %v", err)
	}
	sourceDir := filepath.Join(internalDir, "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "note.txt"), []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	err := materializeHelperPrivateSPIRESocket(runtimePaths{
		internalDir:    internalDir,
		spireSourceDir: sourceDir,
		spireSocket:    filepath.Join(internalDir, spireSocketName),
	})
	if err == nil {
		t.Fatal("expected missing SPIRE socket source to fail")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "does not contain a unix socket") {
		t.Fatalf("expected explicit missing-socket error, got %v", err)
	}
}
