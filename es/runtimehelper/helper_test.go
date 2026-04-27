package runtimehelper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimePathsFromEnvironmentDerivesWorkspaceAndInternalPaths(t *testing.T) {
	t.Setenv(identityEndpointEnvKey, "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock")

	paths, err := runtimePathsFromEnvironment()
	if err != nil {
		t.Fatalf("runtime paths from environment: %v", err)
	}
	if paths.endpointPath != "/run/es-runtime-identity/run-0123456789abcdef/public.sock" {
		t.Fatalf("unexpected endpoint path %q", paths.endpointPath)
	}
	if paths.workspaceDir != "/run/es-runtime-identity/run-0123456789abcdef" {
		t.Fatalf("unexpected workspace dir %q", paths.workspaceDir)
	}
	if paths.internalDir != filepath.Join(paths.workspaceDir, internalDirName) {
		t.Fatalf("expected internal dir under workspace dir, got %q", paths.internalDir)
	}
	if paths.spireSocket != filepath.Join(paths.internalDir, spireSocketName) {
		t.Fatalf("expected helper-private spire socket path, got %q", paths.spireSocket)
	}
}

func TestRuntimePathsFromEnvironmentRejectsNonUnixEndpoint(t *testing.T) {
	t.Setenv(identityEndpointEnvKey, "https://vault.internal/token")

	_, err := runtimePathsFromEnvironment()
	if err == nil {
		t.Fatalf("expected non-unix endpoint to fail validation")
	}
	if !strings.Contains(err.Error(), "must use unix://") {
		t.Fatalf("expected unix endpoint validation error, got %v", err)
	}
}

func TestHelperServerHandleConnectionReturnsCachedJWTForSupportedRequest(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
	})

	server := &helperServer{
		token: cachedToken{
			jwt:    "header.payload.signature",
			expiry: time.Now().Add(time.Minute),
		},
	}
	go server.handleConnection(serverConn)

	if _, err := clientConn.Write([]byte("{\"kind\":\"jwt_svid\",\"target\":\"workload_vault\"}\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	responseLine, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var response endpointResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(responseLine)), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.JWT != "header.payload.signature" {
		t.Fatalf("expected cached jwt response, got %#v", response)
	}
	if response.Error != "" {
		t.Fatalf("did not expect endpoint error, got %#v", response)
	}
}

func TestHelperServerHandleConnectionRejectsUnsupportedRequest(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
	})

	server := &helperServer{
		token: cachedToken{
			jwt:    "header.payload.signature",
			expiry: time.Now().Add(time.Minute),
		},
	}
	go server.handleConnection(serverConn)

	if _, err := clientConn.Write([]byte("{\"kind\":\"jwt_svid\",\"target\":\"unexpected\"}\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	responseLine, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var response endpointResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(responseLine)), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error != "unsupported_request" {
		t.Fatalf("expected unsupported_request error, got %#v", response)
	}
}

func TestWaitForHelperReadinessReturnsHelpfulHelperFailure(t *testing.T) {
	helperErrCh := make(chan error, 1)
	helperErrCh <- fmt.Errorf("boom")

	err := waitForHelperReadiness(filepath.Join(t.TempDir(), "missing.sock"), helperErrCh)
	if err == nil {
		t.Fatalf("expected helper readiness to fail when helper exits early")
	}
	if !strings.Contains(err.Error(), "failed before readiness") {
		t.Fatalf("expected helper failure context, got %v", err)
	}
}

func TestWaitForHelperReadinessReturnsWhenEndpointServesJWT(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "es-runtimehelper-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(rootDir)
	})

	socketPath := filepath.Join(rootDir, "identity.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	defer listener.Close()

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = bufio.NewReader(connection).ReadString('\n')
		_, _ = connection.Write(appendJSONLine(endpointResponse{
			JWT:       "header.payload.signature",
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		}))
	}()

	if err := waitForHelperReadiness(socketPath, make(chan error)); err != nil {
		t.Fatalf("wait for helper readiness: %v", err)
	}
}

func TestWaitForSPIRESocketReadyFailsClosedWhenSocketNeverAppears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	err := waitForSPIRESocketReady(ctx, filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil {
		t.Fatal("expected wait for missing SPIRE socket to fail")
	}
}
