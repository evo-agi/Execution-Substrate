package app_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockVaultCompatServerOptions struct {
	bindAddress string
	authMount   string
	role        string
	audience    string
	subject     string
	secretPath  string
	secretValue string
}

type mockVaultCompatServer struct {
	listener    net.Listener
	server      *http.Server
	address     string
	url         string
	loginPath   string
	secretPath  string
	clientToken string

	mu              sync.Mutex
	loginCount      int
	secretReadCount int
}

func startMockVaultCompatServer(t *testing.T, rootDir string, opts mockVaultCompatServerOptions) *mockVaultCompatServer {
	t.Helper()

	bindAddress := firstNonEmpty(opts.bindAddress, "127.0.0.1")
	authMount := firstNonEmpty(opts.authMount, "jwt")
	role := firstNonEmpty(opts.role, "service_execution")
	audience := firstNonEmpty(opts.audience, "vault")
	secretPath := strings.TrimPrefix(firstNonEmpty(opts.secretPath, "secret/data/runtime-identity-vault-login"), "/")
	secretValue := firstNonEmpty(opts.secretValue, "runtime-identity-ok")

	ca, caKey, _ := createCertificateAuthority(t, "mock-vault-ca")
	certPath, keyPath := writeLeafCertificateFiles(t, rootDir, "mock-vault", ca, caKey, "mock-vault.internal", nil)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load mock vault tls key pair: %v", err)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(bindAddress, "0"))
	if err != nil {
		t.Fatalf("listen for mock vault: %v", err)
	}

	server := &mockVaultCompatServer{
		loginPath:   "/v1/auth/" + authMount + "/login",
		secretPath:  "/v1/" + secretPath,
		clientToken: "runtime-identity-vault-token",
		address:     listener.Addr().String(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON := func(statusCode int, payload any) {
			body, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			_, _ = w.Write(body)
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == server.loginPath:
			var payload struct {
				Role string `json:"role"`
				JWT  string `json:"jwt"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(http.StatusBadRequest, map[string]any{"errors": []string{"invalid json"}})
				return
			}
			if strings.TrimSpace(payload.Role) != role {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"invalid role"}})
				return
			}
			claims, err := decodeJWTClaimsUnverified(strings.TrimSpace(payload.JWT))
			if err != nil {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{fmt.Sprintf("invalid jwt: %v", err)}})
				return
			}
			if !jwtAudienceContains(claims, audience) {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"audience mismatch"}})
				return
			}
			if strings.TrimSpace(opts.subject) != "" && strings.TrimSpace(claims["sub"]) != strings.TrimSpace(opts.subject) {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"subject mismatch"}})
				return
			}
			server.mu.Lock()
			server.loginCount++
			server.mu.Unlock()
			writeJSON(http.StatusOK, map[string]any{
				"auth": map[string]any{
					"client_token": server.clientToken,
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == server.secretPath:
			if strings.TrimSpace(r.Header.Get("X-Vault-Token")) != server.clientToken {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"invalid token"}})
				return
			}
			server.mu.Lock()
			server.secretReadCount++
			server.mu.Unlock()
			writeJSON(http.StatusOK, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"message": secretValue,
					},
				},
			})
		default:
			writeJSON(http.StatusNotFound, map[string]any{"errors": []string{"not found"}})
		}
	})

	server.server = &http.Server{Handler: handler}
	server.listener = tls.NewListener(listener, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	})
	server.url = "https://" + server.address

	go func() {
		_ = server.server.Serve(server.listener)
	}()

	t.Cleanup(func() { server.stop(t) })
	return server
}

func (s *mockVaultCompatServer) stop(t *testing.T) {
	t.Helper()
	if s == nil || s.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
}

func (s *mockVaultCompatServer) loginAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginCount
}

func (s *mockVaultCompatServer) secretReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secretReadCount
}

func (s *mockVaultCompatServer) port(t *testing.T) int {
	t.Helper()
	_, port, err := net.SplitHostPort(s.address)
	if err != nil {
		t.Fatalf("split mock vault address: %v", err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse mock vault port: %v", err)
	}
	return value
}

func decodeJWTClaimsUnverified(token string) (map[string]string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("jwt must contain at least two segments")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt payload: %w", err)
	}

	claims := map[string]string{}
	for key, value := range rawClaims {
		switch typed := value.(type) {
		case string:
			claims[key] = typed
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				values = append(values, fmt.Sprint(item))
			}
			claims[key] = strings.Join(values, ",")
		default:
			claims[key] = fmt.Sprint(value)
		}
	}
	return claims, nil
}

func jwtAudienceContains(claims map[string]string, audience string) bool {
	for _, candidate := range strings.Split(strings.TrimSpace(claims["aud"]), ",") {
		if strings.TrimSpace(candidate) == audience {
			return true
		}
	}
	return false
}

func dockerBridgeGateway(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("slice 1 useful credential flow requires a host probe listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("runtime-identity-host-probe"))
		}),
	}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	candidates := []string{}
	command := exec.Command("docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
	command.Dir = filepath.Clean(filepath.Join(executionPlatformRepoRoot(t)))
	if output, err := command.CombinedOutput(); err == nil {
		if gateway := strings.TrimSpace(string(output)); gateway != "" && net.ParseIP(gateway) != nil {
			candidates = append(candidates, gateway)
		}
	}
	candidates = append(candidates, "host.docker.internal", "gateway.docker.internal")

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}

		probe := exec.Command("docker", "run", "--rm", "--network", "bridge", "alpine:3.20", "sh", "-ceu", fmt.Sprintf("wget -q -O - http://%s:%d", candidate, port))
		probe.Dir = filepath.Clean(filepath.Join(executionPlatformRepoRoot(t)))
		output, err := probe.CombinedOutput()
		if err == nil && strings.TrimSpace(string(output)) == "runtime-identity-host-probe" {
			return candidate
		}
	}

	t.Skip("slice 1 useful credential flow requires a host address that is reachable from bridge-networked Docker workloads")
	return ""
}
