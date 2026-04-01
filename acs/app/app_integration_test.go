package app_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-platform/acs/app"
	"execution-platform/acs/catalog"
	"execution-platform/acs/config"
)

func TestLoadConfigRejectsMissingFile(t *testing.T) {
	t.Parallel()

	_, err := config.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("expected missing-file error, got %v", err)
	}
}

func TestLoadConfigRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "decode config") {
		t.Fatalf("expected malformed-json error, got %v", err)
	}
}

func TestLoadConfigRejectsTrailingData(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cfg := buildConfig(fixture, map[string]catalog.AssignmentKey{
		"sha256:vault": catalog.RequiredWorkloadZoneVault(),
	})

	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	payload = append(payload, []byte("\n{\"trailing\":true}\n")...)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing data after first JSON document") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}

func TestNewRejectsMissingRequiredWorkloadZoneAssignment(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cfgPath := writeConfig(t, fixture, map[string]catalog.AssignmentKey{
		"sha256:artifact": {
			IdentityKind: catalog.AssignmentServiceDockerConfig,
			Service:      "execution",
			Version:      "1.0.0",
			Instance:     "instance-0",
		},
	})

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(cfg)
	if err == nil || !strings.Contains(err.Error(), "missing required seed assignments") {
		t.Fatalf("expected missing required assignment error, got %v", err)
	}
}

func TestNewRejectsDuplicateCanonicalAssignments(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cfgPath := writeConfig(t, fixture, map[string]catalog.AssignmentKey{
		"sha256:a": {
			IdentityKind: catalog.AssignmentServiceDockerConfig,
			Service:      "execution",
			Version:      "1.0.0",
			Instance:     "instance-0",
		},
		"sha256:b": {
			IdentityKind: catalog.AssignmentServiceDockerConfig,
			Service:      "execution",
			Version:      "1.0.0",
			Instance:     "instance-0",
		},
		"sha256:vault": catalog.RequiredWorkloadZoneVault(),
	})

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate identity assignment") {
		t.Fatalf("expected duplicate assignment error, got %v", err)
	}
}

func TestSeedAndSnapshotDigestsAreDeterministicAcrossJSONFieldOrder(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	dir := t.TempDir()
	configA := filepath.Join(dir, "a.json")
	configB := filepath.Join(dir, "b.json")

	rawA := `{
  "http": {"bind_address":"127.0.0.1","port":0,"read_timeout_seconds":5,"write_timeout_seconds":5,"shutdown_timeout_seconds":5},
  "tls": {"cert_file":"` + fixture.serverCertPath + `","key_file":"` + fixture.serverKeyPath + `","client_ca_file":"` + fixture.caPath + `"},
  "authorization": {"allowed_spiffe_path_prefixes":["service/execution","service/deployment","service/credential-governance","operator"]},
  "catalog": {
    "seed_artifact_digests": {
      "sha256:vault": {"identity_kind":"workload_zone_vault"},
      "sha256:svc": {"identity_kind":"service_docker_config","service":"execution/service","version":"1.0.0","instance":"instance-0"}
    }
  },
  "audit": {"mode":"noop"}
}`
	rawB := `{
  "audit": {"mode":"noop"},
  "catalog": {
    "seed_artifact_digests": {
      "sha256:svc": {"instance":"instance-0","version":"1.0.0","service":"execution/service","identity_kind":"service_docker_config"},
      "sha256:vault": {"identity_kind":"workload_zone_vault"}
    }
  },
  "authorization": {"allowed_spiffe_path_prefixes":["service/execution","service/deployment","service/credential-governance","operator"]},
  "tls": {"client_ca_file":"` + fixture.caPath + `","key_file":"` + fixture.serverKeyPath + `","cert_file":"` + fixture.serverCertPath + `"},
  "http": {"shutdown_timeout_seconds":5,"write_timeout_seconds":5,"read_timeout_seconds":5,"port":0,"bind_address":"127.0.0.1"}
}`

	if err := os.WriteFile(configA, []byte(rawA), 0o600); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(configB, []byte(rawB), 0o600); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	loadedA, err := config.Load(configA)
	if err != nil {
		t.Fatalf("load config A: %v", err)
	}
	loadedB, err := config.Load(configB)
	if err != nil {
		t.Fatalf("load config B: %v", err)
	}

	appA, err := app.New(loadedA)
	if err != nil {
		t.Fatalf("build app A: %v", err)
	}
	appB, err := app.New(loadedB)
	if err != nil {
		t.Fatalf("build app B: %v", err)
	}

	if appA.SeedDigest() != appB.SeedDigest() {
		t.Fatalf("seed digests differ: %s vs %s", appA.SeedDigest(), appB.SeedDigest())
	}
	if appA.SnapshotDigest() != appB.SnapshotDigest() {
		t.Fatalf("snapshot digests differ: %s vs %s", appA.SnapshotDigest(), appB.SnapshotDigest())
	}
}

func TestAllLookupRoutesReturnExpectedResponses(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	cases := []struct {
		name       string
		path       string
		clientID   string
		digest     string
		assignment catalog.AssignmentKey
	}{
		{
			name:     "deployment stage",
			path:     "/v1/configuration/deployment/stage/prod",
			clientID: "service/deployment",
			digest:   "sha256:deployment-stage",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentDeploymentStageConfig,
				Stage:        "prod",
			},
		},
		{
			name:     "deployment service",
			path:     "/v1/configuration/deployment/service/prod/service%2Fwith%20spaces/1.2.3",
			clientID: "service/deployment",
			digest:   "sha256:deployment-service",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentDeploymentServiceConfig,
				Stage:        "prod",
				Service:      "service/with spaces",
				Version:      "1.2.3",
			},
		},
		{
			name:     "deployment dependency",
			path:     "/v1/configuration/deployment/dependency/setup",
			clientID: "service/deployment",
			digest:   "sha256:deployment-dependency",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentDeploymentStageDependency,
				Stage:        "setup",
			},
		},
		{
			name:     "service docker",
			path:     "/v1/configuration/service/execution%2Fservice/1.0.0/instance-0:docker",
			clientID: "service/execution",
			digest:   "sha256:service-docker",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentServiceDockerConfig,
				Service:      "execution/service",
				Version:      "1.0.0",
				Instance:     "instance-0",
			},
		},
		{
			name:     "service application",
			path:     "/v1/configuration/service/execution/1.0.0/instance-0:application",
			clientID: "service/execution",
			digest:   "sha256:service-application",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentServiceApplicationConfig,
				Service:      "execution",
				Version:      "1.0.0",
				Instance:     "instance-0",
			},
		},
		{
			name:     "service instances",
			path:     "/v1/configuration/service/execution/1.0.0:instances",
			clientID: "service/execution",
			digest:   "sha256:service-instances",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentServiceInstances,
				Service:      "execution",
				Version:      "1.0.0",
			},
		},
		{
			name:     "sidecar docker",
			path:     "/v1/configuration/sidecar/execution/1.0.0/vault-agent:docker",
			clientID: "service/execution",
			digest:   "sha256:sidecar-docker",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentSidecarDockerConfig,
				Service:      "execution",
				Version:      "1.0.0",
				Instance:     "vault-agent",
			},
		},
		{
			name:     "sidecar instances",
			path:     "/v1/configuration/sidecar/execution/1.0.0:instances",
			clientID: "service/execution",
			digest:   "sha256:sidecar-instances",
			assignment: catalog.AssignmentKey{
				IdentityKind: catalog.AssignmentSidecarInstances,
				Service:      "execution",
				Version:      "1.0.0",
			},
		},
		{
			name:       "workload zone vault",
			path:       "/v1/configuration/workload-zone/vault",
			clientID:   "service/credential-governance",
			digest:     "sha256:vault",
			assignment: catalog.RequiredWorkloadZoneVault(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, tc.path, fixture.clientTLSConfig(t, tc.clientID))
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", response.StatusCode)
			}

			var payload struct {
				Success               bool                  `json:"success"`
				Digest                string                `json:"digest"`
				Assignment            catalog.AssignmentKey `json:"assignment"`
				CatalogSnapshotDigest string                `json:"catalog_snapshot_digest"`
				Error                 string                `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if !payload.Success {
				t.Fatalf("expected success response, got %+v", payload)
			}
			if payload.Digest != tc.digest {
				t.Fatalf("expected digest %q, got %q", tc.digest, payload.Digest)
			}
			if payload.Assignment != tc.assignment {
				t.Fatalf("expected assignment %+v, got %+v", tc.assignment, payload.Assignment)
			}
			if payload.CatalogSnapshotDigest == "" {
				t.Fatal("expected non-empty catalog_snapshot_digest")
			}
			if payload.Error != "" {
				t.Fatalf("expected empty error, got %q", payload.Error)
			}
		})
	}
}

func TestLookupUnknownAssignmentReturnsNotFound(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, map[string]catalog.AssignmentKey{
		"sha256:vault": catalog.RequiredWorkloadZoneVault(),
	})

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/configuration/service/execution/1.0.0/instance-0:docker", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.StatusCode)
	}

	var payload struct {
		Success               bool                  `json:"success"`
		Assignment            catalog.AssignmentKey `json:"assignment"`
		CatalogSnapshotDigest string                `json:"catalog_snapshot_digest"`
		Error                 string                `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Success {
		t.Fatalf("expected unsuccessful response: %+v", payload)
	}
	if payload.Assignment != (catalog.AssignmentKey{
		IdentityKind: catalog.AssignmentServiceDockerConfig,
		Service:      "execution",
		Version:      "1.0.0",
		Instance:     "instance-0",
	}) {
		t.Fatalf("unexpected assignment payload: %+v", payload.Assignment)
	}
	if payload.CatalogSnapshotDigest == "" || !strings.Contains(payload.Error, "No artifact digest mapping found") {
		t.Fatalf("unexpected not-found response: %+v", payload)
	}
}

func TestInvalidConfigurationLookupPathsReturnNotFound(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	paths := []string{
		"/v1/configuration/service/execution/1.0.0",
		"/v1/configuration/service/execution/1.0.0/instance-0:yaml",
		"/v1/configuration/unknown",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, path, fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()

			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("expected 404, got %d", response.StatusCode)
			}
		})
	}
}

func TestMalformedPercentEncodingReturnsBadRequest(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	response := doRawRequest(t, service.Addr(), fixture.clientTLSConfig(t, "service/execution"), http.MethodGet, "/v1/configuration/service/%ZZ/1.0.0/instance-0:docker")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d with body %q", response.StatusCode, response.Body)
	}
}

func TestWrongMethodsReturnMethodNotAllowed(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	cases := []struct {
		name   string
		method string
		path   string
		config *tls.Config
	}{
		{
			name:   "post health",
			method: http.MethodPost,
			path:   "/health",
			config: fixture.baseClientTLSConfig(t),
		},
		{
			name:   "post protected route without client cert",
			method: http.MethodPost,
			path:   "/v1/configuration/workload-zone/vault",
			config: fixture.baseClientTLSConfig(t),
		},
		{
			name:   "put protected route with client cert",
			method: http.MethodPut,
			path:   "/v1/configuration/workload-zone/vault",
			config: fixture.clientTLSConfig(t, "service/execution"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), tc.method, tc.path, tc.config)
			defer response.Body.Close()

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d", response.StatusCode)
			}
			if allow := response.Header.Get("Allow"); !strings.Contains(allow, http.MethodGet) {
				t.Fatalf("expected Allow header to mention GET, got %q", allow)
			}
		})
	}
}

func TestHeadRoutesAreSupported(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	cases := []struct {
		name   string
		path   string
		config *tls.Config
	}{
		{
			name:   "health",
			path:   "/health",
			config: fixture.baseClientTLSConfig(t),
		},
		{
			name:   "protected route",
			path:   "/v1/configuration/workload-zone/vault",
			config: fixture.clientTLSConfig(t, "service/execution"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodHead, tc.path, tc.config)
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", response.StatusCode)
			}

			body := mustReadBody(t, response.Body)
			if len(body) != 0 {
				t.Fatalf("expected empty HEAD body, got %q", string(body))
			}
		})
	}
}

func TestProtectedRouteWithoutClientCertReturnsUnauthorizedWithExactBody(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/configuration/workload-zone/vault", fixture.baseClientTLSConfig(t))
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}

	body := mustReadBody(t, response.Body)
	if string(body) != "Authenticated caller identity required" {
		t.Fatalf("expected exact 401 body, got %q", string(body))
	}
}

func TestProtectedRouteWithUnauthorizedClientReturnsForbiddenWithExactBody(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/configuration/workload-zone/vault", fixture.clientTLSConfig(t, "service/execution-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}

	body := mustReadBody(t, response.Body)
	if string(body) != "Caller not authorized for this operation" {
		t.Fatalf("expected exact 403 body, got %q", string(body))
	}
}

func TestHealthReturnsHealthyWhenStarted(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, fullSeedAssignments())

	response := doRequest(t, service.Addr(), http.MethodGet, "/health", fixture.baseClientTLSConfig(t))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Status                string `json:"status"`
		Ready                 bool   `json:"ready"`
		Service               string `json:"service"`
		CacheEntries          int    `json:"cache_entries"`
		CatalogSeedDigest     string `json:"catalog_seed_digest"`
		CatalogSnapshotDigest string `json:"catalog_snapshot_digest"`
		AdditionalProperties  struct {
			Dependencies struct {
				Audit string `json:"audit"`
			} `json:"dependencies"`
			Readiness struct {
				CacheInitialized        string `json:"cache_initialized"`
				RequiredSeedAssignments string `json:"required_seed_assignments"`
				CatalogSeedDigest       string `json:"catalog_seed_digest"`
				CatalogSnapshotDigest   string `json:"catalog_snapshot_digest"`
			} `json:"readiness"`
		} `json:"additional_properties"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if payload.Status != "healthy" || !payload.Ready || payload.Service != "artifact-catalog" {
		t.Fatalf("unexpected health payload: %+v", payload)
	}
	if payload.CacheEntries != len(fullSeedAssignments()) || payload.CatalogSeedDigest == "" || payload.CatalogSnapshotDigest == "" {
		t.Fatalf("unexpected health payload: %+v", payload)
	}
	if payload.AdditionalProperties.Dependencies.Audit != "healthy" {
		t.Fatalf("unexpected audit health: %+v", payload)
	}
	if payload.AdditionalProperties.Readiness.CacheInitialized != "ready" ||
		payload.AdditionalProperties.Readiness.RequiredSeedAssignments != "ready" ||
		payload.AdditionalProperties.Readiness.CatalogSeedDigest != "ready" ||
		payload.AdditionalProperties.Readiness.CatalogSnapshotDigest != "ready" {
		t.Fatalf("unexpected readiness payload: %+v", payload)
	}
}

type tlsFixture struct {
	caPath         string
	serverCertPath string
	serverKeyPath  string
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
}

type rawHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()

	dir := t.TempDir()

	caCert, caKey, caCertPEM := createCertificateAuthority(t)
	serverCertPEM, serverKeyPEM := createLeafCertificate(t, caCert, caKey, certificateRequest{
		commonName: "artifact-catalog.internal",
		dnsNames:   []string{"localhost"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1")},
	})

	fixture := tlsFixture{
		caPath:         filepath.Join(dir, "ca.pem"),
		serverCertPath: filepath.Join(dir, "server.pem"),
		serverKeyPath:  filepath.Join(dir, "server.key"),
		caCert:         caCert,
		caKey:          caKey,
	}

	writePEMFile(t, fixture.caPath, caCertPEM)
	writePEMFile(t, fixture.serverCertPath, serverCertPEM)
	writePEMFile(t, fixture.serverKeyPath, serverKeyPEM)

	return fixture
}

func (f tlsFixture) baseClientTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(f.caPath)
	if err != nil {
		t.Fatalf("read ca pem: %v", err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("append ca pem: no valid certificates found")
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

func (f tlsFixture) clientTLSConfig(t *testing.T, spiffePath string) *tls.Config {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, f.caCert, f.caKey, certificateRequest{
		commonName: "client",
		uris:       []string{"spiffe://monolith.internal/" + spiffePath},
		clientAuth: true,
	})

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}

	cfg := f.baseClientTLSConfig(t)
	cfg.Certificates = []tls.Certificate{certificate}
	return cfg
}

func startTestApp(t *testing.T, fixture tlsFixture, assignments map[string]catalog.AssignmentKey) *app.App {
	t.Helper()

	cfgPath := writeConfig(t, fixture, assignments)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	service, err := app.New(cfg)
	if err != nil {
		t.Fatalf("build app: %v", err)
	}

	if _, err := service.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	waitForHealth(t, service.Addr(), fixture.baseClientTLSConfig(t))

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown app: %v", err)
		}
	})

	return service
}

func waitForHealth(t *testing.T, addr string, tlsConfig *tls.Config) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := makeClient(tlsConfig).Get("https://" + addr + "/health")
		if err == nil {
			var payload struct {
				Ready bool `json:"ready"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && payload.Ready {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("server at %s did not become ready in time", addr)
}

func doRequest(t *testing.T, addr string, method string, path string, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	request, err := http.NewRequest(method, "https://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}

	response, err := makeClient(tlsConfig).Do(request)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, path, err)
	}

	return response
}

func doRawRequest(t *testing.T, addr string, tlsConfig *tls.Config, method string, rawPath string) rawHTTPResponse {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatalf("raw tls dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, rawPath, addr); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	defer response.Body.Close()

	body := mustReadBody(t, response.Body)
	return rawHTTPResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       string(body),
	}
}

func makeClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}
}

func buildConfig(fixture tlsFixture, assignments map[string]catalog.AssignmentKey) config.Config {
	return config.Config{
		HTTP: config.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: config.TLSConfig{
			CertFile:     fixture.serverCertPath,
			KeyFile:      fixture.serverKeyPath,
			ClientCAFile: fixture.caPath,
		},
		Authorization: config.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{
				"service/execution",
				"service/deployment",
				"service/credential-governance",
				"operator",
			},
		},
		Catalog: config.CatalogConfig{
			SeedArtifactDigests: assignments,
		},
		Audit: config.AuditConfig{
			Mode: "noop",
		},
	}
}

func writeConfig(t *testing.T, fixture tlsFixture, assignments map[string]catalog.AssignmentKey) string {
	t.Helper()

	payload, err := json.MarshalIndent(buildConfig(fixture, assignments), "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "acs.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}

func fullSeedAssignments() map[string]catalog.AssignmentKey {
	return map[string]catalog.AssignmentKey{
		"sha256:deployment-stage": {
			IdentityKind: catalog.AssignmentDeploymentStageConfig,
			Stage:        "prod",
		},
		"sha256:deployment-service": {
			IdentityKind: catalog.AssignmentDeploymentServiceConfig,
			Stage:        "prod",
			Service:      "service/with spaces",
			Version:      "1.2.3",
		},
		"sha256:deployment-dependency": {
			IdentityKind: catalog.AssignmentDeploymentStageDependency,
			Stage:        "setup",
		},
		"sha256:service-docker": {
			IdentityKind: catalog.AssignmentServiceDockerConfig,
			Service:      "execution/service",
			Version:      "1.0.0",
			Instance:     "instance-0",
		},
		"sha256:service-application": {
			IdentityKind: catalog.AssignmentServiceApplicationConfig,
			Service:      "execution",
			Version:      "1.0.0",
			Instance:     "instance-0",
		},
		"sha256:service-instances": {
			IdentityKind: catalog.AssignmentServiceInstances,
			Service:      "execution",
			Version:      "1.0.0",
		},
		"sha256:sidecar-docker": {
			IdentityKind: catalog.AssignmentSidecarDockerConfig,
			Service:      "execution",
			Version:      "1.0.0",
			Instance:     "vault-agent",
		},
		"sha256:sidecar-instances": {
			IdentityKind: catalog.AssignmentSidecarInstances,
			Service:      "execution",
			Version:      "1.0.0",
		},
		"sha256:vault": catalog.RequiredWorkloadZoneVault(),
	}
}

func mustReadBody(t *testing.T, reader io.Reader) []byte {
	t.Helper()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return data
}

type certificateRequest struct {
	commonName string
	dnsNames   []string
	ipAddrs    []net.IP
	uris       []string
	clientAuth bool
}

func createCertificateAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate ca serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "ACS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}

func createLeafCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, request certificateRequest) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: request.commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    request.dnsNames,
		IPAddresses: request.ipAddrs,
	}

	if request.clientAuth {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	for _, rawURI := range request.uris {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatalf("parse uri %q: %v", rawURI, err)
		}
		template.URIs = append(template.URIs, parsed)
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
}

func writePEMFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pem file %s: %v", path, err)
	}
}
