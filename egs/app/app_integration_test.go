package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-platform/egs/app"
	"execution-platform/egs/config"
	"execution-platform/egs/model"
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

	path := filepath.Join(t.TempDir(), "egs.json")
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
	cfg := buildConfig(fixture)
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	payload = append(payload, []byte("\n{\"trailing\":true}\n")...)

	path := filepath.Join(t.TempDir(), "egs.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing data after first JSON document") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}

func TestNewRejectsMismatchedSigningKeyMaterial(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cfg := buildConfig(fixture)
	otherPublicKey := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(otherPublicKey); err != nil {
		t.Fatalf("generate mismatched public key: %v", err)
	}
	cfg.Signer.PublicKeyHex = hex.EncodeToString(otherPublicKey)
	cfgPath := writeConfig(t, cfg)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(loaded)
	if err == nil || !strings.Contains(err.Error(), "signer public key does not match private key") {
		t.Fatalf("expected mismatched signer key error, got %v", err)
	}
}

func TestValidTrustModelFetchReturnsVerifiableSignedPayload(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/trust-model", fixture.clientTLSConfig(t, "service/execution", false))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		RuntimeTrust struct {
			SignerPolicy struct {
				AllowedSigners []string `json:"allowed_signers"`
				RevokedSigners []string `json:"revoked_signers"`
			} `json:"signer_policy"`
			ArtifactPolicy struct {
				RevokedArtifacts []string `json:"revoked_artifacts"`
			} `json:"artifact_policy"`
		} `json:"runtime_trust"`
		Algorithm     string `json:"algorithm"`
		KeyID         string `json:"key_id"`
		PayloadDigest string `json:"payload_digest"`
		Signature     string `json:"signature"`
		Publication   struct {
			Version        string `json:"version"`
			UpdateRevision int    `json:"update_revision"`
		} `json:"publication"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Algorithm != "ed25519" {
		t.Fatalf("unexpected algorithm: %q", payload.Algorithm)
	}
	if payload.KeyID != fixture.keyID {
		t.Fatalf("unexpected key id: %q", payload.KeyID)
	}
	if payload.Publication.Version != "1.0.0" || payload.Publication.UpdateRevision != 7 {
		t.Fatalf("unexpected publication metadata: %+v", payload.Publication)
	}

	canonical := canonicalRuntimeTrustBytes(payload.RuntimeTrust)
	expectedSum := sha256.Sum256(canonical)
	expectedDigest := "sha256:" + hex.EncodeToString(expectedSum[:])
	if payload.PayloadDigest != expectedDigest {
		t.Fatalf("unexpected payload digest: %q", payload.PayloadDigest)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(fixture.publicKey, canonical, signatureBytes) {
		t.Fatalf("expected signature verification to succeed")
	}
}

func TestUnauthorizedCallerReturns401(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/trust-model", fixture.clientTLSConfig(t, "", false))
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Authenticated caller identity required" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestDisallowedCallerReturns403(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/trust-model", fixture.clientTLSConfig(t, "service/deployment", false))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Caller not authorized for this operation" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestBootstrapPKICallerReturns403(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/trust-model", fixture.clientTLSConfig(t, "service/execution", true))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestPayloadDigestIsDeterministicAcrossSignerOrdering(t *testing.T) {
	fixture := newTLSFixture(t)

	cfgA := buildConfig(fixture)
	cfgB := buildConfig(fixture)
	cfgB.RuntimeTrust.SignerPolicy.AllowedSigners = []string{"ags-artifact-fact-signer-b", "ags-artifact-fact-signer-a"}
	cfgB.RuntimeTrust.SignerPolicy.RevokedSigners = []string{"ags-signing-key-compromised", "ags-signing-key-old"}
	cfgA.RuntimeTrust.SignerPolicy.RevokedSigners = []string{"ags-signing-key-old", "ags-signing-key-compromised"}
	cfgB.RuntimeTrust.ArtifactPolicy.RevokedArtifacts = []string{cfgA.RuntimeTrust.ArtifactPolicy.RevokedArtifacts[1], cfgA.RuntimeTrust.ArtifactPolicy.RevokedArtifacts[0]}

	serviceA := startTestApp(t, fixture, cfgA)
	serviceB := startTestApp(t, fixture, cfgB)

	digestA, signatureA := fetchTrustModelDigestAndSignature(t, fixture, serviceA.Addr())
	digestB, signatureB := fetchTrustModelDigestAndSignature(t, fixture, serviceB.Addr())

	if digestA != digestB {
		t.Fatalf("expected equal payload digests, got %q vs %q", digestA, digestB)
	}
	if signatureA != signatureB {
		t.Fatalf("expected deterministic signatures, got %q vs %q", signatureA, signatureB)
	}
}

func TestPayloadDigestIgnoresPublicationMetadata(t *testing.T) {
	fixture := newTLSFixture(t)

	cfgA := buildConfig(fixture)
	cfgB := buildConfig(fixture)
	cfgB.Publication.Version = "2.4.0"
	cfgB.Publication.UpdateRevision = 99

	serviceA := startTestApp(t, fixture, cfgA)
	serviceB := startTestApp(t, fixture, cfgB)

	digestA, signatureA := fetchTrustModelDigestAndSignature(t, fixture, serviceA.Addr())
	digestB, signatureB := fetchTrustModelDigestAndSignature(t, fixture, serviceB.Addr())

	if digestA != digestB {
		t.Fatalf("expected equal payload digests, got %q vs %q", digestA, digestB)
	}
	if signatureA != signatureB {
		t.Fatalf("expected identical signatures, got %q vs %q", signatureA, signatureB)
	}
}

func TestHealthReturnsExpectedShape(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	response := doRequest(t, service.Addr(), http.MethodGet, "/health", fixture.clientTLSConfig(t, "", false))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Status               string `json:"status"`
		Ready                bool   `json:"ready"`
		Service              string `json:"service"`
		AdditionalProperties struct {
			Readiness struct {
				Signer     string `json:"signer"`
				TrustModel string `json:"trust_model"`
			} `json:"readiness"`
		} `json:"additional_properties"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if payload.Status != "healthy" || !payload.Ready {
		t.Fatalf("unexpected health status: %+v", payload)
	}
	if payload.Service != "execution-governance" {
		t.Fatalf("unexpected service name: %q", payload.Service)
	}
	if payload.AdditionalProperties.Readiness.Signer != "initialized" {
		t.Fatalf("unexpected signer readiness: %q", payload.AdditionalProperties.Readiness.Signer)
	}
	if payload.AdditionalProperties.Readiness.TrustModel != "loaded" {
		t.Fatalf("unexpected trust model readiness: %q", payload.AdditionalProperties.Readiness.TrustModel)
	}
}

func fetchTrustModelDigestAndSignature(t *testing.T, fixture *tlsFixture, addr string) (string, string) {
	t.Helper()

	response := doRequest(t, addr, http.MethodGet, "/v1/trust-model", fixture.clientTLSConfig(t, "service/execution", false))
	defer response.Body.Close()

	var payload struct {
		PayloadDigest string `json:"payload_digest"`
		Signature     string `json:"signature"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode trust model response: %v", err)
	}
	return payload.PayloadDigest, payload.Signature
}

func startTestApp(t *testing.T, fixture *tlsFixture, cfg config.Config) *app.App {
	t.Helper()

	cfgPath := writeConfig(t, cfg)
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	service, err := app.New(loaded)
	if err != nil {
		t.Fatalf("build app: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	if _, err := service.Start(ctx); err != nil {
		t.Fatalf("start app: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := service.Shutdown(shutdownCtx); err != nil {
			t.Fatalf("shutdown app: %v", err)
		}
	})

	waitForHealthy(t, service.Addr(), fixture.clientTLSConfig(t, "", false))
	return service
}

func waitForHealthy(t *testing.T, addr string, tlsConfig *tls.Config) {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://" + addr + "/health")
		if err == nil {
			var payload struct {
				Ready bool `json:"ready"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			response.Body.Close()
			if decodeErr == nil && response.StatusCode == http.StatusOK && payload.Ready {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("service at %s did not become healthy", addr)
}

func doRequest(t *testing.T, addr string, method string, path string, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	request, err := http.NewRequest(method, "https://"+addr+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return response
}

func mustReadBody(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()

	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return payload
}

func writeConfig(t *testing.T, cfg config.Config) string {
	t.Helper()

	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "egs.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func buildConfig(fixture *tlsFixture) config.Config {
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
			ClientCAFile: fixture.clientCAPath,
		},
		Security: config.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Signer: config.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.keyID,
			PrivateKeyHex: fixture.privateKeyHex,
			PublicKeyHex:  fixture.publicKeyHex,
		},
		RuntimeTrust: model.RuntimeTrustPolicy{
			SignerPolicy: model.SignerPolicy{
				AllowedSigners: []string{
					"ags-artifact-fact-signer-a",
					"ags-artifact-fact-signer-b",
				},
				RevokedSigners: []string{
					"ags-signing-key-old",
					"ags-signing-key-compromised",
				},
			},
			ArtifactPolicy: model.ArtifactPolicy{
				RevokedArtifacts: []string{
					"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			},
		},
		Publication: model.PublicationMetadata{
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
}

type tlsFixture struct {
	serverCertPath string
	serverKeyPath  string
	clientCAPath   string
	runtimeCA      *x509.Certificate
	runtimeCAKey   *rsa.PrivateKey
	bootstrapCA    *x509.Certificate
	bootstrapCAKey *rsa.PrivateKey
	publicKey      ed25519.PublicKey
	privateKeyHex  string
	publicKeyHex   string
	keyID          string
	bootstrapCACN  string
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()

	runtimeCA, runtimeCAKey, runtimeCAPEM := createCertificateAuthority(t, "runtime-ca")
	bootstrapCA, bootstrapCAKey, bootstrapCAPEM := createCertificateAuthority(t, "bootstrap-ca")
	serverCertPEM, serverKeyPEM := createLeafCertificate(t, runtimeCA, runtimeCAKey, "server.execution-governance.internal", nil)

	serverCertPath := filepath.Join(t.TempDir(), "server-cert.pem")
	serverKeyPath := filepath.Join(t.TempDir(), "server-key.pem")
	clientCAPath := filepath.Join(t.TempDir(), "client-ca.pem")

	if err := os.WriteFile(serverCertPath, serverCertPEM, 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyPath, serverKeyPEM, 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	combinedClientCAs := append(append([]byte(nil), runtimeCAPEM...), bootstrapCAPEM...)
	if err := os.WriteFile(clientCAPath, combinedClientCAs, 0o600); err != nil {
		t.Fatalf("write client ca bundle: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	return &tlsFixture{
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		clientCAPath:   clientCAPath,
		runtimeCA:      runtimeCA,
		runtimeCAKey:   runtimeCAKey,
		bootstrapCA:    bootstrapCA,
		bootstrapCAKey: bootstrapCAKey,
		publicKey:      publicKey,
		privateKeyHex:  hex.EncodeToString(privateKey),
		publicKeyHex:   hex.EncodeToString(publicKey),
		keyID:          "egs-trust-model-signer",
		bootstrapCACN:  "bootstrap-ca",
	}
}

func (f *tlsFixture) clientTLSConfig(t *testing.T, spiffePath string, bootstrap bool) *tls.Config {
	t.Helper()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(f.runtimeCA)

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: "server.execution-governance.internal",
	}

	if strings.TrimSpace(spiffePath) == "" {
		return cfg
	}

	issuer := f.runtimeCA
	issuerKey := f.runtimeCAKey
	if bootstrap {
		issuer = f.bootstrapCA
		issuerKey = f.bootstrapCAKey
	}

	clientCertPEM, clientKeyPEM := createLeafCertificate(
		t,
		issuer,
		issuerKey,
		"client."+strings.ReplaceAll(strings.Trim(spiffePath, "/"), "/", "."),
		[]*url.URL{
			mustSPIFFEURL(t, "spiffe://monolith.internal/"+strings.Trim(spiffePath, "/")),
		},
	)
	certificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	cfg.Certificates = []tls.Certificate{certificate}

	return cfg
}

func createCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func createLeafCertificate(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *rsa.PrivateKey,
	commonName string,
	uris []*url.URL,
) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{commonName},
		URIs:        uris,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &privateKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM
}

func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}
	return value
}

func mustSPIFFEURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse SPIFFE URL: %v", err)
	}
	return parsed
}

func canonicalRuntimeTrustBytes(payload struct {
	SignerPolicy struct {
		AllowedSigners []string `json:"allowed_signers"`
		RevokedSigners []string `json:"revoked_signers"`
	} `json:"signer_policy"`
	ArtifactPolicy struct {
		RevokedArtifacts []string `json:"revoked_artifacts"`
	} `json:"artifact_policy"`
}) []byte {
	encoded, err := model.RuntimeTrustPolicy{
		SignerPolicy: model.SignerPolicy{
			AllowedSigners: append([]string(nil), payload.SignerPolicy.AllowedSigners...),
			RevokedSigners: append([]string(nil), payload.SignerPolicy.RevokedSigners...),
		},
		ArtifactPolicy: model.ArtifactPolicy{
			RevokedArtifacts: append([]string(nil), payload.ArtifactPolicy.RevokedArtifacts...),
		},
	}.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	return encoded
}
