package app_test

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// The shared caller authentication rule holds over a real mutual-TLS
// connection: Go's TLS stack hands ARS a certificate with two URI SANs, or
// with an identity from another trust domain, and ARS refuses it with 401.
func TestReadCallerAuthenticationOverMutualTLS(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	tests := []struct {
		name       string
		uris       []string
		wantStatus int
	}{
		{name: "one conforming URI SAN", uris: []string{"spiffe://execution.internal/service/execution"}, wantStatus: http.StatusOK},
		{name: "two URI SANs", uris: []string{"spiffe://execution.internal/service/execution", "spiffe://execution.internal/service/deployment"}, wantStatus: http.StatusUnauthorized},
		{name: "foreign trust domain", uris: []string{"spiffe://other.internal/service/execution"}, wantStatus: http.StatusUnauthorized},
		{name: "trailing slash", uris: []string{"spiffe://execution.internal/service/execution/"}, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.BlobDigest+":bytes", fixture.clientTLSConfigWithURIs(t, tt.uris...))
			defer response.Body.Close()
			body := string(mustReadBody(t, response.Body))
			if response.StatusCode != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, response.StatusCode, strings.TrimSpace(body))
			}
			if tt.wantStatus == http.StatusUnauthorized && body != "Authenticated caller identity required" {
				t.Fatalf("unexpected 401 body: %q", body)
			}
		})
	}
}

func (f tlsFixture) clientTLSConfigWithURIs(t *testing.T, uris ...string) *tls.Config {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, f.runtimeCA, f.runtimeCAKey, certificateRequest{
		commonName: "client",
		uris:       uris,
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
