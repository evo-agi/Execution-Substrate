package app_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The shared caller authentication rule holds over a real mutual-TLS
// connection: a certificate with two URI SANs is refused with 401.
func TestTrustModelCallerAuthenticationOverMutualTLS(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	tests := []struct {
		name       string
		uris       []string
		wantStatus int
	}{
		{name: "one conforming URI SAN", uris: []string{"spiffe://execution.internal/service/execution"}, wantStatus: http.StatusOK},
		{name: "two URI SANs", uris: []string{"spiffe://execution.internal/service/execution", "spiffe://execution.internal/service/deployment"}, wantStatus: http.StatusUnauthorized},
		{name: "two URI SANs foreign first", uris: []string{"spiffe://other.internal/service/execution", "spiffe://execution.internal/service/execution"}, wantStatus: http.StatusUnauthorized},
		{name: "dot dot segment", uris: []string{"spiffe://execution.internal/service/execution/.."}, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, "/v1/trust-model", fixture.clientTLSConfigWithURIs(t, tt.uris...))
			defer response.Body.Close()
			body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
			if response.StatusCode != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, response.StatusCode, body)
			}
			if tt.wantStatus == http.StatusUnauthorized && body != "Authenticated caller identity required" {
				t.Fatalf("unexpected 401 body: %q", body)
			}
		})
	}
}

func (f *tlsFixture) clientTLSConfigWithURIs(t *testing.T, uris ...string) *tls.Config {
	t.Helper()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(f.runtimeCA)
	parsed := make([]*url.URL, 0, len(uris))
	for _, uri := range uris {
		parsed = append(parsed, mustSPIFFEURL(t, uri))
	}
	clientCertPEM, clientKeyPEM := createLeafCertificate(t, f.runtimeCA, f.runtimeCAKey, "client.callerauth", parsed)
	certificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
		ServerName:   "server.execution-governance.internal",
		Certificates: []tls.Certificate{certificate},
	}
}
