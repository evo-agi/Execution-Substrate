package app_test

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The shared caller authentication rule holds over a real mutual-TLS
// connection: ES refuses a certificate with two URI SANs, and a path that
// only reads as allowed when trailing parts are trimmed, with 401.
func TestProducerContractCallerAuthenticationOverMutualTLS(t *testing.T) {
	stack := startStack(t, stackOptions{})

	tests := []struct {
		name       string
		uris       []string
		wantStatus int
	}{
		{name: "one conforming URI SAN", uris: []string{"spiffe://execution.internal/operator/local"}, wantStatus: http.StatusOK},
		{name: "two URI SANs", uris: []string{"spiffe://execution.internal/operator/local", "spiffe://execution.internal/service/deployment"}, wantStatus: http.StatusUnauthorized},
		{name: "trailing slash", uris: []string{"spiffe://execution.internal/operator/local/"}, wantStatus: http.StatusUnauthorized},
		{name: "query after slash", uris: []string{"spiffe://execution.internal/operator/local/?x=1"}, wantStatus: http.StatusUnauthorized},
		{name: "foreign trust domain", uris: []string{"spiffe://other.internal/operator/local"}, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := doJSONRequest(t, stack.es.Addr(), http.MethodGet, "/v1/executions:contract", stack.fixture.clientTLSConfigWithURIs(t, stack.fixture.esServerName, tt.uris...), nil)
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

func (f *tlsFixture) clientTLSConfigWithURIs(t *testing.T, serverName string, uris ...string) *tls.Config {
	t.Helper()

	cfg := f.clientTLSConfigForServer(t, serverName, "", false)
	parsed := make([]*url.URL, 0, len(uris))
	for _, uri := range uris {
		parsed = append(parsed, mustSPIFFEURL(t, uri))
	}
	clientCertPEM, clientKeyPEM := createLeafCertificate(t, f.runtimeCA, f.runtimeCAKey, "client.callerauth", parsed)
	certificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	cfg.Certificates = []tls.Certificate{certificate}
	return cfg
}
