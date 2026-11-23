package app_test

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The shared caller authentication rule holds over a real mutual-TLS
// connection: a certificate with two URI SANs is refused with 401 before
// AGS publishes anything.
func TestPublishCallerAuthenticationOverMutualTLS(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	tests := []struct {
		name       string
		uris       []string
		wantStatus int
	}{
		{name: "two URI SANs", uris: []string{"spiffe://execution.internal/" + operatorCallerPath, "spiffe://execution.internal/service/deployment"}, wantStatus: http.StatusUnauthorized},
		{name: "foreign trust domain", uris: []string{"spiffe://other.internal/" + operatorCallerPath}, wantStatus: http.StatusUnauthorized},
		{name: "fragment after slash", uris: []string{"spiffe://execution.internal/" + operatorCallerPath + "/#x"}, wantStatus: http.StatusUnauthorized},
		{name: "one conforming URI SAN", uris: []string{"spiffe://execution.internal/" + operatorCallerPath}, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := doJSONRequest(t, stack.ags.Addr(), http.MethodPost, "/v1/artifacts:publish", stack.fixture.clientTLSConfigWithURIs(t, stack.fixture.agsServerName, tt.uris...), mustMarshalJSON(t, buildPublishRequestBody(t, stack)))
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
