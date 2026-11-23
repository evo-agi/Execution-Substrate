package app_test

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// The shared caller authentication rule holds over a real mutual-TLS
// connection. CGS used to accept a caller identity from any trust domain
// and to read the first SPIFFE URI SAN of a certificate with several.
func TestAuthorizeCallerAuthenticationOverMutualTLS(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, checkedInIDConfContents(t))

	tests := []struct {
		name       string
		uris       []string
		workloadID string
		wantStatus int
	}{
		{name: "one conforming URI SAN", uris: []string{"spiffe://execution.internal/service/execution"}, workloadID: "spiffe://execution.internal/service/execution", wantStatus: http.StatusOK},
		{name: "two URI SANs", uris: []string{"spiffe://execution.internal/service/execution", "spiffe://execution.internal/script/bot_test_privileged"}, workloadID: "spiffe://execution.internal/service/execution", wantStatus: http.StatusUnauthorized},
		{name: "foreign trust domain naming itself", uris: []string{"spiffe://other.internal/service/execution"}, workloadID: "spiffe://other.internal/service/execution", wantStatus: http.StatusUnauthorized},
		{name: "trust domain only", uris: []string{"spiffe://execution.internal"}, workloadID: "spiffe://execution.internal", wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]any{
				"workload": map[string]any{
					"type":                 "service",
					"workload_identity_id": tt.workloadID,
				},
				"requested_capabilities": []string{"vault:read"},
			}
			response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/credential/authorize", body, fixture.clientTLSConfigWithURIs(t, tt.uris...))
			defer response.Body.Close()
			got := string(mustReadBody(t, response.Body))
			if response.StatusCode != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, response.StatusCode, strings.TrimSpace(got))
			}
			if tt.wantStatus == http.StatusUnauthorized && got != "Authenticated caller identity required" {
				t.Fatalf("unexpected 401 body: %q", got)
			}
		})
	}
}

func (f tlsFixture) clientTLSConfigWithURIs(t *testing.T, uris ...string) *tls.Config {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, f.normalCACert, f.normalCAKey, certificateRequest{
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
