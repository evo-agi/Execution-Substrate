package app_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Go's TLS server verifies a client certificate once, at the handshake. A
// client that kept its connection busy used to stay authenticated after its
// certificate expired (red-team finding R2 of the caller authentication
// change). This is the red-team's probe as a regression test: the real EGS
// app with its real TLS configuration, a client leaf that expires a few
// seconds after the handshake, and one keep-alive connection. A request on
// that connection after the certificate expired gets 401, and a new
// connection fails the handshake.
func TestTrustModelRefusesARequestOnAConnectionWhoseClientCertificateHasExpired(t *testing.T) {
	fixture := newTLSFixture(t)
	service := startTestApp(t, fixture, buildConfig(fixture))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	// Certificates carry whole seconds, so NotAfter is two to three seconds
	// from now.
	notAfter := time.Now().Add(3 * time.Second).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject:      pkix.Name{CommonName: "client.expiring"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/execution")},
	}, fixture.runtimeCA, &key.PublicKey, fixture.runtimeCAKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(fixture.runtimeCA)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		ServerName:   "server.execution-governance.internal",
		Certificates: []tls.Certificate{pair},
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}

	get := func() (status int, body string, reused bool, err error) {
		request, err := http.NewRequest(http.MethodGet, "https://"+service.Addr()+"/v1/trust-model", nil)
		if err != nil {
			return 0, "", false, err
		}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
		}))
		response, err := client.Do(request)
		if err != nil {
			return 0, "", reused, err
		}
		defer response.Body.Close()
		return response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))), reused, nil
	}

	t.Logf("client certificate NotAfter %s", notAfter.UTC().Format(time.RFC3339))
	if status, body, _, err := get(); err != nil || status != http.StatusOK {
		t.Fatalf("first request inside the validity period: status %d body %q error %v", status, body, err)
	}
	// Keep the connection busy across NotAfter, as the probe did, so that the
	// server's read timeout never closes it.
	for time.Now().Before(notAfter.Add(time.Second)) {
		time.Sleep(500 * time.Millisecond)
		sent := time.Now()
		status, body, reused, err := get()
		t.Logf("%s reused=%v status=%d", sent.UTC().Format("15:04:05.000"), reused, status)
		if err != nil {
			t.Fatalf("request at %s: %v", sent.UTC().Format(time.RFC3339Nano), err)
		}
		if !reused {
			t.Fatalf("request at %s opened a new connection; the test needs one connection that outlives the certificate", sent.UTC().Format(time.RFC3339Nano))
		}
		if sent.Before(notAfter.Add(-500*time.Millisecond)) && status != http.StatusOK {
			t.Fatalf("request at %s, inside the validity period: status %d body %q", sent.UTC().Format(time.RFC3339Nano), status, body)
		}
	}

	status, body, reused, err := get()
	if err != nil || !reused {
		t.Fatalf("request after NotAfter: reused connection %v, error %v", reused, err)
	}
	if status != http.StatusUnauthorized || body != "Authenticated caller identity required" {
		t.Fatalf("request on the same connection after the client certificate expired: status %d body %q, want 401", status, body)
	}

	transport.CloseIdleConnections()
	if status, _, _, err := get(); err == nil {
		t.Fatalf("new connection with the expired client certificate: status %d, want a failed handshake", status)
	}
}
