package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	esconfig "execution-substrate/es/config"
)

// TestDependencyClientsDoNotFollowRedirects builds the ARS and EGS clients
// with the production constructor and points them at a dependency that
// answers with redirects: to a plain-HTTP origin, and to another path on the
// dependency itself. ES must treat every redirect as the dependency's answer:
// no request may reach the address it names, the verified blob read reports
// an unexpected status, and the discovery read refuses. A followed redirect
// would let a compromised dependency make ES send GET requests to any host
// and port it can reach, over cleartext, and learn their status through ES's
// errors. The same-origin case pins that the rule is "never follow", not only
// "never leave the dependency" or "never downgrade to HTTP".
func TestDependencyClientsDoNotFollowRedirects(t *testing.T) {
	var otherMu sync.Mutex
	var otherHits []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherMu.Lock()
		otherHits = append(otherHits, r.Method+" "+r.URL.Path)
		otherMu.Unlock()
		_, _ = w.Write([]byte("{}"))
	}))
	defer other.Close()

	var sameOriginMu sync.Mutex
	var sameOriginHits []string
	dependency := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/same-origin":
			http.Redirect(w, r, "/v1/landed", http.StatusTemporaryRedirect)
		case "/v1/landed":
			sameOriginMu.Lock()
			sameOriginHits = append(sameOriginHits, r.Method+" "+r.URL.Path)
			sameOriginMu.Unlock()
			_, _ = w.Write([]byte("{}"))
		default:
			http.Redirect(w, r, other.URL+"/elsewhere"+r.URL.Path, http.StatusFound)
		}
	}))
	dependency.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	dependency.StartTLS()
	defer dependency.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dependency.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "es-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyConfig := esconfig.DependencyConfig{
		BaseURL:        dependency.URL,
		ServerName:     "example.com",
		ClientCertFile: certFile,
		ClientKeyFile:  keyFile,
		RootCAFile:     caFile,
		TimeoutSeconds: 5,
	}

	for _, name := range []string{"artifact-registry", "execution-governance"} {
		t.Run(name, func(t *testing.T) {
			client, err := newDependencyClient(dependencyConfig, name)
			if err != nil {
				t.Fatal(err)
			}
			for endpoint, wantStatus := range map[string]int{
				"/v1/anything":    http.StatusFound,
				"/v1/same-origin": http.StatusTemporaryRedirect,
			} {
				response, err := client.get(context.Background(), endpoint)
				if err != nil {
					t.Fatalf("redirect answer for %s was not returned to the caller: %v", endpoint, err)
				}
				_ = response.Body.Close()
				if response.StatusCode != wantStatus {
					t.Fatalf("dependency client followed the redirect for %s: final status %d", endpoint, response.StatusCode)
				}
			}
		})
	}

	ars, err := newDependencyClient(dependencyConfig, "artifact-registry")
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{arsClient: ars}
	blob := []byte("{}")
	digest := digestBytes(blob)
	got, fetchErr := service.fetchVerifiedARSBlob(context.Background(), digest, arsBlobViewJSON, maxDependencyJSONResponseBytes)
	if fetchErr == nil || fetchErr.failure != arsBlobUnexpectedStatus || fetchErr.status != http.StatusFound || got != nil {
		t.Fatalf("verified read of a redirect = bytes %q, err %+v; want unexpected status 302 and no bytes", got, fetchErr)
	}
	if _, discoveryErr := service.fetchArtifactDiscoveryRecord(context.Background(), digest); discoveryErr == nil || discoveryErr.Code != codeArtifactEvidenceUnavailable {
		t.Fatalf("discovery read of a redirect = %+v; want %s", discoveryErr, codeArtifactEvidenceUnavailable)
	}

	otherMu.Lock()
	defer otherMu.Unlock()
	if len(otherHits) != 0 {
		t.Fatalf("ES sent requests to the redirect target: %v", otherHits)
	}
	sameOriginMu.Lock()
	defer sameOriginMu.Unlock()
	if len(sameOriginHits) != 0 {
		t.Fatalf("ES followed a same-origin redirect: %v", sameOriginHits)
	}
}
