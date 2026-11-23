package callerauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"execution-substrate/internal/callerauth"
)

// These tests run Authenticate behind a real TLS listener that requires and
// verifies a client certificate, as the five services' listeners do, so Go's
// certificate verifier decides which chains reach the check.

type testCA struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// issue signs template with issuer, or self-signs it when issuer is nil.
func issue(t *testing.T, template *x509.Certificate, key *ecdsa.PrivateKey, issuer *testCA) testCA {
	t.Helper()
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, der: der, key: key}
}

func newRootCA(t *testing.T) testCA {
	t.Helper()
	return issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-root"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, newTestKey(t), nil)
}

// serveMutualTLS starts a TLS server that requires a client certificate
// verified against root and answers 200 with the authenticated caller's ID.
// It returns the status and body of one request that presents chain, the
// client's certificates leaf first, with key.
func serveMutualTLS(t *testing.T, root testCA, chain [][]byte, key *ecdsa.PrivateKey) (int, string) {
	t.Helper()
	auth := callerauth.NewAuthenticator("callerauth-mtls-bootstrap")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := auth.Authenticate(w, r)
		if !ok {
			return
		}
		io.WriteString(w, caller.ID().String())
	}))
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{Certificate: chain, PrivateKey: key}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("handshake or request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

// X.509-SVID section 5.2: a CA certificate that carries an ES identity must
// not authenticate as that caller, although Go's verifier accepts it as the
// client certificate (it has no extended key usage). Found by the audit of
// PR 27 (A2-1).
func TestAuthenticateRefusesACACertificatePresentedAsTheClientCertificate(t *testing.T) {
	root := newRootCA(t)
	key := newTestKey(t)
	intermediate := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-intermediate"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal/operator/local")},
	}, key, &root)

	status, body := serveMutualTLS(t, root, [][]byte{intermediate.der}, key)
	if status != http.StatusUnauthorized || body != unauthenticatedBody {
		t.Fatalf("CA certificate as the client certificate: %d %q, want 401 %q", status, body, unauthenticatedBody)
	}
}

// A SPIRE-style client chain: the leaf carries the caller's ID and the
// intermediate CA carries only the trust domain's ID. The caller is the leaf,
// never the intermediate or the last certificate the client sent.
func TestAuthenticateReadsTheLeafOfAClientChainWithAnIntermediate(t *testing.T) {
	root := newRootCA(t)
	intermediate := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-intermediate"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal")},
	}, newTestKey(t), &root)
	leafKey := newTestKey(t)
	leaf := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "callerauth-mtls-leaf"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustURL(t, "spiffe://execution.internal/operator/local")},
	}, leafKey, &intermediate)

	status, body := serveMutualTLS(t, root, [][]byte{leaf.der, intermediate.der}, leafKey)
	if status != http.StatusOK || body != "spiffe://execution.internal/operator/local" {
		t.Fatalf("leaf and intermediate: %d %q, want 200 with the leaf's ID", status, body)
	}
}
