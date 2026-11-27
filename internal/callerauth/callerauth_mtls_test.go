package callerauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
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
// client's certificates leaf first, with key. With connection set, the server
// accepts connections through callerauth.NewListener, sets
// callerauth.ConnContext as its ConnContext hook and the handler calls
// AuthenticateConnection, as ES does; otherwise it serves TLS with Go's
// listener and the handler calls Authenticate, as the other four services
// do.
func serveMutualTLS(t *testing.T, root testCA, chain [][]byte, key *ecdsa.PrivateKey, connection bool) (int, string) {
	t.Helper()
	return serveMutualTLSWith(t, root, chain, key, connection, nil, nil)
}

// serveMutualTLSWith is serveMutualTLS for a request that carries header,
// where the handler first passes the request to before, when it is set.
func serveMutualTLSWith(t *testing.T, root testCA, chain [][]byte, key *ecdsa.PrivateKey, connection bool, header http.Header, before func(t *testing.T, r *http.Request)) (int, string) {
	t.Helper()
	auth := callerauth.NewAuthenticator("callerauth-mtls-bootstrap")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if before != nil {
			before(t, r)
		}
		var id callerauth.SPIFFEID
		if connection {
			caller, ok := auth.AuthenticateConnection(w, r)
			if !ok {
				return
			}
			id = caller.ID()
		} else {
			caller, ok := auth.Authenticate(w, r)
			if !ok {
				return
			}
			id = caller.ID()
		}
		io.WriteString(w, id.String())
	}))
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	serverCert := newServerCertificate(t)
	config := &tls.Config{Certificates: []tls.Certificate{serverCert.pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	if connection {
		listener, err := callerauth.NewListener(server.Listener, config)
		if err != nil {
			t.Fatal(err)
		}
		// NewListener copied config: a callback set on it now never runs.
		config.VerifyConnection = func(tls.ConnectionState) error {
			return errors.New("the listener used the TLS configuration after NewListener copied it")
		}
		server.Listener = listener
		server.Config.ConnContext = callerauth.ConnContext
		server.Start()
	} else {
		server.TLS = config
		server.StartTLS()
	}
	defer server.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      serverCert.roots,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, "https://"+server.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := client.Do(request)
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

type serverCertificate struct {
	pair  tls.Certificate
	roots *x509.CertPool
}

// newServerCertificate returns a self-signed certificate for 127.0.0.1, the
// address httptest listens on, and a pool that trusts it.
func newServerCertificate(t *testing.T) serverCertificate {
	t.Helper()
	key := newTestKey(t)
	cert := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "callerauth-mtls-server"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, key, nil)
	roots := x509.NewCertPool()
	roots.AddCert(cert.cert)
	return serverCertificate{pair: tls.Certificate{Certificate: [][]byte{cert.der}, PrivateKey: key, Leaf: cert.cert}, roots: roots}
}

// bothReadPaths runs check for Authenticate behind Go's TLS listener, and for
// AuthenticateConnection behind callerauth.NewListener and ConnContext.
func bothReadPaths(t *testing.T, check func(t *testing.T, connection bool)) {
	t.Run("request", func(t *testing.T) { check(t, false) })
	t.Run("connection", func(t *testing.T) { check(t, true) })
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

	bothReadPaths(t, func(t *testing.T, connection bool) {
		status, body := serveMutualTLS(t, root, [][]byte{intermediate.der}, key, connection)
		if status != http.StatusUnauthorized || body != unauthenticatedBody {
			t.Fatalf("CA certificate as the client certificate: %d %q, want 401 %q", status, body, unauthenticatedBody)
		}
	})
}

// The same refusal when the CA certificate sits below an intermediate and
// the client sends both, as a client with a SPIRE-shaped chain would. Found
// by the re-audit of the A2-1 repair (O4-1).
func TestAuthenticateRefusesACACertificateBelowAnIntermediate(t *testing.T) {
	root := newRootCA(t)
	intermediate := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-intermediate"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal")},
	}, newTestKey(t), &root)
	key := newTestKey(t)
	signer := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-signing-leaf"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal/operator/local")},
	}, key, &intermediate)

	bothReadPaths(t, func(t *testing.T, connection bool) {
		status, body := serveMutualTLS(t, root, [][]byte{signer.der, intermediate.der}, key, connection)
		if status != http.StatusUnauthorized || body != unauthenticatedBody {
			t.Fatalf("CA certificate below an intermediate: %d %q, want 401 %q", status, body, unauthenticatedBody)
		}
	})
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
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-leaf"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal/operator/local")},
	}, leafKey, &intermediate)

	bothReadPaths(t, func(t *testing.T, connection bool) {
		status, body := serveMutualTLS(t, root, [][]byte{leaf.der, intermediate.der}, leafKey, connection)
		if status != http.StatusOK || body != "spiffe://execution.internal/operator/local" {
			t.Fatalf("leaf and intermediate: %d %q, want 200 with the leaf's ID", status, body)
		}
	})
}

// A handler cannot change the caller that AuthenticateConnection reads: the
// request carries no TLS state, so decoding into the request, or editing
// whatever TLS state it then holds, reaches nothing the connection's caller
// is read from. Before callerauth.NewListener, r.TLS shared the verified
// certificates with the connection, and both edits below changed the caller
// (report 34, A34-1).
func TestAHandlerCannotChangeTheCallerOfItsConnection(t *testing.T) {
	root := newRootCA(t)
	leafKey := newTestKey(t)
	leaf := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "callerauth-mtls-leaf"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{mustURL(t, "spiffe://execution.internal/operator/local")},
	}, leafKey, &root)
	const forged = `{"TLS":{"VerifiedChains":[[{"URIs":[{"Scheme":"spiffe","Host":"execution.internal","Path":"/service/control-plane"}]}]]}}`
	before := func(t *testing.T, r *http.Request) {
		if r.TLS != nil {
			t.Errorf("the request carries the connection's TLS state")
		}
		if err := json.Unmarshal([]byte(r.Header.Get("X-Forged")), r); err != nil {
			t.Errorf("decode into the request: %v", err)
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			t.Fatalf("the decoded request has no verified chain")
		}
		r.TLS.VerifiedChains[0][0].URIs = []*url.URL{{Scheme: "spiffe", Host: "execution.internal", Path: "/service/control-plane"}}
	}
	status, body := serveMutualTLSWith(t, root, [][]byte{leaf.der}, leafKey, true, http.Header{"X-Forged": {forged}}, before)
	if status != http.StatusOK || body != "spiffe://execution.internal/operator/local" {
		t.Fatalf("after the handler's edits: %d %q, want 200 with the leaf's ID", status, body)
	}
}
